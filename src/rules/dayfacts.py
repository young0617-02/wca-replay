"""把打卡/请假/出差/补卡原始事件归并成「工作日事实」，含跨天班次切分。

这一步是纯确定性的算术，输入顺序无关（结果按时间排序后归并），因此重跑必然一致（A8）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta

from ..config import Config
from ..db import Connection, Row
from ..util import CN_TZ, clamp_minutes, iso_minute, parse_date, parse_timestamp
from .holidays import (
    DAY_PLAIN_REST,
    DAY_UNKNOWN,
    DAY_WORKDAY,
    DayInfo,
    HolidayCalendar,
    YearNotCovered,
)

NIGHT_WINDOW = (time(0, 0), time(6, 0))


@dataclass
class PunchEvent:
    ts: datetime
    punch_type: str
    raw_text: str
    file_id: int | None
    line_no: int | None
    rel_path: str | None = None
    device_id: str = ""
    from_correction: bool = False

    @property
    def key(self) -> tuple:
        return (self.ts, 0 if self.from_correction else 1, self.raw_text)


@dataclass
class DayFacts:
    emp_id: str
    work_date: date
    day_type: str
    holiday_label: str = ""
    in_ts: datetime | None = None
    out_ts: datetime | None = None
    punch_count: int = 0
    minutes_span: int = 0
    minutes_rest: int = 0
    minutes_worked: int = 0
    minutes_leave: int = 0
    minutes_trip: int = 0
    minutes_night: int = 0
    crossed_midnight: bool = False
    quality_flags: list[str] = field(default_factory=list)
    source_refs: list[dict] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)  # OFF-01：同时点同类型的多来源冲突
    plan_present: bool = False                           # SHIFT-01：是否有排班计划
    regime: str = "standard"
    comp_time_granted: bool = False
    planned_minutes: int = 0
    notice_doc_id: str = ""
    ambiguous_day_type: bool = False
    workday_arrangement_unverified: bool = False

    def as_metric(self) -> dict:
        return {
            "day_type": self.day_type,
            "regime": self.regime,
            "minutes_span": self.minutes_span,
            "minutes_rest": self.minutes_rest,
            "minutes_worked": self.minutes_worked,
            "minutes_leave": self.minutes_leave,
            "minutes_trip": self.minutes_trip,
            "minutes_night": self.minutes_night,
            "punch_count": self.punch_count,
            "crossed_midnight": int(self.crossed_midnight),
            "comp_time_granted": int(self.comp_time_granted),
            "planned_minutes": self.planned_minutes,
            "ambiguous_day_type": int(self.ambiguous_day_type),
            "quality_flags": sorted(self.quality_flags),
        }


def _anchor_day(ts: datetime, cut_hour: int) -> date:
    """跨天切分口径：cut_hour 之前（含 00:00–cut_hour）的打卡归属「前一工作日」。

    默认 06:00。该口径需与 HR 实际排班表对齐，属【待确认】项，见 docs/待确认清单.md。
    """
    if ts.hour < cut_hour:
        return (ts - timedelta(days=1)).date()
    return ts.date()


def _overlap_minutes_night(start: datetime, end: datetime, work_date: date) -> int:
    """夜间时段工时：跨零点班次需同时统计「当日凌晨」与「次日凌晨」两段。"""
    total = 0
    for day in (work_date, work_date + timedelta(days=1)):
        n_start = datetime.combine(day, time(0, 0), tzinfo=CN_TZ)
        n_end = n_start + timedelta(hours=NIGHT_WINDOW[1].hour)
        s = max(start, n_start)
        e = min(end, n_end)
        if e > s:
            total += int((e - s).total_seconds() // 60)
    return total


@dataclass
class EmployeeBundle:
    """一个员工的全部原始事实一次性载入内存，之后逐日计算不再碰数据库（O-1 消除 N+1）。

    与旧的逐日查询版语义等价：同一排序、同一配对规则、同一补卡口径、
    同一「date(start_ts) 取 ISO 前缀」解释。等价性由 reports/优化验证.md 的结论摘要比对守住。
    """

    emp_id: str
    regime: str
    punches: dict[str, list[PunchEvent]]
    punch_refs: dict[str, list[dict]]
    corrections: dict[str, list[PunchEvent]]
    corr_refs: dict[str, list[dict]]
    plans: dict[str, Row]
    leaves: list[dict]
    trips: list[dict]
    comp_days: set[str]


def load_employee_bundle(conn: Connection, cfg: Config, emp_id: str,
                         start: date, end: date) -> EmployeeBundle:
    """按员工一次性预取（5 条 SQL），替代原来「每员工每工作日 8 条 SQL」。"""
    emp = conn.execute("SELECT worktime_regime FROM employee WHERE emp_id = ?", (emp_id,)).fetchone()

    punches: dict[str, list[PunchEvent]] = {}
    punch_refs: dict[str, list[dict]] = {}
    file_paths = {int(row["file_id"]): str(row["rel_path"])
                  for row in conn.execute("SELECT file_id, rel_path FROM raw_file").fetchall()}
    for r in conn.execute(
        "SELECT punch_id, event_ts, punch_type, raw_text, day_anchor, device_id, "
        "source_file_id, source_line_no "
        "FROM punch WHERE emp_id = ? ORDER BY event_ts, punch_id", (emp_id,)
    ).fetchall():
        punches.setdefault(r["day_anchor"], []).append(PunchEvent(
            ts=parse_timestamp(r["event_ts"]), punch_type=r["punch_type"], raw_text=r["raw_text"],
            file_id=r["source_file_id"], line_no=r["source_line_no"],
            rel_path=(file_paths.get(int(r["source_file_id"]))
                      if r["source_file_id"] is not None else None),
            device_id=str(r["device_id"] or "")))
        if r["source_file_id"] is not None:
            punch_refs.setdefault(r["day_anchor"], []).append(
                {"file_id": r["source_file_id"], "line_no": r["source_line_no"]})

    # 补卡：仅在已批准时参与配对（未批准补卡不改事实，只在质量门禁里体现）
    corrections: dict[str, list[PunchEvent]] = {}
    corr_refs: dict[str, list[dict]] = {}
    for c in conn.execute(
        "SELECT claimed_ts, claimed_type, source_file_id, source_line_no FROM punch_correction "
        "WHERE emp_id = ? AND approved = 1", (emp_id,)
    ).fetchall():
        ts = parse_timestamp(c["claimed_ts"])
        anchor = _anchor_day(ts, cfg.cross_day_cut_hour).isoformat()
        corrections.setdefault(anchor, []).append(PunchEvent(
            ts=ts, punch_type=c["claimed_type"], raw_text="correction:" + c["claimed_type"],
            file_id=c["source_file_id"], line_no=c["source_line_no"],
            rel_path=(file_paths.get(int(c["source_file_id"]))
                      if c["source_file_id"] is not None else None),
            from_correction=True))
        if c["source_file_id"] is not None:
            corr_refs.setdefault(anchor, []).append(
                {"file_id": c["source_file_id"], "line_no": c["source_line_no"]})

    plans: dict[str, Row] = {}
    for pl in conn.execute(
        "SELECT work_date, planned_start, planned_end, rest_minutes, crosses_midnight, "
        "source_file_id, source_line_no FROM shift_plan WHERE emp_id = ? AND work_date BETWEEN ? AND ?",
        (emp_id, start.isoformat(), end.isoformat())
    ).fetchall():
        plans[pl["work_date"]] = pl

    leaves: list[dict] = []
    comp_days: set[str] = set()
    for r in conn.execute(
        "SELECT leave_kind, start_ts, end_ts, source_file_id, source_line_no, approved "
        "FROM leave_record WHERE emp_id = ?", (emp_id,)
    ).fetchall():
        leaves.append({"start": r["start_ts"], "end": r["end_ts"],
                       "source_file_id": r["source_file_id"], "source_line_no": r["source_line_no"]})
        if r["leave_kind"] == "comp_time" and int(r["approved"] or 0) == 1:
            # 与 SQL date(start_ts) 等价：取 ISO 串日期前缀，SQLite 本来就不做时区换算
            comp_days.add(str(r["start_ts"])[:10])

    trips: list[dict] = []
    for r in conn.execute(
        "SELECT start_ts, end_ts, source_file_id, source_line_no FROM trip_record WHERE emp_id = ?",
        (emp_id,)
    ).fetchall():
        trips.append({"start": r["start_ts"], "end": r["end_ts"],
                      "source_file_id": r["source_file_id"], "source_line_no": r["source_line_no"]})

    return EmployeeBundle(emp_id=emp_id, regime=emp["worktime_regime"] if emp else "standard",
                          punches=punches, punch_refs=punch_refs, corrections=corrections,
                          corr_refs=corr_refs, plans=plans, leaves=leaves, trips=trips,
                          comp_days=comp_days)


def compute_day_facts(bundle: EmployeeBundle, cfg: Config, calendar: HolidayCalendar,
                      work_date: date) -> DayFacts:
    """纯计算，零 SQL：结果与旧的逐日查询版逐字段一致。"""
    iso = work_date.isoformat()
    events: list[PunchEvent] = list(bundle.punches.get(iso, []))
    refs: list[dict] = list(bundle.punch_refs.get(iso, []))
    events += list(bundle.corrections.get(iso, []))
    refs += list(bundle.corr_refs.get(iso, []))

    ins = sorted((e for e in events if e.punch_type == "in"), key=lambda e: e.ts)
    outs = sorted((e for e in events if e.punch_type == "out"), key=lambda e: e.ts)
    first_in = ins[0] if ins else None
    last_out = outs[-1] if outs else None

    # OFF-01：同一时点、同一类型出现不同设备或不同来源 -> 两条事实都保留，只标记冲突。
    # 这里只观察事件，不改变配对结果、minutes_worked 或 source_refs。
    conflicts: list[dict] = []
    by_event: dict[tuple[str, str], list[PunchEvent]] = {}
    for event in events:
        by_event.setdefault((iso_minute(event.ts), event.punch_type), []).append(event)
    for (event_ts, punch_type), group in sorted(by_event.items()):
        identities = {
            (e.from_correction, e.device_id, e.rel_path, e.line_no) for e in group
        }
        if len(identities) < 2:
            continue
        conflicts.append({
            "event_ts": event_ts,
            "punch_type": punch_type,
            "sources": [
                {"kind": "correction" if e.from_correction else "punch",
                 "device_id": e.device_id, "rel_path": e.rel_path, "line_no": e.line_no}
                for e in sorted(group, key=lambda x: (x.from_correction, x.device_id,
                                                      str(x.rel_path), str(x.line_no)))
            ],
        })

    try:
        day_info: DayInfo | None = calendar.classify(work_date)
    except YearNotCovered:
        day_info = None
    plan = bundle.plans.get(iso)
    # plan_present 在 DayFacts 构造时传入，避免先引用未创建的对象

    facts = DayFacts(
        emp_id=bundle.emp_id,
        work_date=work_date,
        day_type=day_info.day_type if day_info else DAY_UNKNOWN,
        holiday_label=day_info.holiday_label if day_info else "",
        regime=bundle.regime,
        source_refs=refs,
        conflicts=conflicts,
        plan_present=plan is not None,
        notice_doc_id=day_info.notice_doc_id if day_info else "",
        ambiguous_day_type=day_info.ambiguous if day_info else False,
        workday_arrangement_unverified=(
            day_info.workday_arrangement_unverified if day_info else False
        ),
    )
    if day_info is None:
        facts.quality_flags.append("CALENDAR-YEAR-NOT-COVERED")

    if plan is not None:
        p_start = parse_timestamp(plan["planned_start"])
        p_end = parse_timestamp(plan["planned_end"])
        facts.minutes_rest = int(plan["rest_minutes"])
        facts.planned_minutes = max(0, int((p_end - p_start).total_seconds() // 60) - facts.minutes_rest)
        facts.crossed_midnight = p_end.date() > p_start.date() or p_end.time() < p_start.time()
        if plan["source_file_id"] is not None:
            facts.source_refs.append({"file_id": plan["source_file_id"], "line_no": plan["source_line_no"]})

    # 无排班计划时按 8 小时标准工时 + 0 休息作为计划口径，并在质量门禁里标注缺失
    if facts.planned_minutes == 0:
        facts.planned_minutes = cfg.daily_std_minutes
        facts.quality_flags.append("PLAN-ABSENT")

    if first_in is None or last_out is None:
        facts.quality_flags.append("PUNCH-MISSING")
        facts.in_ts = first_in.ts if first_in else None
        facts.out_ts = last_out.ts if last_out else None
        facts.minutes_span = 0
        facts.minutes_worked = 0
    else:
        if last_out.ts <= first_in.ts:
            facts.quality_flags.append("PUNCH-ORDER")
            facts.minutes_span = 0
            facts.minutes_worked = 0
        else:
            facts.in_ts = first_in.ts
            facts.out_ts = last_out.ts
            facts.minutes_span = int((last_out.ts - first_in.ts).total_seconds() // 60)
            facts.minutes_worked = clamp_minutes(facts.minutes_span - facts.minutes_rest)
            facts.minutes_night = _overlap_minutes_night(first_in.ts, last_out.ts, work_date)

    if len(ins) + len(outs) > 2:
        facts.quality_flags.append("PUNCH-EXTRA")

    # 请假 / 出差 覆盖当天多少分钟
    window_start = first_in.ts if first_in else datetime.combine(work_date, time(0, 0), tzinfo=CN_TZ)
    window_end = last_out.ts if last_out else datetime.combine(work_date, time(23, 59), tzinfo=CN_TZ)
    for rows, column in ((bundle.leaves, "minutes_leave"), (bundle.trips, "minutes_trip")):
        total = 0
        for r in rows:
            s = max(parse_timestamp(r["start"]), window_start)
            e = min(parse_timestamp(r["end"]), window_end)
            if e > s:
                total += int((e - s).total_seconds() // 60)
                if r["source_file_id"] is not None:
                    facts.source_refs.append({"file_id": r["source_file_id"], "line_no": r["source_line_no"]})
        setattr(facts, column, total)

    # 已批准补休（comp_time 记录）标记
    facts.comp_time_granted = iso in bundle.comp_days

    facts.punch_count = len(ins) + len(outs)
    # 跨天判定只看事实：下班打卡落在下一个日历日，即为跨零点班次
    if facts.out_ts is not None and facts.out_ts.date() > facts.work_date:
        facts.crossed_midnight = True
    return facts


def build_day_facts(
    conn: Connection,
    cfg: Config,
    emp_id: str,
    work_date: date,
    calendar: HolidayCalendar,
) -> DayFacts:
    """兼容旧签名（单日调用，如单测与局部查询）。批量路径请用 load_employee_bundle + compute_day_facts。"""
    bundle = load_employee_bundle(conn, cfg, emp_id, work_date, work_date)
    return compute_day_facts(bundle, cfg, calendar, work_date)



def day_anchor_of(ts: datetime, cfg: Config) -> str:
    """供导入器使用：把打卡时间落到工作日锚点（与 compute_day_facts 同一口径）。"""
    return _anchor_day(parse_timestamp(ts), cfg.cross_day_cut_hour).isoformat()


def anchor_day(ts: datetime, cfg: Config) -> str:
    """公开别名：导入器与校验层共用同一个切天口径，私有函数不该被跨模块 import。"""
    return day_anchor_of(ts, cfg)


def iter_employee_dates(conn: Connection, emp_id: str,
                        start: date, end: date, cfg: Config) -> list[date]:
    """该员工在区间内出现过工作日锚点的日期集合（含排班计划日期）。"""
    rows = conn.execute(
        "SELECT DISTINCT day_anchor FROM punch WHERE emp_id = ? AND day_anchor BETWEEN ? AND ?",
        (emp_id, start.isoformat(), end.isoformat()),
    ).fetchall()
    out = {parse_date(r["day_anchor"]) for r in rows}
    plans = conn.execute(
        "SELECT work_date FROM shift_plan WHERE emp_id = ? AND work_date BETWEEN ? AND ?",
        (emp_id, start.isoformat(), end.isoformat()),
    ).fetchall()
    out |= {parse_date(r["work_date"]) for r in plans}
    return sorted(out)


def stamp(dt: datetime | None) -> str:
    return iso_minute(dt) if dt else ""
