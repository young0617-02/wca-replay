"""F-005 确定性合规校验引擎：规则注册表与规则实现。

硬约束（A1 红线）：
  * 只做整数分钟 / 整数分的算术，不出现 float，不调用任何 LLM；
  * 每条 Finding 必须挂 `citations`，否则 Finding.__post_init__ 直接抛错；
  * 金额只作为「参考测算明细」输出且 `authorized_final=0`，最终数额由人工复核决定（A4）。

严重级分工（这套克制是设计要点，不是偷懒）：
  * 时长上限类规则（CAP-*、WK-W02）可以下「明显违规」——纯数值超限，不依赖外部事实；
  * 报酬类规则（OT-D01/02/03/04、COMP-C01）最高只到「需复核」——是否足额支付需要工资台账，
    本项目按 §1.3 明确不做薪酬核算，因此绝不越权下判决；
  * 口径存在地方差异或年度排班未核实时，一律再降级为「需复核」，并把差异写进 explanation。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from ..config import Config
from ..util import round_half_up
from . import citations as C
from .dayfacts import DayFacts
from .findings import SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION, Finding
from .holidays import DAY_PLAIN_REST, DAY_REST_SWAP, DAY_STATUTORY_HOLIDAY, DAY_WORKDAY
from .quantities import (
    RATE_HOLIDAY_OT_PERMILLE,
    RATE_RESTDAY_OT_PERMILLE,
    RATE_WEEKDAY_OT_PERMILLE,
    overtime_pay_cents,
)
from .regime import (
    CYCLE_DAYS,
    REGIME_COMPREHENSIVE,
    REGIME_FLEXIBLE,
    REGIME_STANDARD,
    RegimeDecision,
)

RULE_PACK_VERSION = "rp-2026.10.shenzhen-standard.v2"

# 《劳动法》第 36 条：平均每周不超过 44 小时（40 小时来自国务院令第 174 号第 3 条）
WEEKLY_STATUTORY_CAP_MINUTES = 44 * 60


@dataclass
class EmpScope:
    """单个员工在校验区间内的全部事实（区间内每个日历日一条 DayFacts）。"""

    emp_id: str
    job_code: str
    region_code: str
    org_id: str
    decision: RegimeDecision
    hourly_normal_cents: int
    daily_std_minutes: int
    weekly_std_minutes: int
    facts: list[DayFacts] = field(default_factory=list)
    quality_issues: list[dict] = field(default_factory=list)
    cycle_expected_minutes: dict[str, int] = field(default_factory=dict)

    @property
    def regime(self) -> str:
        return self.decision.effective_regime


@dataclass
class RuleMeta:
    rule_id: str
    name_zh: str
    tier: str            # day / week / month / cycle / quality / scope
    citations: list[str]
    severity_kind: str   # pay(报酬类，最高需复核) / cap(上限类，可下违规) / scope / quality
    version: str = RULE_PACK_VERSION


RULE_CATALOG: list[RuleMeta] = [
    RuleMeta("OT-D01", "工作日延长工作时间", "day", [C.LABOR_LAW_41, C.WAGE_PAYMENT_13, C.SZ_WAGE_18], "pay"),
    RuleMeta("OT-D02", "休息日工作安排与补休", "day", [C.LABOR_LAW_44, C.MOHRSS_503_6, C.SZ_WAGE_18], "pay"),
    RuleMeta("OT-D03", "法定节假日当天工作安排", "day",
             [C.LABOR_LAW_44, C.LABOR_LAW_40, C.LABOR_LAW_51, C.SZ_WAGE_18], "pay"),
    RuleMeta("OT-D04", "不定时工时员工法定节假日（深圳特有）", "day", [C.SZ_WAGE_20, C.LABOR_LAW_44], "pay"),
    RuleMeta("CAP-D05", "单日加班超过 3 小时", "day", [C.LABOR_LAW_41, C.SC_WORKTIME_3], "cap"),
    RuleMeta("CAP-W01", "连续工作 7 天无休息日", "week", [C.LABOR_LAW_38], "cap"),
    RuleMeta("WK-W02", "周实际工时超过 44 小时", "week", [C.LABOR_LAW_36], "cap"),
    RuleMeta("WK-W01", "周实际工时超过 40 小时（解释差异）", "week", [C.SC_WORKTIME_3, C.LABOR_LAW_36], "pay"),
    RuleMeta("CAP-M01", "月延长工时累计超过 36 小时", "month", [C.LABOR_LAW_41], "cap"),
    RuleMeta("CAP-M02", "月延长工时超过内部预警线", "month", [C.POLICY_OT_APPROVAL, C.LABOR_LAW_41], "quality"),
    RuleMeta("COMP-C01", "综合计算工时周期超额", "cycle", [C.MOHRSS_503_5, C.WAGE_PAYMENT_13, C.SZ_WAGE_19], "pay"),
    RuleMeta("COMP-C02", "未经审批按特殊工时执行", "scope",
             [C.MOHRSS_503_3, C.MOHRSS_503_7, C.GD_APPROVAL_2009], "cap"),
    RuleMeta("COMP-C03", "岗位不在特殊工时适用范围内", "scope", [C.MOHRSS_503_4, C.MOHRSS_503_5], "cap"),
    RuleMeta("FX-F01", "特殊工时豁免/范围说明", "scope", [C.MOHRSS_503_4, C.WAGE_PAYMENT_13], "scope"),
    RuleMeta("XD-01", "跨天班次切分依据不足", "quality", [C.LABOR_LAW_41, C.MOHRSS_503_6], "quality"),
    RuleMeta("NIGHT-01", "夜间时段工时统计（无全国统一标准）", "scope", [C.LABOR_LAW_36], "scope"),
    RuleMeta("QUAL-01", "数据质量异常（缺卡/重复/顺序/畸形入参）", "quality",
             [C.POLICY_ATTENDANCE, C.LCT_4], "quality"),
    RuleMeta("QUAL-02", "被拒收的输入行（事实缺口，须补录后重跑）", "quality",
             [C.POLICY_ATTENDANCE, C.LCT_4], "quality"),
    RuleMeta("POL-01", "加班缺审批记录（内部制度层）", "quality", [C.POLICY_OT_APPROVAL, C.LCT_4], "quality"),
    RuleMeta("SCOPE-01", "校验范围外：年度日历或调休安排未核实", "scope",
             [C.HOLIDAY_MEASURE_2, C.HOLIDAY_NOTICE_2026], "scope"),
]

CATALOG_BY_ID = {m.rule_id: m for m in RULE_CATALOG}


def _estimate(emp: EmpScope, minutes: int, rate_permille: int) -> int:
    return overtime_pay_cents(emp.hourly_normal_cents, minutes, rate_permille)


def _finding(
    emp: EmpScope,
    rule_id: str,
    severity: str,
    explanation: str,
    metric: dict,
    facts: DayFacts | None = None,
    work_date: str | None = None,
    period_key: str | None = None,
    citations: list[str] | None = None,
) -> Finding:
    meta = CATALOG_BY_ID[rule_id]
    if facts is not None and work_date is None:
        work_date = facts.work_date.isoformat()
    if meta.severity_kind == "pay" and severity == SEV_VIOLATION:
        # 结构性兜底：报酬类规则不得下「明显违规」
        severity = SEV_REVIEW
    return Finding(
        rule_id=rule_id,
        rule_version=meta.version,
        emp_id=emp.emp_id,
        severity=severity,
        explanation=explanation,
        citations=list(citations or meta.citations),
        metric=metric,
        source_refs=(list(facts.source_refs) if facts else []),
        work_date=work_date,
        period_key=period_key,
    )


def _demote(severity: str, facts: DayFacts) -> str:
    """口径不明时不得给出「明显违规」结论——降级为需复核。"""
    if facts.ambiguous_day_type or facts.workday_arrangement_unverified:
        return SEV_REVIEW
    return severity


def _is_rest(facts: DayFacts) -> bool:
    return facts.day_type in (DAY_REST_SWAP, DAY_PLAIN_REST)


# ------------------------------------------------------------------ 日级
def rule_day(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for facts in emp.facts:
        worked = facts.minutes_worked

        if emp.regime == REGIME_FLEXIBLE:
            if worked > 0 and facts.day_type == DAY_STATUTORY_HOLIDAY and cfg.region_code.startswith("4403"):
                out.append(_finding(
                    emp, "OT-D04", SEV_REVIEW,
                    f"不定时工作制员工 {facts.work_date} 在法定节假日「{facts.holiday_label}」工作 {worked} 分钟。"
                    "深圳口径要求按不低于 300% 支付（《深圳市员工工资支付条例》第 20 条），"
                    "而全国层面（《工资支付暂行规定》第 13 条）对不定时工时不执行该标准；"
                    "本规则采用更严的深圳口径，最终数额须人工复核。",
                    {
                        "minutes_holiday": worked,
                        "rate_permille": RATE_HOLIDAY_OT_PERMILLE,
                        "estimate_cents": _estimate(emp, worked, RATE_HOLIDAY_OT_PERMILLE),
                        "authorized_final": 0,
                        "region_divergence": "sz-stricter-than-national",
                    },
                    facts,
                ))
            _append_night(emp, facts, out, cfg)
            continue

        if worked <= 0:
            continue

        if emp.regime in REGIME_COMPREHENSIVE:
            if facts.day_type == DAY_STATUTORY_HOLIDAY:
                out.append(_finding(
                    emp, "OT-D03", SEV_REVIEW,
                    f"综合计算工时员工 {facts.work_date} 在法定节假日「{facts.holiday_label}」工作 {worked} 分钟，"
                    "应按不低于 300% 支付（《工资支付暂行规定》第 13 条第 3 项、"
                    "《深圳市员工工资支付条例》第 18/19 条）。是否已足额支付须人工核对。",
                    {
                        "minutes_holiday": worked,
                        "rate_permille": RATE_HOLIDAY_OT_PERMILLE,
                        "estimate_cents": _estimate(emp, worked, RATE_HOLIDAY_OT_PERMILLE),
                        "authorized_final": 0,
                        "regime": emp.regime,
                        "ambiguous_day_type": int(facts.ambiguous_day_type),
                    },
                    facts,
                ))
            _append_night(emp, facts, out, cfg)
            continue

        # ---- 标准工时
        if facts.day_type == DAY_STATUTORY_HOLIDAY:
            note = ""
            if facts.ambiguous_day_type:
                note = "（该日在法定节假日当天与调休休息日之间口径待核对，见 docs/待确认清单.md）"
            out.append(_finding(
                emp, "OT-D03", SEV_REVIEW,
                f"{facts.work_date} 为法定节假日「{facts.holiday_label}」，实际工作 {worked} 分钟，"
                "应支付不低于 300% 的报酬且不得以补休替代（《劳动法》第 44 条第 3 项、第 40/51 条）。"
                f"是否已足额支付须人工核对{note}",
                {
                    "minutes_holiday": worked,
                    "rate_permille": RATE_HOLIDAY_OT_PERMILLE,
                    "estimate_cents": _estimate(emp, worked, RATE_HOLIDAY_OT_PERMILLE),
                    "holiday_label": facts.holiday_label,
                    "authorized_final": 0,
                    "ambiguous_day_type": int(facts.ambiguous_day_type),
                },
                facts,
            ))
            _append_night(emp, facts, out, cfg)
            continue

        if _is_rest(facts):
            if facts.comp_time_granted:
                text = (
                    f"{facts.work_date} 为休息日（{facts.day_type}），安排工作 {worked} 分钟但已安排补休，"
                    "《劳动法》第 44 条第 2 项的 200% 支付义务可由补休替代，属可申辩；须留存补休安排证据。"
                )
                sev = SEV_DEFENSIBLE
            else:
                text = (
                    f"{facts.work_date} 为休息日（{facts.day_type}），安排工作 {worked} 分钟且未见补休记录，"
                    "应按不低于 200% 支付（《劳动法》第 44 条第 2 项、《深圳市员工工资支付条例》第 18 条）。"
                )
                sev = _demote(SEV_REVIEW, facts)
            out.append(_finding(
                emp, "OT-D02", sev, text,
                {
                    "minutes_restdays": worked,
                    "day_type": facts.day_type,
                    "rate_permille": RATE_RESTDAY_OT_PERMILLE,
                    "estimate_cents": _estimate(emp, worked, RATE_RESTDAY_OT_PERMILLE),
                    "comp_time_granted": int(facts.comp_time_granted),
                    "authorized_final": 0,
                },
                facts,
            ))
            _append_night(emp, facts, out, cfg)
            continue

        # 工作日
        extension = max(0, worked - emp.daily_std_minutes)
        if extension > 0:
            if extension <= cfg.ot_cap_daily_general_minutes:
                sev = SEV_DEFENSIBLE
                text = (
                    f"{facts.work_date} 延长工作 {extension} 分钟"
                    f"（≤{cfg.ot_cap_daily_general_minutes} 分钟），落在《劳动法》第 41 条"
                    "「一般每日不得超过一小时」区间内；须留存协商记录与 150% 支付凭证。"
                )
            elif extension <= cfg.ot_cap_daily_special_minutes:
                sev = SEV_REVIEW
                text = (
                    f"{facts.work_date} 延长工作 {extension} 分钟，超过每日 1 小时但仍在"
                    "「特殊原因每日不超过 3 小时」内，须核实是否满足《劳动法》第 41 条的"
                    "协商前提与保障身体健康条件。"
                )
            else:
                sev = SEV_REVIEW  # 报酬类不下违规，超限由 CAP-D05 负责
                text = (
                    f"{facts.work_date} 延长工作 {extension} 分钟，报酬按不低于 150% 测算；"
                    "时长超限结论见 CAP-D05。"
                )
            out.append(_finding(
                emp, "OT-D01", _demote(sev, facts), text,
                {
                    "minutes_extension": extension,
                    "minutes_worked": worked,
                    "daily_std_minutes": emp.daily_std_minutes,
                    "rate_permille": RATE_WEEKDAY_OT_PERMILLE,
                    "estimate_cents": _estimate(emp, extension, RATE_WEEKDAY_OT_PERMILLE),
                    "authorized_final": 0,
                    "leave_minutes_covered": facts.minutes_leave,
                    "trip_minutes_covered": facts.minutes_trip,
                },
                facts,
            ))
            if "PLAN-ABSENT" in facts.quality_flags:
                out.append(_finding(
                    emp, "POL-01", SEV_DEFENSIBLE,
                    f"{facts.work_date} 存在延长工时但当天无排班/加班审批记录，"
                    "按内部制度（policy.sz.overtime-approval）应先审批后加班；属证据缺口，可申辩。",
                    {"minutes_extension": extension, "approval_record_present": 0},
                    facts,
                ))
        _append_cap_daily(emp, facts, worked, cfg, out)
        _append_night(emp, facts, out, cfg)
    return out


def _append_cap_daily(emp: EmpScope, facts: DayFacts, worked: int, cfg: Config,
                      out: list[Finding]) -> None:
    extension = max(0, worked - emp.daily_std_minutes)
    if extension > cfg.ot_cap_daily_special_minutes:
        out.append(_finding(
            emp, "CAP-D05", _demote(SEV_VIOLATION, facts),
            f"{facts.work_date} 单日延长工作 {extension} 分钟 > {cfg.ot_cap_daily_special_minutes} 分钟，"
            "突破《劳动法》第 41 条「特殊原因每日不得超过三小时」上限；"
            "该结论纯由数值超限得出，不依赖工资支付情况。",
            {"minutes_extension": extension, "cap_minutes": cfg.ot_cap_daily_special_minutes},
            facts,
        ))


def _append_night(emp: EmpScope, facts: DayFacts, out: list[Finding], cfg: Config | None = None) -> None:
    """夜间时段统计与跨零点切分依据：两类信息在所有工时制分支上都要出。"""
    if facts.crossed_midnight and "PLAN-ABSENT" in facts.quality_flags:
        cut = getattr(cfg, "cross_day_cut_hour", -1)
        out.append(_finding(
            emp, "XD-01", SEV_REVIEW,
            f"{facts.work_date} 班次跨 00:00 且当天无排班计划，下班打卡落在下一个日历日；"
            f"该工时归属依赖 cut_hour={cut} 时切分约定，须人工确认切分方式后才能定论"
            "（见 docs/待确认清单.md 第 Q2 项）。",
            {"crossed_midnight": 1, "planned_minutes": facts.planned_minutes,
             "minutes_worked": facts.minutes_worked, "cut_hour": cut},
            facts,
        ))
    if facts.minutes_night > 0:
        out.append(_finding(
            emp, "NIGHT-01", SEV_DEFENSIBLE,
            f"{facts.work_date} 落在 00:00–06:00 的工时 {facts.minutes_night} 分钟。"
            "国家层面无统一夜班津贴标准，地方口径本项目未覆盖，只作事实统计不作违规判定"
            "（见 docs/口径声明.md 未覆盖清单）。",
            {"minutes_night": facts.minutes_night},
            facts,
        ))


# ------------------------------------------------------------------ 周级
def _iso_week_key(d: date) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


def _month_key(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"


def _cycle_key(d: date, regime: str) -> str:
    if regime == "comprehensive_monthly":
        return _month_key(d)
    if regime == "comprehensive_quarterly":
        q = (d.month - 1) // 3 + 1
        return f"{d.year:04d}-Q{q}"
    return f"{d.year:04d}"


def rule_week(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if emp.regime != REGIME_STANDARD:
        return out
    by_week: dict[str, list[DayFacts]] = {}
    for facts in emp.facts:
        by_week.setdefault(_iso_week_key(facts.work_date), []).append(facts)

    weeks = [(k, ds) for k, ds in sorted(by_week.items()) if len(ds) >= 7]
    totals = [sum(d.minutes_worked for d in ds) for _k, ds in weeks]

    for idx, (week_key, days) in enumerate(weeks):
        total = totals[idx]
        expected = sum(emp.daily_std_minutes for d in days if d.day_type == DAY_WORKDAY)
        rest_days = [d for d in days if d.minutes_worked == 0 and d.punch_count == 0]
        ambiguous = any(d.ambiguous_day_type or d.workday_arrangement_unverified for d in days)

        if not rest_days:
            sev = SEV_REVIEW if ambiguous else SEV_VIOLATION
            out.append(_finding(
                emp, "CAP-W01", sev,
                f"{week_key} 内 7 个日历日均有出勤记录、无整天休息，违反《劳动法》第 38 条"
                "「每周至少休息一日」。（若其中含调休上班日，须人工核对该年度放假安排）",
                {"days_present": len(days), "rest_days": 0, "minutes_worked": total},
                period_key=week_key,
            ))

        if total > WEEKLY_STATUTORY_CAP_MINUTES:
            # 《劳动法》第 36 条的 44 小时是「平均每周」：单周超标只到需复核，
            # 只有连续 4 周（含本周）平均仍超 44 小时才下明显违规。
            window = totals[max(0, idx - 3): idx + 1]
            avg_week = round_half_up(sum(window), len(window))
            over_avg = avg_week > WEEKLY_STATUTORY_CAP_MINUTES
            sev = SEV_REVIEW if (ambiguous or not over_avg) else SEV_VIOLATION
            basis = (f"近 {len(window)} 周平均 {avg_week} 分钟仍超 44 小时" if over_avg else
                     f"仅本周超标（近 {len(window)} 周平均 {avg_week} 分钟未超），须按平均口径复核")
            out.append(_finding(
                emp, "WK-W02", sev,
                f"{week_key} 实际工时 {total} 分钟 > 44 小时（{WEEKLY_STATUTORY_CAP_MINUTES} 分钟）；{basis}。"
                "《劳动法》第 36 条表述为「平均每周工作时间不超过四十四小时」，"
                "因此单周超标不直接判违规。",
                {"minutes_worked": total, "cap_minutes": WEEKLY_STATUTORY_CAP_MINUTES,
                 "minutes_over": total - WEEKLY_STATUTORY_CAP_MINUTES,
                 "avg_4w_minutes": avg_week, "weeks_in_avg": len(window),
                 "expected_minutes": expected},
                period_key=week_key,
            ))
        elif total > emp.weekly_std_minutes:
            out.append(_finding(
                emp, "WK-W01", SEV_REVIEW,
                f"{week_key} 实际工时 {total} 分钟 > 40 小时（{emp.weekly_std_minutes} 分钟）但不超 44 小时。"
                "「每日不超 8 小时而每周超 40 小时」是否一律计为延长工作时间，裁口径存在差异；"
                "本项目锁定深圳并按需复核处理（见 docs/待确认清单.md 第 Q4 项）。",
                {"minutes_worked": total, "expected_minutes": expected,
                 "minutes_over": total - emp.weekly_std_minutes},
                period_key=week_key,
            ))
    return out


# ------------------------------------------------------------------ 月级 / 周期级
def rule_month(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if emp.regime != REGIME_STANDARD:
        return out
    by_month: dict[str, dict[str, int]] = {}
    for facts in emp.facts:
        agg = by_month.setdefault(_month_key(facts.work_date),
                                  {"weekday": 0, "restdays": 0, "holiday": 0})
        extension = max(0, facts.minutes_worked - emp.daily_std_minutes)
        if facts.day_type == DAY_WORKDAY:
            agg["weekday"] += extension
        elif _is_rest(facts):
            agg["restdays"] += facts.minutes_worked
        elif facts.day_type == DAY_STATUTORY_HOLIDAY:
            agg["holiday"] += facts.minutes_worked

    for month_key, agg in sorted(by_month.items()):
        scope_label = cfg.ot_cap_scope
        if scope_label == "weekday_plus_rest":
            counted = agg["weekday"] + agg["restdays"]
        else:
            counted = agg["weekday"]
        warn_line = cfg.ot_cap_monthly_minutes * 9 // 10
        if counted > cfg.ot_cap_monthly_minutes:
            out.append(_finding(
                emp, "CAP-M01", SEV_VIOLATION,
                f"{month_key} 延长工时累计 {counted} 分钟 > 36 小时（{cfg.ot_cap_monthly_minutes} 分钟），"
                f"违反《劳动法》第 41 条每月上限。统计口径 count_scope={scope_label}"
                "（休息日加班是否计入 36 小时上限存在裁口径差异，默认只计工作日延长部分）。",
                {**agg, "counted_minutes": counted, "cap_minutes": cfg.ot_cap_monthly_minutes,
                 "counting_scope": scope_label},
                period_key=month_key,
            ))
        elif counted > warn_line:
            out.append(_finding(
                emp, "CAP-M02", SEV_DEFENSIBLE,
                f"{month_key} 延长工时累计 {counted} 分钟，已达 36 小时上限的 90% 以上，"
                "触发内部制度预警线（policy.sz.overtime-approval），建议排班干预。",
                {**agg, "counted_minutes": counted, "warn_threshold_minutes": warn_line},
                period_key=month_key,
            ))
    return out


def rule_cycle(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if emp.regime not in REGIME_COMPREHENSIVE:
        return out
    agg: dict[str, dict[str, int | bool]] = {}
    for facts in emp.facts:
        key = _cycle_key(facts.work_date, emp.regime)
        cur = agg.setdefault(key, {"worked": 0, "holiday": 0, "calendar_days": 0,
                                   "workday_slots": 0, "ambiguous": 0})
        cur["worked"] = int(cur["worked"]) + facts.minutes_worked
        cur["calendar_days"] = int(cur["calendar_days"]) + 1
        if facts.day_type == DAY_WORKDAY:
            cur["workday_slots"] = int(cur["workday_slots"]) + 1
        if facts.day_type == DAY_STATUTORY_HOLIDAY:
            cur["holiday"] = int(cur["holiday"]) + facts.minutes_worked
        if facts.ambiguous_day_type or facts.workday_arrangement_unverified:
            cur["ambiguous"] = 1

    for cycle_key, cur in sorted(agg.items()):
        expected = emp.cycle_expected_minutes.get(cycle_key)
        if expected is None:
            # 区间把周期截断了，周期法定标准无法成立，不下结论（明确记为范围外）
            out.append(_finding(
                emp, "SCOPE-01", SEV_REVIEW,
                f"周期 {cycle_key} 未完整落在本次校验区间内，无法确定该周期的法定标准工时，"
                "本次不产出周期超额结论；请扩大区间后重跑。",
                {"cycle_key": cycle_key, "days_in_scope": int(cur["calendar_days"]),
                 "cycle_kind": CYCLE_DAYS.get(emp.regime, ("?", 0))[0]},
                period_key=cycle_key,
            ))
            continue
        over = int(cur["worked"]) - expected
        if over > 0:
            note = ("36 小时每月上限是否适用于综合计算工时存在口径差异，"
                    "本项目保守定为需复核（见 docs/待确认清单.md 第 Q5 项）。"
                    if not cur["ambiguous"] else
                    "本周期含调休上班日安排未核实的日期，结论只能到需复核。")
            out.append(_finding(
                emp, "COMP-C01", SEV_REVIEW,
                f"综合计算工时周期 {cycle_key}（{emp.regime}）：实际 {int(cur['worked'])} 分钟，"
                f"对照周期法定标准 {expected} 分钟，超额 {over} 分钟，按不低于 150% 测算"
                "（劳部发〔1994〕503 号第 5 条、《工资支付暂行规定》第 13 条、"
                f"《深圳市员工工资支付条例》第 19 条）。{note}",
                {
                    "minutes_worked": int(cur["worked"]),
                    "expected_minutes": expected,
                    "minutes_over": over,
                    "rate_permille": RATE_WEEKDAY_OT_PERMILLE,
                    "estimate_cents": _estimate(emp, over, RATE_WEEKDAY_OT_PERMILLE),
                    "authorized_final": 0,
                    "holiday_minutes": int(cur["holiday"]),
                    "cycle_kind": CYCLE_DAYS.get(emp.regime, ("?", 0))[0],
                },
                period_key=cycle_key,
            ))
    return out


# ------------------------------------------------------------------ 范围与资质
def rule_scope(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    dec = emp.decision

    if dec.declared_regime != REGIME_STANDARD and dec.effective_regime == REGIME_STANDARD:
        reasons = "；".join(dec.reasons or ["未说明回落原因"])
        out.append(_finding(
            emp, "COMP-C02", SEV_VIOLATION,
            f"声明 {dec.declared_regime} 但本周期按标准工时校验：{reasons}。"
            "特殊工时须经劳动行政部门批准（劳部发〔1994〕503 号第 3/7 条、粤劳社发〔2009〕8 号、"
            "深劳社规〔2009〕13 号），缺审批不得免除加班工资义务。",
            dec.metric(),
        ))
    elif dec.declared_regime == REGIME_FLEXIBLE and dec.effective_regime == REGIME_FLEXIBLE:
        extra = ("深圳口径下法定节假日仍按 300%（《深圳市员工工资支付条例》第 20 条）。"
                 if cfg.region_code.startswith("4403") else
                 "法定节假日是否支付 300% 存在地方差异，本项目未在锁定了深圳之外的口径。")
        out.append(_finding(
            emp, "FX-F01", SEV_DEFENSIBLE,
            "不定时工作制已审批且岗位在适用范围内（503 号文第 4 条）：工作日延长工时与每月上限不执行"
            f"（《工资支付暂行规定》第 13 条）；{extra}本条为豁免说明，非违规。",
            dec.metric(),
        ))
    elif dec.declared_regime in REGIME_COMPREHENSIVE and dec.effective_regime == dec.declared_regime:
        out.append(_finding(
            emp, "FX-F01", SEV_DEFENSIBLE,
            f"综合计算工时（{dec.declared_regime}）已审批且在适用范围内（503 号文第 5 条），"
            "工时以周期平均对照法定标准；周期内法定节假日当天仍按 300%。本条为范围说明。",
            dec.metric(),
        ))

    if dec.declared_regime != REGIME_STANDARD and not dec.eligible_by_job:
        out.append(_finding(
            emp, "COMP-C03", SEV_VIOLATION,
            f"岗位 {dec.job_code} 不属于所声明特殊工时的法定适用范围（503 号文第 4/5 条列举岗位），"
            "即使取得审批也不得对该岗位适用，须重新申报或改回标准工时。",
            dec.metric(),
        ))

    for facts in emp.facts:
        if "PUNCH-MISSING" in facts.quality_flags and facts.punch_count > 0:
            out.append(_finding(
                emp, "QUAL-01", SEV_REVIEW,
                f"{facts.work_date} 缺"
                + ("下班卡" if facts.in_ts and not facts.out_ts else "上班卡")
                + "且无已批准补卡，出勤事实无法闭合；该日不进入工时计算，须补录后重跑。"
                "（补卡未经批准不参与配对，这是 F-004 的硬门禁）",
                {"punch_count": facts.punch_count, "day_type": facts.day_type,
                 "minutes_worked": facts.minutes_worked},
                facts,
            ))
        if "CALENDAR-YEAR-NOT-COVERED" in facts.quality_flags:
            out.append(_finding(
                emp, "SCOPE-01", SEV_REVIEW,
                f"{facts.work_date} 所属年度未收录国务院办公厅节假日安排，无法区分法定节假日当天与"
                "调休休息日，本项目不产出该日的倍数结论（明确记为未覆盖，见 docs/口径声明.md）。",
                {"work_date": facts.work_date.isoformat()},
                facts,
            ))
    return out


# ------------------------------------------------------------------ 质量门禁结论化
def rule_quality(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    by_day: dict[str, list[dict]] = {}
    for issue in emp.quality_issues:
        by_day.setdefault(str(issue.get("work_date") or ""), []).append(issue)

    for day_key, issues in sorted(by_day.items()):
        rule_ids = sorted({str(i["rule_id"]) for i in issues})
        if any(i.get("severity") == SEV_VIOLATION for i in issues):
            worst = SEV_REVIEW   # 数据质量本身不直接判违规，最多要求复核
        elif "QUAL-DUP" in rule_ids or "QUAL-MISSING" in rule_ids:
            worst = SEV_REVIEW
        else:
            worst = SEV_DEFENSIBLE
        out.append(_finding(
            emp, "QUAL-01", worst,
            f"{day_key or '期间汇总'} 存在数据质量问题：{', '.join(rule_ids)}。"
            "质量门禁不改写原始事实，只标注并保留行级来源，举证包可反查原始行（A7）。",
            {
                "issue_rule_ids": rule_ids,
                "issue_count": len(issues),
                "sample_raw_values": [str(i.get("raw_value", ""))[:64] for i in issues[:3]],
                "line_refs": [{"file_id": i.get("file_id"), "line_no": i.get("line_no")}
                              for i in issues[:5]],
            },
            work_date=day_key or None,
        ))

    # O-2：整行被拒收 = 该日事实缺失。这类缺口过去只躺在 quality_issues.csv 与举证包里，
    # 不进结论也不开复核单 —— 最该补录的数据反而没人看见。
    reject_days: dict[str, list[dict]] = {}
    for issue in emp.quality_issues:
        if str(issue.get("severity")) == "REJECT":
            reject_days.setdefault(str(issue.get("work_date") or ""), []).append(issue)
    for day_key, items in sorted(reject_days.items()):
        out.append(_finding(
            emp, "QUAL-02", SEV_REVIEW,
            f"{day_key or '期间汇总'} 有 {len(items)} 行输入被质量门禁整行拒收"
            f"（{', '.join(sorted({str(i['rule_id']) for i in items}))}）。"
            "被拒收即该日事实不完整：不进入工时计算，须补录后重跑校验；"
            "原始行与文件指纹保留，可逐行反查（A7）。",
            {
                "rejected_lines": len(items),
                "issue_rule_ids": sorted({str(i["rule_id"]) for i in items}),
                "line_refs": [{"file_id": i.get("file_id"), "line_no": i.get("line_no")}
                              for i in items[:5]],
                "sample_raw_values": [str(i.get("raw_value", ""))[:64] for i in items[:3]],
            },
            work_date=day_key or None,
        ))
    return out


DAY_RULES = [rule_day, rule_week, rule_month, rule_cycle, rule_scope, rule_quality]
