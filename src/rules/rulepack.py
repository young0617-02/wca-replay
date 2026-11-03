"""F-005 确定性合规校验引擎：规则注册表与规则实现。

硬约束（A1 红线）：
  * 只做整数分钟 / 整数分的算术，不出现 float，不调用任何 LLM；
  * 每条 Finding 必须挂 `citations`，否则 Finding.__post_init__ 直接抛错；
  * **引擎不输出任何应付金额**（需求 D-03 / A4）：只出小时数与倍数档位；
    金额由 HR 负责人在复核台具名录入，`rules/` 里不存在算钱代码。

严重级分工（这套克制是设计要点，不是偷懒）：
  * 时长上限类规则（CAP-*、WK-W02）可以下「明显违规」——纯数值超限，不依赖外部事实；
  * 报酬类规则（OT-D01/02/03）最高只到「需复核」——是否足额支付需要工资台账，
    本项目按 §1.3 明确不做薪酬核算，因此绝不越权下判决；
  * 口径存在地方差异或年度排班未核实时，一律再降级为「需复核」，并把差异写进 explanation。
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import date

from ..config import Config
from ..util import round_half_up
from . import citations as C
from .approvals import evaluate_approval_evidence
from .dayfacts import DayFacts
from .findings import SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION, Finding
from .holidays import DAY_PLAIN_REST, DAY_REST_SWAP, DAY_STATUTORY_HOLIDAY, DAY_WORKDAY
from .quantities import (
    RATE_HOLIDAY_OT_PERMILLE,
    RATE_RESTDAY_OT_PERMILLE,
    RATE_WEEKDAY_OT_PERMILLE,
)
from .regime import (
    CYCLE_DAYS,
    REGIME_FLEXIBLE,
    REGIME_STANDARD,
    RegimeDecision,
)

RULE_PACK_V4 = "rp-2026.10.gd-pilot-standard.v4"
RULE_PACK_V5 = "rp-2026.11.gd-pilot-standard.v5"
RULE_PACK_V6 = "rp-2026.11.gd-pilot-standard.v6"
RULE_PACK_VERSION = RULE_PACK_V5   # 默认仍 v5；v6 需显式 WCA_RULE_PACK 启用

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
    daily_std_minutes: int
    weekly_std_minutes: int
    facts: list[DayFacts] = field(default_factory=list)
    quality_issues: list[dict] = field(default_factory=list)
    approvals: list[dict] = field(default_factory=list)
    range_start: date | None = None
    range_end: date | None = None
    # 产出该员工结论的规则包版本；v6 用它把 finding.rule_version 标成 v6，
    # v4/v5 仍沿用 RuleMeta.version，保证历史包摘要可复现。
    rule_pack_version: str = RULE_PACK_V4
    # 城市档：地方倍数条文与是否建档，来自 config/region_profile.json（src 里没有市名）
    local_citations: list[str] = field(default_factory=list)
    region_label: str = ""
    region_known: bool = True

    @property
    def regime(self) -> str:
        return self.decision.effective_regime


@dataclass
class RuleMeta:
    rule_id: str
    name_zh: str
    tier: str            # day / week / month / quality / scope
    citations: list[str]
    severity_kind: str   # pay(报酬类，最高需复核) / cap(上限类，可下违规) / scope / quality
    # v5 保留 v4 规则的回放：未改语义的旧规则继续标记 v4；新增规则标记 v5。
    version: str = RULE_PACK_V4


RULE_CATALOG: list[RuleMeta] = [
    RuleMeta("OT-D01", "工作日延长工作时间", "day", [C.LABOR_LAW_41, C.WAGE_PAYMENT_13], "pay"),
    RuleMeta("OT-D02", "休息日工作安排与补休", "day", [C.LABOR_LAW_44, C.MOHRSS_503_6], "pay"),
    RuleMeta("OT-D03", "法定节假日当天工作安排", "day",
             [C.LABOR_LAW_44, C.LABOR_LAW_40, C.LABOR_LAW_51], "pay"),
    RuleMeta("CAP-D05", "单日加班超过 3 小时", "day", [C.LABOR_LAW_41, C.SC_WORKTIME_3], "cap"),
    RuleMeta("CAP-W01", "连续工作 7 天无休息日", "week", [C.LABOR_LAW_38], "cap"),
    RuleMeta("WK-W02", "周实际工时超过 44 小时", "week", [C.LABOR_LAW_36], "cap"),
    RuleMeta("WK-W01", "周实际工时超过 40 小时（解释差异）", "week", [C.SC_WORKTIME_3, C.LABOR_LAW_36], "pay"),
    RuleMeta("CAP-M01", "月延长工时累计超过 36 小时", "month", [C.LABOR_LAW_41], "cap"),
    RuleMeta("CAP-M02", "月延长工时超过内部预警线", "month", [C.POLICY_OT_APPROVAL, C.LABOR_LAW_41], "quality"),
    RuleMeta("XD-01", "跨天班次切分依据不足", "quality", [C.LABOR_LAW_41, C.MOHRSS_503_6], "quality"),
    RuleMeta("NIGHT-01", "夜间时段工时统计（无全国统一标准）", "scope", [C.LABOR_LAW_36], "scope"),
    RuleMeta("QUAL-01", "数据质量异常（缺卡/重复/顺序/畸形入参）", "quality",
             [C.POLICY_ATTENDANCE, C.LCT_4], "quality"),
    RuleMeta("QUAL-02", "被拒收的输入行（事实缺口，须补录后重跑）", "quality",
             [C.POLICY_ATTENDANCE, C.LCT_4], "quality"),
    RuleMeta("POL-01", "加班缺审批记录（内部制度层）", "quality", [C.POLICY_OT_APPROVAL, C.LCT_4], "quality"),
    RuleMeta("SCOPE-01", "校验范围外：年度日历或调休安排未核实", "scope",
             [C.HOLIDAY_MEASURE_2, C.HOLIDAY_NOTICE_2026], "scope"),
    RuleMeta("SCOPE-02", "工时制不在本期范围（综合计算工时/不定时），未覆盖", "scope",
             [C.MOHRSS_503_3, C.MOHRSS_503_5], "scope"),
    RuleMeta("SCOPE-03", "申报特殊工时但缺审批证据，本期按标准工时校验并提示核实资质", "scope",
             [C.MOHRSS_503_3, C.MOHRSS_503_7], "scope"),
    RuleMeta("SCOPE-04", "员工所属城市不在档位表内，只出国家层面结论", "scope",
             [C.LABOR_LAW_44], "scope"),
    # ---------------------------------------------------------------- v5 新增
    RuleMeta("REG-01", "特殊工时审批覆盖核验（缺失/过期/岗位/城市）", "scope",
             [C.MOHRSS_503_3, C.MOHRSS_503_7], "scope", RULE_PACK_V5),
    RuleMeta("COMP-C01", "综合工时周期统计（总工时与法定标准差值）", "period",
             [C.MOHRSS_503_5, C.WAGE_PAYMENT_13], "scope", RULE_PACK_V5),
    RuleMeta("SHIFT-01", "多段班次不可拼接（打卡事实不闭合）", "quality",
             [C.POLICY_ATTENDANCE, C.MOHRSS_503_6], "quality", RULE_PACK_V5),
    RuleMeta("OFF-01", "离线补传冲突（同时点同类型多来源）", "quality",
             [C.POLICY_ATTENDANCE, C.LCT_4], "quality", RULE_PACK_V5),
]

CATALOG_BY_ID = {m.rule_id: m for m in RULE_CATALOG}


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
    source_refs: list[dict] | None = None,
    evidence: dict | None = None,
) -> Finding:
    meta = CATALOG_BY_ID[rule_id]
    if facts is not None and work_date is None:
        work_date = facts.work_date.isoformat()
    if meta.severity_kind == "pay" and severity == SEV_VIOLATION:
        # 结构性兜底：报酬类规则不得下「明显违规」
        severity = SEV_REVIEW
    base = list(citations if citations is not None else meta.citations)
    if not citations and meta.severity_kind == "pay":
        for cite in emp.local_citations:          # 报酬类结论按员工所属城市补地方条文
            if cite not in base:
                base.append(cite)
    refs = list(source_refs) if source_refs is not None else (list(facts.source_refs) if facts else [])
    return Finding(
        rule_id=rule_id,
        rule_version=(emp.rule_pack_version
                      if emp.rule_pack_version == RULE_PACK_V6 else meta.version),
        emp_id=emp.emp_id,
        severity=severity,
        explanation=explanation,
        citations=base,
        metric=metric,
        evidence=evidence or {},
        source_refs=refs,
        work_date=work_date,
        period_key=period_key,
    )


def _aggregate_evidence(rule_ids: list[str], window_kind: str, window_key: str,
                        dates: list, *, aggregation: str) -> dict:
    """周期聚合结论的定位元数据；独立于 metric，由 evidence_digest 覆盖。"""
    clean = sorted({d for d in dates if d is not None})
    return {
        "tables": ["punch.csv", "schedule.csv"],
        "window": {
            "kind": window_kind,
            "key": window_key,
            "start": clean[0].isoformat() if clean else None,
            "end": clean[-1].isoformat() if clean else None,
        },
        "rules": rule_ids,
        "aggregation": aggregation,
    }


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
    # 范围裁决 D-02（2026-10-08）：本期只判 8 小时标准工时。声明为综合计算工时/不定时
    # 的员工**不套用标准工时判据**（那会把不定时岗位的正常工作误判成违规），
    # 改由 rule_scope 统一产出 SCOPE-02「未覆盖」结论。
    if emp.regime != REGIME_STANDARD:
        return out
    for facts in emp.facts:
        worked = facts.minutes_worked

        if worked <= 0:
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
                    "holiday_label": facts.holiday_label,
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
                    "应按不低于 200% 支付（《劳动法》第 44 条第 2 项；地方依据见本条 citations 挂的条文，"
                    "按员工所属城市档位解析，不在文案里写死某个城市）。"
                )
                sev = _demote(SEV_REVIEW, facts)
            out.append(_finding(
                emp, "OT-D02", sev, text,
                {
                    "minutes_restdays": worked,
                    "day_type": facts.day_type,
                    "rate_permille": RATE_RESTDAY_OT_PERMILLE,
                    "comp_time_granted": int(facts.comp_time_granted),
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
                evidence=_aggregate_evidence(
                    ["CAP-W01", "SCOPE-01"], "iso_week", week_key,
                    [d.work_date for d in days],
                    aggregation="同一 ISO 周 7 个日历日逐日 minutes_worked/punch_count 聚合；"
                                "任一整天零工作且零打卡即视为休息日"),
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
                evidence=_aggregate_evidence(
                    ["WK-W02", "OT-D01"], "iso_week_4w_average", week_key,
                    [d.work_date for _k, ds in weeks[max(0, idx - 3): idx + 1] for d in ds],
                    aggregation="本周及前 3 个 ISO 周的 minutes_worked 求和后按周数平均；"
                                "本周 minutes_worked 同时进入周总计与 4 周平均"),
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
                evidence=_aggregate_evidence(
                    ["WK-W01", "OT-D01"], "iso_week", week_key,
                    [d.work_date for d in days],
                    aggregation="同一 ISO 周 minutes_worked 求和，与 weekly_std_minutes 比较"),
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
                evidence=_aggregate_evidence(
                    ["CAP-M01", "OT-D01"], "calendar_month", month_key,
                    [f.work_date for f in emp.facts
                     if _month_key(f.work_date) == month_key],
                    aggregation="自然月内逐日 max(0, minutes_worked-daily_std_minutes) 按 "
                                "counting_scope 求和；只计工作日延长"),
                period_key=month_key,
            ))
        elif counted > warn_line:
            out.append(_finding(
                emp, "CAP-M02", SEV_DEFENSIBLE,
                f"{month_key} 延长工时累计 {counted} 分钟，已达 36 小时上限的 90% 以上，"
                "触发内部制度预警线（policy.sz.overtime-approval），建议排班干预。",
                {**agg, "counted_minutes": counted, "warn_threshold_minutes": warn_line},
                evidence=_aggregate_evidence(
                    ["CAP-M02", "OT-D01"], "calendar_month", month_key,
                    [f.work_date for f in emp.facts
                     if _month_key(f.work_date) == month_key],
                    aggregation="自然月内工作日延长分钟按 counting_scope 求和；"
                                "与月上限 90% 预警线比较"),
                period_key=month_key,
            ))
    return out


# ------------------------------------------------------------------ 范围与资质
def rule_scope(emp: EmpScope, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    dec = emp.decision

    # 范围裁决 D-02（2026-10-08）分两种情形，保守口径不同：
    # 1) **实际按特殊工时执行**（已审批且岗位适用）——本期不判，产出 SCOPE-02「未覆盖」。
    #    周期超额与豁免适用都属退出的判据分支，硬套标准工时会把合法的特殊工时排班误判成违规。
    # 2) **申报特殊工时但回落为标准工时**（缺审批或岗位不符）——法律上就该按标准工时执行，
    #    所以照常判 J1~J6；但审批资质判定需要审批台账，本期不作违规结论，只出 SCOPE-03 提示复核。
    if not emp.region_known:
        out.append(_finding(
            emp, "SCOPE-04", SEV_REVIEW,
            f"员工所属城市代码 {emp.region_code} 不在城市档位表内：本次只产出国家层面条文依据的结论，"
            "不套用任何地方倍数条文，也不默认并入深圳档（需求 §7.3-3 不允许一套规则强盖多城）。"
            "要纳入该城市请在 config/region_profile.json 增加一档并核实其适用法规。",
            {"region_code": emp.region_code, "region_label": emp.region_label,
             "unlisted": 1},
            citations=[C.LABOR_LAW_44],
        ))

    if dec.effective_regime != REGIME_STANDARD:
        out.append(_finding(
            emp, "SCOPE-02", SEV_REVIEW,
            f"该员工按 {dec.effective_regime} 执行（岗位 {dec.job_code}，审批标记 {int(dec.approved)}），"
            "不属于本期覆盖的 8 小时标准工时判据。本期**不产出**周期超额、豁免适用或岗位适用性结论"
            "（综合计算工时/不定时的判据分支不可控，见需求 §6.2 与举证包「未覆盖清单」）；"
            "全部出勤事实按未覆盖登记，需要判定请扩范围后重跑，不得套用标准工时判据硬算。",
            {**dec.metric(), "excluded_reason": "regime-out-of-scope"},
        ))
    elif dec.declared_regime != REGIME_STANDARD:
        reasons = "；".join(dec.reasons or ["未说明回落原因"])
        out.append(_finding(
            emp, "SCOPE-03", SEV_REVIEW,
            f"申报 {dec.declared_regime} 但按标准工时校验（{reasons}）：本期对这类员工**照常产出 J1~J6 结论**，"
            "因为缺审批时法律上应执行标准工时；而「未取得审批本身是否构成违规」需要行政审批台账，"
            "本期不作违规结论（需求 §6.1-A 只包含 6 类标准工时判据），只提示人工核实资质。",
            {**dec.metric(), "judged_as": REGIME_STANDARD},
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


# ------------------------------------------------------------------ v5 新增规则
REG01_REVIEW_CITATIONS = [C.MOHRSS_503_3, C.MOHRSS_503_7]


def rule_reg_01(emp: EmpScope, cfg: Config) -> list[Finding]:
    """特殊工时审批覆盖：只核验台账，不改变 effective_regime，不下违规/倍数/金额。"""
    declared = emp.decision.declared_regime
    if declared == REGIME_STANDARD or (declared not in CYCLE_DAYS
                                       and declared != REGIME_FLEXIBLE):
        return []
    evidence = evaluate_approval_evidence(
        declared_regime=declared, job_code=emp.job_code, region_code=emp.region_code,
        approvals=emp.approvals, start=emp.range_start, end=emp.range_end,
    )
    if evidence.covered:
        return []
    selected = evidence.selected or {}
    text = (
        f"员工申报 {declared}，但审批台账不能证明覆盖本次校验："
        + "；".join(evidence.reasons)
        + f"。实际执行工时制仍按 regime.decide 的 {emp.regime} 处理（本规则不改变它）；"
        "本结论只要求补正/复核审批证据，不产出违规、倍数或金额。"
    )
    return [_finding(
        emp, "REG-01", SEV_REVIEW, text,
        {
            "declared_regime": declared,
            "effective_regime": emp.regime,
            "reasons": evidence.reasons,
            "approval_rows_checked": evidence.checked,
            "doc_no": str(selected.get("doc_no") or ""),
            "valid_from": str(selected.get("valid_from") or ""),
            "valid_to": str(selected.get("valid_to") or ""),
            "job_codes": str(selected.get("job_codes") or ""),
            "region_code": str(selected.get("region_code") or ""),
            "attachment_present": int(bool(str(selected.get("attachment_sha256") or ""))),
        },
        citations=REG01_REVIEW_CITATIONS,
    )]


def _month_periods(start: date, end: date) -> list[tuple[str, date, date]]:
    out: list[tuple[str, date, date]] = []
    y, m = start.year, start.month
    while (y, m) <= (end.year, end.month):
        last = calendar.monthrange(y, m)[1]
        p_start, p_end = date(y, m, 1), date(y, m, last)
        out.append((f"{y:04d}-{m:02d}", p_start, p_end))
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return out


def _quarter_periods(start: date, end: date) -> list[tuple[str, date, date]]:
    out: list[tuple[str, date, date]] = []
    for y in range(start.year, end.year + 1):
        for q in range(1, 5):
            first_month = 3 * q - 2
            last_month = 3 * q
            p_start = date(y, first_month, 1)
            p_end = date(y, last_month, calendar.monthrange(y, last_month)[1])
            out.append((f"{y:04d}-Q{q}", p_start, p_end))
    return out


def _year_periods(start: date, end: date) -> list[tuple[str, date, date]]:
    return [(f"{y:04d}", date(y, 1, 1), date(y, 12, 31))
            for y in range(start.year, end.year + 1)]


def _periods_for(declared_regime: str, start: date, end: date) -> list[tuple[str, date, date]]:
    if declared_regime == "comprehensive_monthly":
        return _month_periods(start, end)
    if declared_regime == "comprehensive_quarterly":
        return _quarter_periods(start, end)
    if declared_regime == "comprehensive_yearly":
        return _year_periods(start, end)
    return []


def _merge_refs(facts: list[DayFacts]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in facts:
        for ref in f.source_refs:
            key = (ref.get("file_id"), ref.get("line_no"))
            if key in seen:
                continue
            seen.add(key)
            out.append({"file_id": key[0], "line_no": key[1]})
    return sorted(out, key=lambda x: (str(x["file_id"]), str(x["line_no"])))


def rule_comp_c01(emp: EmpScope, cfg: Config) -> list[Finding]:
    """综合工时完整周期统计：只算总工时与法定标准差值，不下违规、不出倍数。"""
    dec = emp.decision
    if dec.declared_regime not in CYCLE_DAYS:
        return []
    if not (dec.approved and dec.eligible_by_job):
        return []
    if emp.range_start is None or emp.range_end is None:
        return []
    out: list[Finding] = []
    for period_key, p_start, p_end in _periods_for(dec.declared_regime,
                                                   emp.range_start, emp.range_end):
        if p_start < emp.range_start or p_end > emp.range_end:
            continue
        period_facts = [f for f in emp.facts if p_start <= f.work_date <= p_end]
        expected_days = (p_end - p_start).days + 1
        if len({f.work_date for f in period_facts}) < expected_days:
            continue
        if any("CALENDAR-YEAR-NOT-COVERED" in f.quality_flags for f in period_facts):
            continue
        if not any(f.punch_count > 0 or f.minutes_worked > 0 for f in period_facts):
            continue
        total = sum(f.minutes_worked for f in period_facts)
        standard = sum(emp.daily_std_minutes for f in period_facts
                       if f.day_type == DAY_WORKDAY)
        difference = total - standard
        severity = SEV_REVIEW if difference > 0 else SEV_DEFENSIBLE
        out.append(_finding(
            emp, "COMP-C01", severity,
            f"{period_key} 完整周期统计：实际总工时 {total} 分钟，法定标准 {standard} 分钟，"
            f"差值 {difference:+d} 分钟（{dec.declared_regime}）。"
            "本结论只作统计，不判违规、不出倍数；周期是否被批准覆盖仍以 REG-01 台账核验为准。",
            {
                "cycle": dec.declared_regime,
                "period_key": period_key,
                "coverage_days": expected_days,
                "workdays": sum(1 for f in period_facts if f.day_type == DAY_WORKDAY),
                "minutes_worked": total,
                "standard_minutes": standard,
                "difference_minutes": difference,
            },
            period_key=period_key,
            source_refs=_merge_refs(period_facts),
        ))
    return out


def rule_shift_01(emp: EmpScope, cfg: Config) -> list[Finding]:
    """当日 >2 次打卡且无排班：事实不闭合，只标复核；不改 minutes_worked。"""
    out: list[Finding] = []
    for facts in emp.facts:
        if facts.punch_count <= 2 or facts.plan_present:
            continue
        flags = set(facts.quality_flags)
        if {"PUNCH-MISSING", "PUNCH-ORDER"} & flags:
            continue   # 缺卡/顺序异常已由 QUAL-01 负责，避免重复
        out.append(_finding(
            emp, "SHIFT-01", SEV_REVIEW,
            f"{facts.work_date} 当日打卡 {facts.punch_count} 次（>2）且无排班计划，"
            "无法判断哪些事件属于同一段班次；不拼接、不修改 minutes_worked，"
            "保留原始行并要求人工核对班次切分。",
            {"punch_count": facts.punch_count, "minutes_worked": facts.minutes_worked,
             "planned_minutes": facts.planned_minutes, "plan_present": 0},
            facts,
        ))
    return out


def rule_off_01(emp: EmpScope, cfg: Config) -> list[Finding]:
    """离线补传冲突：同时点同类型多来源，两条都保留，冲突日不计倍数。"""
    out: list[Finding] = []
    for facts in emp.facts:
        if not facts.conflicts:
            continue
        out.append(_finding(
            emp, "OFF-01", SEV_REVIEW,
            f"{facts.work_date} 存在 {len(facts.conflicts)} 组同时点、同打卡类型的多来源冲突；"
            "两条事实均已保留，不静默丢弃任一条；本日不进入倍数结论，"
            "须人工确认以哪条为准并补正离线补传记录。",
            {"conflict_count": len(facts.conflicts), "conflicts": facts.conflicts,
             "minutes_worked": facts.minutes_worked, "punch_count": facts.punch_count,
             "multiplier_excluded": 1},
            facts,
        ))
    return out


_MULTIPLIER_RULES = {"OT-D01", "OT-D02", "OT-D03"}


def rule_day_v5(emp: EmpScope, cfg: Config, *, base_findings: list[Finding] | None = None
                ) -> list[Finding]:
    """v5 日级包装：v4 日规则照跑，但冲突日不得进入倍数结论。"""
    base = list(base_findings) if base_findings is not None else rule_day(emp, cfg)
    conflict_dates = {f.work_date.isoformat() for f in emp.facts if f.conflicts}
    return [f for f in base
            if not (f.work_date in conflict_dates and f.rule_id in _MULTIPLIER_RULES)]


# ------------------------------------------------------------------ 规则包注册
DAY_RULES_V4 = [rule_day, rule_week, rule_month, rule_scope, rule_quality]
DAY_RULES_V5 = [rule_day_v5, rule_week, rule_month, rule_scope, rule_quality,
                rule_reg_01, rule_comp_c01, rule_shift_01, rule_off_01]
DAY_RULES = DAY_RULES_V5

_RULES_BY_PACK = {RULE_PACK_V4: DAY_RULES_V4, RULE_PACK_V5: DAY_RULES_V5,
                  RULE_PACK_V6: DAY_RULES_V5}


def rules_for_pack(rule_pack_id: str) -> list | None:
    """按规则包版本选规则；未知版本返回 None，由调用方明确报错而不是猜。"""
    return _RULES_BY_PACK.get(str(rule_pack_id))
