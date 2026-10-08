"""F-005/F-006 确定性校验引擎单测。

金额与分钟数的期望值都写成手工推导式（基数取 3000 分/小时这种能手算的数），
避免「引擎自己生成、引擎自己判分」的循环论证。
"""

from __future__ import annotations

from datetime import date

import pytest

from conftest import find, load_ambiguous_holiday, load_night_shift, load_streak
from src.engine import run_check
from src.rules.findings import SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION
from src.rules.quantities import overtime_pay_cents

BASE = 3000  # T-STD 正常工作时间小时工资（分）


def _m(f) -> dict:
    import json

    return f.metric if isinstance(f.metric, dict) else json.loads(f.metric)


# ------------------------------------------------------------------ 工作日延长工时
def test_exactly_8_hours_produces_no_overtime(checked):
    conn, cfg, out = checked
    assert not find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-01")


def test_extension_60min_is_defensible_and_pays_150_percent(checked):
    conn, cfg, out = checked
    f = find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-02")
    assert len(f) == 1
    got = f[0]
    assert got.severity == SEV_DEFENSIBLE
    assert _m(got)["minutes_extension"] == 60
    # 3000 分/小时 x 60 分钟 x 150% = 4500 分（45 元）
    assert _m(got)["estimate_cents"] == overtime_pay_cents(BASE, 60, 1500) == 4500
    assert _m(got)["authorized_final"] == 0


def test_extension_120min_requires_review(checked):
    conn, cfg, out = checked
    got = find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-03")[0]
    assert got.severity == SEV_REVIEW
    assert _m(got)["estimate_cents"] == 9000  # 3000 x 2 小时 x 1.5


def test_extension_180min_at_cap_does_not_trigger_daily_violation(checked):
    conn, cfg, out = checked
    assert find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-04")
    assert not find(out.findings, "CAP-D05", emp="T-STD", work_date="2025-09-04")


def test_extension_beyond_3_hours_is_clear_violation(checked):
    conn, cfg, out = checked
    cap = find(out.findings, "CAP-D05", emp="T-STD", work_date="2025-09-05")
    assert len(cap) == 1 and cap[0].severity == SEV_VIOLATION
    assert _m(cap[0])["minutes_extension"] == 240
    ot = find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-05")[0]
    assert _m(ot)["estimate_cents"] == 18000  # 3000 x 4 小时 x 1.5
    # 报酬类规则即便同日也不下违规结论
    assert ot.severity != SEV_VIOLATION


# ------------------------------------------------------------------ 休息日与法定节假日
def test_rest_day_work_is_200_percent_and_needs_review(checked):
    conn, cfg, out = checked
    got = find(out.findings, "OT-D02", emp="T-STD", work_date="2025-09-06")[0]
    assert got.severity == SEV_REVIEW
    assert _m(got)["minutes_restdays"] == 480
    assert _m(got)["estimate_cents"] == 48000  # 3000 x 8 小时 x 2


def test_rest_day_with_comp_time_is_defensible(conn, cfg):
    from conftest import load_base

    load_base(conn, cfg)
    from conftest import punch, schedule
    from src.ingest import import_rows

    import_rows(conn, cfg, "schedule", [
        schedule("T-STD", "2025-09-13", "2025-09-13T10:00:00+08:00",
                 "2025-09-13T18:00:00+08:00", rest=0)])
    import_rows(conn, cfg, "punch", [punch("T-STD", "2025-09-13T10:00:00+08:00", "in"),
                                     punch("T-STD", "2025-09-13T18:00:00+08:00", "out")])
    conn.execute(
        "INSERT INTO leave_record(emp_id, leave_kind, start_ts, end_ts, approved, paid) "
        "VALUES('T-STD','comp_time','2025-09-20T10:00:00+08:00','2025-09-20T18:00:00+08:00',1,0)"
    )
    # 把补休直接标在上班那天，验证 comp_time_granted 分支
    conn.execute("UPDATE leave_record SET start_ts='2025-09-13T10:00:00+08:00', "
                 "end_ts='2025-09-13T18:00:00+08:00' WHERE emp_id='T-STD'")
    out = run_check(conn, cfg, start=date(2025, 9, 13), end=date(2025, 9, 13))
    got = find(out.findings, "OT-D02", emp="T-STD", work_date="2025-09-13")[0]
    assert got.severity == SEV_DEFENSIBLE
    assert _m(got)["comp_time_granted"] == 1


def test_statutory_holiday_work_is_300_percent(checked):
    conn, cfg, out = checked
    got = find(out.findings, "OT-D03", emp="T-STD", work_date="2025-10-01")[0]
    assert _m(got)["minutes_holiday"] == 600
    assert _m(got)["rate_permille"] == 3000
    assert _m(got)["estimate_cents"] == 90000  # 3000 x 10 小时 x 3
    assert got.severity == SEV_REVIEW  # 是否足额支付需人工核对，报酬类不下判决


def test_swap_rest_day_inside_holiday_block_is_200_percent(checked):
    conn, cfg, out = checked
    got = find(out.findings, "OT-D02", emp="T-STD", work_date="2025-10-04")[0]
    assert _m(got)["day_type"] == "rest_day_swap"
    assert _m(got)["rate_permille"] == 2000


# ------------------------------------------------------------------ 每周休息与周工时
def test_seven_consecutive_workdays_violates_weekly_rest(conn, cfg):
    load_streak(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 29), end=date(2025, 10, 5))
    got = find(out.findings, "CAP-W01", emp="T-OTHER")
    assert len(got) == 1, "2025-W40 内 7 天全部出勤且无整天休息"
    assert got[0].severity == SEV_VIOLATION
    assert got[0].period_key == "2025-W40"
    assert _m(got[0])["days_present"] == 7


def test_incomplete_week_at_range_edge_is_not_judged(conn, cfg):
    load_streak(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 10, 1), end=date(2025, 10, 4))  # 截断的 4 天
    assert not find(out.findings, "CAP-W01", emp="T-OTHER")


def test_single_week_over_44h_is_review_but_persistent_is_violation(checked):
    conn, cfg, out = checked
    # 单周超标（11 月每周 5 天 x 630 = 3150 > 2640）但 4 周平均尚未超标 -> 只到需复核
    w45 = find(out.findings, "WK-W02", emp="T-STD", period="2025-W45")
    assert w45, "2025-W45 = 11/3~11/9，5 个工作日 x 630 分钟 = 3150 > 2640"
    assert _m(w45[0])["cap_minutes"] == 2640
    # 连续四周都超（W45~W48 各 3150）-> 平均值口径也超标 -> 明显违规
    w48 = find(out.findings, "WK-W02", emp="T-STD", period="2025-W48")
    assert w48, "2025-W48 = 11/24~11/30"
    assert w48[0].severity == SEV_VIOLATION
    assert _m(w48[0])["avg_4w_minutes"] == 3150
    assert _m(w45[0])["weeks_in_avg"] < 4 or _m(w45[0])["avg_4w_minutes"] <= 2640


def test_weekly_40h_divergence_is_flagged_not_decided(checked):
    conn, cfg, out = checked
    got = find(out.findings, "WK-W01", emp="T-STD")
    for f in got:
        assert f.severity == SEV_REVIEW
        assert "裁口径" in f.explanation or "口径" in f.explanation


# ------------------------------------------------------------------ 月上限与周期综合
def test_monthly_overtime_over_36h_is_violation(checked):
    conn, cfg, out = checked
    got = find(out.findings, "CAP-M01", emp="T-STD", period="2025-11")
    assert len(got) == 1 and got[0].severity == SEV_VIOLATION
    # 20 个工作日 x 150 分钟 = 3000 分钟 > 2160
    assert _m(got[0])["counted_minutes"] == 3000
    # 上限本身必须是 36 小时（2160 分钟）：默认值被改大也要能被发现
    assert _m(got[0])["cap_minutes"] == 2160
    assert cfg.ot_cap_monthly_minutes == 2160
    assert _m(got[0])["counting_scope"] == "weekday_only"


def test_comprehensive_cycle_excess_pays_150_percent(checked):
    conn, cfg, out = checked
    got = find(out.findings, "COMP-C01", emp="T-CMP", period="2025-11")
    assert len(got) == 1
    m = _m(got[0])
    assert m["expected_minutes"] == 9600   # 2025-11 法定工作日 20 天 x 480
    assert m["minutes_worked"] == 10800    # 20 天 x 540
    assert m["minutes_over"] == 1200
    assert m["estimate_cents"] == 60000    # 2000 分/小时 x 20 小时 x 1.5
    assert got[0].severity == SEV_REVIEW   # 是否足额支付需人工核对


def test_partial_cycle_is_declared_out_of_scope_not_guessed(conn, cfg):
    from conftest import load_base

    load_base(conn, cfg)
    # 只给 11 月前 5 天数据：周期被截断，不得按「超额」下结论
    from conftest import punch, schedule
    from src.ingest import import_rows

    for day in ("2025-11-03", "2025-11-04", "2025-11-05"):
        import_rows(conn, cfg, "schedule", [
            schedule("T-CMP", day, f"{day}T09:00:00+08:00", f"{day}T22:00:00+08:00", rest=0)],
            rel_path=f"inline://sched-{day}")
        import_rows(conn, cfg, "punch", [punch("T-CMP", f"{day}T09:00:00+08:00", "in"),
                                         punch("T-CMP", f"{day}T22:00:00+08:00", "out")],
                    rel_path=f"inline://punch-{day}")
    out = run_check(conn, cfg, start=date(2025, 11, 3), end=date(2025, 11, 5))
    assert not find(out.findings, "COMP-C01", emp="T-CMP")
    assert find(out.findings, "SCOPE-01", emp="T-CMP")


# ------------------------------------------------------------------ 特殊工时资质
def test_flexible_regime_earns_holiday_premium_in_shenzhen(checked):
    conn, cfg, out = checked
    got = find(out.findings, "OT-D04", emp="T-FLX", work_date="2025-10-01")
    assert len(got) == 1
    m = _m(got[0])
    assert m["rate_permille"] == 3000
    assert m["estimate_cents"] == 120000  # 5000 分/小时 x 8 小时 x 3
    assert m["region_divergence"] == "sz-stricter-than-national"


def test_flexible_regime_exempt_from_daily_overtime(checked):
    conn, cfg, out = checked
    assert not find(out.findings, "OT-D01", emp="T-FLX", work_date="2025-10-09")
    assert not find(out.findings, "CAP-D05", emp="T-FLX", work_date="2025-10-09")
    assert find(out.findings, "FX-F01", emp="T-FLX")


def test_unapproved_regime_falls_back_to_standard_and_is_violation(checked):
    conn, cfg, out = checked
    got = find(out.findings, "COMP-C02", emp="T-NAPPR")
    assert len(got) == 1 and got[0].severity == SEV_VIOLATION
    # 回落后必须按标准工时校验，所以延长 60 分钟要出 OT-D01
    assert find(out.findings, "OT-D01", emp="T-NAPPR", work_date="2025-09-02")


def test_job_not_eligible_for_special_regime_is_violation(conn, cfg):
    from conftest import load_base

    load_base(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 1))
    assert find(out.findings, "COMP-C03", emp="T-BADJOB")


# ------------------------------------------------------------------ 跨零点与夜班
def test_cross_midnight_without_schedule_needs_review(conn, cfg):
    load_night_shift(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 12, 14), end=date(2025, 12, 14))
    xd = find(out.findings, "XD-01", emp="T-STD")
    assert len(xd) == 1 and xd[0].severity == SEV_REVIEW
    assert _m(xd[0])["cut_hour"] == cfg.cross_day_cut_hour
    night = find(out.findings, "NIGHT-01", emp="T-STD")
    assert night and _m(night[0])["minutes_night"] == 360  # 夜间窗口 00:00-06:00 整


def test_cross_midnight_punches_pair_into_one_workday(conn, cfg):
    load_night_shift(conn, cfg)
    run_check(conn, cfg, start=date(2025, 12, 14), end=date(2025, 12, 14))
    row = conn.execute(
        "SELECT minutes_worked, crossed_midnight FROM attendance_day "
        "WHERE emp_id='T-STD' AND work_date='2025-12-14'"
    ).fetchone()
    assert row["minutes_worked"] == 570  # 21:00 -> 次日 06:30 = 570 分钟，无休息
    assert row["crossed_midnight"] == 1


# ------------------------------------------------------------------ 口径歧义降级
def test_ambiguous_holiday_date_is_marked_and_undecidable(conn, cfg):
    load_ambiguous_holiday(conn, cfg)
    out = run_check(conn, cfg, start=date(2026, 4, 5), end=date(2026, 4, 5))
    got = find(out.findings, "OT-D03", emp="T-STD", work_date="2026-04-05")
    assert len(got) == 1
    assert got[0].severity == SEV_REVIEW
    assert _m(got[0])["ambiguous_day_type"] == 1
    assert "待核对" in got[0].explanation


def test_ambiguity_demotes_clear_violation_to_review():
    """直接验证降级函数：口径不明时，上限类结论也不得下「明显违规」。"""
    from datetime import date as _date

    from src.rules.dayfacts import DayFacts
    from src.rules.rulepack import _demote

    plain = DayFacts(emp_id="X", work_date=_date(2025, 9, 5), day_type="workday")
    ambig = DayFacts(emp_id="X", work_date=_date(2026, 4, 5), day_type="statutory_holiday",
                     ambiguous_day_type=True)
    assert _demote(SEV_VIOLATION, plain) == SEV_VIOLATION
    assert _demote(SEV_VIOLATION, ambig) == SEV_REVIEW


# ------------------------------------------------------------------ 结构与不变量
def test_pay_rules_never_emit_violation(checked):
    conn, cfg, out = checked
    from src.rules.rulepack import CATALOG_BY_ID

    for f in out.findings:
        if CATALOG_BY_ID[f.rule_id].severity_kind == "pay":
            assert f.severity != SEV_VIOLATION, f"{f.rule_id} 不得下明显违规结论"


def test_every_finding_carries_citation_and_line_refs(checked):
    conn, cfg, out = checked
    for f in out.findings:
        assert f.citations, f"规则 {f.rule_id} 的结论缺条文依据"
    # 日级结论必须能反查到原始行（A7）
    for f in out.findings:
        if f.work_date:
            assert f.source_refs, f"{f.rule_id}@{f.emp_id} 缺行级来源"


def test_recheck_is_deterministic(checked):
    conn, cfg, out = checked
    again = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                      notes="pytest rerun")
    assert again.conclusion_digest == out.conclusion_digest
    assert again.input_fingerprint == out.input_fingerprint


def test_money_math_uses_integers_only():
    import pytest

    from src.util import canonical_json

    assert overtime_pay_cents(3000, 60, 1500) == 4500
    assert overtime_pay_cents(1, 1, 1) == 0          # 3/60000 -> 0
    assert overtime_pay_cents(1, 30, 1000) == 1      # 半进位：0.5 分 -> 1 分
    assert overtime_pay_cents(2, 15, 1000) == 1      # 半进位：0.5 分 -> 1 分
    with pytest.raises(TypeError):
        canonical_json({"x": 0.5})


def test_pay_rule_violation_is_structurally_demoted():
    """报酬类规则即使传入「明显违规」也必须被降级为需复核（结构性兜底）。"""
    from src.rules.findings import Finding  # noqa: F401  (确认Finding校验存在)
    from src.rules.rulepack import EmpScope, _finding, CATALOG_BY_ID
    from src.rules.regime import decide

    emp = EmpScope(
        emp_id="T-X", job_code="assembly_line", region_code="440300", org_id="ORG-A",
        decision=decide("T-X", "assembly_line", "standard", False),
        hourly_normal_cents=1000, daily_std_minutes=480, weekly_std_minutes=2400,
    )
    assert CATALOG_BY_ID["OT-D01"].severity_kind == "pay"
    got = _finding(emp, "OT-D01", SEV_VIOLATION, "x", {"minutes_extension": 60})
    assert got.severity == SEV_REVIEW, "报酬类规则不得产出明显违规结论"
    cap = _finding(emp, "CAP-D05", SEV_VIOLATION, "x", {"minutes_extension": 240})
    assert cap.severity == SEV_VIOLATION, "上限类规则仍应可以下违规结论（否则降级过度）"
