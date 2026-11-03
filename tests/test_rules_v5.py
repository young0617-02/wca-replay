"""v5 新增四条规则的判据测试（测试先于实现）。

覆盖用户要求的最小矩阵：
  REG-01  缺失 / 过期 / 岗位不符 / 城市不符 / 有效
  COMP-C01 完整周期 / 截断周期 / 未审批 / 岗位不符 / 等于标准
  SHIFT-01 4 卡无排班 / 4 卡有排班 / 2 卡 / 缺卡
  OFF-01  跨设备 / 同设备 / 补卡冲突 / 普通日
另外守三条结构约束：v4 不产新规则、v5 新规则不下违规/不出倍数、冲突日不计倍数。
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date, timedelta

import pytest

from conftest import find, load_base, load_full_facts, punch, schedule
from src.engine import run_check
from src.ingest import import_rows
from src.rules.dayfacts import DayFacts
from src.rules.findings import SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION
from src.rules.holidays import DAY_PLAIN_REST, DAY_WORKDAY
from src.rules.regime import decide
from src.rules.rulepack import (DAY_RULES_V4, DAY_RULES_V5, RULE_PACK_V4, RULE_PACK_V5,
                                EmpScope, rule_comp_c01, rule_off_01, rule_reg_01,
                                rule_shift_01, rules_for_pack)

V5 = RULE_PACK_V5


def _m(f) -> dict:
    return f.metric if isinstance(f.metric, dict) else json.loads(f.metric)


def _cfg5(cfg):
    return replace(cfg, rule_pack_id=V5)


def _scope(*, emp_id="T-CMP", declared="comprehensive_monthly", job="warehouse_shift",
           region="440300", approved=True, approvals=None, start=None, end=None,
           facts=None) -> EmpScope:
    decision = decide(emp_id, job, declared, approved)
    return EmpScope(
        emp_id=emp_id, job_code=job, region_code=region, org_id="ORG-A",
        decision=decision, daily_std_minutes=480, weekly_std_minutes=2400,
        facts=list(facts or []), approvals=list(approvals or []),
        range_start=start, range_end=end,
    )


def _month_facts(year: int, month: int, *, daily_minutes=540) -> list[DayFacts]:
    out: list[DayFacts] = []
    cur = date(year, month, 1)
    while cur.month == month:
        is_workday = cur.weekday() < 5
        out.append(DayFacts(
            emp_id="T-CMP", work_date=cur,
            day_type=DAY_WORKDAY if is_workday else DAY_PLAIN_REST,
            minutes_worked=daily_minutes if is_workday else 0,
            punch_count=2 if is_workday else 0,
            in_ts=None, out_ts=None,
            source_refs=[{"file_id": 1, "line_no": len(out) + 1}] if is_workday else [],
        ))
        cur += timedelta(days=1)
    return out


def _approval(**overrides) -> dict:
    row = {
        "approval_id": 1, "emp_id": "T-CMP", "doc_no": "深人社函〔2025〕001号",
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": json.dumps(["warehouse_shift"]),
        "region_code": "440300",
        "attachment_sha256": "a" * 64, "recorded_at": "2025-01-02T00:00:00+08:00",
    }
    row.update(overrides)
    return row


# ------------------------------------------------------------------ REG-01
def test_reg01_missing_ledger_is_review_and_does_not_change_effective_regime(cfg):
    scope = _scope(start=date(2025, 11, 1), end=date(2025, 11, 30), approvals=[])
    out = rule_reg_01(scope, cfg)
    assert len(out) == 1
    got = out[0]
    assert got.rule_id == "REG-01" and got.severity == SEV_REVIEW
    assert scope.regime == "comprehensive_monthly", "REG-01 不得改 regime.decide 的 effective_regime"
    assert "台账" in got.explanation and "未" in got.explanation
    assert "rate_permille" not in _m(got), "资质类规则不得出倍数"


@pytest.mark.parametrize("field,value,keyword", [
    ("valid_to", "2025-08-31", "期限"),
    ("valid_from", "2025-12-01", "期限"),
    ("job_codes", json.dumps(["tourism_seasonal"]), "岗位"),
    ("region_code", "440100", "城市"),
    ("doc_no", "", "文号"),
])
def test_reg01_invalid_approval_fields_are_review(cfg, field, value, keyword):
    scope = _scope(start=date(2025, 11, 1), end=date(2025, 11, 30),
                   approvals=[_approval(**{field: value})])
    out = rule_reg_01(scope, cfg)
    assert len(out) == 1 and out[0].severity == SEV_REVIEW
    assert keyword in out[0].explanation
    assert not out[0].metric.get("rate_permille")


def test_reg01_valid_approval_produces_nothing(cfg):
    scope = _scope(start=date(2025, 11, 1), end=date(2025, 11, 30),
                   approvals=[_approval()])
    assert rule_reg_01(scope, cfg) == []


def test_reg01_ignores_standard_regime(cfg):
    scope = _scope(declared="standard", job="assembly_line", approved=True,
                   start=date(2025, 11, 1), end=date(2025, 11, 30), approvals=[])
    assert rule_reg_01(scope, cfg) == []


# ------------------------------------------------------------------ COMP-C01
def test_comp_c01_complete_month_reports_difference_without_violation(cfg):
    start, end = date(2025, 11, 1), date(2025, 11, 30)
    scope = _scope(start=start, end=end, facts=_month_facts(2025, 11, daily_minutes=540))
    out = rule_comp_c01(scope, cfg)
    assert len(out) == 1
    got = out[0]
    assert got.rule_id == "COMP-C01" and got.period_key == "2025-11"
    assert got.severity == SEV_REVIEW
    assert got.severity != SEV_VIOLATION
    m = _m(got)
    assert m["minutes_worked"] == 20 * 540
    assert m["standard_minutes"] == 20 * 480
    assert m["difference_minutes"] == 20 * 60
    assert "rate_permille" not in m


def test_comp_c01_equal_to_standard_is_defensible_statistics(cfg):
    start, end = date(2025, 11, 1), date(2025, 11, 30)
    scope = _scope(start=start, end=end, facts=_month_facts(2025, 11, daily_minutes=480))
    out = rule_comp_c01(scope, cfg)
    assert len(out) == 1 and out[0].severity == SEV_DEFENSIBLE
    assert _m(out[0])["difference_minutes"] == 0
    assert "rate_permille" not in _m(out[0])


def test_comp_c01_truncated_period_produces_nothing(cfg):
    start, end = date(2025, 11, 5), date(2025, 11, 30)
    scope = _scope(start=start, end=end, facts=_month_facts(2025, 11, daily_minutes=540))
    assert rule_comp_c01(scope, cfg) == []


def test_comp_c01_unapproved_or_ineligible_produces_nothing(cfg):
    start, end = date(2025, 11, 1), date(2025, 11, 30)
    facts = _month_facts(2025, 11, daily_minutes=540)
    unapproved = _scope(approved=False, start=start, end=end, facts=facts)
    ineligible = _scope(job="store_clerk", approved=True, start=start, end=end, facts=facts)
    assert rule_comp_c01(unapproved, cfg) == []
    assert rule_comp_c01(ineligible, cfg) == []


def test_comp_c01_full_quarter_gets_quarter_period_key(cfg):
    start, end = date(2025, 10, 1), date(2025, 12, 31)
    facts: list[DayFacts] = []
    cur = start
    while cur <= end:
        is_workday = cur.weekday() < 5
        facts.append(DayFacts(
            emp_id="T-CMP", work_date=cur,
            day_type=DAY_WORKDAY if is_workday else DAY_PLAIN_REST,
            minutes_worked=510 if is_workday else 0,
            punch_count=2 if is_workday else 0,
            source_refs=[{"file_id": 2, "line_no": len(facts) + 1}] if is_workday else [],
        ))
        cur += timedelta(days=1)
    scope = _scope(declared="comprehensive_quarterly", start=start, end=end, facts=facts)
    out = rule_comp_c01(scope, cfg)
    assert len(out) == 1 and out[0].period_key == "2025-Q4"
    assert _m(out[0])["cycle"] == "comprehensive_quarterly"


# ------------------------------------------------------------------ SHIFT-01
def _day(*, punch_count=4, plan_present=False, flags=None) -> DayFacts:
    return DayFacts(
        emp_id="T-STD", work_date=date(2025, 11, 3), day_type=DAY_WORKDAY,
        minutes_worked=780, punch_count=punch_count, plan_present=plan_present,
        quality_flags=list(flags or []), source_refs=[{"file_id": 3, "line_no": 1}],
    )


def test_shift01_four_punches_without_plan_is_review(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line", facts=[_day()])
    out = rule_shift_01(scope, cfg)
    assert len(out) == 1 and out[0].severity == SEV_REVIEW
    assert _m(out[0])["punch_count"] == 4
    assert _m(out[0])["minutes_worked"] == 780, "规则不得改 minutes_worked"


def test_shift01_four_punches_with_plan_produces_nothing(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line",
                   facts=[_day(plan_present=True)])
    assert rule_shift_01(scope, cfg) == []


def test_shift01_two_punches_without_plan_produces_nothing(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line",
                   facts=[_day(punch_count=2)])
    assert rule_shift_01(scope, cfg) == []


def test_shift01_missing_punch_is_left_to_qual01(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line",
                   facts=[_day(flags=["PUNCH-MISSING"])])
    assert rule_shift_01(scope, cfg) == [], "缺卡由 QUAL-01 负责，SHIFT-01 不得重复"


# ------------------------------------------------------------------ OFF-01
def _conflict_day() -> DayFacts:
    return DayFacts(
        emp_id="T-STD", work_date=date(2025, 11, 4), day_type=DAY_WORKDAY,
        minutes_worked=540, punch_count=3,
        source_refs=[{"file_id": 4, "line_no": 1}, {"file_id": 4, "line_no": 2},
                     {"file_id": 5, "line_no": 2}],
        conflicts=[{
            "event_ts": "2025-11-04T09:00:00+08:00", "punch_type": "in",
            "sources": [{"kind": "punch", "device_id": "DEV-1", "file_id": 4, "line_no": 1},
                        {"kind": "punch", "device_id": "DEV-2", "file_id": 5, "line_no": 2}],
        }],
    )


def test_off01_cross_device_conflict_is_review_and_keeps_sources(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line",
                   facts=[_conflict_day()])
    out = rule_off_01(scope, cfg)
    assert len(out) == 1 and out[0].severity == SEV_REVIEW
    m = _m(out[0])
    assert m["conflict_count"] == 1
    assert len(m["conflicts"][0]["sources"]) == 2
    assert m["minutes_worked"] == 540
    assert "rate_permille" not in m


def test_off01_no_conflict_produces_nothing(cfg):
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line",
                   facts=[_day(punch_count=2)])
    assert rule_off_01(scope, cfg) == []


def test_off01_multiplier_is_suppressed_on_conflict_day(cfg):
    """冲突日可以保留事实与 CAP 类结论，但不得出 OT-D01/02/03 倍数。"""
    facts = _conflict_day()
    scope = _scope(emp_id="T-STD", declared="standard", job="assembly_line", facts=[facts])
    # 模拟普通日规则已产出的倍数结论：v5 包装层必须过滤掉
    from src.rules.rulepack import rule_day_v5
    from src.rules.findings import Finding
    base = Finding(rule_id="OT-D01", rule_version="v4", emp_id="T-STD", severity=SEV_REVIEW,
                   explanation="x", citations=["law.labor.44"],
                   metric={"minutes_extension": 60, "rate_permille": 1500},
                   work_date="2025-11-04", source_refs=facts.source_refs)
    assert rule_day_v5(scope, cfg, base_findings=[base]) == []
    assert rule_off_01(scope, cfg)[0].severity == SEV_REVIEW


def test_v4_and_v5_rule_registries_are_separate():
    assert rules_for_pack(RULE_PACK_V4) == DAY_RULES_V4
    assert rules_for_pack(V5) == DAY_RULES_V5
    assert rule_reg_01 not in DAY_RULES_V4
    assert rule_comp_c01 not in DAY_RULES_V4
    assert rule_shift_01 not in DAY_RULES_V4
    assert rule_off_01 not in DAY_RULES_V4
    assert rules_for_pack("rp-does-not-exist") is None


# ------------------------------------------------------------------ 集成
def test_v5_run_adds_new_rules_to_existing_v4_conclusions(conn, cfg):
    cfg5 = _cfg5(cfg)
    # v5 是新的审计链纪元：用 v5 配置从零装载同一批事实，避免在 v4 审计起点上强写。
    load_full_facts(conn, cfg5)
    out = run_check(conn, cfg5, start=date(2025, 9, 1), end=date(2025, 11, 30),
                    notes="v5 rules")
    # 标准工时员工仍有 v4 结论
    assert find(out.findings, "OT-D01", emp="T-STD", work_date="2025-09-02")
    # 综合工时员工：SCOPE-02 仍独立存在，同时新增 REG-01 + COMP-C01
    assert find(out.findings, "SCOPE-02", emp="T-CMP")
    assert find(out.findings, "REG-01", emp="T-CMP")
    comp = find(out.findings, "COMP-C01", emp="T-CMP", period="2025-11")
    assert len(comp) == 1 and comp[0].severity == SEV_REVIEW
    assert _m(comp[0])["difference_minutes"] == 20 * 60
    assert "rate_permille" not in _m(comp[0])
    # 新规则绝不出现违规/倍数
    for f in out.findings:
        if f.rule_id in {"REG-01", "COMP-C01", "SHIFT-01", "OFF-01"}:
            assert f.severity != SEV_VIOLATION
            assert "rate_permille" not in _m(f)


def test_v4_run_still_has_no_new_rules(facts_conn, cfg):
    out = run_check(facts_conn, cfg, start=date(2025, 9, 1), end=date(2025, 11, 30))
    ids = {f.rule_id for f in out.findings}
    assert not ({"REG-01", "COMP-C01", "SHIFT-01", "OFF-01"} & ids)


def test_v5_shift01_integration_keeps_minutes_and_qual01_out(conn, cfg):
    cfg5 = _cfg5(cfg)
    load_base(conn, cfg5)
    import_rows(conn, cfg5, "punch", [
        punch("T-STD", "2025-11-03T09:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-11-03T12:00:00+08:00", "out", "DEV-1"),
        punch("T-STD", "2025-11-03T13:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-11-03T18:00:00+08:00", "out", "DEV-1"),
    ], rel_path="inline://v5-shift")
    out = run_check(conn, cfg5, start=date(2025, 11, 3), end=date(2025, 11, 3))
    shift = find(out.findings, "SHIFT-01", emp="T-STD", work_date="2025-11-03")
    assert len(shift) == 1 and shift[0].severity == SEV_REVIEW
    row = conn.execute("SELECT minutes_worked, punch_count FROM attendance_day "
                       "WHERE emp_id='T-STD' AND work_date='2025-11-03'").fetchone()
    assert row["punch_count"] == 4
    assert row["minutes_worked"] == 540, "SHIFT-01 不得改 minutes_worked（09:00-18:00 口径不变）"
    assert not find(out.findings, "QUAL-01", emp="T-STD", work_date="2025-11-03")


def test_v5_off01_integration_keeps_both_rows_and_suppresses_multiplier(conn, cfg):
    cfg5 = _cfg5(cfg)
    load_base(conn, cfg5)
    import_rows(conn, cfg5, "punch", [
        punch("T-STD", "2025-11-04T09:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-11-04T09:00:00+08:00", "in", "DEV-2"),
        punch("T-STD", "2025-11-04T19:00:00+08:00", "out", "DEV-1"),
    ], rel_path="inline://v5-off")
    out = run_check(conn, cfg5, start=date(2025, 11, 4), end=date(2025, 11, 4))
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 3
    off = find(out.findings, "OFF-01", emp="T-STD", work_date="2025-11-04")
    assert len(off) == 1 and off[0].severity == SEV_REVIEW
    assert len(_m(off[0])["conflicts"][0]["sources"]) == 2
    assert not find(out.findings, "OT-D01", emp="T-STD", work_date="2025-11-04")


def test_v5_off01_same_device_duplicate_is_not_a_conflict(conn, cfg):
    cfg5 = _cfg5(cfg)
    load_base(conn, cfg5)
    row = punch("T-STD", "2025-11-05T09:00:00+08:00", "in", "DEV-1")
    import_rows(conn, cfg5, "punch", [row, dict(row)], rel_path="inline://v5-same-dev")
    out = run_check(conn, cfg5, start=date(2025, 11, 5), end=date(2025, 11, 5))
    assert not find(out.findings, "OFF-01", emp="T-STD")
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 1


def test_v5_off01_approved_correction_conflict_is_detected(conn, cfg):
    cfg5 = _cfg5(cfg)
    load_base(conn, cfg5)
    import_rows(conn, cfg5, "punch", [
        punch("T-STD", "2025-11-06T09:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-11-06T18:00:00+08:00", "out", "DEV-1"),
    ], rel_path="inline://v5-corr-punch")
    import_rows(conn, cfg5, "correction", [{
        "emp_id": "T-STD", "claimed_ts": "2025-11-06T09:00:00+08:00",
        "claimed_type": "in", "reason": "补录上班卡", "approved": "1"}],
        rel_path="inline://v5-corr")
    out = run_check(conn, cfg5, start=date(2025, 11, 6), end=date(2025, 11, 6))
    off = find(out.findings, "OFF-01", emp="T-STD", work_date="2025-11-06")
    assert len(off) == 1
    kinds = {s["kind"] for s in _m(off[0])["conflicts"][0]["sources"]}
    assert kinds == {"punch", "correction"}
    assert conn.execute("SELECT COUNT(*) AS c FROM punch_correction").fetchone()["c"] == 1


def test_v5_on_v4_library_creates_explicit_epoch(facts_conn, cfg):
    """v5 不能静默接在 v4 genesis 上；单库切换必须留下 epoch/切换事件且不重置旧链。"""
    from src.db import get_meta

    cfg5 = _cfg5(cfg)
    run_check(facts_conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 2))
    old_genesis = get_meta(facts_conn, "audit_genesis")
    out = run_check(facts_conn, cfg5, start=date(2025, 9, 1), end=date(2025, 9, 2))
    assert out.run_id
    assert get_meta(facts_conn, "audit_genesis") == old_genesis
    epoch = facts_conn.execute(
        "SELECT epoch_id, prev_rule_pack_version, prev_head_hash, segment_start_prev_hash "
        "FROM rule_pack_epoch WHERE rule_pack_version = ?", (RULE_PACK_V5,)).fetchone()
    assert epoch is not None and epoch["prev_rule_pack_version"] == RULE_PACK_V4
    transition = facts_conn.execute(
        "SELECT entry_hash, segment_id FROM audit_event WHERE action = 'rule_pack.epoch.start'"
    ).fetchone()
    assert transition is not None and transition["segment_id"] is None
    assert epoch["segment_start_prev_hash"] == transition["entry_hash"]


def test_v5_approval_ledger_changes_input_fingerprint(conn, cfg):
    """审批台账是 v5 的输入：台账变化必须改变 input_fingerprint（不能只看原始 CSV）。"""
    cfg5 = _cfg5(cfg)
    load_base(conn, cfg5)
    first = run_check(conn, cfg5, start=date(2025, 11, 1), end=date(2025, 11, 30))
    conn.execute(
        "INSERT INTO worktime_approval(emp_id, doc_no, regime, valid_from, valid_to, "
        "job_codes, region_code, attachment_sha256, recorded_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        ("T-CMP", "深人社函〔2025〕002号", "comprehensive_monthly", "2025-01-01",
         "2025-12-31", json.dumps(["warehouse_shift"]), "440300", "b" * 64,
         "2025-01-02T00:00:00+08:00"))
    second = run_check(conn, cfg5, start=date(2025, 11, 1), end=date(2025, 11, 30))
    assert second.input_fingerprint != first.input_fingerprint
    assert not find(second.findings, "REG-01", emp="T-CMP")
    assert find(first.findings, "REG-01", emp="T-CMP")


def test_v5_approval_ledger_roundtrip_removes_reg01(conn, cfg):
    cfg5 = _cfg5(cfg)
    load_full_facts(conn, cfg5)
    conn.execute(
        "INSERT INTO worktime_approval(emp_id, doc_no, regime, valid_from, valid_to, "
        "job_codes, region_code, attachment_sha256, recorded_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        ("T-CMP", "深人社函〔2025〕001号", "comprehensive_monthly", "2025-01-01",
         "2025-12-31", json.dumps(["warehouse_shift"]), "440300", "a" * 64,
         "2025-01-02T00:00:00+08:00"))
    out = run_check(conn, cfg5, start=date(2025, 11, 1), end=date(2025, 11, 30))
    assert not find(out.findings, "REG-01", emp="T-CMP"), "有效台账应消掉 REG-01"
    comp = find(out.findings, "COMP-C01", emp="T-CMP", period="2025-11")
    assert len(comp) == 1
