"""V1.1 优化项（O-1 / O-2 / O-3 / O-11a）的回归钉子。

这几条改的是**实现与可见性**，不是判据本身，所以每条测试都对应 reports/判据修订.md
REV-001 表格里的一行断言。任何一条跑不过，就说明「等价重构 / 只增可见性」的前提破了，
必须重新走判据修订流程，而不是把测试改掉。
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import date, timedelta

from conftest import find, load_base, punch
from src.anomaly import build_anomalies
from src.engine import run_check
from src.evidence import input_fingerprint
from src.ingest import import_rows
from src.rules.dayfacts import (build_day_facts, compute_day_facts,
                                load_employee_bundle, stamp)
from src.rules.findings import SEV_REVIEW, UNATTRIBUTED
from src.rules.holidays import HolidayCalendar


def _m(f) -> dict:
    import json

    return f.metric if isinstance(f.metric, dict) else json.loads(f.metric)


def _review_sources(conn, run_id: str) -> list[str]:
    return [r["source_id"] for r in conn.execute(
        "SELECT source_id FROM review_item WHERE run_id = ? AND source_type = 'finding' "
        "ORDER BY source_id", (run_id,)).fetchall()]


# ------------------------------------------------------------------ O-1 装配等价性
def test_o1_prefetch_window_does_not_change_day_facts(facts_conn, cfg):
    """批量路径（整段区间预取一次）与兼容路径（逐日预取）必须逐字段一致。

    唯一按窗口取的输入是 shift_plan，其余（打卡/补卡/请假/出差）都是整段历史预取，
    因此跨天请假与补卡最容易暴露差异，这里专门造一条跨 3 天的请假和一条补卡。
    """
    import_rows(facts_conn, cfg, "leave", [{
        "emp_id": "T-STD", "leave_kind": "annual",
        "start_ts": "2025-09-01T09:00:00+08:00", "end_ts": "2025-09-03T18:00:00+08:00",
        "approved": "1", "paid": "1"}], rel_path="inline://o1-leave")
    import_rows(facts_conn, cfg, "correction", [{
        "emp_id": "T-STD", "claimed_ts": "2025-09-10T18:30:00+08:00",
        "claimed_type": "out", "reason": "补录下班卡", "approved": "1"}],
        rel_path="inline://o1-correction")

    calendar = HolidayCalendar.load()
    start, end = date(2025, 9, 1), date(2025, 9, 30)
    wide = load_employee_bundle(facts_conn, cfg, "T-STD", start, end)

    diffs = []
    cur = start
    while cur <= end:
        narrow = load_employee_bundle(facts_conn, cfg, "T-STD", cur, cur)
        batch = asdict(compute_day_facts(wide, cfg, calendar, cur))
        single = asdict(compute_day_facts(narrow, cfg, calendar, cur))
        if batch != single:
            diffs.append((cur.isoformat(), {k: (batch[k], single[k])
                                            for k in batch if batch[k] != single[k]}))
        cur += timedelta(days=1)
    assert not diffs, f"批量装配与逐日装配结果出现差异：{diffs}"
    # 反向确认这条测试不是空跑：09-02 是 09:00-19:00 排班、休息 60 分钟
    spot = compute_day_facts(wide, cfg, calendar, date(2025, 9, 2))
    assert (spot.minutes_span, spot.minutes_rest, spot.minutes_worked) == (600, 60, 540)


def test_o1_batch_persistence_matches_legacy_single_day_path(facts_conn, cfg):
    """落库的 attendance_day（批量路径产出）必须与兼容实现 build_day_facts 逐日算出的一致。

    这条是「参考实现」钉子：批量路径改了 SQL 形状，兼容签名留着做对照，
    两者一旦漂移就说明其中一侧被单方面改过。
    """
    run_check(facts_conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5))
    calendar = HolidayCalendar.load()
    for emp_id in ("T-STD", "T-CMP", "T-OTHER"):
        cur = date(2025, 9, 1)
        while cur <= date(2025, 9, 5):
            ref = build_day_facts(facts_conn, cfg, emp_id, cur, calendar)
            got = facts_conn.execute(
                "SELECT day_type, minutes_worked, minutes_night, minutes_rest, punch_count, "
                "first_punch, last_punch FROM attendance_day "
                "WHERE emp_id = ? AND work_date = ?", (emp_id, cur.isoformat())).fetchone()
            assert got is not None, f"{emp_id} {cur} 未落库"
            assert tuple(got) == (
                ref.day_type, ref.minutes_worked, ref.minutes_night, ref.minutes_rest,
                ref.punch_count, stamp(ref.in_ts), stamp(ref.out_ts),
            ), f"批量路径与兼容实现不一致：{emp_id} {cur}"
            cur += timedelta(days=1)


# ------------------------------------------------------------------ O-2 缺口可见性
def test_o2_rejected_row_becomes_a_conclusion_and_a_review_item(conn, cfg):
    """旧行为：整行被拒收只进 quality_issues.csv，不进结论、不开复核单。"""
    load_base(conn, cfg)
    res = import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-16T09:00:00+08:00", "in"),
        {"emp_id": "T-STD", "event_ts": "2025-13-45T99:99:00+08:00", "punch_type": "in"},
    ], rel_path="inline://o2-rejected")
    assert res.rows_accepted == 1 and res.rows_rejected == 1

    out = run_check(conn, cfg, start=date(2025, 9, 16), end=date(2025, 9, 16))
    qual = find(out.findings, "QUAL-02", emp="T-STD")
    assert len(qual) == 1, "被拒收的行必须形成结论"
    assert qual[0].severity == SEV_REVIEW
    assert "拒收" in qual[0].explanation
    assert _m(qual[0])["rejected_lines"] == 1
    assert "QUAL-TS" in _m(qual[0])["issue_rule_ids"]

    # A7 反查：结论里带的行号要能回到原始文件与原始行
    refs = _m(qual[0])["line_refs"]
    assert refs and refs[0]["file_id"] == res.file_id
    got = conn.execute("SELECT rel_path, sha256 FROM raw_file WHERE file_id = ?",
                       (refs[0]["file_id"],)).fetchone()
    assert got["rel_path"] == "inline://o2-rejected" and len(got["sha256"]) == 64

    # 自动开单：质量缺口进复核队列（旧行为是零条）
    assert any(s.startswith("QUAL-02:T-STD") for s in _review_sources(conn, out.run_id))


def test_o2_unattributable_issues_are_not_invisible_anymore(conn, cfg):
    """归属不到人的问题（主数据缺员工）汇成一条「未归属」结论，且报表/复核单都看得见。"""
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("E404", "2025-09-17T09:00:00+08:00", "in"),
        punch("E405", "2025-09-17T18:00:00+08:00", "out"),
    ], rel_path="inline://o2-ghost")

    out = run_check(conn, cfg, start=date(2025, 9, 17), end=date(2025, 9, 17))
    un = [f for f in out.findings if f.emp_id == UNATTRIBUTED]
    assert len(un) == 1, "未归属问题必须汇成且只汇成一条结论，避免举证噪声"
    assert un[0].rule_id == "QUAL-02"
    assert _m(un[0])["issue_rule_counts"]["QUAL-EMP"] == 2
    assert un[0].source_refs, "未归属结论同样要可行级反查"

    anomalies = build_anomalies(conn, out.run_id)
    hit = [a for a in anomalies if a.emp_id == UNATTRIBUTED]
    assert hit, "异常报表不得用 INNER JOIN 把未归属结论丢掉"
    assert hit[0].pseudonym == UNATTRIBUTED
    assert any(s.startswith(f"QUAL-02:{UNATTRIBUTED}") for s in _review_sources(conn, out.run_id))


def test_o2_quality_gate_is_reported_per_employee_not_merged_away(conn, cfg):
    """QUAL-01 归属到人并按天分组：两个人的缺口不会被并成一条。"""
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-18T09:00:00+08:00", "in"),           # 缺下班卡
        punch("T-OTHER", "2025-09-18T09:00:00+08:00", "in"),         # 缺下班卡
    ], rel_path="inline://o2-missing")
    out = run_check(conn, cfg, start=date(2025, 9, 18), end=date(2025, 9, 18))
    by_emp = {f.emp_id for f in find(out.findings, "QUAL-01")}
    assert {"T-STD", "T-OTHER"} <= by_emp


# ------------------------------------------------------------------ O-3 内容唯一
def test_o3_same_content_reimported_under_new_name_is_not_double_counted(conn, cfg):
    """终端重传 / 档案改名：内容相同的打卡行不得二次入账，但必须留痕。"""
    load_base(conn, cfg)
    rows = [punch("T-STD", "2025-09-15T09:00:00+08:00", "in", "DEV-1"),
            punch("T-STD", "2025-09-15T18:00:00+08:00", "out", "DEV-1")]
    import_rows(conn, cfg, "punch", rows, rel_path="inline://o3-original")
    again = import_rows(conn, cfg, "punch", rows, rel_path="inline://o3-renamed")

    assert again.file_id != 0
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2
    dups = conn.execute("SELECT rule_id, emp_id, work_date, severity FROM ingest_issue "
                        "WHERE rule_id = 'QUAL-DUP'").fetchall()
    assert len(dups) == 2
    assert all(d["emp_id"] == "T-STD" and d["work_date"] == "2025-09-15" for d in dups)

    run_check(conn, cfg, start=date(2025, 9, 15), end=date(2025, 9, 15))
    day = conn.execute("SELECT minutes_worked, punch_count FROM attendance_day "
                       "WHERE emp_id = 'T-STD' AND work_date = '2025-09-15'").fetchone()
    assert day["punch_count"] == 2, "重复内容不得虚增打卡次数"
    assert day["minutes_worked"] == 540, "重复内容不得虚增工时"


def test_o3_different_device_is_a_distinct_fact(conn, cfg):
    """唯一键含 device_id：同人同时刻不同终端仍是两条事实（漏打卡申诉要用到）。"""
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-15T09:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-09-15T09:00:00+08:00", "in", "DEV-2"),
    ], rel_path="inline://o3-device")
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2


# ------------------------------------------------------------------ O-11a 指纹口径
def test_o11a_unrelated_input_does_not_move_the_fingerprint(facts_conn, cfg):
    """旧口径把库里登记过的所有文件都算进指纹，于是「无关数据进来」也会让可复现性说明变复杂。"""
    scope = (date(2025, 9, 1), date(2025, 9, 2))
    first = run_check(facts_conn, cfg, start=scope[0], end=scope[1])

    import_rows(facts_conn, cfg, "punch", [
        punch("T-STD", "2025-12-25T09:00:00+08:00", "in"),
        punch("T-STD", "2025-12-25T18:00:00+08:00", "out"),
    ], rel_path="inline://o11-out-of-window")
    second = run_check(facts_conn, cfg, start=scope[0], end=scope[1])

    assert second.input_fingerprint == first.input_fingerprint, "范围外文件不应改变本次输入指纹"
    assert second.conclusion_digest == first.conclusion_digest

    # 反向钉子：指纹不是常量——把范围换成真正引用到该文件的区间，它必须变
    third = run_check(facts_conn, cfg, start=date(2025, 12, 25), end=date(2025, 12, 25))
    assert third.input_fingerprint != first.input_fingerprint

    # 两种口径都还在（旧的全库口径保留为默认参数，供取证时对照解释）
    scope = {"start": "2025-09-01", "end": "2025-09-02", "region_code": cfg.region_code}
    all_files = input_fingerprint(facts_conn, scope)
    referenced = input_fingerprint(facts_conn, scope, file_ids=set())
    assert all_files != referenced, "「全库登记」与「引用集合」必须是可区分的两种口径"
