"""F-003/F-004 导入器与数据质量门禁（含 A7 行级可追溯、畸形入参不崩、幂等重导）。"""

from __future__ import annotations

from datetime import date

from conftest import load_base, punch
from src.engine import run_check
from src.ingest import import_csv_file, import_rows
from src.util import sha256_hex


def test_row_level_traceability(conn, cfg):
    """任取一条打卡事实，能反查到文件 sha256 + 行号（A7 的地基）。"""
    load_base(conn, cfg)
    res = import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-01T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-01T19:00:00+08:00", "out"),
    ], rel_path="inline://trace")
    row = conn.execute(
        "SELECT p.source_file_id, p.source_line_no, f.sha256, f.rel_path, p.raw_text "
        "FROM punch p JOIN raw_file f ON f.file_id = p.source_file_id "
        "WHERE p.source_file_id = ? ORDER BY p.source_line_no", (res.file_id,)
    ).fetchall()
    assert len(row) == 2
    assert [r["source_line_no"] for r in row] == [1, 2]
    assert row[0]["sha256"] == res.sha256
    assert row[0]["rel_path"] == "inline://trace"
    assert "event_ts=2025-09-01T09:00:00+08:00" in row[0]["raw_text"]


def test_finding_carries_line_refs_back_to_file(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
    ], rel_path="inline://ref-check")
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    day_findings = [f for f in out.findings if f.work_date]
    assert day_findings, "应产出日级结论"
    f = day_findings[0]
    assert f.source_refs, "结论必须携带行级来源"
    ref = f.source_refs[0]
    got = conn.execute("SELECT rel_path, sha256 FROM raw_file WHERE file_id = ?",
                       (ref["file_id"],)).fetchone()
    assert got["rel_path"] == "inline://ref-check"
    assert len(got["sha256"]) == 64


def test_malformed_inputs_never_crash_import(conn, cfg):
    """非字符串入参（None / 布尔 / NaN / 无穷 / bytes / dict / list）必须被隔离成记录，不许打断流程。"""
    load_base(conn, cfg)
    junk = [
        {"emp_id": "T-STD", "event_ts": None, "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": True, "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": float("nan"), "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": float("inf"), "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": b"\xff\xfe\x00bad", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": {"nested": [1, 2]}, "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": [1, 2, 3], "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-13-45T99:99:00+08:00", "punch_type": "in"},
        {"emp_id": 12345, "event_ts": "2025-09-01T09:00:00+08:00", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-09-01T09:00:00+08:00", "punch_type": "in",
         "device_id": ["dev", "list"]},
    ]
    res = import_rows(conn, cfg, "punch", junk, rel_path="inline://junk")
    assert res.rows_seen == len(junk)
    # 只有「必填字段都合法、仅可选字段 device_id 畸形」的那一行被保留（置空 + 降级留痕）
    assert res.rows_accepted == 1
    assert res.rows_rejected == len(junk) - 1
    assert res.rows_accepted + res.rows_rejected == res.rows_seen
    rules = {i.rule_id for i in res.issues}
    assert {"QUAL-EMPTY", "QUAL-ENC", "QUAL-TS", "QUAL-EMP"} <= rules
    kept = conn.execute("SELECT device_id, punch_type FROM punch").fetchall()
    assert len(kept) == 1 and kept[0]["device_id"] is None


def test_naive_timestamp_is_flagged_not_silently_assumed(conn, cfg):
    load_base(conn, cfg)
    res = import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-01 09:00:00", "in"),
        punch("T-STD", "2025/09/01 18:00:00", "out"),
    ], rel_path="inline://naive")
    assert res.rows_accepted == 2
    tz_issues = [i for i in res.issues if i.rule_id == "QUAL-TZ"]
    assert len(tz_issues) == 2
    stored = conn.execute("SELECT event_ts FROM punch ORDER BY source_line_no").fetchall()
    assert all(r["event_ts"].endswith("+08:00") for r in stored)


def test_duplicate_identical_punch_row_is_dropped_with_issue(conn, cfg):
    load_base(conn, cfg)
    row = punch("T-STD", "2025-09-01T09:00:00+08:00", "in", "DEV-1")
    res = import_rows(conn, cfg, "punch", [row, dict(row)], rel_path="inline://dup")
    assert res.rows_accepted == 1
    assert res.rows_rejected == 1
    assert any(i.rule_id == "QUAL-DUP" for i in res.issues)
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 1


def test_unknown_employee_is_rejected(conn, cfg):
    load_base(conn, cfg)
    res = import_rows(conn, cfg, "punch", [
        punch("E999", "2025-09-01T09:00:00+08:00", "in")], rel_path="inline://ghost")
    assert res.rows_rejected == 1
    assert any(i.rule_id == "QUAL-EMP" for i in res.issues)


def test_missing_column_rejects_whole_file(conn, cfg, tmp_path):
    bad = tmp_path / "punch.csv"
    bad.write_text("emp_id,event_ts\nT-STD,2025-09-01T09:00:00+08:00\n", encoding="utf-8")
    res = import_csv_file(conn, cfg, bad, kind="punch")
    assert any(i.rule_id == "QUAL-HDR" for i in res.issues)
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 0


def test_reimport_same_file_is_idempotent(conn, cfg):
    """幂等键 (rel_path, sha256)：重复导入同一文件不得产生重复事实（auscult 幂等键方法迁移）。"""
    load_base(conn, cfg)
    rows = [punch("T-STD", "2025-09-01T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-01T18:00:00+08:00", "out")]
    first = import_rows(conn, cfg, "punch", rows, rel_path="inline://idem")
    again = import_rows(conn, cfg, "punch", rows, rel_path="inline://idem")
    assert first.file_id == again.file_id
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2
    issues = conn.execute("SELECT COUNT(*) AS c FROM ingest_issue WHERE file_id = ?",
                          (first.file_id,)).fetchone()["c"]
    assert issues == 0
    # 审计链为每次导入追加一条事件（重跑留痕，不静默覆盖）
    events = conn.execute("SELECT seq, action FROM audit_event WHERE action = 'ingest.file' "
                          "ORDER BY seq").fetchall()
    # org + employee + 该文件的两次导入：重跑不静默覆盖，每次都留下审计事件
    assert len(events) == 4


def test_employee_negative_wage_is_rejected(conn, cfg):
    from conftest import EMPLOYEES as _E
    from src.ingest import import_rows as _I

    load_base(conn, cfg)
    bad_emp = [dict(_E[0], emp_id="T-NEG", normal_hourly_cents=-5)]
    res = _I(conn, cfg, "employee", bad_emp, rel_path="inline://neg")
    assert res.rows_rejected == 1
    assert any(i.rule_id == "QUAL-RANGE" for i in res.issues)


def test_unapproved_correction_does_not_close_missing_punch(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [punch("T-STD", "2025-09-08T09:00:00+08:00", "in")],
                rel_path="inline://only-in")
    import_rows(conn, cfg, "correction", [{
        "emp_id": "T-STD", "claimed_ts": "2025-09-08T18:00:00+08:00",
        "claimed_type": "out", "reason": "忘打卡", "approved": "0"}],
        rel_path="inline://corr-unapproved")
    out = run_check(conn, cfg, start=date(2025, 9, 8), end=date(2025, 9, 8))
    qual = [f for f in out.findings if f.rule_id == "QUAL-01" and f.emp_id == "T-STD"]
    assert qual, "未批准补卡不得闭合缺卡事实"
    assert "无已批准补卡" in qual[0].explanation


def test_approved_correction_closes_missing_punch(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [punch("T-STD", "2025-09-08T09:00:00+08:00", "in")],
                rel_path="inline://only-in2")
    import_rows(conn, cfg, "correction", [{
        "emp_id": "T-STD", "claimed_ts": "2025-09-08T18:00:00+08:00",
        "claimed_type": "out", "reason": "忘打卡", "approved": "1"}],
        rel_path="inline://corr-approved")
    out = run_check(conn, cfg, start=date(2025, 9, 8), end=date(2025, 9, 8))
    row = conn.execute("SELECT minutes_worked FROM attendance_day "
                       "WHERE emp_id='T-STD' AND work_date='2025-09-08'").fetchone()
    assert row["minutes_worked"] == 540  # 09:00 -> 补卡 18:00，无排班计划故不扣休息
    assert not any(f.rule_id == "QUAL-01" for f in out.findings)


def test_quality_report_counts_issues(conn, cfg):
    from src.ingest import quality_report

    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [{"emp_id": "T-STD", "event_ts": "not-a-date",
                                       "punch_type": "in"}], rel_path="inline://q")
    rep = quality_report(conn)
    assert rep and all({"rule_id", "severity", "count"} <= set(r) for r in rep)
    assert any(r["rule_id"] == "QUAL-TS" for r in rep)


def test_cross_day_anchor_follows_cut_hour(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-22T05:30:00+08:00", "in"),
    ], rel_path="inline://anchor")
    anchor = conn.execute("SELECT day_anchor FROM punch").fetchone()["day_anchor"]
    assert anchor == "2025-09-21", "05:30 早于 cut_hour 应归属前一工作日"
