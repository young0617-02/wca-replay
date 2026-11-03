"""F-003/F-004 导入器与数据质量门禁（含 A7 行级可追溯、畸形入参不崩、幂等重导）。"""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import replace
from datetime import date

import pytest

import src.ingest as ingest
from conftest import load_base, punch
from src.engine import run_check
from src.ingest import import_csv_file, import_rows
from src.util import sha256_hex


def test_sqlite_import_abort_rolls_back_raw_file_and_punch(conn, cfg, tmp_path, monkeypatch):
    """SQLite：导入事务内异常必须同时回滚 raw_file 与 punch（不是只回滚派生行）。"""
    load_base(conn, cfg)
    before_raw = int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"])
    path = tmp_path / "punch.csv"
    path.write_text("emp_id,event_ts,punch_type,device_id\n"
                    "T-STD,2025-09-01T09:00:00+08:00,in,DEV-1\n"
                    "T-STD,2025-09-01T18:00:00+08:00,out,DEV-1\n", encoding="utf-8")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated audit failure after ingest writes")

    monkeypatch.setattr(ingest, "append_audit", boom)
    with pytest.raises(RuntimeError, match="simulated audit failure"):
        ingest.import_csv_file(conn, cfg, path, kind="punch", rel_path="punch.csv")
    assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 0
    assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw
    assert int(conn.execute("SELECT COUNT(*) c FROM ingest_issue").fetchone()["c"]) == 0


def test_sqlite_crash_retry_matches_normal_import_triple(conn, cfg, monkeypatch):
    """SQLite：中断回滚后重跑同一文件，指纹/摘要/结论条数与正常导入一致。

    数据里专门放一条同时点同类型、不同设备的打卡（OFF-01 冲突），
    因为冲突结论的 metric 会写入 source file_id；只有 file_id 也稳定，摘要才可能一致。
    """
    load_base(conn, cfg)
    rows = [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in", "DEV-1"),
        punch("T-STD", "2025-09-02T18:00:00+08:00", "out", "DEV-1"),
        punch("T-STD", "2025-09-02T18:00:00+08:00", "out", "DEV-2"),
    ]
    expected = import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-crash-retry")
    expected_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                             notes="sqlite crash expected")
    file_id = expected.file_id
    before_raw = int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) - 1
    conn.execute("DELETE FROM punch WHERE source_file_id = ?", (file_id,))
    conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
    conn.execute("DELETE FROM raw_file WHERE file_id = ?", (file_id,))

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash after sqlite ingest writes")

    monkeypatch.setattr(ingest, "append_audit", boom)
    with pytest.raises(RuntimeError, match="simulated crash"):
        import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-crash-retry")
    assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 0
    assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw
    monkeypatch.undo()

    retry = import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-crash-retry")
    assert retry.reimported is False
    retry_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                          notes="sqlite crash retry")
    assert retry_out.input_fingerprint == expected_out.input_fingerprint
    assert retry_out.conclusion_digest == expected_out.conclusion_digest
    assert len(retry_out.findings) == len(expected_out.findings)
    assert retry_out.counts == expected_out.counts


def test_sqlite_reimport_after_crash_keeps_file_id_stable(conn, cfg, monkeypatch):
    """回滚不得让 raw_file 主键跳号：否则引用 file_id 的结论摘要会漂移。"""
    load_base(conn, cfg)
    rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in", "DEV-1")]
    expected = import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-file-id")
    file_id = expected.file_id
    conn.execute("DELETE FROM punch WHERE source_file_id = ?", (file_id,))
    conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
    conn.execute("DELETE FROM raw_file WHERE file_id = ?", (file_id,))

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(ingest, "append_audit", boom)
    with pytest.raises(RuntimeError):
        import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-file-id")
    monkeypatch.undo()
    retry = import_rows(conn, cfg, "punch", rows, rel_path="inline://sqlite-file-id")
    assert retry.file_id == file_id


def test_sqlite_first_v5_import_after_v4_chain_does_not_nest_transaction(conn, cfg):
    """规则包从 v4 切到 v5 后的首次导入：epoch 创建不能嵌套在外层导入事务里。

    SQLite 在事务内再执行 BEGIN 会直接报“cannot start a transaction within a
    transaction”；若 epoch 创建发生在导入事务内，首次 v5 导入就会整批失败。
    """
    from src.evidence import verify_chain
    from src.rules.rulepack import RULE_PACK_V5

    load_base(conn, cfg)
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    res = import_rows(conn, cfg5, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in")],
        rel_path="inline://first-v5")
    assert res.rows_accepted == 1
    assert conn.execute(
        "SELECT COUNT(*) c FROM rule_pack_epoch WHERE rule_pack_version = ?",
        (RULE_PACK_V5,)).fetchone()["c"] == 1
    assert verify_chain(conn, cfg5).ok


@pytest.mark.parametrize("mode", ["executemany", "copy"])
def test_sqlite_bulk_mode_degrades_to_single(conn, cfg, caplog, mode):
    """SQLite 请求批量写入：必须降级为 single、日志可观测、结果与 single 一致。"""
    load_base(conn, cfg)
    rows = [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T18:00:00+08:00", "out"),
    ]
    rel = f"inline://sqlite-fallback-{mode}"
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="src.ingest"):
        res = import_rows(conn, replace(cfg, import_write_mode=mode), "punch", rows,
                          rel_path=rel)
    assert res.write_mode == "single"
    assert res.requested_write_mode == mode
    assert res.degraded_from == mode
    assert res.chunk_rows == cfg.import_batch_size
    assert res.rows_accepted == 2
    messages = [r.getMessage() for r in caplog.records
                if r.name == "src.ingest" and "SQLite" in r.getMessage()]
    assert len(messages) == 1, messages
    assert mode in messages[0]
    assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 2

    first = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                      notes=f"sqlite {mode} fallback")
    again = import_rows(conn, cfg, "punch", rows, rel_path=rel)
    assert again.reimported is True
    second = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                       notes="sqlite single control")
    assert first.input_fingerprint == second.input_fingerprint
    assert first.conclusion_digest == second.conclusion_digest
    assert len(first.findings) == len(second.findings)


def test_run_check_appends_audit_inside_transaction(conn, cfg, monkeypatch):
    """run_check 的审计 append 必须在 run/finding 事务内，锁才能覆盖到提交。"""
    import src.engine as engine
    from src.db import in_transaction
    from src.evidence import verify_chain

    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in")],
        rel_path="inline://audit-tx")
    original = engine.append_audit
    seen: list[bool] = []

    def wrapper(c, *args, **kwargs):
        seen.append(in_transaction(c))
        return original(c, *args, **kwargs)

    monkeypatch.setattr(engine, "append_audit", wrapper)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                    notes="audit tx")
    assert seen == [True], "run_check 的审计 append 不能在事务提交之后才执行"
    assert out.run_id
    assert verify_chain(conn, cfg).ok


def _legacy_import_csv(conn, cfg, path, *, kind: str, rel_path: str, created_at: str):
    """测试用：复刻流式改造前的整文件读取路径（raw bytes + 解码文本 + StringIO）。"""
    from src.db import transaction

    raw = path.read_bytes()
    digest = sha256_hex(raw)
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    header = list(reader.fieldnames or [])
    header_digest = sha256_hex("|".join(header).encode("utf-8"))
    with transaction(conn, immediate=True):
        ingest._acquire_import_lock(conn, rel_path, digest)
        file_id, reimported = ingest._register_file(
            conn, rel_path, digest, kind, header_digest, created_at, len(header))
        result = ingest._ingest_rows(
            conn, cfg, file_id=file_id, kind=kind, rows=reader, actor="system:ingest",
            rel_path=rel_path, digest=digest, created_at=created_at, start_line=2,
            manage_transaction=False)
        # 与当前 CSV 路径同一语义：row_count 是数据行数，不是表头列数。
        conn.execute("UPDATE raw_file SET row_count = ? WHERE file_id = ?",
                     (result.rows_seen, file_id))
        result.reimported = reimported
        return result


def test_stream_sha256_matches_full_read_across_chunk_boundaries(tmp_path):
    """流式哈希换块大小（1/7/4096/1 MiB）都必须与整文件 sha256 一致。"""
    path = tmp_path / "blob.csv"
    data = ("中文,设备,时间\n" * 5000).encode("utf-8") + b"x" * 123
    path.write_bytes(data)
    expected = sha256_hex(data)
    for chunk in (1, 7, 4096, 1 << 20):
        assert ingest._stream_sha256(path, chunk) == expected


def test_streaming_csv_matches_legacy_sha_rows_and_triple(conn, cfg, tmp_path):
    """流式 sha256/解析与旧整文件路径必须给出相同 sha256、行数与三元组。

    文件含 BOM、CRLF、带逗号的引号字段、中文设备名和一处非法 UTF-8 字节，
    覆盖解码换块、行尾与 errors='replace' 的等价性。
    """
    load_base(conn, cfg)
    path = tmp_path / "stream-parity.csv"
    header = b"\xef\xbb\xbfemp_id,event_ts,punch_type,device_id\r\n"
    lines = []
    for i in range(20):
        ts = f"2025-09-01T{9 + i // 6:02d}:{(i % 6) * 10:02d}:00+08:00"
        ptype = "in" if i % 2 == 0 else "out"
        device = ["DEV-1", '"DEV,1"', "设备一"][i % 3]
        lines.append(f"T-STD,{ts},{ptype},{device}\r\n".encode("utf-8"))
    # 第 19 行（0-based 18）的 device 塞一个非法字节：两条路径都必须替换而不崩。
    lines[18] = b"T-STD,2025-09-01T13:00:00+08:00,in,\xff\r\n"
    path.write_bytes(header + b"".join(lines))

    created_at = "2025-09-02T00:00:00+08:00"
    rel = "stream-parity.csv"
    legacy = _legacy_import_csv(conn, cfg, path, kind="punch", rel_path=rel,
                                created_at=created_at)
    first = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 1),
                      notes="legacy full read")
    streamed = import_csv_file(conn, cfg, path, kind="punch", rel_path=rel,
                               created_at=created_at)
    second = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 1),
                       notes="streaming read")

    expected_sha = sha256_hex(path.read_bytes())
    assert legacy.sha256 == streamed.sha256 == expected_sha
    assert (legacy.rows_seen, legacy.rows_accepted, legacy.rows_rejected) == \
           (streamed.rows_seen, streamed.rows_accepted, streamed.rows_rejected)
    stored_sha = conn.execute("SELECT sha256 FROM raw_file WHERE rel_path = ?",
                              (rel,)).fetchone()["sha256"]
    assert stored_sha == expected_sha
    assert streamed.reimported is True
    assert first.input_fingerprint == second.input_fingerprint
    assert first.conclusion_digest == second.conclusion_digest
    assert len(first.findings) == len(second.findings)
    assert first.counts == second.counts


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


def test_qual_dup_summary_keeps_issue_count_bounded_and_conclusion_same(conn, cfg):
    """同一员工大量 QUAL-DUP：汇总一条，但引擎展开后的结论/指纹与逐行存储一致。"""
    load_base(conn, cfg)
    rows = [punch("T-STD", f"2025-09-02T{9 + i // 6:02d}:{(i % 6) * 10:02d}:00+08:00",
                  "in" if i % 2 == 0 else "out", "DEV-1") for i in range(30)]
    import_rows(conn, cfg, "punch", rows, rel_path="inline://dup-original")
    # 0 = 关闭汇总，作为逐行存储对照；20 = 默认阈值，触发汇总。
    before = import_rows(conn, replace(cfg, qual_dup_aggregate_threshold=0),
                         "punch", rows, rel_path="inline://dup-file")
    first = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                      notes="qual-dup individual")
    after = import_rows(conn, replace(cfg, qual_dup_aggregate_threshold=20),
                        "punch", rows, rel_path="inline://dup-file")
    second = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                       notes="qual-dup summary")
    assert len(before.issues) == 30
    assert len(after.issues) == 1
    detail = json.loads(after.issues[0].detail)
    assert detail["qual_dup_summary"] is True
    assert detail["count"] == 30 and detail["line_min"] == 1 and detail["line_max"] == 30
    assert sum(meta["count"] for meta in detail["days"].values()) == detail["count"]
    assert conn.execute(
        "SELECT COUNT(*) c FROM ingest_issue WHERE rule_id = 'QUAL-DUP'").fetchone()["c"] == 1
    assert first.input_fingerprint == second.input_fingerprint
    assert first.conclusion_digest == second.conclusion_digest
    assert len(first.findings) == len(second.findings)
    assert first.counts == second.counts, "分级分布不得因 QUAL-DUP 汇总而变化"


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
