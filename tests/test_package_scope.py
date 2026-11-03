"""Phase 3A：举证包只带本次 run 相关记录，不做全表扫描；无关数据不得入包。"""

from __future__ import annotations

import json
import re
import zipfile
from datetime import date
from pathlib import Path

from conftest import load_base, punch
from src.engine import run_check
from src.evidence import append_audit, export_package
from src.ingest import import_rows


def _trace(conn) -> list[str]:
    out: list[str] = []
    conn.set_trace_callback(out.append)
    return out


def test_unrelated_raw_files_and_issues_never_enter_package(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
    ], rel_path="inline://in-scope")
    # 范围外打卡：同一员工、不同日期；本次 run 不需要它
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-12-25T09:00:00+08:00", "in"),
        punch("T-STD", "2025-12-25T18:00:00+08:00", "out"),
    ], rel_path="inline://out-of-scope")
    # 范围外员工的坏行：只影响 T-OTHER，本次只校验 T-STD
    import_rows(conn, cfg, "punch", [
        {"emp_id": "T-OTHER", "event_ts": "not-a-date", "punch_type": "in"},
    ], rel_path="inline://unrelated-issue")

    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                    emp_ids=["T-STD"])
    append_audit(conn, run_id=None, actor="system:unrelated", action="unrelated.event",
                 payload={"note": "不属于本次 run"}, cfg=cfg)
    manifest = export_package(conn, cfg, out.run_id)

    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        input_files = zf.read("input_files.csv").decode("utf-8")
        inputs = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        chain = zf.read("audit_chain.jsonl").decode("utf-8")
        issues = zf.read("quality_issues.csv").decode("utf-8")
        assert "inline://out-of-scope" not in input_files
        assert "inline://unrelated-issue" not in input_files
        assert all("out-of-scope" not in e["rel_path"] for e in inputs["entries"])
        assert all("unrelated-issue" not in e["rel_path"] for e in inputs["entries"])
        assert "unrelated.event" not in chain, "run 之后的无关审计事件不得进入包"
        assert "unrelated-issue" not in issues


def test_export_queries_are_scoped_not_full_table_scans(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
    ], rel_path="inline://query-scope")
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))

    statements = _trace(conn)
    try:
        export_package(conn, cfg, out.run_id)
    finally:
        conn.set_trace_callback(None)

    # 三张表都不允许出现「无 WHERE 的 SELECT * ... ORDER BY」形状
    banned = re.compile(r"SELECT\s+\*\s+FROM\s+(raw_file|audit_event|ingest_issue)\s+ORDER\s+BY",
                        re.I)
    assert not [s for s in statements if banned.search(s)], \
        [s for s in statements if banned.search(s)]
    raw_queries = [s for s in statements if "FROM raw_file" in s]
    audit_queries = [s for s in statements if "FROM audit_event" in s]
    issue_queries = [s for s in statements if "FROM ingest_issue" in s]
    assert any("file_id IN" in s for s in raw_queries), "raw_file 必须按本次引用集合过滤"
    assert any("seq <=" in s for s in audit_queries), "audit_event 必须按 run 链前缀过滤"
    assert any("i.file_id IN" in s for s in issue_queries), "ingest_issue 必须按引用文件过滤"
    assert len(raw_queries) <= 4
    assert len(audit_queries) <= 5
    assert len(issue_queries) <= 2
