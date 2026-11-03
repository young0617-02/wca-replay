"""审批台账 P0：T-AL-01 ~ T-AL-12。"""

from __future__ import annotations

import csv
import inspect
import threading
from pathlib import Path

import pytest

from src.auth import User
from src.db import connect
from src.rules.approval_docs import (ApprovalConflictError, coverage_for, create_draft,
                                     import_drafts_csv, list_docs, publish_doc,
                                     refresh_org_paths)
from src.rules.approval_docs import CSV_FIELDS

AD = User("ad1", "E1", ("AD",), "ORG-A", "440300", "管理员")
AU = User("au1", "E1", ("AU",), "ORG-A", "440300", "审计员")


def _seed(conn) -> None:
    for org_id, parent in (("ORG-ROOT", ""), ("ORG-A", "ORG-ROOT"),
                           ("ORG-A1", "ORG-A"), ("ORG-B", "ORG-ROOT")):
        conn.execute("INSERT INTO org_unit(org_id, org_name, parent_id) VALUES(?,?,?)",
                     (org_id, org_id, parent or None))
    for emp_id, org_id in (("E1", "ORG-A"), ("E2", "ORG-A1"),
                           ("E3", "ORG-B"), ("E4", "ORG-A")):
        conn.execute(
            "INSERT INTO employee(emp_id, pseudonym, job_code, org_id, region_code, "
            "worktime_regime, contract_approved_flex, pay_base_cents, pay_base_hourly_cents, "
            "normal_hourly_cents, is_manager, acl_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp_id, emp_id, "warehouse_shift", org_id, "440300", "standard", 0,
             0, 0, 0, 0, "self"))
    for emp_id, job, region in (("E5", "assembly_line", "440300"),
                                ("E6", "warehouse_shift", "440100")):
        conn.execute(
            "INSERT INTO employee(emp_id, pseudonym, job_code, org_id, region_code, "
            "worktime_regime, contract_approved_flex, pay_base_cents, pay_base_hourly_cents, "
            "normal_hourly_cents, is_manager, acl_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp_id, emp_id, job, "ORG-A", region, "standard", 0, 0, 0, 0, 0, "self"))
    refresh_org_paths(conn)


def _kw(doc_no: str, *, version_no: int = 1, scopes=(), regime="comprehensive_monthly",
        start="2025-01-01", end="2025-12-31", sha="a" * 64) -> dict:
    return {
        "doc_no": doc_no, "title": f"批文 {doc_no}", "issuer": "深圳市人社局",
        "regime": regime, "version_no": version_no, "valid_from": start, "valid_to": end,
        "job_codes": '["warehouse_shift"]', "region_code": "440300",
        "attachment_sha256": sha, "scopes": scopes,
        "change_note": f"v{version_no}",
    }


def _write_csv(path: Path, rows: list[dict]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_FIELDS), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
    return path


def test_t_al_01_au_can_read_docs_and_coverage(conn, cfg):
    _seed(conn)
    created = create_draft(conn, cfg, AD, **_kw("DOC-R1", scopes=[("employee", "E1")]))
    publish_doc(conn, cfg, AD, "DOC-R1")
    assert [d["doc_no"] for d in list_docs(conn, AU)] == ["DOC-R1"]
    rows = coverage_for(conn, AU, "E1")
    assert len(rows) == 1 and rows[0]["doc_no"] == "DOC-R1"
    assert created["version_no"] == 1


def test_t_al_02_au_cannot_write_or_publish(conn, cfg, tmp_path):
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-W1", scopes=[("employee", "E1")]))
    with pytest.raises(PermissionError):
        create_draft(conn, cfg, AU, **_kw("DOC-W2", scopes=[("employee", "E1")]))
    with pytest.raises(PermissionError):
        publish_doc(conn, cfg, AU, "DOC-W1")
    with pytest.raises(PermissionError):
        import_drafts_csv(conn, cfg, AU, tmp_path / "none.csv")


def test_t_al_03_schema_has_doc_version_scope_coverage_and_org_path(conn, cfg):
    _seed(conn)
    for table in ("approval_doc", "approval_doc_version", "approval_doc_scope",
                  "employee_approval_coverage"):
        assert conn.execute("SELECT COUNT(*) AS c FROM " + table).fetchone()["c"] == 0
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(org_unit)").fetchall()}
    assert {"org_path", "org_level"} <= columns


def test_t_al_04_org_paths_are_materialised(conn, cfg):
    _seed(conn)
    rows = {r["org_id"]: dict(r) for r in conn.execute(
        "SELECT org_id, org_path, org_level FROM org_unit").fetchall()}
    assert rows["ORG-ROOT"]["org_path"] == "/ORG-ROOT/"
    assert rows["ORG-A"]["org_path"] == "/ORG-ROOT/ORG-A/"
    assert rows["ORG-A1"]["org_path"] == "/ORG-ROOT/ORG-A/ORG-A1/"
    assert rows["ORG-A1"]["org_level"] == 2


def test_t_al_05_employee_scope_projects_to_one_employee(conn, cfg):
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-E1", scopes=[("employee", "E1")]))
    out = publish_doc(conn, cfg, AD, "DOC-E1")
    assert out["coverage_employees"] == 1
    assert [r["emp_id"] for r in coverage_for(conn, AU, "E1")] == ["E1"]
    assert coverage_for(conn, AU, "E2") == []


def test_t_al_06_org_scope_expands_descendants(conn, cfg):
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-ORG", scopes=[("org", "ORG-A")]))
    out = publish_doc(conn, cfg, AD, "DOC-ORG")
    covered = {r["emp_id"] for emp in ("E1", "E2", "E4")
               for r in coverage_for(conn, AU, emp)}
    assert out["coverage_employees"] == 3
    assert covered == {"E1", "E2", "E4"}
    assert coverage_for(conn, AU, "E3") == []
    assert coverage_for(conn, AU, "E5") == []   # 岗位不符
    assert coverage_for(conn, AU, "E6") == []   # 城市不符


def test_t_al_07_new_version_supersedes_old_coverage(conn, cfg):
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-V", version_no=1, scopes=[("employee", "E1")]))
    publish_doc(conn, cfg, AD, "DOC-V", 1)
    with pytest.raises(ApprovalConflictError, match="版本 1 已存在"):
        create_draft(conn, cfg, AD, **_kw("DOC-V", version_no=1,
                                          scopes=[("employee", "E1")]))
    create_draft(conn, cfg, AD, **_kw("DOC-V", version_no=2, scopes=[("employee", "E1")],
                                     start="2026-01-01", end="2026-12-31"))
    publish_doc(conn, cfg, AD, "DOC-V", 2)
    versions = conn.execute(
        "SELECT version_no, status FROM approval_doc_version ORDER BY version_no").fetchall()
    assert [(r["version_no"], r["status"]) for r in versions] == [(1, "SUPERSEDED"),
                                                                   (2, "PUBLISHED")]
    doc = conn.execute("SELECT current_version FROM approval_doc WHERE doc_no='DOC-V'").fetchone()
    assert doc["current_version"] == 2
    rows = coverage_for(conn, AU, "E1")
    assert len(rows) == 1 and rows[0]["version_no"] == 2


def test_t_al_08_overlapping_published_coverage_is_rejected(conn, cfg):
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-C1", scopes=[("employee", "E1")]))
    publish_doc(conn, cfg, AD, "DOC-C1")
    create_draft(conn, cfg, AD, **_kw("DOC-C2", scopes=[("employee", "E1")]))
    with pytest.raises(ApprovalConflictError, match="覆盖冲突"):
        publish_doc(conn, cfg, AD, "DOC-C2")
    assert coverage_for(conn, AU, "E1")[0]["doc_no"] == "DOC-C1"
    assert conn.execute("SELECT COUNT(*) AS c FROM employee_approval_coverage").fetchone()["c"] == 1


def test_t_al_09_csv_import_is_atomic(conn, cfg, tmp_path):
    _seed(conn)
    good = _write_csv(tmp_path / "good.csv", [
        {"doc_no": "DOC-CSV", "title": "批文 CSV", "issuer": "人社局",
         "regime": "comprehensive_monthly", "version_no": 1, "valid_from": "2025-01-01",
         "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
         "region_code": "440300", "attachment_sha256": "a" * 64,
         "scope_type": "employee", "scope_value": "E1"},
        {"doc_no": "DOC-CSV", "title": "批文 CSV", "issuer": "人社局",
         "regime": "comprehensive_monthly", "version_no": 1, "valid_from": "2025-01-01",
         "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
         "region_code": "440300", "attachment_sha256": "a" * 64,
         "scope_type": "employee", "scope_value": "E2"},
    ])
    out = import_drafts_csv(conn, cfg, AD, good)
    assert out["docs"] == 1 and out["versions"] == 1 and out["rows"] == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM approval_doc_scope").fetchone()["c"] == 2

    bad = _write_csv(tmp_path / "bad.csv", [
        {"doc_no": "DOC-BAD", "title": "坏批文", "issuer": "人社局",
         "regime": "comprehensive_monthly", "version_no": 1, "valid_from": "2025-01-01",
         "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
         "region_code": "440300", "attachment_sha256": "a" * 64,
         "scope_type": "employee", "scope_value": "E1"},
        {"doc_no": "DOC-BAD", "title": "坏批文", "issuer": "人社局",
         "regime": "comprehensive_monthly", "version_no": 1, "valid_from": "2025-01-01",
         "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
         "region_code": "440300", "attachment_sha256": "not-a-sha",
         "scope_type": "employee", "scope_value": "E2"},
    ])
    with pytest.raises(ValueError):
        import_drafts_csv(conn, cfg, AD, bad)
    assert conn.execute("SELECT COUNT(*) AS c FROM approval_doc WHERE doc_no='DOC-BAD'"
                        ).fetchone()["c"] == 0
    assert conn.execute("SELECT COUNT(*) AS c FROM approval_doc_version").fetchone()["c"] == 1


def test_t_al_10_attachment_is_only_sha256(conn, cfg):
    _seed(conn)
    with pytest.raises(ValueError, match="sha256"):
        create_draft(conn, cfg, AD, **_kw("DOC-BAD-SHA", sha="x" * 64,
                                          scopes=[("employee", "E1")]))
    create_draft(conn, cfg, AD, **_kw("DOC-SHA", scopes=[("employee", "E1")]))
    columns = {r["name"] for r in conn.execute(
        "PRAGMA table_info(approval_doc_version)").fetchall()}
    assert "attachment_sha256" in columns
    assert not ({"attachment_file", "file_path", "blob", "original"} & columns)


def test_t_al_11_new_chain_never_calls_legacy_upsert(conn, cfg):
    from src.rules import approval_docs
    source = inspect.getsource(approval_docs)
    assert "upsert_approval" not in source
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-NO-UPSERT", scopes=[("employee", "E1")]))
    publish_doc(conn, cfg, AD, "DOC-NO-UPSERT")
    assert coverage_for(conn, AU, "E1")


def test_t_al_12_draft_import_and_publish_are_audited(conn, cfg, tmp_path):
    _seed(conn)
    path = _write_csv(tmp_path / "audit.csv", [
        {"doc_no": "DOC-AUD", "title": "审计批文", "issuer": "人社局",
         "regime": "comprehensive_monthly", "version_no": 1, "valid_from": "2025-01-01",
         "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
         "region_code": "440300", "attachment_sha256": "a" * 64,
         "scope_type": "employee", "scope_value": "E1"},
    ])
    import_drafts_csv(conn, cfg, AD, path)
    publish_doc(conn, cfg, AD, "DOC-AUD")
    actions = [r["action"] for r in conn.execute(
        "SELECT action FROM audit_event ORDER BY seq").fetchall()]
    assert "approval_doc.import" in actions
    assert "approval_doc.publish" in actions
    payloads = [r["payload_sha256"] for r in conn.execute(
        "SELECT payload_sha256 FROM audit_event ORDER BY seq").fetchall()]
    assert len(payloads) >= 2

def test_t_al_13_parallel_publish_is_serialised_by_database_lock(conn, cfg):
    """两个发布者同时发布同一员工/工时制的重叠批文：只能一个成功，另一个冲突。"""
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-P1", scopes=[("employee", "E1")]))
    create_draft(conn, cfg, AD, **_kw("DOC-P2", scopes=[("employee", "E1")]))

    barrier = threading.Barrier(2)
    results: list[tuple[str, str]] = []

    def worker(doc_no: str) -> None:
        worker_conn = connect(cfg.db_path, cfg.sqlite_synchronous)
        try:
            barrier.wait(timeout=10)
            try:
                publish_doc(worker_conn, cfg, AD, doc_no)
                results.append(("ok", doc_no))
            except ApprovalConflictError:
                results.append(("conflict", doc_no))
        finally:
            worker_conn.close()

    threads = [threading.Thread(target=worker, args=(d,)) for d in ("DOC-P1", "DOC-P2")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert sorted(status for status, _ in results) == ["conflict", "ok"]
    assert conn.execute("SELECT COUNT(*) AS c FROM employee_approval_coverage"
                        ).fetchone()["c"] == 1

def test_t_al_14_org_scope_like_wildcards_are_literal(conn, cfg):
    """M-04：org_id 里的 `_` / `%` 必须按字面匹配，不能扩大审批覆盖。"""
    for org_id, parent in (("ORG-ROOT", ""), ("A_B", "ORG-ROOT"), ("AXB", "ORG-ROOT"),
                           ("A%B", "ORG-ROOT"), ("A_B-SUB", "A_B")):
        conn.execute("INSERT INTO org_unit(org_id, org_name, parent_id) VALUES(?,?,?)",
                     (org_id, org_id, parent or None))
    for emp_id, org_id in (("E-UNDER", "A_B"), ("E-SUB", "A_B-SUB"),
                           ("E-X", "AXB"), ("E-PCT", "A%B")):
        conn.execute(
            "INSERT INTO employee(emp_id, pseudonym, job_code, org_id, region_code, "
            "worktime_regime, contract_approved_flex, pay_base_cents, pay_base_hourly_cents, "
            "normal_hourly_cents, is_manager, acl_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp_id, emp_id, "warehouse_shift", org_id, "440300", "standard", 0,
             0, 0, 0, 0, "self"))
    refresh_org_paths(conn)

    create_draft(conn, cfg, AD, **_kw("DOC-UNDERSCORE", scopes=[("org", "A_B")]))
    out = publish_doc(conn, cfg, AD, "DOC-UNDERSCORE")
    covered = {r["emp_id"] for emp in ("E-UNDER", "E-SUB", "E-X", "E-PCT")
               for r in coverage_for(conn, AU, emp)}
    assert out["coverage_employees"] == 2
    assert covered == {"E-UNDER", "E-SUB"}      # 子组织仍展开；AXB / A%B 不得被覆盖

    create_draft(conn, cfg, AD, **_kw("DOC-PERCENT", scopes=[("org", "A%B")]))
    pct = publish_doc(conn, cfg, AD, "DOC-PERCENT")
    pct_covered = {emp for emp in ("E-UNDER", "E-SUB", "E-X", "E-PCT")
                   for r in coverage_for(conn, AU, emp) if r["doc_no"] == "DOC-PERCENT"}
    assert pct["coverage_employees"] == 1
    assert pct_covered == {"E-PCT"}


def _cli_args(**kwargs):
    import argparse
    base = {"docs": False, "coverage": "", "versions": "", "role": "AU"}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_t_al_cli_01_au_can_list_docs_coverage_and_versions(conn, cfg, monkeypatch, capsys):
    from src import cli
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-CLI", scopes=[("employee", "E1")]))
    publish_doc(conn, cfg, AD, "DOC-CLI")
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg)

    assert cli.cmd_approval_doc(_cli_args(docs=True)) == 0
    assert "DOC-CLI" in capsys.readouterr().out
    assert cli.cmd_approval_doc(_cli_args(coverage="E1")) == 0
    assert "DOC-CLI" in capsys.readouterr().out
    assert cli.cmd_approval_doc(_cli_args(versions="DOC-CLI")) == 0
    assert "v1" in capsys.readouterr().out


def test_t_al_cli_02_non_read_role_is_rejected_not_downgraded(conn, cfg, monkeypatch, capsys):
    from src import cli
    _seed(conn)
    create_draft(conn, cfg, AD, **_kw("DOC-CLI2", scopes=[("employee", "E1")]))
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg)
    assert cli.cmd_approval_doc(_cli_args(docs=True, role="OP")) == 2
    err = capsys.readouterr().err
    assert "越权" in err and "读权限" in err
    assert "DOC-CLI2" not in capsys.readouterr().out
