"""v6 规则包：REG-01 只读 employee_approval_coverage，旧 v5 保持 legacy。"""

from __future__ import annotations

import csv
import json
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS
from src.auth import User
from src.config import Config
from src.engine import run_check
from src.evidence import export_package, verify_chain
from src.ingest import import_csv_file
from src.replay import replay
from src.rules.approval_docs import create_draft, publish_doc
from src.rules.rulepack import RULE_PACK_V5, RULE_PACK_V6

DAY = date(2025, 9, 2)
AD = User("ad-v6", "T-STD", ("AD",), "ORG-A", "440300", "管理员")


def _seed(conn, cfg: Config) -> None:
    """用真实 CSV 文件导入主数据，保证包内 inputs 能反查文件（inline:// 路径无法打包）。"""
    cfg.ensure_dirs()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    for name, kind, rows in (("org.csv", "org", ORGS), ("employee.csv", "employee", EMPLOYEES)):
        path = cfg.data_dir / name
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)


def _v5(cfg: Config) -> Config:
    return replace(cfg, rule_pack_id=RULE_PACK_V5)


def _v6(cfg: Config) -> Config:
    return replace(cfg, rule_pack_id=RULE_PACK_V6)


def _coverage_doc(conn, cfg6: Config, emp_ids: list[str], doc_no: str = "V6-DOC",
                  start: str = "2025-01-01", end: str = "2025-12-31") -> None:
    create_draft(
        conn, cfg6, AD, doc_no=doc_no, title="v6 批文", issuer="人社局",
        regime="comprehensive_monthly", version_no=1,
        valid_from=start, valid_to=end,
        job_codes='["warehouse_shift"]', region_code="440300",
        attachment_sha256="a" * 64,
        scopes=[("employee", e) for e in emp_ids])
    publish_doc(conn, cfg6, AD, doc_no)


def _reg01_ids(out) -> set[str]:
    return {f.emp_id for f in out.findings if f.rule_id == "REG-01"}


def test_v6_reads_new_coverage_and_v5_unchanged(conn, cfg):
    _seed(conn, cfg)
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    out5 = run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 before coverage")
    assert "T-CMP" in _reg01_ids(out5)
    _coverage_doc(conn, cfg6, ["T-CMP"])
    out6 = run_check(conn, cfg6, start=DAY, end=DAY, notes="v6 with coverage")
    again = run_check(conn, cfg6, start=DAY, end=DAY, notes="v6 same input")
    assert again.input_fingerprint == out6.input_fingerprint
    assert {f.rule_version for f in out6.findings} == {RULE_PACK_V6}
    reg01_v5 = next(f for f in out5.findings if f.rule_id == "REG-01")
    assert reg01_v5.rule_version == RULE_PACK_V5
    assert "T-CMP" not in _reg01_ids(out6)
    assert {"T-NAPPR", "T-BADJOB"} <= _reg01_ids(out6)
    assert out6.counts["REVIEW"] <= out5.counts["REVIEW"]


def test_v6_ignores_legacy_worktime_approval_and_warns(conn, cfg):
    _seed(conn, cfg)
    from src.rules.approvals import upsert_approval
    upsert_approval(conn, {
        "emp_id": "T-CMP", "doc_no": "LEGACY-V6", "regime": "comprehensive_monthly",
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": '["warehouse_shift"]', "region_code": "440300",
        "attachment_sha256": "b" * 64, "recorded_at": "2025-01-02T00:00:00+08:00",
    })
    out = run_check(conn, _v6(cfg), start=DAY, end=DAY, notes="v6 legacy ignored")
    assert "T-CMP" in _reg01_ids(out)
    assert any("旧 worktime_approval" in w for w in out.warnings)


def test_v6_epoch_keeps_v5_genesis_and_verifies(conn, cfg):
    _seed(conn, cfg)
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    old = run_check(conn, cfg5, start=DAY, end=DAY)
    from src.db import get_meta
    genesis = get_meta(conn, "audit_genesis")
    new = run_check(conn, cfg6, start=DAY, end=DAY)
    assert get_meta(conn, "audit_genesis") == genesis
    old_versions = {r["rule_version"] for r in conn.execute(
        "SELECT DISTINCT rule_version FROM finding WHERE run_id = ?", (old.run_id,)).fetchall()}
    assert RULE_PACK_V6 not in old_versions, "v6 不得批量改写旧 finding 的 rule_version"
    epochs = conn.execute(
        "SELECT rule_pack_version, prev_rule_pack_version FROM rule_pack_epoch "
        "WHERE rule_pack_version = ?", (RULE_PACK_V6,)).fetchall()
    assert epochs and epochs[0]["prev_rule_pack_version"] == RULE_PACK_V5
    assert verify_chain(conn, cfg5).ok
    assert verify_chain(conn, cfg6).ok
    assert old.run_id and new.run_id


def test_v6_package_uses_coverage_csv_and_replays(conn, cfg):
    _seed(conn, cfg)
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    run_check(conn, cfg5, start=DAY, end=DAY)
    _coverage_doc(conn, cfg6, ["T-CMP"])
    out = run_check(conn, cfg6, start=DAY, end=DAY, notes="v6 package")
    manifest = export_package(conn, cfg6, out.run_id)
    assert manifest["inputs"]["approval_source"] == "v6-coverage"
    assert manifest["inputs"]["approval_rows"] == 1
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        assert im["approval_source"] == "v6-coverage"
        rows = list(csv.DictReader(zf.read("inputs/000-approval.csv").decode("utf-8")
                                   .splitlines()))
        assert rows and "version_no" in rows[0] and "published_at" in rows[0]
        findings = list(csv.DictReader(zf.read("findings.csv").decode("utf-8").splitlines()))
        assert findings and {f["rule_version"] for f in findings} == {RULE_PACK_V6}
        assert json.loads(zf.read("manifest.json").decode("utf-8"))["triple"][
            "rule_pack_version"] == RULE_PACK_V6
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]
    assert res["findings_actual"] == res["findings_expected"]


def test_v6_package_replays_when_legacy_table_still_has_rows(conn, cfg):
    """旧表仍有行时 v6 会告警；告警不能进 scope/指纹，否则 replay 永远对不上。"""
    from src.rules.approvals import upsert_approval

    _seed(conn, cfg)
    upsert_approval(conn, {
        "emp_id": "T-CMP", "doc_no": "LEGACY-WARN", "regime": "comprehensive_monthly",
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": '["warehouse_shift"]', "region_code": "440300",
        "attachment_sha256": "b" * 64, "recorded_at": "2025-01-02T00:00:00+08:00",
    })
    cfg6 = _v6(cfg)
    run_check(conn, _v5(cfg), start=DAY, end=DAY, notes="v5 before warning package")
    _coverage_doc(conn, cfg6, ["T-CMP"])
    out = run_check(conn, cfg6, start=DAY, end=DAY, notes="v6 with legacy warning")
    assert any("旧 worktime_approval" in w for w in out.warnings)
    scope = json.loads(conn.execute(
        "SELECT scope_json FROM run WHERE run_id = ?", (out.run_id,)).fetchone()["scope_json"])
    assert "legacy_approval_warning" not in scope
    manifest = export_package(conn, cfg6, out.run_id)
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]


def test_v5_package_still_replays_legacy_after_v6_epoch(conn, cfg):
    _seed(conn, cfg)
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    run_check(conn, cfg5, start=DAY, end=DAY)
    old_manifest = export_package(conn, cfg5, conn.execute(
        "SELECT run_id FROM run ORDER BY started_at DESC LIMIT 1").fetchone()["run_id"])
    _coverage_doc(conn, cfg6, ["T-CMP"])
    run_check(conn, cfg6, start=DAY, end=DAY)
    res = replay(Path(old_manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]


def test_v6_coverage_change_changes_fingerprint_without_double_count(conn, cfg):
    _seed(conn, cfg)
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    run_check(conn, cfg5, start=DAY, end=DAY)
    _coverage_doc(conn, cfg6, ["T-CMP"])
    first = run_check(conn, cfg6, start=DAY, end=DAY)
    _coverage_doc(conn, cfg6, ["T-CMP"], doc_no="V6-DOC-2",
                  start="2026-01-01", end="2026-12-31")
    second = run_check(conn, cfg6, start=DAY, end=DAY)
    assert first.input_fingerprint != second.input_fingerprint
    manifest = export_package(conn, cfg6, second.run_id)
    assert manifest["inputs"]["approval_rows"] == 2
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]


def test_v6_v5_reg01_hit_sets_are_identical_on_equivalent_450_rows(conn, cfg):
    """等价性验证：450 行旧台账 → 等价新投影，v5/v6 的 REG-01 命中员工逐一相同。"""
    from src.rules.approvals import upsert_approval
    for org_id, parent in (("ORG-ROOT", None), ("ORG-A", "ORG-ROOT"), ("ORG-B", "ORG-ROOT")):
        conn.execute("INSERT INTO org_unit(org_id, org_name, parent_id) VALUES(?,?,?)",
                     (org_id, org_id, parent))
    for i in range(1, 601):
        emp = f"P{i:04d}"
        org = "ORG-A" if i <= 450 else "ORG-B"
        conn.execute(
            "INSERT INTO employee(emp_id, pseudonym, job_code, org_id, region_code, "
            "worktime_regime, contract_approved_flex, pay_base_cents, pay_base_hourly_cents, "
            "normal_hourly_cents, is_manager, acl_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp, emp, "warehouse_shift", org, "440300", "comprehensive_monthly", 1,
             0, 0, 0, 0, "self"))
        if i <= 450:
            upsert_approval(conn, {
                "emp_id": emp, "doc_no": f"LEGACY-{i:04d}",
                "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
                "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
                "region_code": "440300", "attachment_sha256": "c" * 64,
                "recorded_at": "2025-01-02T00:00:00+08:00",
            })
    cfg5, cfg6 = _v5(cfg), _v6(cfg)
    out5 = run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 450 equivalent")
    _coverage_doc(conn, cfg6, [f"P{i:04d}" for i in range(1, 451)], doc_no="EQUIV-V6")
    out6 = run_check(conn, cfg6, start=DAY, end=DAY, notes="v6 450 equivalent")
    v5_hits = _reg01_ids(out5)
    v6_hits = _reg01_ids(out6)
    assert v5_hits == v6_hits == {f"P{i:04d}" for i in range(451, 601)}
