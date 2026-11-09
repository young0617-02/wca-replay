"""0.4.18 三处字段/文案变更的行为锁定（先写测试，后改实现）。

覆盖施工单第 (2) 类：
- 8：`counts.approved_conclusions` 只数 `decision=APPROVED`；
- 9：`responsibility.json` 用 `delivery_registered` / `approved_findings`，verify 双读旧 `signed`；
- 20：员工主数据导出默认剔除 `name` / `emp_no`，列不存在时不报错。

以及 `wca-verify` 输出不再重复标签前缀（显示层修正）。
"""
from __future__ import annotations

import csv
import json
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src.anomaly import decide_review
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.kb import build_kb
from src.package_verify import check_findings, check_inputs_completeness
from src.replay import replay

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _employee_rows(with_identity: bool) -> list[dict]:
    rows = [dict(r) for r in EMPLOYEES]
    if with_identity:
        for i, row in enumerate(rows):
            row["name"] = f"张三{i}"
            row["emp_no"] = f"A{i:03d}"
    return rows


def _seed(conn, cfg, *, with_identity: bool = False) -> None:
    cfg.ensure_dirs()
    files = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", _employee_rows(with_identity)),
        "schedule.csv": ("schedule", [schedule(
            "T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
            "2025-09-02T21:00:00+08:00", rest=60)]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, rows) in files.items():
        path = cfg.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)
    build_kb(conn, include_personnel=True)


def _build(conn, cfg, *, decision: str | None = None, with_identity: bool = False):
    _seed(conn, cfg, with_identity=with_identity)
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="0.4.18 fields")
    if decision:
        rid = conn.execute(
            "SELECT review_id FROM review_item WHERE run_id=? AND status='OPEN' "
            "ORDER BY review_id LIMIT 1", (out.run_id,)).fetchone()["review_id"]
        decide_review(conn, cfg, rid, reviewer="rv1", decision=decision, note="测试")
    manifest = export_package(conn, cfg, out.run_id)
    return Path(manifest["package_zip"]), manifest


def _unpack(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    return dest


# ---- 第 9 条：字段名 ---------------------------------------------------------

def test_responsibility_uses_delivery_registered(conn, cfg):
    zip_path, manifest = _build(conn, cfg)
    with zipfile.ZipFile(zip_path) as zf:
        resp = json.loads(zf.read("responsibility.json").decode("utf-8"))
    assert "signed" not in resp and "signed_by" not in resp
    assert "human_confirmed_findings" not in resp
    assert isinstance(resp["delivery_registered"], bool)
    assert "delivery_registered_by" in resp
    assert resp["approved_findings"] == 0
    assert manifest["responsibility"]["delivery_registered"] == resp["delivery_registered"]
    assert "signed" not in manifest["responsibility"]


# ---- 第 8 条：确认成立数只数 APPROVED ----------------------------------------

def test_approved_conclusions_counts_only_approved(conn, cfg):
    zip_path, manifest = _build(conn, cfg, decision="APPROVED")
    with zipfile.ZipFile(zip_path) as zf:
        resp = json.loads(zf.read("responsibility.json").decode("utf-8"))
        rows = list(csv.DictReader(
            zf.read("conclusions_final.csv").decode("utf-8").splitlines()))
    assert len(rows) == 1 and rows[0]["decision"] == "APPROVED"
    assert manifest["counts"]["final_conclusions"] == 1
    assert manifest["counts"]["approved_conclusions"] == 1
    assert resp["approved_findings"] == 1


@pytest.mark.parametrize("decision", ["REJECTED", "NEEDS_MORE_DATA"])
def test_non_approved_decision_is_not_counted_as_approved(conn, cfg, decision):
    zip_path, manifest = _build(conn, cfg, decision=decision)
    assert manifest["counts"]["final_conclusions"] == 1
    assert manifest["counts"]["approved_conclusions"] == 0


# ---- 第 9 条：verify 双读 ---------------------------------------------------

def test_verify_falls_back_to_legacy_signed(conn, cfg, tmp_path):
    zip_path, _ = _build(conn, cfg)
    root = _unpack(zip_path, tmp_path / "pkg")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))

    resp = json.loads((root / "responsibility.json").read_text(encoding="utf-8"))
    legacy = {k: v for k, v in resp.items()
              if k not in ("delivery_registered", "delivery_registered_by")}
    legacy["signed"] = True
    legacy["signed_by"] = []
    (root / "responsibility.json").write_text(
        json.dumps(legacy, ensure_ascii=False), encoding="utf-8")
    result = check_findings(root, manifest)
    assert result["ok"] is True, result["reason"]
    assert result["delivery_registered"] is True


def test_verify_rejects_half_migrated_responsibility(conn, cfg, tmp_path):
    zip_path, _ = _build(conn, cfg)
    root = _unpack(zip_path, tmp_path / "pkg2")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    resp = json.loads((root / "responsibility.json").read_text(encoding="utf-8"))
    resp["delivery_registered"] = True
    resp["signed"] = False
    (root / "responsibility.json").write_text(
        json.dumps(resp, ensure_ascii=False), encoding="utf-8")
    result = check_findings(root, manifest)
    assert result["ok"] is False
    assert result["reason"].startswith("RESPONSIBILITY FAIL")


def test_verify_ignores_package_without_registration_flag(conn, cfg, tmp_path):
    zip_path, _ = _build(conn, cfg)
    root = _unpack(zip_path, tmp_path / "pkg3")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    resp = json.loads((root / "responsibility.json").read_text(encoding="utf-8"))
    resp.pop("delivery_registered", None)
    resp.pop("delivery_registered_by", None)
    (root / "responsibility.json").write_text(
        json.dumps(resp, ensure_ascii=False), encoding="utf-8")
    result = check_findings(root, manifest)
    assert result["ok"] is True, result["reason"]
    assert result["delivery_registered"] is None


def test_verify_rejects_wrong_approved_count(conn, cfg, tmp_path):
    zip_path, _ = _build(conn, cfg, decision="APPROVED")
    root = _unpack(zip_path, tmp_path / "pkg4")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    manifest["counts"]["approved_conclusions"] = 0
    result = check_findings(root, manifest)
    assert result["ok"] is False
    assert result["reason"].startswith("COUNTS FAIL")
    assert "approved_conclusions" in result["reason"]


# ---- 第 20 条：员工主数据默认剔除姓名/工号 -----------------------------------

def test_employee_export_drops_name_and_emp_no(conn, cfg):
    zip_path, manifest = _build(conn, cfg, with_identity=True)
    with zipfile.ZipFile(zip_path) as zf:
        header = next(csv.reader(zf.read("inputs/employee.csv").decode("utf-8").splitlines()))
    assert "name" not in header and "emp_no" not in header
    assert "emp_id" in header and "normal_hourly_cents" in header
    omitted = manifest["inputs"].get("omitted_fields") or []
    fields = {(str(x.get("kind")), str(x.get("field"))) for x in omitted}
    assert ("employee", "name") in fields and ("employee", "emp_no") in fields
    assert replay(zip_path)["ok"] is True


def test_employee_export_without_identity_columns_is_unchanged(conn, cfg):
    zip_path, manifest = _build(conn, cfg)
    with zipfile.ZipFile(zip_path) as zf:
        header = next(csv.reader(zf.read("inputs/employee.csv").decode("utf-8").splitlines()))
    assert header == list(EMPLOYEES[0].keys())
    assert not (manifest["inputs"].get("omitted_fields") or [])
    assert replay(zip_path)["ok"] is True


# ---- 显示层：OK 行不再重复标签前缀 -------------------------------------------

def test_completeness_ok_reason_has_no_duplicate_tag(conn, cfg, tmp_path):
    zip_path, manifest = _build(conn, cfg)
    root = _unpack(zip_path, tmp_path / "pkg5")
    schema_ver = 6
    result = check_inputs_completeness(root, manifest, schema_ver)
    assert result["ok"] is True
    assert not result["reason"].startswith("INPUTS COMPLETENESS")
    assert "输入清单" in result["reason"]
