"""安全审查 M-03 / M-05 / M-06 的回归测试（先于实现编写）。

覆盖三件事：
1. 包内 `verify.py` 任一校验失败必须非零退出，并打印统一 `RESULT FAIL`；
2. `verify.py` / `replay` 不得读取包根目录之外的路径，zip 成员路径同样校验；
3. 报表与审批导出 CSV 统一做公式前缀转义，且不改变三元组与结论条数。
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, load_base, punch, schedule
from src import evidence
from src.anomaly import write_anomaly_report
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file, import_rows
from src.replay import replay
from src.rules.approvals import (export_coverage_csv, import_approval_csv,
                                 upsert_approval)
from src.rules.rulepack import RULE_PACK_V5
from src.util import csv_safe_cell, csv_unescape_cell

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _unpack(zip_path: Path, into: Path) -> Path:
    into.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(into)
    return into


def _read_zip_rows(zip_path: Path, name: str) -> list[dict]:
    with zipfile.ZipFile(zip_path) as zf:
        text = zf.read(name).decode("utf-8")
    return list(csv.DictReader(text.splitlines()))


def _rewrite_manifest(pkg: Path, mutate) -> None:
    path = pkg / "manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    mutate(doc)
    path.write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _run_verify(pkg: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "verify.py"], cwd=pkg, capture_output=True,
                          text=True, encoding="utf-8", timeout=120)


@pytest.fixture
def packed(conn, cfg):
    """正常自含输入包：org/employee/schedule/punch 四个真实文件。"""
    cfg.ensure_dirs()
    rows = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [schedule(
            "T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
            "2025-09-02T19:00:00+08:00")]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T19:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, data) in rows.items():
        path = cfg.data_dir / name
        _write_csv(path, data)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="security hardening")
    manifest = export_package(conn, cfg, out.run_id)
    return out, Path(manifest["package_zip"]), manifest


# ---------------------------------------------------------------- M-06 退出码
def test_verify_returns_zero_and_result_ok_for_good_package(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "good")
    proc = _run_verify(pkg)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "EPOCH OK" in proc.stdout
    assert "CHAIN OK" in proc.stdout
    assert "INPUTS OK" in proc.stdout
    assert "RESULT OK" in proc.stdout
    assert "RESULT FAIL" not in proc.stdout


def test_verify_nonzero_when_input_content_tampered(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "tamper-input")
    im = json.loads((pkg / "inputs" / "manifest.json").read_text(encoding="utf-8"))
    target = next(e for e in im["entries"] if e["kind"] == "punch")
    path = pkg / target["arcname"]
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    proc = _run_verify(pkg)
    assert proc.returncode != 0, "输入哈希不一致必须返回非零退出码"
    assert "INPUTS FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout


def test_verify_nonzero_when_audit_event_tampered(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "tamper-chain")
    lines = (pkg / "audit_chain.jsonl").read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["actor"] = "system:forged"
    lines[1] = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    (pkg / "audit_chain.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    proc = _run_verify(pkg)
    assert proc.returncode != 0, "审计事件被改写必须返回非零退出码"
    assert "CHAIN FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout


def test_verify_nonzero_when_manifest_field_missing(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "missing-field")

    def mutate(doc):
        # 旧 schema + 无自校验和，才能让本用例走到“三元组缺字段”分支；
        # 新 schema 缺校验和会按新规则直接 MANIFEST FAIL（见 anchor 用例）。
        doc["schema"] = "wca-evidence-package-v1"
        doc.pop("manifest_checksum", None)
        doc["triple"].pop("conclusion_digest")

    _rewrite_manifest(pkg, mutate)

    proc = _run_verify(pkg)
    assert proc.returncode != 0, "manifest 缺字段必须返回非零退出码"
    assert "RESULT FAIL" in proc.stdout
    assert "conclusion_digest" in proc.stdout


def test_verify_nonzero_when_triple_disagrees_with_package_scope(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "triple-mismatch")
    _rewrite_manifest(pkg, lambda doc: doc["triple"].update(rule_pack_version="rp-forged.v9"))

    proc = _run_verify(pkg)
    assert proc.returncode != 0, "三元组与包内 scope 不一致必须返回非零退出码"
    assert "RESULT FAIL" in proc.stdout


# ---------------------------------------------------------------- M-03 路径穿越
def _set_first_arcname(pkg: Path, arcname: str) -> None:
    path = pkg / "inputs" / "manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["entries"], "测试包必须至少带一个输入"
    doc["entries"][0]["arcname"] = arcname
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")


@pytest.mark.parametrize("kind", ["relative", "absolute"])
def test_verify_and_replay_reject_out_of_root_arcname(packed, tmp_path, kind):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / f"escape-{kind}")
    outside = tmp_path / f"outside-{kind}.csv"
    outside.write_text("emp_id,event_ts\nT-STD,2025-09-02T09:00:00+08:00\n", encoding="utf-8")
    arcname = (f"..{os.sep}{outside.name}" if kind == "relative" else str(outside))
    _set_first_arcname(pkg, arcname)

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "INPUTS FAIL" in proc.stdout
    assert "包内路径非法" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    with pytest.raises(ValueError, match="包内路径"):
        replay(pkg)


@pytest.mark.parametrize("member", [
    r"..\evil.csv",
    "../evil.csv",
    "/evil.csv",
    r"C:\evil.csv",
    "C:/evil.csv",
])
def test_replay_rejects_zip_member_traversal(packed, tmp_path, member):
    _, zip_path, _ = packed
    malicious = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files[member] = b"evil"
    with zipfile.ZipFile(malicious, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)

    with pytest.raises(ValueError, match="zip 内路径非法"):
        replay(malicious)


def test_normal_relative_arcname_still_readable(packed):
    _, zip_path, _ = packed
    res = replay(zip_path)
    assert res["ok"], res["reason"]
    assert res["inputs_packed"] == 4


# ---------------------------------------------------------------- M-05 公式注入
@pytest.mark.parametrize("value", [
    "=cmd|' /C calc'!A0",
    "+1+1",
    "-1+1",
    "@SUM(A1)",
    "\t=cmd",
    "\r=cmd",
])
def test_csv_formula_escape_contract(value):
    assert csv_safe_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["普通中文", "T-STD", "440300", "2025-09-02", "", 4500, None])
def test_csv_normal_cells_are_unchanged(value):
    assert csv_safe_cell(value) == value


def test_csv_formula_escape_is_reversible_for_leading_apostrophes():
    assert csv_safe_cell("'=cmd") == "''=cmd"
    assert csv_safe_cell("''=cmd") == "'''=cmd"
    assert csv_safe_cell("'普通中文") == "'普通中文"
    assert csv_unescape_cell("'=cmd") == "=cmd"
    assert csv_unescape_cell("''=cmd") == "'=cmd"
    assert csv_unescape_cell("'''=cmd") == "''=cmd"
    assert csv_unescape_cell("'\t=cmd") == "\t=cmd"
    assert csv_unescape_cell("普通中文") == "普通中文"
    assert csv_unescape_cell("'普通中文") == "'普通中文"


def test_quality_issues_csv_escapes_formula_cells(conn, cfg):
    load_base(conn, cfg)
    path = cfg.data_dir / "quality.csv"
    _write_csv(path, [
        {"emp_id": "T-STD", "event_ts": "=cmd|' /C calc'!A0", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "not-a-date", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-09-02T09:00:00+08:00", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-09-02T21:00:00+08:00", "punch_type": "out"},
    ])
    import_csv_file(conn, cfg, path, kind="punch", rel_path="quality.csv")
    out = run_check(conn, cfg, start=DAY, end=DAY)
    manifest = export_package(conn, cfg, out.run_id)
    rows = _read_zip_rows(Path(manifest["package_zip"]), "quality_issues.csv")

    bad = next(r for r in rows if r["raw_value"].startswith("'=cmd"))
    assert bad["raw_value"] == "'=cmd|' /C calc'!A0"
    assert bad["line_no"] == "2" and bad["rule_id"] == "QUAL-TS"
    assert any(r["raw_value"] == "not-a-date" for r in rows), "普通脏值不得被改写"
    assert all(not cell.startswith(("=", "+", "-", "@")) for r in rows for cell in r.values())


def test_conclusions_csv_escapes_formula_cells_without_changing_triple(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
    ], rel_path="inline://conclusions")
    out = run_check(conn, cfg, start=DAY, end=DAY)
    rid = conn.execute("SELECT review_id FROM review_item WHERE run_id=? AND status='OPEN' "
                       "ORDER BY review_id LIMIT 1", (out.run_id,)).fetchone()["review_id"]

    from src.anomaly import decide_review
    decide_review(conn, cfg, rid, reviewer="@SUM(A1)", decision="APPROVED",
                  note="\t=cmd|' /C calc'!A0", amount_cents=4500)

    manifest = export_package(conn, cfg, out.run_id)
    rows = _read_zip_rows(Path(manifest["package_zip"]), "conclusions_final.csv")
    assert len(rows) == 1, "转义不得改变结论条数"
    row = rows[0]
    assert row["confirmed_by"] == "'@SUM(A1)"
    assert row["note"] == "'\t=cmd|' /C calc'!A0"
    assert row["amount_cents_input"] == "4500", "正常金额字段不得被改写"
    assert manifest["counts"]["final_conclusions"] == 1
    assert manifest["triple"] == {
        "rule_pack_version": cfg.rule_pack_id,
        "input_fingerprint": out.input_fingerprint,
        "conclusion_digest": out.conclusion_digest,
    }


def test_findings_csv_escapes_formula_cells(tmp_path):
    path = tmp_path / "findings.csv"
    row = {
        "rule_id": "OT-D01", "rule_version": "rp-1", "emp_id": "T-STD",
        "work_date": "2025-09-02", "period_key": "", "severity": "DEFENSIBLE",
        "citation_ids": "=cmd", "metric_json": '{"note":"+1+1"}',
        "explanation": "@SUM(A1)", "source_refs": "[]",
    }
    evidence._write_findings_csv(path, [row], {})
    with path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["citations"] == "'=cmd"
    assert rows[0]["explanation"] == "'@SUM(A1)"
    assert rows[0]["metric_json"] == '{"note":"+1+1"}', "JSON 首字符不是公式起始符，不应改写"
    assert rows[0]["emp_id"] == "T-STD"


def test_anomaly_report_escapes_formula_cells(conn, cfg):
    load_base(conn, cfg)
    conn.execute("UPDATE employee SET pseudonym = ? WHERE emp_id = ?",
                 ("=cmd|' /C calc'!A0", "T-STD"))
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
    ], rel_path="inline://report")
    out = run_check(conn, cfg, start=DAY, end=DAY)
    path = write_anomaly_report(conn, cfg, out.run_id)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))

    row = next(r for r in rows if r["emp_id"] == "T-STD")
    assert row["pseudonym"] == "'=cmd|' /C calc'!A0"
    assert row["work_date"] == "2025-09-02", "正常日期字段不得被改写"
    assert row["severity"] in ("DEFENSIBLE", "REVIEW", "VIOLATION")
    assert row["emp_id"] == "T-STD", "普通工号字段不得被改写"


def test_coverage_export_escapes_formula_cells(conn, cfg, tmp_path, monkeypatch):
    malicious = [{
        "emp_id": "T-CMP", "doc_no": "+1+1", "version_no": 1,
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "a" * 64,
        "published_at": "\r=cmd",
    }]
    monkeypatch.setattr("src.rules.approvals._coverage_rows", lambda *_a: malicious)
    meta = export_coverage_csv(conn, ["T-CMP"], tmp_path / "coverage.csv")
    with Path(meta["path"]).open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["doc_no"] == "'+1+1"
    assert rows[0]["published_at"] == "'\r=cmd"
    assert rows[0]["valid_from"] == "2025-01-01"
    assert rows[0]["attachment_sha256"] == "a" * 64


def test_approval_csv_escape_keeps_replay_triple_and_counts(conn, cfg, tmp_path):
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    cfg5.ensure_dirs()
    files = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [schedule(
            "T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
            "2025-09-02T19:00:00+08:00")]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T19:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, data) in files.items():
        path = cfg5.data_dir / name
        _write_csv(path, data)
        import_csv_file(conn, cfg5, path, kind=kind, rel_path=name)

    malicious = {
        "emp_id": "T-CMP", "doc_no": "=cmd|' /C calc'!A0",
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "a" * 64,
        "recorded_at": "\t2025-01-02T00:00:00+08:00",
    }
    upsert_approval(conn, malicious)
    out = run_check(conn, cfg5, start=DAY, end=DAY)
    manifest = export_package(conn, cfg5, out.run_id)

    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        inputs_doc = json.loads(zf.read("inputs/manifest.json"))
    assert inputs_doc["csv_formula_escape"] == "apostrophe", \
        "重放必须靠包内显式声明识别转义，不能靠猜"

    rows = _read_zip_rows(Path(manifest["package_zip"]), "inputs/000-approval.csv")
    assert rows[0]["doc_no"] == "'=cmd|' /C calc'!A0"
    assert rows[0]["recorded_at"] == "'\t2025-01-02T00:00:00+08:00"
    assert rows[0]["valid_from"] == "2025-01-01", "正常日期字段不得被改写"
    assert rows[0]["job_codes"] == '["warehouse_shift"]'

    assert manifest["triple"] == {
        "rule_pack_version": RULE_PACK_V5,
        "input_fingerprint": out.input_fingerprint,
        "conclusion_digest": out.conclusion_digest,
    }
    assert manifest["counts"]["findings"] == len(out.findings)

    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]
    assert res["findings_actual"] == res["findings_expected"] == len(out.findings)


def test_approval_csv_unescape_is_opt_in(conn, cfg, tmp_path):
    """普通用户上传/导入路径不得被包内转义规则反向改写。"""
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    load_base(conn, cfg5)
    path = tmp_path / "upload.csv"
    path.write_text(
        "emp_id,doc_no,regime,valid_from,valid_to,job_codes,region_code,"
        "attachment_sha256,recorded_at\n"
        f"T-CMP,'=cmd,comprehensive_monthly,2025-01-01,2025-12-31,"
        f'["warehouse_shift"],440300,{"c" * 64},2025-01-02T00:00:00+08:00\n',
        encoding="utf-8")
    import_approval_csv(conn, path)
    row = conn.execute("SELECT doc_no FROM worktime_approval WHERE emp_id = ?",
                       ("T-CMP",)).fetchone()
    assert row["doc_no"] == "'=cmd", "默认导入必须保留用户原文"
