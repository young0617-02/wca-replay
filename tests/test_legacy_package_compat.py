"""旧包兼容：无 `csv_formula_escape` 声明时不得反向剥前缀；有声明时精确还原。"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

from conftest import EMPLOYEES, ORGS, load_base, punch, schedule
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay
from src.rules.approvals import import_approval_csv, upsert_approval
from src.rules.rulepack import RULE_PACK_V5
from src.util import csv_unescape_cell, sha256_hex

DAY = date(2025, 9, 2)
RAW_DOC = "=cmd|' /C calc'!A0"
RAW_RECORDED = "\t2025-01-02T00:00:00+08:00"


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _approval(doc_no: str = RAW_DOC, recorded_at: str = RAW_RECORDED) -> dict:
    return {
        "emp_id": "T-CMP", "doc_no": doc_no,
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "a" * 64,
        "recorded_at": recorded_at,
    }


def _seed_v5(conn, cfg) -> tuple[object, object, dict]:
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
    for name, (kind, rows) in files.items():
        path = cfg5.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg5, path, kind=kind, rel_path=name)
    upsert_approval(conn, _approval())
    out = run_check(conn, cfg5, start=DAY, end=DAY, notes="legacy package compat")
    return cfg5, out, export_package(conn, cfg5, out.run_id)


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


def test_default_import_without_marker_keeps_raw_formula_characters(conn, cfg, tmp_path):
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    load_base(conn, cfg5)
    path = tmp_path / "legacy-upload.csv"
    _write_csv(path, [_approval()])

    import_approval_csv(conn, path)  # 旧包/普通上传：默认不剥前缀
    row = conn.execute("SELECT doc_no, recorded_at FROM worktime_approval").fetchone()
    assert row["doc_no"] == RAW_DOC, "首字符 = 不得被误删"
    assert row["recorded_at"] == RAW_RECORDED, "前导制表符不得被误删"


def test_apostrophe_marker_restores_values_exactly(conn, cfg, tmp_path):
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    load_base(conn, cfg5)
    path = tmp_path / "marked-upload.csv"
    _write_csv(path, [_approval("'" + RAW_DOC, "'" + RAW_RECORDED)])

    import_approval_csv(conn, path, unescape_formula=True)
    row = conn.execute("SELECT doc_no, recorded_at FROM worktime_approval").fetchone()
    assert row["doc_no"] == RAW_DOC
    assert row["recorded_at"] == RAW_RECORDED


def test_legacy_manifest_without_marker_replays_same_triple(conn, cfg, tmp_path):
    """旧形态包：无 csv_formula_escape，审批 CSV 是原值；重放不得剥首字符。"""
    _, out, manifest = _seed_v5(conn, cfg)
    src = Path(manifest["package_zip"])

    def mutate(files):
        im = json.loads(files["inputs/manifest.json"])
        im.pop("csv_formula_escape", None)
        escaped_text = files["inputs/000-approval.csv"].decode("utf-8")
        rows = list(csv.DictReader(escaped_text.splitlines()))
        raw_rows = [{k: csv_unescape_cell(v) for k, v in row.items()} for row in rows]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(raw_rows)
        data = buf.getvalue().encode("utf-8")
        files["inputs/000-approval.csv"] = data
        for entry in im["entries"]:
            if entry["kind"] == "approval":
                entry["sha256"] = sha256_hex(data)
                entry["bytes"] = len(data)
        im["total_bytes"] = sum(int(e.get("bytes") or 0) for e in im["entries"])
        files["inputs/manifest.json"] = json.dumps(
            im, ensure_ascii=False, sort_keys=True).encode("utf-8")

        top = json.loads(files["manifest.json"])
        # 旧包形态：v1 schema + 无 checksum + 无 csv_formula_escape。
        top["schema"] = "wca-evidence-package-v1"
        top.pop("manifest_checksum", None)
        top["inputs"].pop("csv_formula_escape", None)
        top["inputs"]["approval_sha256"] = sha256_hex(data)
        top["inputs"]["total_bytes"] = im["total_bytes"]
        files["manifest.json"] = json.dumps(
            top, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return files

    legacy = _rezip(src, tmp_path / "legacy.zip", mutate)
    with zipfile.ZipFile(legacy) as zf:
        im = json.loads(zf.read("inputs/manifest.json"))
        text = zf.read("inputs/000-approval.csv").decode("utf-8")
    assert "csv_formula_escape" not in im
    assert "'=cmd" not in text and "=cmd" in text, "旧包 CSV 必须是未转义的原值"

    res = replay(legacy)
    assert res["ok"], res["reason"]
    assert res["manifest_checksum"] == "missing"
    assert res["actual_triple"] == res["expected_triple"]
    assert res["findings_actual"] == res["findings_expected"] == len(out.findings)
