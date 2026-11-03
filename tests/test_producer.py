"""producer 版本块：包内代码版本必须能与当前验算代码核对。"""
from __future__ import annotations

import csv
import json
import zipfile
from datetime import date
from pathlib import Path

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import producer
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay
from src.util import canonical_json, manifest_checksum

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _seed(conn, cfg):
    cfg.ensure_dirs()
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
        path = cfg.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)


def test_package_producer_matches_current_code(conn, cfg):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    manifest = export_package(conn, cfg, out.run_id)
    block = manifest["producer"]
    assert block["version"] == producer.PACKAGE_VERSION
    assert block["commit"] == producer.current_commit()
    assert block["python"]
    assert block["rule_pack_version"] == cfg.rule_pack_id
    ok, reason = producer.check_manifest_producer(manifest)
    assert ok, reason
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["producer_ok"] is True


def test_package_producer_mismatch_fails_replay(conn, cfg, tmp_path):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    manifest = export_package(conn, cfg, out.run_id)
    src = Path(manifest["package_zip"])
    dst = tmp_path / "producer-mismatch.zip"
    with zipfile.ZipFile(src) as zin:
        files = {n: zin.read(n) for n in zin.namelist()}
    doc = json.loads(files["manifest.json"])
    doc["producer"]["commit"] = "0" * 40
    doc["manifest_checksum"] = manifest_checksum(doc)
    files["manifest.json"] = canonical_json(doc).encode("utf-8")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)

    res = replay(dst)
    assert not res["ok"]
    assert "PRODUCER FAIL" in res["reason"]
    assert res["producer_ok"] is False
    assert "commit" in res["producer_reason"]
