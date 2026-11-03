"""包外第五段锚点：projection_fingerprint（裁剪包完整验收）。

四段行为保持不变；五段在包内无投影时按失败关闭处理。
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import signing
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay

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
        "leave.csv": ("leave", [{
            "emp_id": "T-STD", "leave_kind": "comp_time",
            "start_ts": "2025-09-02T10:00:00+08:00",
            "end_ts": "2025-09-02T11:00:00+08:00",
            "approved": 1, "paid": 0,
        }]),
    }
    for name, (kind, rows) in files.items():
        path = cfg.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)


def _zip_manifest(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("manifest.json"))


def _unpack(zip_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    return dest


def _run_verify(pkg: Path, *args: str):
    env = os.environ.copy()
    for name in ("WCA_PUBLIC_KEY", "WCA_REQUIRE_SIGNATURE", "WCA_EXPECT_ANCHOR"):
        env.pop(name, None)
    return subprocess.run([sys.executable, "verify.py", *args], cwd=pkg,
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=120, env=env)


def _four(manifest: dict) -> str:
    triple = manifest["triple"]
    schema_version = str(manifest["schema"]).rsplit("-v", 1)[-1]
    return ",".join([schema_version, triple["rule_pack_version"],
                     triple["input_fingerprint"], triple["conclusion_digest"]])


def _five(manifest: dict) -> str:
    return _four(manifest) + "," + manifest["projection_fingerprint"]


def _signed_manifest(conn, cfg, *, omit: bool):
    out = run_check(conn, cfg, start=DAY, end=DAY)
    key = signing.generate_keypair()
    manifest = export_package(
        conn, cfg, out.run_id, signing_key=key,
        omit_fields={"leave:paid"} if omit else None)
    return manifest, key


def test_five_segment_anchor_on_trimmed_package_passes(conn, cfg, tmp_path):
    _seed(conn, cfg)
    manifest, _ = _signed_manifest(conn, cfg, omit=True)
    assert manifest["omitted_fields"]
    pkg = _unpack(Path(manifest["package_zip"]), tmp_path / "trimmed")

    proc = _run_verify(pkg, "--expect-anchor", _five(manifest))
    assert proc.returncode == 0, proc.stdout
    assert "ANCHOR CHECK OK" in proc.stdout
    assert "RESULT OK" in proc.stdout

    res = replay(Path(manifest["package_zip"]), expect_anchor=_five(manifest))
    assert res["ok"], res["reason"]
    assert res["external_mismatched_fields"] == []
    assert res["expected_external_anchor"]["projection_fingerprint"] == \
        manifest["projection_fingerprint"]


def test_five_segment_mismatch_names_projection(conn, cfg, tmp_path):
    _seed(conn, cfg)
    manifest, _ = _signed_manifest(conn, cfg, omit=True)
    bad = "0" * 64
    anchor = _four(manifest) + "," + bad
    pkg = _unpack(Path(manifest["package_zip"]), tmp_path / "mismatch")

    proc = _run_verify(pkg, "--expect-anchor", anchor)
    assert proc.returncode != 0
    assert "ANCHOR FAIL" in proc.stdout
    assert "projection_fingerprint" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(Path(manifest["package_zip"]), expect_anchor=anchor)
    assert not res["ok"]
    assert "ANCHOR FAIL" in res["reason"]
    assert res["external_mismatched_fields"] == ["projection_fingerprint"]


def test_five_segment_on_untrimmed_package_fails_closed(conn, cfg, tmp_path):
    """该包没有投影字段，第五段无法校验；选择失败关闭，避免把“无法校验”读成 OK。"""
    _seed(conn, cfg)
    manifest, _ = _signed_manifest(conn, cfg, omit=False)
    assert "projection_fingerprint" not in manifest
    anchor = _four(manifest) + "," + ("a" * 64)
    pkg = _unpack(Path(manifest["package_zip"]), tmp_path / "untrimmed")

    proc = _run_verify(pkg, "--expect-anchor", anchor)
    assert proc.returncode != 0
    assert "ANCHOR FAIL" in proc.stdout
    assert "projection_fingerprint" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(Path(manifest["package_zip"]), expect_anchor=anchor)
    assert not res["ok"]
    assert "ANCHOR FAIL" in res["reason"]
    assert res["external_mismatched_fields"] == ["projection_fingerprint"]


def test_four_segment_anchor_behavior_is_unchanged_on_trimmed_package(conn, cfg, tmp_path):
    _seed(conn, cfg)
    manifest, _ = _signed_manifest(conn, cfg, omit=True)
    pkg = _unpack(Path(manifest["package_zip"]), tmp_path / "four")

    proc = _run_verify(pkg, "--expect-anchor", _four(manifest))
    assert proc.returncode == 0, proc.stdout
    assert "ANCHOR CHECK OK" in proc.stdout
    assert "RESULT OK" in proc.stdout

    res = replay(Path(manifest["package_zip"]), expect_anchor=_four(manifest))
    assert res["ok"], res["reason"]
    assert res["external_mismatched_fields"] == []


def test_five_segment_anchor_from_environment(conn, cfg, tmp_path, monkeypatch):
    _seed(conn, cfg)
    manifest, _ = _signed_manifest(conn, cfg, omit=True)
    pkg = _unpack(Path(manifest["package_zip"]), tmp_path / "env")
    monkeypatch.setenv("WCA_EXPECT_ANCHOR", _five(manifest))
    monkeypatch.delenv("WCA_EXPECT_TRIPLE", raising=False)

    env = os.environ.copy()
    for name in ("WCA_PUBLIC_KEY", "WCA_REQUIRE_SIGNATURE"):
        env.pop(name, None)
    proc = subprocess.run([sys.executable, "verify.py"], cwd=pkg,
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=120, env=env)
    assert proc.returncode == 0, proc.stdout
    assert "ANCHOR CHECK OK" in proc.stdout
    res = replay(Path(manifest["package_zip"])
                 )
    assert res["ok"], res["reason"]
    assert res["external_mismatched_fields"] == []
