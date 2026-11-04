"""H-01 外部锚点：manifest 自校验和 + 期望三元组比对。"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import cli
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay

DAY = date(2025, 9, 2)
TRIPLE_KEYS = ("rule_pack_version", "input_fingerprint", "conclusion_digest")


def _checksum(doc: dict) -> str:
    """独立实现，刻意不复用生产 helper，避免用被测代码证明它自己。"""
    payload = {k: v for k, v in doc.items() if k != "manifest_checksum"}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _unpack(zip_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    return dest


def _run_verify(pkg: Path, *args: str, env_extra: dict | None = None):
    env = os.environ.copy()
    env.pop("WCA_EXPECT_TRIPLE", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, "verify.py", *args], cwd=pkg,
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=120, env=env)


def _triple_arg(triple: dict) -> str:
    return ",".join(str(triple[k]) for k in TRIPLE_KEYS)


def _anchor_arg(schema_version, triple: dict) -> str:
    return ",".join([str(schema_version), _triple_arg(triple)])


def _make_disguised_v1(src: Path, dst: Path) -> Path:
    """把正常 v2 包伪装成 v1：改 schema + 删除 manifest_checksum。"""
    def mutate(files):
        doc = json.loads(files["manifest.json"])
        doc["schema"] = "wca-evidence-package-v1"
        doc.pop("manifest_checksum", None)
        files["manifest.json"] = json.dumps(
            doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return files

    return _rezip(src, dst, mutate)


def _mutate_manifest(pkg: Path, mutate, *, recompute: bool = False) -> dict:
    path = pkg / "manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    mutate(doc)
    if recompute:
        doc["manifest_checksum"] = _checksum(doc)
    path.write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return doc


@pytest.fixture
def packed(conn, cfg):
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
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="anchor fixture")
    manifest = export_package(conn, cfg, out.run_id)
    return out, Path(manifest["package_zip"]), manifest


def _zip_manifest(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("manifest.json"))


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


def test_exported_manifest_checksum_covers_all_manifest_groups(packed):
    _, zip_path, manifest = packed
    doc = _zip_manifest(zip_path)
    assert doc["schema"] == "wca-evidence-package-v2", "新导出必须使用新 schema"
    assert doc["manifest_checksum"] == _checksum(doc)
    assert manifest["manifest_checksum"] == doc["manifest_checksum"]

    base = doc["manifest_checksum"]
    mutations = {
        "triple": lambda d: d["triple"].update(conclusion_digest="0" * 64),
        "scope_json": lambda d: d["scope_json"].update(start="2025-09-03"),
        "counts": lambda d: d["counts"].update(findings=d["counts"]["findings"] + 1),
        "chain_verification": lambda d: d["chain_verification"].update(length=999),
        "inputs": lambda d: d["inputs"].update(packed=d["inputs"]["packed"] + 1),
    }
    for name, mutate in mutations.items():
        changed = copy.deepcopy(doc)
        changed.pop("manifest_checksum", None)
        mutate(changed)
        assert _checksum(changed) != base, f"{name} 变化必须改变自校验和"


def test_verify_manifest_checksum_mismatch_is_failure(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "checksum-mismatch")
    _mutate_manifest(pkg, lambda d: d["counts"].update(findings=d["counts"]["findings"] + 1))

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "MANIFEST FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout


def test_verify_recomputed_checksum_but_external_anchor_catches(packed, tmp_path):
    """关键场景：攻击者重算自校验和能让 manifest 自洽，但外部锚点仍能戳穿。"""
    _, zip_path, _ = packed
    original = copy.deepcopy(_zip_manifest(zip_path)["triple"])
    pkg = _unpack(zip_path, tmp_path / "recomputed")
    forged_digest = "0" * 64 if original["conclusion_digest"] != "0" * 64 else "1" * 64
    _mutate_manifest(
        pkg, lambda d: d["triple"].update(conclusion_digest=forged_digest),
        recompute=True)

    plain = _run_verify(pkg)
    assert plain.returncode == 0, "自校验和重算后，无外部锚点只靠 verify 无法识别伪造"
    assert "RESULT OK" in plain.stdout

    with_arg = _run_verify(pkg, "--expect-triple", _triple_arg(original))
    assert with_arg.returncode != 0
    assert "TRIPLE FAIL" in with_arg.stdout
    assert "conclusion_digest" in with_arg.stdout
    assert "RESULT FAIL" in with_arg.stdout

    with_env = _run_verify(pkg, env_extra={"WCA_EXPECT_TRIPLE": _triple_arg(original)})
    assert with_env.returncode != 0
    assert "TRIPLE FAIL" in with_env.stdout
    assert "RESULT FAIL" in with_env.stdout


def _make_legacy_v1(doc: dict) -> None:
    doc["schema"] = "wca-evidence-package-v1"
    doc.pop("manifest_checksum", None)


def test_verify_missing_checksum_keeps_legacy_behavior(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "no-checksum")
    _mutate_manifest(pkg, _make_legacy_v1)

    proc = _run_verify(pkg)
    assert proc.returncode == 0
    assert "MANIFEST CHECKSUM MISSING" in proc.stdout
    assert "RESULT OK" in proc.stdout


def test_new_schema_missing_checksum_fails_closed(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "v2-no-checksum")
    _mutate_manifest(pkg, lambda d: d.pop("manifest_checksum", None))

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "MANIFEST FAIL" in proc.stdout
    assert "schema" in proc.stdout and "manifest_checksum" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(zip_path)
    assert res["ok"], "原始正常包不应受影响"

    def drop_checksum(files):
        doc = json.loads(files["manifest.json"])
        doc.pop("manifest_checksum", None)
        files["manifest.json"] = json.dumps(doc, ensure_ascii=False, sort_keys=True).encode()
        return files
    broken = _rezip(zip_path, tmp_path / "v2-no-checksum.zip", drop_checksum)
    res = replay(broken)
    assert not res["ok"]
    assert "manifest_checksum" in res["reason"]


def test_old_schema_missing_checksum_still_passes(packed):
    _, zip_path, _ = packed

    def to_v1(files):
        doc = json.loads(files["manifest.json"])
        doc["schema"] = "wca-evidence-package-v1"
        doc.pop("manifest_checksum", None)
        files["manifest.json"] = json.dumps(doc, ensure_ascii=False, sort_keys=True).encode()
        return files

    legacy = _rezip(zip_path, zip_path.parent / "anchor-v1.zip", to_v1)
    res = replay(legacy)
    assert res["ok"], res["reason"]
    assert res["manifest_checksum"] == "missing"


def test_unknown_schema_fails_closed(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "unknown-schema")
    _mutate_manifest(pkg, lambda d: d.update(schema="wca-evidence-package-vX"),
                     recompute=True)
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "MANIFEST FAIL" in proc.stdout
    assert "schema" in proc.stdout
    assert "RESULT FAIL" in proc.stdout
    res = replay(pkg)
    assert not res["ok"]
    assert "schema" in res["reason"]


def test_missing_schema_fails_closed(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "missing-schema")
    _mutate_manifest(pkg, lambda d: d.pop("schema", None), recompute=True)
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "MANIFEST FAIL" in proc.stdout
    assert "schema" in proc.stdout
    assert "RESULT FAIL" in proc.stdout
    res = replay(pkg)
    assert not res["ok"]
    assert "schema" in res["reason"]


def test_verify_no_external_anchor_behavior_unchanged(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "no-anchor")
    proc = _run_verify(pkg)
    assert proc.returncode == 0
    assert "MANIFEST CHECKSUM OK" in proc.stdout
    assert "RESULT OK" in proc.stdout
    assert "TRIPLE FAIL" not in proc.stdout


def test_replay_manifest_checksum_mismatch_fails(packed):
    _, zip_path, _ = packed

    def mutate(files):
        doc = json.loads(files["manifest.json"])
        doc["manifest_checksum"] = "0" * 64
        files["manifest.json"] = json.dumps(
            doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return files

    broken = _rezip(zip_path, zip_path.parent / "replay-checksum-broken.zip", mutate)
    res = replay(broken)
    assert not res["ok"]
    assert res["manifest_checksum"] == "mismatch"
    assert "MANIFEST FAIL" in res["reason"]


def test_replay_missing_checksum_continues_as_old_package(packed):
    _, zip_path, _ = packed

    def mutate(files):
        doc = json.loads(files["manifest.json"])
        doc["schema"] = "wca-evidence-package-v1"
        doc.pop("manifest_checksum", None)
        files["manifest.json"] = json.dumps(
            doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return files

    legacy = _rezip(zip_path, zip_path.parent / "replay-legacy-no-checksum.zip", mutate)
    res = replay(legacy)
    assert res["ok"], res["reason"]
    assert res["manifest_checksum"] == "missing"


def test_replay_external_anchor_mismatch_reports_fields(packed):
    _, zip_path, _ = packed
    original = copy.deepcopy(_zip_manifest(zip_path)["triple"])
    forged_fp = "0" * 64 if original["input_fingerprint"] != "0" * 64 else "1" * 64

    def mutate(files):
        # 改 input_fingerprint：findings 工件与反算摘要仍自洽，只有包外锚点能戳穿。
        doc = json.loads(files["manifest.json"])
        doc["triple"]["input_fingerprint"] = forged_fp
        doc["manifest_checksum"] = _checksum(doc)
        files["manifest.json"] = json.dumps(
            doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return files

    forged = _rezip(zip_path, zip_path.parent / "replay-external-forged.zip", mutate)
    res = replay(forged, expect_triple=_triple_arg(original))
    assert not res["ok"]
    assert res["external_mismatched_fields"] == ["input_fingerprint"]
    assert res["expected_external_triple"] == original
    assert "外部三元组" in res["reason"]
    assert cli.main(["replay", str(forged), "--expect-triple",
                     _triple_arg(original)]) == 1


def test_replay_external_anchor_match_keeps_normal_behavior(packed):
    _, zip_path, _ = packed
    original = _zip_manifest(zip_path)["triple"]
    res = replay(zip_path, expect_triple=_triple_arg(original))
    assert res["ok"], res["reason"]
    assert res["expected_external_triple"] == original
    assert res["external_mismatched_fields"] == []


def test_cli_replay_expect_triple_and_help(packed):
    _, zip_path, _ = packed
    original = _zip_manifest(zip_path)["triple"]
    # P0-3：没有 --expect-anchor 时不再给完整通过，只给 PARTIAL（exit 2）。
    assert cli.main(["replay", str(zip_path)]) == 2
    assert cli.main(["replay", str(zip_path), "--expect-triple",
                     _triple_arg(original)]) == 2

    parser = cli.build_parser()
    sub = next(action for action in parser._actions
               if isinstance(action, argparse._SubParsersAction))
    replay_help = sub.choices["replay"].format_help()
    assert "--expect-triple" in replay_help
    assert "WCA_EXPECT_TRIPLE" in replay_help
    assert "--expect-anchor" in replay_help
    assert "WCA_EXPECT_ANCHOR" in replay_help


def test_disguised_v1_triple_passes_but_anchor_fails(packed, tmp_path):
    """核心场景：伪装 v1 后，三元组仍放行，四元组必须戳穿 schema 降级。"""
    _, zip_path, _ = packed
    original = _zip_manifest(zip_path)["triple"]
    disguised = _make_disguised_v1(zip_path, tmp_path / "disguised-v1.zip")
    pkg = _unpack(disguised, tmp_path / "disguised-v1")

    triple_only = _run_verify(pkg, "--expect-triple", _triple_arg(original))
    assert triple_only.returncode == 0, "旧参数只看三元组，不约束 schema"
    assert "MANIFEST CHECKSUM MISSING" in triple_only.stdout
    assert "RESULT OK" in triple_only.stdout

    anchor = _run_verify(pkg, "--expect-anchor", _anchor_arg(2, original))
    assert anchor.returncode == 3
    assert "ANCHOR INCOMPARABLE" in anchor.stdout
    assert "schema_version" in anchor.stdout
    assert "RESULT INCOMPARABLE" in anchor.stdout

    env_anchor = _run_verify(pkg, env_extra={
        "WCA_EXPECT_ANCHOR": _anchor_arg(2, original)})
    assert env_anchor.returncode == 3
    assert "ANCHOR INCOMPARABLE" in env_anchor.stdout

    triple_res = replay(disguised, expect_triple=_triple_arg(original))
    assert triple_res["ok"], "仅三元组时伪装 v1 仍按旧包兼容路径通过"
    anchor_res = replay(disguised, expect_anchor=_anchor_arg(2, original))
    assert not anchor_res["ok"]
    assert anchor_res["incomparable"]
    assert "schema_version" in anchor_res["external_mismatched_fields"]
    assert anchor_res["expected_external_anchor"]["schema_version"] == 2

    assert cli.main(["replay", str(disguised), "--expect-anchor",
                     _anchor_arg(2, original)]) == 3


def test_normal_v2_package_with_matching_anchor_passes(packed, tmp_path):
    _, zip_path, _ = packed
    original = _zip_manifest(zip_path)["triple"]
    pkg = _unpack(zip_path, tmp_path / "anchor-match")
    proc = _run_verify(pkg, "--expect-anchor", _anchor_arg(2, original))
    assert proc.returncode == 0
    assert "ANCHOR CHECK OK" in proc.stdout
    assert "RESULT OK" in proc.stdout

    # schema_version 同时接受完整 schema 字符串写法。
    full = _run_verify(pkg, "--expect-anchor",
                       _anchor_arg("wca-evidence-package-v2", original))
    assert full.returncode == 0

    res = replay(zip_path, expect_anchor=_anchor_arg(2, original))
    assert res["ok"], res["reason"]
    assert res["expected_external_anchor"]["schema_version"] == 2
    assert res["external_mismatched_fields"] == []


def test_replay_anchor_from_environment(packed, monkeypatch):
    _, zip_path, _ = packed
    original = _zip_manifest(zip_path)["triple"]
    monkeypatch.setenv("WCA_EXPECT_ANCHOR", _anchor_arg(2, original))
    monkeypatch.delenv("WCA_EXPECT_TRIPLE", raising=False)
    res = replay(zip_path)
    assert res["ok"], res["reason"]
    assert res["expected_external_anchor"]["schema_version"] == 2
    assert res["external_mismatched_fields"] == []


def test_anchor_format_error_is_explicit(packed, tmp_path):
    _, zip_path, _ = packed
    pkg = _unpack(zip_path, tmp_path / "bad-anchor")
    proc = _run_verify(pkg, "--expect-anchor", "2,only-two")
    assert proc.returncode != 0
    assert "ANCHOR FAIL" in proc.stdout
    assert "四元组" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(zip_path, expect_anchor="2,only-two")
    assert not res["ok"]
    assert "四元组" in res["reason"]
