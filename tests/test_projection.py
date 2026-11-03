"""两层指纹：projection_fingerprint 与受控字段裁剪。

本轮默认不裁剪；测试显式传入 omit_fields={"leave:paid"} 才启用。
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

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import projection, signing
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


def _scope(conn, run_id: str) -> dict:
    row = conn.execute("SELECT scope_json FROM run WHERE run_id = ?", (run_id,)).fetchone()
    return json.loads(row["scope_json"])


def test_projection_fingerprint_ignores_non_projection_field_and_normalizes_time(conn, cfg):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    scope = _scope(conn, out.run_id)
    base = projection.projection_fingerprint(conn, scope, cfg.rule_pack_id)

    # leave.paid 不在投影字段：改它不应改变投影指纹。
    conn.execute("UPDATE leave_record SET paid = 0")
    assert projection.projection_fingerprint(conn, scope, cfg.rule_pack_id) == base

    # 时间格式扰动经规范化后仍相同。
    conn.execute(
        "UPDATE punch SET event_ts = '2025-09-02 09:00:00+08:00' "
        "WHERE emp_id = 'T-STD' AND punch_type = 'in'")
    assert projection.projection_fingerprint(conn, scope, cfg.rule_pack_id) == base

    # 投影字段变化必须改变指纹。
    conn.execute("UPDATE punch SET punch_type = 'out' "
                 "WHERE emp_id = 'T-STD' AND punch_type = 'in'")
    assert projection.projection_fingerprint(conn, scope, cfg.rule_pack_id) != base


def test_projection_field_list_has_source_evidence():
    root = Path(__file__).resolve().parent.parent
    source = "\n".join(
        p.read_text(encoding="utf-8") for p in (root / "src" / "rules").glob("*.py")
    ) + (root / "src" / "engine.py").read_text(encoding="utf-8")
    ingests = (root / "src" / "ingest.py").read_text(encoding="utf-8")
    missing = []
    for table, fields in projection.PROJECTION_TABLE_FIELDS.items():
        for field in fields:
            direct = field in source
            indirect = (table, field) in projection.PROJECTION_INDIRECT_FIELDS
            if not direct and not indirect:
                missing.append(f"{table}.{field}")
            if indirect:
                marker = projection.PROJECTION_INDIRECT_FIELDS[(table, field)]
                assert marker in ingests or marker in source, f"间接证据缺失：{marker}"
    assert not missing, f"投影字段没有源码证据：{missing}"
    # 明确不应进入投影的字段。
    flat = {f for fields in projection.PROJECTION_TABLE_FIELDS.values() for f in fields}
    for field in ("pseudonym", "normal_hourly_cents", "paid", "recorded_at"):
        assert field not in flat


def test_untrimmed_package_keeps_old_replay_semantics(conn, cfg):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    manifest = export_package(conn, cfg, out.run_id)
    # 默认开关关闭：manifest 不新增投影/裁剪字段，旧包语义不变。
    assert "projection_fingerprint" not in manifest
    assert "omitted_fields" not in manifest
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["expected_triple"]["input_fingerprint"] == \
        res["actual_triple"]["input_fingerprint"]
    assert res["projection_ok"] is False


def test_omit_non_projection_field_replays_with_omitted_fields(conn, cfg, tmp_path):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    manifest = export_package(conn, cfg, out.run_id, omit_fields={"leave:paid"})
    assert manifest["omitted_fields"] == [{
        "kind": "leave", "field": "paid", "reason": projection.OMITTED_REASON}]

    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        # 文件名序号由导入顺序决定；用 inputs/manifest 找到 leave 条目。
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        leave = next(e for e in im["entries"] if e["kind"] == "leave")
        header = zf.read(leave["arcname"]).decode("utf-8").splitlines()[0]
        assert "paid" not in header
        assert im["omitted_fields"] == manifest["omitted_fields"]

    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert res["projection_ok"] is True
    assert res["input_fingerprint_recomputed"] is True, \
        "裁剪后原始输入指纹必然不同，必须明确标记而不是当回归"

    key = signing.generate_keypair()
    pub = tmp_path / "projection.pub"
    signing.write_public_key(pub, key.verify_key.encode(), force=True)
    signed_manifest = export_package(conn, cfg, out.run_id, signing_key=key,
                                     omit_fields={"leave:paid"})
    signed = replay(Path(signed_manifest["package_zip"]), public_keys=[str(pub)])
    assert signed["ok"], signed["reason"]
    assert signed["signature_ok"] is True
    assert signed["inputs_digest_ok"] is True
    assert signed["projection_ok"] is True

    # 包内独立 verify.py 仍要能验签 + 校验裁剪后的 inputs_digest。
    extracted = tmp_path / "verify-trimmed"
    with zipfile.ZipFile(Path(signed_manifest["package_zip"])) as zf:
        zf.extractall(extracted)
    env = os.environ.copy()
    for name in ("WCA_PUBLIC_KEY", "WCA_REQUIRE_SIGNATURE"):
        env.pop(name, None)
    proc = subprocess.run(
        [sys.executable, "verify.py", "--public-key", str(pub)],
        cwd=extracted, capture_output=True, text=True, encoding="utf-8",
        timeout=120, env=env)
    assert proc.returncode == 0, proc.stdout
    assert "INPUTS DIGEST OK" in proc.stdout
    assert "SIGNATURE OK (pinned" in proc.stdout
    assert "RESULT OK" in proc.stdout


def test_omit_projection_field_is_rejected_at_export(conn, cfg):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY)
    with pytest.raises(ValueError, match="投影字段"):
        export_package(conn, cfg, out.run_id,
                       omit_fields={"employee:worktime_regime"})
