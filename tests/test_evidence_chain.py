"""F-007 举证包与审计 hash 链：篡改必须可检出，三元组必须可复现（A8）。"""

from __future__ import annotations

import json
import zipfile
from datetime import date

import pytest

from conftest import load_base
from src.db import get_meta
from src.engine import run_check
from src.ingest import import_rows
from src.evidence import (
    append_audit,
    conclusion_digest,
    export_package,
    genesis_hash,
    input_fingerprint,
    set_genesis,
    verify_chain,
)
from src.rules.findings import Finding
from src.util import sha256_hex


def _seed_facts(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        {"emp_id": "T-STD", "event_ts": "2025-09-02T09:00:00+08:00", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-09-02T21:00:00+08:00", "punch_type": "out"},
    ], rel_path="inline://ev")


def test_chain_verifies_after_run(conn, cfg):
    _seed_facts(conn, cfg)
    run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    res = verify_chain(conn, cfg)
    assert res.ok, res.reason
    assert res.length >= 3


def test_chain_detects_payload_tampering(conn, cfg):
    _seed_facts(conn, cfg)
    run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    row = conn.execute("SELECT seq FROM audit_event ORDER BY seq LIMIT 1").fetchone()
    conn.execute("UPDATE audit_event SET payload_sha256 = ? WHERE seq = ?",
                 (sha256_hex("伪造的结论"), row["seq"]))
    res = verify_chain(conn, cfg)
    assert not res.ok
    assert res.broken_at_seq == row["seq"]
    assert "entry_hash" in res.reason or "不衔接" in res.reason


def test_chain_detects_row_deletion(conn, cfg):
    _seed_facts(conn, cfg)
    run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    middle = conn.execute("SELECT seq FROM audit_event ORDER BY seq").fetchall()[1]["seq"]
    conn.execute("DELETE FROM audit_event WHERE seq = ?", (middle,))
    res = verify_chain(conn, cfg)
    assert not res.ok, "删除中间一条必须被发现（prev_hash 不衔接）"


def test_genesis_is_bound_to_engine_and_rule_pack(conn, cfg):
    assert genesis_hash(cfg) != genesis_hash(
        type(cfg).load(env_path=None, WCA_RULE_PACK="rp-other.v9")
    )


def test_conclusion_digest_ignores_timestamps(conn, cfg):
    """同一结论在不同时间重跑，摘要必须一致——否则举证包无法复核。"""
    _seed_facts(conn, cfg)
    f = Finding(
        rule_id="OT-D01", rule_version="rp-1", emp_id="T-STD", severity="DEFENSIBLE",
        explanation="x", citations=["law.labor.41"], metric={"minutes_extension": 120},
        work_date="2025-09-02",
    )
    assert conclusion_digest([f]) == conclusion_digest([f])


def test_export_package_contains_triple_and_chain(conn, cfg):
    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    manifest = export_package(conn, cfg, out.run_id)
    assert manifest["triple"]["rule_pack_version"] == cfg.rule_pack_id
    assert manifest["triple"]["input_fingerprint"] == out.input_fingerprint
    assert manifest["triple"]["conclusion_digest"] == out.conclusion_digest
    assert manifest["chain_verification"]["ok"] is True
    zip_path = cfg.packages_dir / f"{out.run_id}.zip"
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        assert {"manifest.json", "findings.csv", "input_files.csv", "audit_chain.jsonl",
                "quality_issues.csv", "verify.py", "README.txt"} <= names
        m = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert m["triple"] == manifest["triple"]
        assert m["disclaimer"]
        findings_csv = zf.read("findings.csv").decode("utf-8")
        assert "inline://ev" in findings_csv, "举证包必须能反查原始文件"


def test_exported_package_reproduces_same_triple(conn, cfg):
    """A8：相同输入 + 相同规则版本 -> 相同结论摘要（确定性）。"""
    _seed_facts(conn, cfg)
    first = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    again = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    assert first.conclusion_digest == again.conclusion_digest
    assert first.input_fingerprint == again.input_fingerprint
    m1 = export_package(conn, cfg, first.run_id)
    m2 = export_package(conn, cfg, again.run_id)
    assert m1["triple"] == m2["triple"]
    # 结论正文逐字节一致；manifest 本身含导出时刻的链状态，因此不要求相同（如实区分）
    import zipfile
    from src.util import sha256_hex

    with zipfile.ZipFile(cfg.packages_dir / f"{first.run_id}.zip") as z1,             zipfile.ZipFile(cfg.packages_dir / f"{again.run_id}.zip") as z2:
        assert sha256_hex(z1.read("findings.csv")) == sha256_hex(z2.read("findings.csv"))
        assert sha256_hex(z1.read("input_files.csv")) == sha256_hex(z2.read("input_files.csv"))


def test_input_fingerprint_changes_when_source_file_changes(conn, cfg):
    _seed_facts(conn, cfg)
    scope = {"start": "2025-09-02", "end": "2025-09-02", "region_code": cfg.region_code}
    before = input_fingerprint(conn, scope)
    assert input_fingerprint(conn, scope) == before, "同输入必须同指纹（确定性）"
    import_rows(conn, cfg, "punch", [
        {"emp_id": "T-STD", "event_ts": "2025-09-03T09:00:00+08:00", "punch_type": "in"},
        {"emp_id": "T-STD", "event_ts": "2025-09-03T22:00:00+08:00", "punch_type": "out"},
    ], rel_path="inline://extra")
    assert input_fingerprint(conn, scope) != before, "新增输入文件必须改变指纹"
    assert input_fingerprint(conn, dict(scope, region_code="310100")) !=         input_fingerprint(conn, scope), "范围（地域）变化也要改变指纹"


def test_audit_append_requires_genesis(conn, cfg):
    cfg.ensure_dirs()
    from src.db import connect, init_db

    other = connect(cfg.db_path.parent / "fresh.sqlite3", cfg.sqlite_synchronous)
    init_db(other)
    with pytest.raises(ValueError):
        append_audit(other, run_id=None, actor="t", action="x", payload={})
    set_genesis(other, cfg)
    seq, entry = append_audit(other, run_id=None, actor="t", action="x", payload={}, cfg=cfg)
    assert seq == 1 and len(entry) == 64
