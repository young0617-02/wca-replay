"""Phase 3B：单库 v4→v5 规则包纪元/审计段切换。"""

from __future__ import annotations

import csv
import json
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src.config import Config
from src.db import get_meta
from src.engine import run_check
from src.evidence import append_audit, export_package, verify_chain
from src.ingest import import_csv_file
from src.replay import replay
from src.rules.approvals import upsert_approval
from src.rules.rulepack import RULE_PACK_V4, RULE_PACK_V5

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _seed(conn, cfg) -> None:
    cfg.ensure_dirs()
    rows = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [
            schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
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


def _approval() -> dict:
    return {
        "emp_id": "T-CMP", "doc_no": "深人社函〔2025〕EPOCH-01号",
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "1" * 64,
        "recorded_at": "2025-01-02T00:00:00+08:00",
    }


def _epoch(conn) -> dict | None:
    row = conn.execute("SELECT * FROM rule_pack_epoch WHERE rule_pack_version = ?",
                       (RULE_PACK_V5,)).fetchone()
    return dict(row) if row else None


def test_v4_then_v5_creates_epoch_without_resetting_old_genesis(conn, cfg):
    cfg = replace(cfg, rule_pack_id=RULE_PACK_V4)
    _seed(conn, cfg)
    v4_run = run_check(conn, cfg, start=DAY, end=DAY, notes="v4 before epoch")
    v4_zip = Path(export_package(conn, cfg, v4_run.run_id)["package_zip"])
    old_genesis = get_meta(conn, "audit_genesis")
    old_head = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1"
                            ).fetchone()
    assert old_head is not None

    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    upsert_approval(conn, _approval())
    v5_run = run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 after epoch")

    assert get_meta(conn, "audit_genesis") == old_genesis, "旧 v4 genesis 不能被重置/改写"
    transition = conn.execute(
        "SELECT seq, entry_hash, rule_pack_version, segment_id, action FROM audit_event "
        "WHERE action = 'rule_pack.epoch.start'").fetchone()
    assert transition is not None
    epoch = _epoch(conn)
    assert epoch is not None
    assert epoch["prev_head_hash"] == old_head["entry_hash"]
    assert epoch["activation_event_seq"] == transition["seq"]
    assert epoch["segment_start_prev_hash"] == transition["entry_hash"]
    assert transition["segment_id"] is None and transition["rule_pack_version"] == RULE_PACK_V4
    assert int(epoch["segment_start_seq"]) == int(transition["seq"]) + 1

    assert verify_chain(conn, cfg).ok, "旧 v4 链在切换后仍须独立可验证"
    assert verify_chain(conn, cfg5).ok, "v5 新段须可验证，同时覆盖旧链"

    v5_manifest = export_package(conn, cfg5, v5_run.run_id)
    segment = v5_manifest.get("audit_segment")
    assert segment and segment["epoch_id"] == epoch["epoch_id"]
    assert segment["segment_start_prev_hash"] == transition["entry_hash"]
    assert segment["activation_event"]["entry_hash"] == transition["entry_hash"]
    assert segment["activation_event"]["action"] == "rule_pack.epoch.start"
    with zipfile.ZipFile(Path(v5_manifest["package_zip"])) as zf:
        first = json.loads(zf.read("audit_chain.jsonl").decode("utf-8").splitlines()[0])
        assert first["prev_hash"] == transition["entry_hash"]
        assert all(json.loads(line)["rule_pack_version"] == RULE_PACK_V5
                   for line in zf.read("audit_chain.jsonl").decode("utf-8").splitlines())
    assert replay(Path(v5_manifest["package_zip"]))["ok"] is True
    assert replay(v4_zip)["ok"] is True, "纪元切换后旧的 v4 包仍须 legacy 回放"


def test_epoch_switch_is_idempotent_and_v4_writes_are_closed(conn, cfg):
    cfg = replace(cfg, rule_pack_id=RULE_PACK_V4)
    _seed(conn, cfg)
    run_check(conn, cfg, start=DAY, end=DAY, notes="v4")
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 first")
    first = _epoch(conn)
    run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 second")
    assert _epoch(conn) == first, "重复 v5 运行必须复用同一纪元"
    assert conn.execute("SELECT COUNT(*) AS n FROM audit_event "
                        "WHERE action = 'rule_pack.epoch.start'").fetchone()["n"] == 1
    with pytest.raises(RuntimeError, match="v4|封闭|纪元"):
        append_audit(conn, run_id=None, actor="system:test", action="legacy.write",
                     payload={}, cfg=cfg)


def test_v5_epoch_package_with_approval_replays(conn, cfg):
    cfg = replace(cfg, rule_pack_id=RULE_PACK_V4)
    _seed(conn, cfg)
    run_check(conn, cfg, start=DAY, end=DAY, notes="v4")
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    upsert_approval(conn, _approval())
    out = run_check(conn, cfg5, start=DAY, end=DAY, notes="v5 epoch approval")
    manifest = export_package(conn, cfg5, out.run_id)
    assert manifest["inputs"]["approval_rows"] == 1
    res = replay(Path(manifest["package_zip"]))
    assert res["ok"], res["reason"]
    assert any(i["kind"] == "approval" for i in res["imports"])
    assert res["actual_triple"] == res["expected_triple"]
