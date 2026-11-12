"""活动库审计链只读自检：覆盖 verify_chain 不检查的跳号、截断与跨段漏洞。"""

from __future__ import annotations

from dataclasses import replace
from datetime import date

from conftest import load_base
from src.db import set_meta
from src.engine import run_check
from src.evidence import (_chain_hash, append_audit, ensure_audit_epoch,
                          scan_audit_chain, verify_chain)
from src.rules.rulepack import RULE_PACK_V5, RULE_PACK_V6
from src.util import sha256_hex

DAY = date(2025, 9, 2)


def _seed(conn, cfg) -> None:
    load_base(conn, cfg)
    run_check(conn, cfg, start=DAY, end=DAY)


def _seqs(conn) -> list[int]:
    return [int(row["seq"]) for row in conn.execute(
        "SELECT seq FROM audit_event ORDER BY seq").fetchall()]


def _rebuild_hashes_after(conn, keep_seq: int) -> None:
    """模拟“删行后重算哈希”：seq 仍跳号，但 prev_hash/entry_hash 自洽。"""
    anchor = conn.execute("SELECT entry_hash FROM audit_event WHERE seq = ?",
                          (keep_seq,)).fetchone()
    prev = str(anchor["entry_hash"])
    rows = conn.execute(
        "SELECT seq, actor, action, ts, payload_sha256 FROM audit_event "
        "WHERE seq > ? ORDER BY seq", (keep_seq,)).fetchall()
    for row in rows:
        entry = _chain_hash(prev, int(row["seq"]), row["actor"], row["action"], row["ts"],
                            row["payload_sha256"])
        conn.execute("UPDATE audit_event SET prev_hash = ?, entry_hash = ? WHERE seq = ?",
                     (prev, entry, int(row["seq"])))
        prev = entry


def test_clean_chain_scans_ok_and_does_not_write(conn, cfg):
    _seed(conn, cfg)
    before = conn.total_changes
    scan = scan_audit_chain(conn, cfg)
    assert scan.ok, scan.issues
    assert scan.total_rows == len(_seqs(conn))
    assert conn.total_changes == before, "自检必须只读，不得写库"
    assert scan.note, "未给外部锚点时必须明确告知开放段尾部不可自证"


def test_deleted_middle_event_is_reported_with_first_bad_seq(conn, cfg):
    _seed(conn, cfg)
    seqs = _seqs(conn)
    middle = seqs[1]
    conn.execute("DELETE FROM audit_event WHERE seq = ?", (middle,))
    scan = scan_audit_chain(conn, cfg)
    assert not scan.ok
    assert scan.first_issue is not None
    assert "prev_hash_break" in {item["kind"] for item in scan.issues}


def test_seq_gap_survives_hash_rebuild_but_scan_catches_it(conn, cfg):
    """删除中间事件后重算后续哈希：verify_chain 会放过，自检必须按 seq 跳号抓住。"""
    _seed(conn, cfg)
    seqs = _seqs(conn)
    middle = seqs[1]
    conn.execute("DELETE FROM audit_event WHERE seq = ?", (middle,))
    _rebuild_hashes_after(conn, middle - 1)

    assert verify_chain(conn, cfg).ok, "前提：只验哈希时这条链看起来是完整的"
    scan = scan_audit_chain(conn, cfg)
    assert not scan.ok
    assert scan.first_issue["kind"] == "seq_gap"
    assert scan.first_issue["seq"] == middle


def test_open_tail_truncation_needs_external_anchor(conn, cfg):
    _seed(conn, cfg)
    last = conn.execute("SELECT seq, entry_hash FROM audit_event ORDER BY seq DESC LIMIT 1"
                        ).fetchone()
    conn.execute("DELETE FROM audit_event WHERE seq = ?", (int(last["seq"]),))

    assert verify_chain(conn, cfg).ok, "前提：尾部整段删除后剩余链仍然自洽"
    blind = scan_audit_chain(conn, cfg)
    assert blind.ok and not blind.open_tail_checked

    caught = scan_audit_chain(conn, cfg, expect_head=str(last["entry_hash"]),
                              expect_max_seq=int(last["seq"]))
    assert not caught.ok
    assert caught.first_issue["kind"] == "head_truncated"


def test_deleted_epoch_activation_event_is_caught_by_anchor(conn, cfg):
    """切换事件是旧段最后一条；删掉它旧段仍自洽、新段为空，只有纪元锚点能发现。"""
    append_audit(conn, run_id=None, actor="tester", action="demo.before", payload={"n": 1},
                 cfg=cfg)
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    epoch = ensure_audit_epoch(conn, cfg5)
    assert epoch and int(epoch["activation_event_seq"]) > 0
    conn.execute("DELETE FROM audit_event WHERE seq = ?",
                 (int(epoch["activation_event_seq"]),))

    assert verify_chain(conn, cfg5).ok, "前提：verify_chain 看不到纪元锚点缺失"
    scan = scan_audit_chain(conn, cfg5)
    assert not scan.ok
    assert "epoch_anchor_missing" in {item["kind"] for item in scan.issues}


def test_tampered_closed_segment_is_scanned_when_cfg_is_later_pack(conn, cfg):
    """v6 配置下 verify_chain 只验 legacy + v6 段；v5 段被篡改必须由全量扫描发现。"""
    append_audit(conn, run_id=None, actor="tester", action="demo.v4", payload={"n": 4}, cfg=cfg)

    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    epoch5 = ensure_audit_epoch(conn, cfg5)
    append_audit(conn, run_id=None, actor="tester", action="demo.v5", payload={"n": 5}, cfg=cfg5)

    cfg6 = replace(cfg, rule_pack_id=RULE_PACK_V6)
    set_meta(conn, "rule_pack_version", RULE_PACK_V5)
    ensure_audit_epoch(conn, cfg6)
    append_audit(conn, run_id=None, actor="tester", action="demo.v6", payload={"n": 6}, cfg=cfg6)

    target = conn.execute(
        "SELECT seq FROM audit_event WHERE segment_id = ? AND action = ?",
        (epoch5["epoch_id"], "demo.v5")).fetchone()
    conn.execute("UPDATE audit_event SET payload_sha256 = ? WHERE seq = ?",
                 (sha256_hex("伪造的 v5 事件"), int(target["seq"])))

    assert verify_chain(conn, cfg6).ok, "前提：当前配置的 verify_chain 会跳过 v5 段"
    scan = scan_audit_chain(conn, cfg6)
    assert not scan.ok
    assert scan.first_issue["kind"] == "entry_hash_mismatch"
    assert scan.first_issue["seq"] == int(target["seq"])
