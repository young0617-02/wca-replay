"""F-007 举证包与审计 hash 链：篡改必须可检出，三元组必须可复现（A8）。"""

from __future__ import annotations

import json
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import load_base
from src.anomaly import decide_review
from src.db import get_meta
from src.engine import run_check
from src.ingest import import_rows
from src.evidence import (
    append_audit,
    conclusion_digest,
    export_package,
    genesis_hash,
    input_fingerprint,
    not_covered_block,
    record_delivery_event,
    responsibility_block,
    set_genesis,
    sign_package,
    verify_chain,
)
from src.rules.findings import Finding
from src.util import canonical_json, sha256_hex


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
    zip_path = Path(manifest["package_zip"])
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

    with zipfile.ZipFile(Path(m1["package_zip"])) as z1,             zipfile.ZipFile(Path(m2["package_zip"])) as z2:
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


def test_unsigned_findings_never_reach_the_conclusion_set(conn, cfg):
    """US-RV-01（★）：没有人登记结论的异常，一条都不许进对外结论集。"""
    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))

    cold = export_package(conn, cfg, out.run_id)
    assert cold["counts"]["findings"] > 0
    assert cold["counts"]["final_conclusions"] == 0
    assert cold["counts"]["unsigned_pending"] == cold["counts"]["findings"]
    with zipfile.ZipFile(Path(cold["package_zip"])) as zf:
        lines = zf.read("conclusions_final.csv").decode("utf-8").strip().split(chr(10))
        assert len(lines) == 1, f"未复核时结论集只应有表头：{lines}"

    rid = conn.execute("SELECT review_id FROM review_item WHERE run_id=? AND status='OPEN' "
                       "ORDER BY review_id LIMIT 1", (out.run_id,)).fetchone()["review_id"]
    decide_review(conn, cfg, rid, reviewer="rv1", decision="APPROVED",
                  note="人工核对无误", amount_cents=4500)

    warm = export_package(conn, cfg, out.run_id)
    assert warm["counts"]["final_conclusions"] == 1, "登记了几条就进几条，不多不少"
    assert warm["counts"]["unsigned_pending"] == warm["counts"]["findings"] - 1
    with zipfile.ZipFile(Path(warm["package_zip"])) as zf:
        body = zf.read("conclusions_final.csv").decode("utf-8")
        assert body.strip().count(chr(10)) == 1, "结论集必须只有那一条已确认记录"
        assert "rv1" in body and "amount_cents_input" not in body
        assert "4500" not in body, "金额只留在库/复核台，不进入举证包"


def test_delivery_event_and_sign_alias_share_the_same_audit_bytes(conn, cfg):
    """改名只改函数名/CLI 文案；evidence.sign 的事件字段与 payload 哈希不能变。"""
    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    first = record_delivery_event(conn, cfg, out.run_id, recorded_by="rv1")
    second = sign_package(conn, cfg, out.run_id, signed_by="rv1")

    rows = conn.execute(
        "SELECT seq, actor, action, run_id, payload_sha256 FROM audit_event "
        "WHERE action = 'evidence.sign' AND run_id = ? ORDER BY seq",
        (out.run_id,)).fetchall()
    expected_payload = sha256_hex(canonical_json(
        {"run_id": out.run_id, "signed_by": "rv1"}))
    assert len(rows) == 2
    assert {r["actor"] for r in rows} == {"human:rv1"}
    assert {r["action"] for r in rows} == {"evidence.sign"}
    assert {r["payload_sha256"] for r in rows} == {expected_payload}
    assert first["audit_seq"] != second["audit_seq"]
    assert first["signed_by"] == second["signed_by"] == "rv1"
    assert verify_chain(conn, cfg).ok, "追加两条交付事件后链仍必须完整"


def test_signing_puts_a_named_actor_in_the_chain(conn, cfg):
    """US-RV-04：签发只追加审计事件，签名人具名、可回看，链仍完整。"""
    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))

    rec = sign_package(conn, cfg, out.run_id, signed_by="rv1")
    row = conn.execute("SELECT actor, action, run_id FROM audit_event WHERE seq = ?",
                       (rec["audit_seq"],)).fetchone()
    assert (row["actor"], row["action"], row["run_id"]) == ("human:rv1", "evidence.sign", out.run_id)

    ver = verify_chain(conn, cfg)
    assert ver.ok, ver.reason
    resp = responsibility_block(conn, cfg, out.run_id)
    assert resp["signed"] is True
    assert [s["actor"] for s in resp["signed_by"]] == ["human:rv1"]

    manifest = export_package(conn, cfg, out.run_id)
    assert manifest["responsibility"]["signed"] is True
    assert manifest["chain_verification"]["ok"] is True

    with pytest.raises(ValueError):
        sign_package(conn, cfg, out.run_id, signed_by="   ")


def test_export_from_other_cwd_still_reads_repo_config(conn, cfg, tmp_path, monkeypatch):
    """配置路径必须相对仓库根解析：换目录执行 export 不能因 CWD 找不到 not_covered.json。"""
    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    monkeypatch.chdir(tmp_path)
    nc = not_covered_block(cfg)
    assert nc["scope"]["cities_covered"] == cfg.region_profile.codes()
    manifest = export_package(conn, cfg, out.run_id)
    assert manifest["not_covered"]["rules_excluded"] == [r["rule_id"] for r in nc["rules_excluded"]]
    assert Path(manifest["package_zip"]).is_file()


def test_package_declares_what_it_does_not_cover(conn, cfg):
    """US-EX-03：未覆盖范围随包给出，接收方不必先问才知道边界在哪。"""
    nc = not_covered_block(cfg)
    assert nc["rules_excluded"] and nc["not_tested"] and nc["known_limitations"]
    assert nc["scope"]["worktime_regimes_excluded"]
    assert len(nc["scope"]["cities_covered"]) == len(cfg.region_profile.codes())

    _seed_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    excluded = {r["rule_id"] for r in nc["rules_excluded"]}
    assert not ({f.rule_id for f in out.findings} & excluded), "摘除的规则不能再产生结论"

    manifest = export_package(conn, cfg, out.run_id)
    assert manifest["not_covered"]["rules_excluded"] == [r["rule_id"] for r in nc["rules_excluded"]]
    assert manifest["not_covered"]["not_tested_count"] == len(nc["not_tested"])
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        names = set(zf.namelist())
        assert {"not_covered.json", "未覆盖清单.md"} <= names
        md = zf.read("未覆盖清单.md").decode("utf-8")
        assert "未测项" in md and "本期不做" in md
        for rid in excluded:
            assert rid in md, f"摘除的判据 {rid} 必须自己列出来"


def test_responsibility_block_separates_machine_and_human(conn, cfg):
    """US-EX-02（★）：机器算了什么、AI 碰过什么、人确认了什么、谁签的字，一份说清。"""
    from src.agent import ComplianceAgent
    from src.kb import build_kb

    _seed_facts(conn, cfg)
    build_kb(conn, include_personnel=True)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    ComplianceAgent(conn, cfg).ask("我 2025-09 加班多少小时", actor_emp_id="T-STD")

    rid = conn.execute("SELECT review_id FROM review_item WHERE run_id=? AND status='OPEN' "
                       "ORDER BY review_id LIMIT 1", (out.run_id,)).fetchone()["review_id"]
    decide_review(conn, cfg, rid, reviewer="rv1", decision="APPROVED",
                  note="按省口径人工核额", amount_cents=8800)

    resp = responsibility_block(conn, cfg, out.run_id)
    assert resp["human_confirmed_findings"] == 1
    one = resp["human_confirmations"][0]
    assert one["confirmed_by"] == "rv1" and one["decision"] == "APPROVED"
    assert one["amount_cents_input"] == 8800 and one["amount_entered_by"] == "human:rv1"
    total = conn.execute("SELECT COUNT(*) AS n FROM finding WHERE run_id = ?",
                         (out.run_id,)).fetchone()["n"]
    assert resp["human_confirmed_findings"] + \
        resp["unsigned_findings_excluded_from_conclusions"] == total, "两个桶必须盖住全部结论"

    # 引擎只做数值档位，金额/定性一律不是它的输出
    assert not any("金额" in x for x in resp["engine_only_outputs"])
    assert "应付金额" in resp["never_output"] and "违法定性" in resp["never_output"]

    assert resp["ai_participation_count"] == len(resp["ai_participation"]) == 1
    q = resp["ai_participation"][0]
    assert q["actor_emp_id"] == "T-STD" and q["provider"]
    assert q["gate_decision"] in ("ANSWERED", "EXPLAIN_ONLY", "ESCALATED")
    assert "本 run" in resp["ai_participation_scope_note"], "问答留痕必须标明按 run 过滤"

    assert resp["signed"] is False, "没签字就不能显示成已签发"
    manifest = export_package(conn, cfg, out.run_id)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        in_zip = json.loads(zf.read("responsibility.json").decode("utf-8"))
        assert in_zip["human_confirmed_findings"] == 1
        assert in_zip["ai_participation_count"] == 1
        text = json.dumps(in_zip, ensure_ascii=False)
        assert "amount_cents_input" not in text and "amount_entered_by" not in text
        assert "8800" not in text, "金额只留在库/复核台，不进入举证包"
