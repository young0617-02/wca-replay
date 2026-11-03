"""M-02 数据最小化：问答记录按 run 过滤、导出产物去掉金额字段。

先写测试再实现；输入 CSV 字段不在本轮裁剪（会改变输入指纹/ replay，见 docs/数据最小化方案.md）。
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import date
from pathlib import Path

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import signing
from src.agent import ComplianceAgent
from src.anomaly import decide_review
from src.engine import run_check
from src.evidence import export_package, responsibility_block
from src.ingest import import_csv_file
from src.kb import build_kb
from src.replay import replay

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _seed(conn, cfg):
    """写真实 CSV 再导入，保证包内输入可 replay；不用 inline://。"""
    cfg.ensure_dirs()
    files = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [schedule(
            "T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
            "2025-09-02T21:00:00+08:00", rest=60)]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T21:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, rows) in files.items():
        path = cfg.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)
    build_kb(conn, include_personnel=True)


def test_question_log_is_filtered_to_exported_run(conn, cfg):
    _seed(conn, cfg)
    first = run_check(conn, cfg, start=DAY, end=DAY, notes="minimization run 1")
    q1 = ComplianceAgent(conn, cfg).ask("我 2025-09 加班多少小时", actor_emp_id="T-STD")
    second = run_check(conn, cfg, start=DAY, end=DAY, notes="minimization run 2")
    q2 = ComplianceAgent(conn, cfg).ask("我 2025-09 加班多少小时", actor_emp_id="T-STD")

    rows = conn.execute(
        "SELECT qid, run_id FROM question_log ORDER BY asked_at, qid").fetchall()
    by_qid = {str(r["qid"]): str(r["run_id"] or "") for r in rows}
    assert by_qid[q1.qid] == first.run_id, "同 run 的问答必须关联到该 run"
    assert by_qid[q2.qid] == second.run_id, "后一个 run 的问答必须关联到后一个 run"

    resp = responsibility_block(conn, cfg, second.run_id)
    assert [q["qid"] for q in resp["ai_participation"]] == [q2.qid]
    assert "本 run" in resp["ai_participation_scope_note"]
    assert "全仓" not in resp["ai_participation_scope_note"]

    manifest = export_package(conn, cfg, second.run_id)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        doc = json.loads(zf.read("responsibility.json").decode("utf-8"))
        assert doc["ai_participation_count"] == 1
        assert [q["qid"] for q in doc["ai_participation"]] == [q2.qid]
        assert q1.qid not in json.dumps(doc, ensure_ascii=False), \
            "其他 run 的问答记录不得进入包内"


def test_export_redacts_amount_fields_but_db_keeps_them(conn, cfg, tmp_path):
    _seed(conn, cfg)
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="minimization amount")
    rid = conn.execute(
        "SELECT review_id FROM review_item WHERE run_id=? AND status='OPEN' "
        "ORDER BY review_id LIMIT 1", (out.run_id,)).fetchone()["review_id"]
    decide_review(conn, cfg, rid, reviewer="rv1", decision="APPROVED",
                  note="人工核额", amount_cents=8800)

    resp = responsibility_block(conn, cfg, out.run_id)
    assert resp["human_confirmations"][0]["amount_cents_input"] == 8800, \
        "数据库/复核台的金额不能被导出裁剪改掉"

    manifest = export_package(conn, cfg, out.run_id)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        doc = json.loads(zf.read("responsibility.json").decode("utf-8"))
        text = json.dumps(doc, ensure_ascii=False)
        assert "amount_cents_input" not in text
        assert "amount_entered_by" not in text
        assert "8800" not in text, "包内不得带人工金额"

        rows = list(csv.DictReader(io.StringIO(
            zf.read("conclusions_final.csv").decode("utf-8"))))
        assert rows and "amount_cents_input" not in rows[0]
        assert "amount_entered_by" not in rows[0]

    # 导出裁剪不改变三元组；新包仍可 replay。
    assert manifest["triple"]["input_fingerprint"] == out.input_fingerprint
    assert manifest["triple"]["conclusion_digest"] == out.conclusion_digest
    result = replay(Path(manifest["package_zip"]))
    assert result["ok"], result["reason"]

    # 再走一次签名导出：金额裁剪只改输出产物，inputs_digest 与三元组都不变。
    key = signing.generate_keypair()
    signed_manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    pub = tmp_path / "minimization.pub"
    signing.write_public_key(pub, key.verify_key.encode(), force=True)
    signed = replay(Path(signed_manifest["package_zip"]), public_keys=[str(pub)])
    assert signed["ok"], signed["reason"]
    assert signed["signature_ok"] is True
    assert signed["inputs_digest_ok"] is True
    assert signed["expected_triple"] == manifest["triple"]
