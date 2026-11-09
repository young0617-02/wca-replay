"""对外材料：policies 独立可读、CONFIDENCE 按包生成、VIOLATION 证据定位。"""
from __future__ import annotations

import csv
import io
import json
import shutil
import zipfile
from datetime import date
from pathlib import Path

from conftest import load_full_facts
from src import signing
from src.anomaly import decide_review, review_queue
from src.engine import run_check
from src.evidence import export_package, record_delivery_event

ROOT = Path(__file__).resolve().parent.parent


def _policy_text(name: str) -> str:
    return (ROOT / "policies" / name).read_text(encoding="utf-8")


def _export_pair(conn, cfg, tmp_path: Path) -> tuple[Path, Path, dict, dict]:
    load_full_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30))
    key = signing.generate_keypair()
    engine_manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    engine_zip = tmp_path / "engine-only.zip"
    shutil.copy2(engine_manifest["package_zip"], engine_zip)

    queue = review_queue(conn, run_id=out.run_id, only_open=True)
    chosen = queue[:2]
    assert len(chosen) == 2
    for item in chosen:
        decide_review(conn, cfg, int(item["review_id"]), "auditor", "APPROVED",
                      "测试：临时确认")
    record_delivery_event(conn, cfg, out.run_id, recorded_by="auditor")
    confirmed_manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    return engine_zip, Path(confirmed_manifest["package_zip"]), engine_manifest, confirmed_manifest


def _package_docs(zip_path: Path) -> tuple[dict, str, str, list[dict]]:
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        confidence = zf.read("policies/CONFIDENCE.md").decode("utf-8")
        not_covered = zf.read("未覆盖清单.md").decode("utf-8")
        findings = list(csv.DictReader(io.StringIO(
            zf.read("findings.csv").decode("utf-8-sig"), newline="")))
    return manifest, confidence, not_covered, findings


def test_policies_have_no_internal_refs_and_required_sections():
    forbidden = ("src/", "docs/", "REV-", "data/")
    for path in sorted((ROOT / "policies").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, (path.name, token)

    rule_pack = _policy_text("RULE-PACK.md")
    assert "法律条文生效日" in rule_pack
    assert "规则包冻结/切换日" in rule_pack
    assert "不可变快照" in rule_pack
    assert "不是按事件日期回溯适用" in rule_pack
    assert "操作性代理口径：`CAP-M01`" in rule_pack
    assert "偏保守的下界" in rule_pack
    assert "操作性代理口径：`CAP-W01`" in rule_pack
    assert "可能产生假阳性" in rule_pack

    field_doc = _policy_text("字段口径与条文依据-对外版.md")
    assert "存疑编号 → 受影响 rule_id" in field_doc
    assert "影响阈值还是事实认定" in field_doc
    assert "当前处置" in field_doc
    for idx in range(1, 14):
        assert f"| {idx} " in field_doc


def test_confidence_matches_manifest_and_not_covered_for_both_packages(conn, cfg, tmp_path):
    engine_zip, confirmed_zip, engine_manifest, confirmed_manifest = _export_pair(
        conn, cfg, tmp_path)
    assert engine_manifest["counts"]["final_conclusions"] == 0
    assert confirmed_manifest["counts"]["final_conclusions"] == 2

    for zip_path, expected_final, role in (
            (engine_zip, 0, "engine-only（无已确认结论）"),
            (confirmed_zip, 2, "含已确认结论")):
        manifest, confidence, not_covered, _findings = _package_docs(zip_path)
        findings_n = int(manifest["counts"]["findings"])
        final_n = int(manifest["counts"]["final_conclusions"])
        approved_n = int(manifest["counts"]["approved_conclusions"])
        assert findings_n == len(_findings)
        assert final_n == expected_final
        assert f"- 发现（未签认）：{findings_n} 条" in confidence
        assert f"- 已确认结论（decision=APPROVED）：{approved_n} 条" in confidence
        assert f"- 本包角色：{role}" in confidence
        assert "本包 0 条" not in confidence
        assert (
            f"发现（未签认）{findings_n} 条 / 已确认结论（APPROVED）{approved_n} 条"
            f" / 已人工处置合计 {final_n} 条"
            in not_covered
        )


def _evidence_of(finding: dict) -> dict:
    """新包读 evidence_json；第三轮旧包兼容读 metric 里的 evidence_* 键。"""
    raw = finding.get("evidence_json")
    if raw:
        evidence = json.loads(raw)
        if evidence:
            return evidence
    metric = json.loads(finding["metric_json"])
    if metric.get("evidence_tables") or metric.get("evidence_window"):
        return {
            "tables": metric.get("evidence_tables") or [],
            "window": metric.get("evidence_window") or {},
            "rules": metric.get("evidence_rules") or [],
            "aggregation": metric.get("evidence_aggregation") or "",
        }
    return {}


def _assert_evidence_scope(manifest: dict, not_covered: str, findings: list[dict]) -> tuple[int, dict]:
    assert manifest["counts"]["findings"] == len(findings)
    aggregate = [f for f in findings if _evidence_of(f)]
    severity_counts = {name: 0 for name in ("VIOLATION", "REVIEW", "DEFENSIBLE")}
    for f in aggregate:
        evidence = _evidence_of(f)
        assert evidence.get("tables") == ["punch.csv", "schedule.csv"], f
        window = evidence.get("window") or {}
        assert window.get("start") and window.get("end"), f
        assert evidence.get("rules"), f
        assert evidence.get("aggregation"), f
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        assert "该结论为周期聚合，无法定位到单行" in not_covered
        assert f["rule_id"] in not_covered
        assert f["emp_id"] in not_covered
    return len(aggregate), severity_counts


def test_violations_have_line_or_aggregate_scope(conn, cfg, tmp_path):
    _engine, confirmed_zip, _em, _cm = _export_pair(conn, cfg, tmp_path)
    manifest, _confidence, not_covered, findings = _package_docs(confirmed_zip)
    violations = [f for f in findings if f["severity"] == "VIOLATION"]
    assert violations, "测试夹具应至少产生一条 VIOLATION"
    count, severity_counts = _assert_evidence_scope(manifest, not_covered, findings)
    assert count >= 1
    assert severity_counts["VIOLATION"] >= 1


def test_handoff_package_has_7_violations_and_24_aggregate_scopes():
    """交接包实测：7 条 VIOLATION，24 条带 evidence 定位元数据（6/17/1）。"""
    import pytest

    fifth = ROOT / "handoff" / "20261104-第五轮整改"
    fourth = ROOT / "handoff" / "20261104-第四轮整改"
    confirmed = next((fifth.glob("package/confirmed-*.zip")), None)
    if confirmed is None:
        confirmed = next((fourth.glob("package/confirmed-*.zip")), None)
    if confirmed is None:
        pytest.skip("本工作区没有第四/五轮交接包，跳过 24 条证据定位实测")
    manifest, _confidence, not_covered, findings = _package_docs(confirmed)
    violations = [f for f in findings if f["severity"] == "VIOLATION"]
    assert len(violations) == 7
    count, severity_counts = _assert_evidence_scope(manifest, not_covered, findings)
    assert count == 24
    assert severity_counts == {"VIOLATION": 6, "REVIEW": 17, "DEFENSIBLE": 1}
    assert "共 24 条：VIOLATION 6 / REVIEW 17 / DEFENSIBLE 1" in not_covered
    assert "config/region_profile.json" not in not_covered
