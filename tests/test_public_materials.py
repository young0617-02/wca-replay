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
        assert findings_n == len(_findings)
        assert final_n == expected_final
        assert f"- 发现（未签认）：{findings_n} 条" in confidence
        assert f"- 已确认结论：{final_n} 条" in confidence
        assert f"- 本包角色：{role}" in confidence
        assert "本包 0 条" not in confidence
        assert (
            f"发现（未签认）{findings_n} 条 / 已确认结论 {final_n} 条"
            in not_covered
        )


def _assert_violation_scope(manifest: dict, not_covered: str, findings: list[dict]) -> int:
    assert manifest["counts"]["findings"] == len(findings)
    violations = [f for f in findings if f["severity"] == "VIOLATION"]
    aggregate = []
    for f in violations:
        if f["source_line_no"]:
            continue
        metric = json.loads(f["metric_json"])
        assert metric.get("evidence_tables") == ["punch.csv", "schedule.csv"], f
        window = metric.get("evidence_window") or {}
        assert window.get("start") and window.get("end"), f
        assert metric.get("evidence_rules"), f
        assert metric.get("evidence_aggregation"), f
        aggregate.append(f)
    for f in aggregate:
        assert "该结论为周期聚合，无法定位到单行" in not_covered
        assert f["rule_id"] in not_covered
        assert f["emp_id"] in not_covered
    return len(aggregate)


def test_violations_have_line_or_aggregate_scope(conn, cfg, tmp_path):
    _engine, confirmed_zip, _em, _cm = _export_pair(conn, cfg, tmp_path)
    manifest, _confidence, not_covered, findings = _package_docs(confirmed_zip)
    violations = [f for f in findings if f["severity"] == "VIOLATION"]
    assert violations, "测试夹具应至少产生一条 VIOLATION"
    _assert_violation_scope(manifest, not_covered, findings)


def test_handoff_package_has_7_violations_and_6_aggregate_scopes():
    """本工作区的交接包实测：7 条 VIOLATION，6 条无法定位单行；缺包时跳过。"""
    import pytest

    confirmed = next((ROOT / "handoff" / "20261104-第三轮整改").glob(
        "package/confirmed-*.zip"), None)
    if confirmed is None:
        pytest.skip("本工作区没有第三轮交接包，跳过 7 条 VIOLATION 实测")
    manifest, _confidence, not_covered, findings = _package_docs(confirmed)
    violations = [f for f in findings if f["severity"] == "VIOLATION"]
    assert len(violations) == 7
    assert _assert_violation_scope(manifest, not_covered, findings) == 6
