"""第四轮阻断项：evidence 定位元数据与 conclusion_digest 解耦。

验收标准（用户第四轮原文）:
  * 同一输入 + 同一规则包 → conclusion_digest 回到 01bd4403…；
  * 同一批输入、不同 run 导包 → inputs_digest 完全相同；
  * 只补一条 evidence 注释 → 只有 evidence_digest 变化；
  * 删掉 evidence 块的新版本包 → EVIDENCE DIGEST 失败关闭。
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, load_full_facts, punch, schedule
from src import signing
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import conclusion_digest, export_package
from src.evidence_digest import evidence_digest
from src.ingest import import_csv_file
from src.package_verify import (conclusion_digest_from_findings,
                                evidence_digest_from_findings, verify_package)
from src.util import canonical_json, manifest_checksum, sha256_hex

ROOT = Path(__file__).resolve().parent.parent
KNOWN_DIGEST = "01bd44034d61a8ead8248a1b7845b794488b46a26424c488bb525ff0d25ac10a"

# 与第三轮 handoff 相同的输入与扫描范围；这两个数字必须与第三轮实测一致。
RAW_KINDS = {
    "org": "org", "employee": "employee", "approval_ledger": "approval",
    "schedule": "schedule", "punch": "punch", "leave": "leave",
    "trip": "trip", "correction": "correction",
}


@pytest.fixture(scope="module")
def full_v5(tmp_path_factory):
    work = tmp_path_factory.mktemp("full-v5")
    data_dir = work / "data"
    data_dir.mkdir()
    for path in (ROOT / "data" / "raw").glob("*.csv"):
        shutil.copy2(path, data_dir / path.name)
    cfg = Config.load(
        env_path=work / "nonexistent.env",
        WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(work / "full.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(work / "db_target.json"),
        WCA_DATA_DIR=str(data_dir),
        WCA_REPORTS_DIR=str(work / "reports"),
        WCA_PACKAGES_DIR=str(work / "packages"),
        WCA_USERS_PATH=str(work / "users.json"),
        WCA_UPLOAD_DIR=str(work / "uploads"),
        WCA_REGION_CODE="440300",
        WCA_RULE_PACK="rp-2026.11.gd-pilot-standard.v5",
        WCA_LLM_PROVIDER="stub",
        WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    cfg.ensure_dirs()
    conn = connect(cfg.db_path)
    init_db(conn)
    by_kind = {}
    for path in data_dir.glob("*.csv"):
        kind = RAW_KINDS.get(path.stem)
        if kind:
            by_kind[kind] = path
    for kind in ("org", "employee", "approval", "schedule", "punch", "leave",
                 "trip", "correction"):
        if kind in by_kind:
            path = by_kind[kind]
            import_csv_file(conn, cfg, path, kind=kind, rel_path=path.name)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30))
    key = signing.generate_keypair()
    manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    return {"conn": conn, "cfg": cfg, "out": out, "manifest": manifest, "key": key}


@pytest.fixture
def small_runs(conn, cfg):
    load_full_facts(conn, cfg)
    key = signing.generate_keypair()
    first = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30),
                      notes="evidence digest first run")
    first_manifest = export_package(conn, cfg, first.run_id, signing_key=key)
    second = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30),
                       notes="evidence digest second run")
    second_manifest = export_package(conn, cfg, second.run_id, signing_key=key)
    return conn, cfg, key, first, first_manifest, second, second_manifest


def _zip_member(zip_path: Path, name: str) -> bytes:
    with zipfile.ZipFile(zip_path) as zf:
        return zf.read(name)


def _manifest_of(zip_path: Path) -> dict:
    return json.loads(_zip_member(zip_path, "manifest.json").decode("utf-8"))


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


def _resign(manifest: dict, key) -> None:
    manifest["manifest_checksum"] = manifest_checksum(manifest)
    manifest[signing.SIGNATURE_FIELD] = signing.create_signature(
        manifest, key, manifest["chain_verification"]["head_hash"])


def test_full_v5_conclusion_digest_returns_to_01bd4403(full_v5):
    out = full_v5["out"]
    manifest = full_v5["manifest"]
    assert len(out.findings) == 116
    assert out.conclusion_digest == KNOWN_DIGEST, out.conclusion_digest
    assert manifest["triple"]["conclusion_digest"] == KNOWN_DIGEST
    assert manifest["evidence_digest"]

    evidence_rows = [finding for finding in out.findings if finding.evidence]
    assert len(evidence_rows) == 24
    assert {finding.severity for finding in evidence_rows} == {
        "VIOLATION", "REVIEW", "DEFENSIBLE"}
    for finding in evidence_rows:
        assert not any(str(key).startswith("evidence_") for key in finding.metric), finding.metric


def test_not_covered_lists_all_24_evidence_findings(full_v5):
    manifest = full_v5["manifest"]
    text = _zip_member(Path(manifest["package_zip"]), "未覆盖清单.md").decode("utf-8")
    assert "config/region_profile.json" not in text
    assert "共 24 条：VIOLATION 6 / REVIEW 17 / DEFENSIBLE 1" in text
    bullets = re.findall(r"^- `(?:VIOLATION|REVIEW|DEFENSIBLE) / ", text, flags=re.M)
    assert len(bullets) == 24
    for finding in full_v5["out"].findings:
        if not finding.evidence:
            continue
        assert finding.rule_id in text
        assert finding.emp_id in text
        assert (finding.period_key or finding.work_date or "") in text


def test_inputs_digest_stable_across_runs_same_inputs(small_runs):
    _conn, _cfg, _key, first, first_manifest, second, second_manifest = small_runs
    assert first.run_id != second.run_id
    assert first_manifest["inputs_digest"] == second_manifest["inputs_digest"]
    assert first_manifest["triple"]["input_fingerprint"] == \
        second_manifest["triple"]["input_fingerprint"]
    assert first_manifest["triple"]["conclusion_digest"] == \
        second_manifest["triple"]["conclusion_digest"]
    # inputs/manifest.json 不再记录 run_id；run_id 只在顶层 manifest。
    inputs_doc = json.loads(_zip_member(
        Path(first_manifest["package_zip"]), "inputs/manifest.json").decode("utf-8"))
    assert "run_id" not in inputs_doc
    assert first_manifest["run_id"] == first.run_id


def test_evidence_annotation_changes_only_evidence_digest(small_runs, tmp_path):
    conn, cfg, key, first, first_manifest, _second, _second_manifest = small_runs
    row = conn.execute(
        "SELECT finding_id, evidence_json FROM finding WHERE run_id = ? "
        "AND evidence_json <> '{}' ORDER BY finding_id LIMIT 1", (first.run_id,)
    ).fetchone()
    assert row is not None

    first_zip = tmp_path / "before.zip"
    shutil.copy2(first_manifest["package_zip"], first_zip)
    evidence = json.loads(row["evidence_json"])
    evidence["aggregation"] = str(evidence.get("aggregation") or "") + "；复核注释：追加测试"
    conn.execute("UPDATE finding SET evidence_json = ? WHERE finding_id = ?",
                 (canonical_json(evidence), int(row["finding_id"])))
    second_manifest = export_package(conn, cfg, first.run_id, signing_key=key)
    second_zip = Path(second_manifest["package_zip"])

    assert first_manifest["triple"]["conclusion_digest"] == \
        second_manifest["triple"]["conclusion_digest"]
    assert first_manifest["triple"]["input_fingerprint"] == \
        second_manifest["triple"]["input_fingerprint"]
    assert first_manifest["evidence_digest"] != second_manifest["evidence_digest"]

    first_csv = tmp_path / "before.csv"
    second_csv = tmp_path / "after.csv"
    first_csv.write_bytes(_zip_member(first_zip, "findings.csv"))
    second_csv.write_bytes(_zip_member(second_zip, "findings.csv"))
    first_conclusion, _, _ = conclusion_digest_from_findings(first_csv)
    second_conclusion, _, _ = conclusion_digest_from_findings(second_csv)
    first_evidence, _ = evidence_digest_from_findings(first_csv)
    second_evidence, _ = evidence_digest_from_findings(second_csv)
    assert first_conclusion == second_conclusion == first_manifest["triple"]["conclusion_digest"]
    assert first_evidence == first_manifest["evidence_digest"]
    assert second_evidence == second_manifest["evidence_digest"]
    assert first_evidence != second_evidence

    # 内存对象的 canonical 也必须忽略 evidence：这是阻断项的根因断言。
    finding = next(f for f in first.findings if f.evidence)
    changed = replace(finding, evidence=dict(finding.evidence, aggregation="另一条注释"))
    assert conclusion_digest([finding]) == conclusion_digest([changed])
    assert evidence_digest([finding.evidence_record()]) != \
        evidence_digest([changed.evidence_record()])


def test_inputs_manifest_cross_database_stable(tmp_path, cfg):
    """换空库、反向导入同一批 CSV：inputs_digest 必须只由文件本身决定。"""
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
    key = signing.generate_keypair()

    def build(tag: str, order: list[str]):
        work = tmp_path / tag
        data_dir = work / "data"
        work.mkdir()
        data_dir.mkdir()
        for name, (_kind, rows) in files.items():
            path = data_dir / name
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()),
                                        lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
        config = Config.load(
            env_path=work / "nonexistent.env",
            WCA_DB_BACKEND="sqlite",
            WCA_DB_PATH=str(work / "db.sqlite3"),
            WCA_DB_IDENTITY_PATH=str(work / "db_target.json"),
            WCA_DATA_DIR=str(data_dir),
            WCA_REPORTS_DIR=str(work / "reports"),
            WCA_PACKAGES_DIR=str(work / "packages"),
            WCA_USERS_PATH=str(work / "users.json"),
            WCA_UPLOAD_DIR=str(work / "uploads"),
            WCA_REGION_CODE="440300",
            WCA_RULE_PACK="rp-2026.10.gd-pilot-standard.v4",
            WCA_LLM_PROVIDER="stub",
            WCA_EMBEDDING_BACKEND="bm25",
            WCA_SQLITE_SYNCHRONOUS="OFF",
        )
        config.ensure_dirs()
        conn = connect(config.db_path)
        init_db(conn)
        for name in order:
            kind = files[name][0]
            import_csv_file(conn, config, data_dir / name, kind=kind, rel_path=name)
        out = run_check(conn, config, start=date(2025, 9, 2), end=date(2025, 9, 2))
        manifest = export_package(conn, config, out.run_id, signing_key=key)
        with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
            inputs_doc = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        return out, manifest, inputs_doc, conn

    out_a, manifest_a, inputs_a, conn_a = build("db-a", ["org.csv", "employee.csv",
                                                        "schedule.csv", "punch.csv"])
    out_b, manifest_b, inputs_b, conn_b = build("db-b", ["org.csv", "employee.csv",
                                                        "punch.csv", "schedule.csv"])
    try:
        file_ids_a = [int(r["file_id"]) for r in conn_a.execute(
            "SELECT file_id FROM raw_file ORDER BY file_id").fetchall()]
        file_ids_b = [int(r["file_id"]) for r in conn_b.execute(
            "SELECT file_id FROM raw_file ORDER BY file_id").fetchall()]
        assert file_ids_a == [1, 2, 3, 4]
        assert file_ids_b == [1, 2, 3, 4]
        # 同一批文件反向导入：内容/路径相同，只是 kind 与 file_id 的对应关系不同。
        rel_a = {r["rel_path"]: int(r["file_id"]) for r in conn_a.execute(
            "SELECT file_id, rel_path FROM raw_file").fetchall()}
        rel_b = {r["rel_path"]: int(r["file_id"]) for r in conn_b.execute(
            "SELECT file_id, rel_path FROM raw_file").fetchall()}
        assert rel_a["punch.csv"] != rel_b["punch.csv"]
    finally:
        conn_a.close()
        conn_b.close()

    assert manifest_a["inputs_digest"] == manifest_b["inputs_digest"]
    assert manifest_a["triple"]["input_fingerprint"] == \
        manifest_b["triple"]["input_fingerprint"]
    assert out_a.conclusion_digest == out_b.conclusion_digest
    assert manifest_a["evidence_digest"] == manifest_b["evidence_digest"]
    for doc in (inputs_a, inputs_b):
        for entry in doc["entries"]:
            assert set(entry) == {"rel_path", "kind", "sha256", "bytes", "row_count"}, entry
        assert all(int(entry["row_count"]) >= 0 for entry in doc["entries"])


def test_new_package_missing_evidence_digest_fails_closed(small_runs, tmp_path):
    _conn, _cfg, key, _first, first_manifest, _second, _second_manifest = small_runs
    src = Path(first_manifest["package_zip"])
    dst = tmp_path / "missing-evidence-digest.zip"

    def mutate(files):
        manifest = json.loads(files["manifest.json"])
        manifest.pop("evidence_digest", None)
        _resign(manifest, key)
        files["manifest.json"] = canonical_json(manifest).encode("utf-8")
        return files

    mutated = _rezip(src, dst, mutate)
    result = verify_package(mutated)
    assert result["checks"]["evidence"] == "FAIL", result
    assert result["reason"].startswith("EVIDENCE DIGEST FAIL"), result["reason"]


def test_removed_evidence_blocks_fail_while_conclusion_digest_stays(small_runs, tmp_path):
    _conn, _cfg, key, _first, first_manifest, _second, _second_manifest = small_runs
    src = Path(first_manifest["package_zip"])
    dst = tmp_path / "removed-evidence-column.zip"

    def mutate(files):
        text = files["findings.csv"].decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        fields = [name for name in rows[0].keys() if name != "evidence_json"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row[name] for name in fields})
        data = buf.getvalue().encode("utf-8")
        files["findings.csv"] = data

        manifest = json.loads(files["manifest.json"])
        manifest["artifact_sha256"]["findings.csv"] = sha256_hex(data)
        manifest["artifacts_digest"] = signing.artifact_digest(manifest["artifact_sha256"])
        _resign(manifest, key)
        files["manifest.json"] = canonical_json(manifest).encode("utf-8")
        return files

    mutated = _rezip(src, dst, mutate)
    result = verify_package(mutated)
    assert result["checks"]["findings"] == "OK", result
    assert result["checks"]["evidence"] == "FAIL", result
    assert result["reason"].startswith("EVIDENCE DIGEST FAIL"), result["reason"]


def test_old_producer_without_evidence_digest_is_not_checked(small_runs, tmp_path):
    _conn, _cfg, key, _first, first_manifest, _second, _second_manifest = small_runs
    src = Path(first_manifest["package_zip"])
    dst = tmp_path / "old-producer.zip"

    def mutate(files):
        manifest = json.loads(files["manifest.json"])
        manifest.pop("evidence_digest", None)
        # 修订前旧包可能没有 producer；既有分档把它当“无法核对版本”，而不是新包。
        manifest.pop("producer", None)
        _resign(manifest, key)
        files["manifest.json"] = canonical_json(manifest).encode("utf-8")
        return files

    mutated = _rezip(src, dst, mutate)
    result = verify_package(mutated)
    assert result["checks"]["evidence"] == "NOT CHECKED", result
    assert result["evidence_legacy"] is True
    assert "EVIDENCE DIGEST FAIL" not in result["reason"]
    assert result["partial"] is True


def test_old_package_without_evidence_digest_cannot_result_ok(small_runs, tmp_path):
    """旧包即使其余四项外部凭据齐全，也不能因 evidence NOT CHECKED 给 RESULT OK。"""
    _conn, _cfg, key, _first, first_manifest, _second, _second_manifest = small_runs
    src = Path(first_manifest["package_zip"])
    dst = tmp_path / "old-four-gates.zip"

    def mutate(files):
        manifest = json.loads(files["manifest.json"])
        manifest.pop("evidence_digest", None)
        manifest.pop("producer", None)
        _resign(manifest, key)
        files["manifest.json"] = canonical_json(manifest).encode("utf-8")
        return files

    mutated = _rezip(src, dst, mutate)
    manifest = json.loads(_zip_member(mutated, "manifest.json").decode("utf-8"))
    triple = manifest["triple"]
    anchor = ",".join(["3", triple["rule_pack_version"], triple["input_fingerprint"],
                       triple["conclusion_digest"]])
    result = verify_package(
        mutated,
        public_keys=[signing.public_key_b64(key.verify_key.encode())],
        expect_anchor=anchor,
        expect_package_sha256=sha256_hex(mutated.read_bytes()),
        expect_artifacts_digest=manifest["artifacts_digest"],
    )
    assert result["ok"] is False, result
    assert result["partial"] is True, result
    assert result["checks"]["evidence_digest_external"] == "NOT CHECKED"
    assert "外部 evidence_digest" in result["reason"]

