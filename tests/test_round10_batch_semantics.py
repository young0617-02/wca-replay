"""0.4.8 批次语义验收：单批 finding、内容派生 batch_id、计数口径与空日期消失。"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

from src import signing
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.quality_batch import batch_id_from_sources

ROOT = Path(__file__).resolve().parent.parent

ORG = [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""}]
EMP = [{
    "emp_id": "E-BATCH", "pseudonym": "批次员工", "job_code": "assembly_line",
    "org_id": "ORG-A", "region_code": "440300", "worktime_regime": "standard",
    "contract_approved_flex": 0, "normal_hourly_cents": 3000,
}]
SCHEDULE = [{
    "emp_id": "E-BATCH", "work_date": "2025-09-01",
    "planned_start": "2025-09-01T09:00:00+08:00",
    "planned_end": "2025-09-01T18:00:00+08:00", "rest_minutes": 60,
}]
DUP = {"emp_id": "E-BATCH", "event_ts": "2025-09-01T09:00:00+08:00",
       "punch_type": "in", "device_id": "DEV-BATCH"}
OUT = {"emp_id": "E-BATCH", "event_ts": "2025-09-01T18:00:00+08:00",
       "punch_type": "out", "device_id": "DEV-BATCH"}
# 1 条首次出现 + 49 条文件内重复 + 1 条下班卡。
ROWS_49 = [DUP] * 50 + [OUT]


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build(work: Path, order=("org", "employee", "schedule", "punch")) -> dict:
    data = work / "data"
    data.mkdir(parents=True)
    _write_csv(data / "org.csv", ORG)
    _write_csv(data / "employee.csv", EMP)
    _write_csv(data / "schedule.csv", SCHEDULE)
    _write_csv(data / "punch.csv", ROWS_49)
    cfg = Config.load(
        env_path=work / "nonexistent.env",
        WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(work / "db.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(work / "db_target.json"),
        WCA_DATA_DIR=str(data),
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
    for kind in order:
        import_csv_file(conn, cfg, data / f"{kind}.csv", kind=kind,
                        rel_path=f"{kind}.csv")
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 1))
    manifest = export_package(conn, cfg, out.run_id, signing_key=signing.generate_keypair())
    return {"conn": conn, "cfg": cfg, "out": out, "manifest": manifest}


def _zip_text(manifest: dict, name: str) -> str:
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        return zf.read(name).decode("utf-8-sig")


def _expected_batch_id(sources: list[dict]) -> str:
    """独立复算：与 src 实现无关，只按报告里的四步规范重算。"""
    lines = sorted({f"{item['rel_path']}:{item['line_no']}" for item in sources},
                   key=lambda text: text.encode("utf-8"))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def test_single_batch_finding_shape_with_49_sources(tmp_path):
    built = _build(tmp_path / "one-db")
    try:
        out = built["out"]
        assert len(out.findings) == 1, [f.rule_id for f in out.findings]
        finding = out.findings[0]
        assert finding.rule_id == "QUAL-01"
        assert finding.work_date == finding.period_key == "2025-09-01"
        metric = finding.metric
        assert metric["batch_size"] == 49
        assert len(metric["sources"]) == 49
        assert metric["sources"][0] == {"rel_path": "punch.csv", "line_no": 3}
        assert metric["sources"][-1] == {"rel_path": "punch.csv", "line_no": 51}
        assert metric["batch_id"] == _expected_batch_id(metric["sources"])
        # 0.4.9：被保留的首行（punch.csv 第 2 行）只进 evidence，可定位；
        # 不得进入 canonical 九字段。
        assert finding.evidence == {"retained_refs": ["punch.csv:2"]}
        assert "retained_refs" not in finding.canonical()
        assert "retained_refs" not in finding.canonical()["metric"]
        # 没有任何空 work_date / period_key 的汇总条。
        assert all(f.work_date and f.period_key for f in out.findings)
    finally:
        built["conn"].close()


def test_quality_issues_csv_has_one_batch_row_listing_all_sources(tmp_path):
    built = _build(tmp_path / "one-db")
    try:
        text = _zip_text(built["manifest"], "quality_issues.csv")
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        dup_rows = [row for row in rows if row["rule_id"] == "QUAL-DUP"]
        assert len(dup_rows) == 1
        detail = dup_rows[0]["detail"]
        assert "batch_size=49" in detail
        for line_no in range(3, 52):
            assert f"punch.csv:{line_no}" in detail
        assert "file_id" not in text and "related_file_ids" not in text
    finally:
        built["conn"].close()


def test_batch_id_identical_across_reimport_reverse_order_and_hash_seed(tmp_path):
    a = _build(tmp_path / "first")
    b = _build(tmp_path / "reimport")
    c = _build(tmp_path / "reverse", order=("org", "employee", "punch", "schedule"))
    try:
        files = (a, b, c)
        ids = [item["out"].findings[0].metric["batch_id"] for item in files]
        assert len(set(ids)) == 1, ids
        digests = {item["manifest"]["triple"]["conclusion_digest"] for item in files}
        assert len(digests) == 1
        fingerprints = {item["manifest"]["triple"]["input_fingerprint"] for item in files}
        assert len(fingerprints) == 1

        # 不同进程 + 不同 PYTHONHASHSEED：证明不依赖哈希随机化或机器状态。
        snippet = (
            "import json,sys\n"
            "from src.quality_batch import batch_id_from_sources\n"
            "sources=json.loads(sys.argv[1])\n"
            "print(batch_id_from_sources(sources))\n"
        )
        sources = a["out"].findings[0].metric["sources"]
        outputs = set()
        for seed in ("0", "12345"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            proc = subprocess.run(
                [sys.executable, "-c", snippet, json.dumps(sources)],
                cwd=ROOT, env=env, capture_output=True, text=True, check=True)
            outputs.add(proc.stdout.strip())
        assert outputs == {ids[0]}, outputs
    finally:
        for item in (a, b, c):
            item["conn"].close()


def test_counts_three_places_agree_after_batching(tmp_path):
    built = _build(tmp_path / "one-db")
    try:
        manifest = built["manifest"]
        counts = manifest["counts"]
        assert counts["findings_total"] == 1
        assert counts["findings_batched"] == 1
        assert counts["issues_total"] == 49
        assert counts["quality_issues"] == 1

        confidence = _zip_text(manifest, "policies/CONFIDENCE.md")
        not_covered = _zip_text(manifest, "未覆盖清单.md")
        assert "- 发现（未签认）：1 条" in confidence
        assert "- 其中批次 finding：1 条" in confidence
        assert "- 按问题条数计：49 条" in confidence
        assert "发现（未签认）1 条 / 已确认结论 0 条" in not_covered
        assert "批次 finding 1 条，按问题条数计 49 条" in not_covered
    finally:
        built["conn"].close()


def test_batch_id_format_is_documented_and_order_insensitive():
    sources = [{"rel_path": "b/punch.csv", "line_no": 7},
               {"rel_path": "a/punch.csv", "line_no": 2},
               {"rel_path": "a/punch.csv", "line_no": 10}]
    expected = _expected_batch_id(sources)
    assert batch_id_from_sources(sources) == expected
    assert batch_id_from_sources(list(reversed(sources))) == expected
    assert batch_id_from_sources(sources + sources) == expected
    changed = [dict(item) for item in sources]
    changed[0]["line_no"] = 8
    assert batch_id_from_sources(changed) != expected
