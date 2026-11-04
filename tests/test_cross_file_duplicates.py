"""第七轮：两个 punch CSV 含完全相同行时，导入顺序不得改变结论摘要。

构造：punch-a.csv = 重复的 in 行 + 唯一的 out 行；punch-b.csv = 同一 in 行。
a→b 与 b→a 两种导入顺序各建一个临时库、各导一个包，比较四联值与 QUAL-01 行引用。
"""
from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

from src import signing
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file

ORG = [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""}]
EMP = [{
    "emp_id": "E-DUP", "pseudonym": "重复行员工", "job_code": "assembly_line",
    "org_id": "ORG-A", "region_code": "440300", "worktime_regime": "standard",
    "contract_approved_flex": 0, "normal_hourly_cents": 3000,
}]
SCHEDULE = [{
    "emp_id": "E-DUP", "work_date": "2025-09-02",
    "planned_start": "2025-09-02T09:00:00+08:00",
    "planned_end": "2025-09-02T18:00:00+08:00", "rest_minutes": 60,
}]
DUP = {"emp_id": "E-DUP", "event_ts": "2025-09-02T09:00:00+08:00",
       "punch_type": "in", "device_id": "DEV-DUP"}
OUT = {"emp_id": "E-DUP", "event_ts": "2025-09-02T18:00:00+08:00",
       "punch_type": "out", "device_id": "DEV-DUP"}
FILES = {
    "org": "org.csv", "employee": "employee.csv", "schedule": "schedule.csv",
    "punch-a": "punch-a.csv", "punch-b": "punch-b.csv",
}


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build(work: Path, order: tuple[str, ...], *,
           punch_a: list[dict] | None = None, punch_b: list[dict] | None = None) -> dict:
    data = work / "data"
    data.mkdir(parents=True)
    _write_csv(data / "org.csv", ORG)
    _write_csv(data / "employee.csv", EMP)
    _write_csv(data / "schedule.csv", SCHEDULE)
    _write_csv(data / "punch-a.csv", punch_a if punch_a is not None else [DUP, OUT])
    _write_csv(data / "punch-b.csv", punch_b if punch_b is not None else [DUP])
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
        import_csv_file(conn, cfg, data / FILES[kind],
                        kind="punch" if kind.startswith("punch") else kind,
                        rel_path=FILES[kind])
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    manifest = export_package(conn, cfg, out.run_id, signing_key=signing.generate_keypair())
    return {"conn": conn, "out": out, "manifest": manifest}


def _punch_file_id(conn, rel_path: str) -> int:
    return int(conn.execute(
        "SELECT file_id FROM raw_file WHERE rel_path = ?", (rel_path,)
    ).fetchone()["file_id"])


def _dup_batches(out) -> list:
    return [finding for finding in out.findings
            if finding.rule_id == "QUAL-01" and "batch_id" in finding.metric]


def _quality_refs(out) -> list[list[dict]]:
    return [
        finding.metric.get("line_refs") or []
        for finding in _dup_batches(out)
    ]


def test_cross_file_duplicate_import_order_stable(tmp_path):
    a = _build(tmp_path / "a-then-b", ("org", "employee", "schedule", "punch-a", "punch-b"))
    b = _build(tmp_path / "b-then-a", ("org", "employee", "schedule", "punch-b", "punch-a"))
    try:
        # 两种顺序确实把同一个文件映射到不同 DB file_id。
        assert _punch_file_id(a["conn"], "punch-a.csv") != \
            _punch_file_id(b["conn"], "punch-a.csv")

        assert a["out"].conclusion_digest == b["out"].conclusion_digest
        assert a["manifest"]["triple"]["conclusion_digest"] == \
            b["manifest"]["triple"]["conclusion_digest"]
        assert a["manifest"]["evidence_digest"] == b["manifest"]["evidence_digest"]
        assert a["manifest"]["inputs_digest"] == b["manifest"]["inputs_digest"]
        assert a["manifest"]["triple"]["input_fingerprint"] == \
            b["manifest"]["triple"]["input_fingerprint"]

        batches_a = _dup_batches(a["out"])
        batches_b = _dup_batches(b["out"])
        assert len(batches_a) == len(batches_b) == 1
        assert batches_a[0].work_date == batches_a[0].period_key == "2025-09-02"
        assert batches_a[0].metric["batch_size"] == 1
        assert batches_a[0].metric["sources"] == [{"rel_path": "punch-a.csv", "line_no": 2}]
        assert batches_a[0].metric["batch_id"] == batches_b[0].metric["batch_id"]
        assert _quality_refs(a["out"]) == _quality_refs(b["out"]) == [
            [{"rel_path": "punch-a.csv", "line_no": 2}]]
        # 不能残留空日期汇总条。
        assert all(f.work_date and f.period_key
                   for f in a["out"].findings if f.rule_id == "QUAL-01")
    finally:
        a["conn"].close()
        b["conn"].close()


def test_cross_file_duplicate_aggregate_import_order_stable(tmp_path):
    """重复行超过汇总阈值（20）时，聚合路径也不得随导入顺序改变摘要。"""
    many = [{"emp_id": "E-DUP", "event_ts": f"2025-09-02T09:{i:02d}:00+08:00",
             "punch_type": "in", "device_id": "DEV-DUP"} for i in range(25)]
    rows = many + [OUT]
    a = _build(tmp_path / "a-then-b", ("org", "employee", "schedule", "punch-a", "punch-b"),
               punch_a=rows, punch_b=rows)
    b = _build(tmp_path / "b-then-a", ("org", "employee", "schedule", "punch-b", "punch-a"),
               punch_a=rows, punch_b=rows)
    try:
        assert _punch_file_id(a["conn"], "punch-a.csv") != \
            _punch_file_id(b["conn"], "punch-a.csv")
        assert a["out"].conclusion_digest == b["out"].conclusion_digest
        assert a["manifest"]["triple"]["conclusion_digest"] == \
            b["manifest"]["triple"]["conclusion_digest"]
        assert a["manifest"]["evidence_digest"] == b["manifest"]["evidence_digest"]
        assert a["manifest"]["inputs_digest"] == b["manifest"]["inputs_digest"]
        assert a["manifest"]["triple"]["input_fingerprint"] == \
            b["manifest"]["triple"]["input_fingerprint"]
        batches_a = _dup_batches(a["out"])
        batches_b = _dup_batches(b["out"])
        assert len(batches_a) == len(batches_b) == 1
        batch_a = batches_a[0]
        assert batch_a.metric["batch_size"] == 26
        assert len(batch_a.metric["sources"]) == 26
        assert batch_a.metric["batch_id"] == batches_b[0].metric["batch_id"]
        assert batch_a.work_date == batch_a.period_key == "2025-09-02"
        refs_a = _quality_refs(a["out"])
        refs_b = _quality_refs(b["out"])
        assert refs_a == refs_b
        assert len(refs_a[0]) == 26
        assert refs_a[0][0] == {"rel_path": "punch-a.csv", "line_no": 2}
    finally:
        a["conn"].close()
        b["conn"].close()
