"""第九轮整改（0.4.7）：A5 包内主键、A4 展示层、A13 导入契约、zip 唯一名。

本文件先于实现落地，首轮运行应红；修复后应全绿。
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sqlite3
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import load_full_facts
from src import signing
from src.anomaly import build_anomalies
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file

ORG = [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""}]
EMP = [{
    "emp_id": "E-NEST", "pseudonym": "嵌套路径员工", "job_code": "assembly_line",
    "org_id": "ORG-A", "region_code": "440300", "worktime_regime": "standard",
    "contract_approved_flex": 0, "normal_hourly_cents": 3000,
}]
SCHEDULE = [{
    "emp_id": "E-NEST", "work_date": "2025-09-02",
    "planned_start": "2025-09-02T09:00:00+08:00",
    "planned_end": "2025-09-02T18:00:00+08:00", "rest_minutes": 60,
}]
IN_ROW = {"emp_id": "E-NEST", "event_ts": "2025-09-02T09:00:00+08:00",
          "punch_type": "in", "device_id": "DEV-NEST"}
OUT_ROW = {"emp_id": "E-NEST", "event_ts": "2025-09-02T18:00:00+08:00",
           "punch_type": "out", "device_id": "DEV-NEST"}


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _cfg(work: Path) -> Config:
    cfg = Config.load(
        env_path=work / "nonexistent.env",
        WCA_DB_BACKEND="sqlite", WCA_DB_PATH=str(work / "db.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(work / "db_target.json"),
        WCA_DATA_DIR=str(work / "data"), WCA_REPORTS_DIR=str(work / "reports"),
        WCA_PACKAGES_DIR=str(work / "packages"), WCA_USERS_PATH=str(work / "users.json"),
        WCA_UPLOAD_DIR=str(work / "uploads"), WCA_REGION_CODE="440300",
        WCA_RULE_PACK="rp-2026.11.gd-pilot-standard.v5",
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    cfg.ensure_dirs()
    return cfg


def _build_dup(work: Path) -> dict:
    """两个不同子目录各放一份同字节 punch，触发 QUAL-DUP。"""
    if work.exists():
        shutil.rmtree(work)
    cfg = _cfg(work)
    data = Path(cfg.data_dir)
    _write_csv(data / "org.csv", ORG)
    _write_csv(data / "employee.csv", EMP)
    _write_csv(data / "schedule.csv", SCHEDULE)
    _write_csv(data / "a" / "punch-a.csv", [IN_ROW, OUT_ROW])
    _write_csv(data / "b" / "punch-b.csv", [IN_ROW, OUT_ROW])
    conn = connect(cfg.db_path)
    init_db(conn)
    for rel, kind in (("org.csv", "org"), ("employee.csv", "employee"),
                      ("schedule.csv", "schedule"),
                      ("a/punch-a.csv", "punch"), ("b/punch-b.csv", "punch")):
        import_csv_file(conn, cfg, data / rel, kind=kind, rel_path=rel)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    return {"conn": conn, "cfg": cfg, "out": out,
            "key": signing.generate_keypair(), "data": data}


def _export(item: dict) -> dict:
    return export_package(item["conn"], item["cfg"], item["out"].run_id,
                          signing_key=item["key"])


def _csv_rows(blob: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(blob.decode("utf-8-sig"))))

FORBIDDEN_VALUES = ("file_id", "related_file_ids", "run_id", "segment_id")


def test_package_csvs_have_no_db_primary_key_values(tmp_path):
    """A5.3：包内任何 CSV 的数据值都不得出现 DB 主键标识。"""
    item = _build_dup(tmp_path / "dup")
    manifest = _export(item)
    path = Path(manifest["package_zip"])
    offenders = []
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".csv"):
                continue
            for row_no, row in enumerate(_csv_rows(zf.read(name)), 1):
                for cell in row:
                    for token in FORBIDDEN_VALUES:
                        if token in cell:
                            offenders.append((name, row_no, token, cell[:120]))
    assert not offenders, offenders


def test_quality_issue_detail_uses_rel_paths_only(tmp_path):
    """A5.1：多来源只渲染 rel_path:line_no，DB 内部 related_file_ids 仍在。"""
    item = _build_dup(tmp_path / "dup-detail")
    manifest = _export(item)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        text = zf.read("quality_issues.csv").decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    dup = [r for r in rows if "punch-a.csv" in r.get("detail", "")]
    assert dup, rows
    for r in dup:
        assert "related_file_ids" not in r["detail"]
        assert re.search(r"a/punch-a\.csv:\d+", r["detail"]), r["detail"]
        assert re.search(r"b/punch-b\.csv:\d+", r["detail"]), r["detail"]
    internal = item["conn"].execute(
        "SELECT detail FROM ingest_issue WHERE detail LIKE '%related_file_ids%' LIMIT 1"
    ).fetchone()
    assert internal and "related_file_ids" in internal["detail"]


def _decorate(row, file_map=None):
    import src.api  # noqa: F401  确保路由已注册
    from src.web.routes import _decorate_review_row
    return _decorate_review_row(row, file_map)


def test_review_row_falls_back_to_metric_line_refs():
    """A4.2：source_refs 为空时用 metric_json.line_refs，来源行不得为空。"""
    row = {
        "review_id": 1, "status": "OPEN", "source_type": "finding",
        "source_id": "QUAL-01:E-NEST:2025-09-02", "run_id": "r1",
        "severity": "VIOLATION", "emp_pseudonym": "员工", "emp_id": "E-NEST",
        "work_date": "2025-09-02", "period_key": None, "rule_id": "QUAL-01",
        "explanation": "", "citations": "[]",
        "source_refs": "[]",
        "metric_json": json.dumps({"line_refs": [
            {"rel_path": "schedule.csv", "line_no": 2}]}, ensure_ascii=False),
    }
    out = _decorate(row)
    assert out["line_refs"].strip()
    assert "schedule.csv:2" in out["line_refs"]
    assert "file_id" not in json.dumps(out, ensure_ascii=False)


def test_review_row_resolves_file_id_via_map():
    """A4.1：DB source_refs 只有 file_id 时，用 file_id→rel_path 映射还原。"""
    row = {
        "review_id": 2, "status": "OPEN", "source_type": "finding",
        "source_id": "QUAL-02:E-NEST:2025-09-02", "run_id": "r1",
        "severity": "REVIEW", "emp_pseudonym": "员工", "emp_id": "E-NEST",
        "work_date": "2025-09-02", "period_key": None, "rule_id": "QUAL-02",
        "explanation": "", "citations": "[]",
        "source_refs": json.dumps([{"file_id": 7, "line_no": 2}]),
        "metric_json": "{}",
    }
    out = _decorate(row, {7: "a/punch-a.csv"})
    assert out["line_refs"] == "a/punch-a.csv:2"
    assert "file_id" not in json.dumps(out, ensure_ascii=False)


def test_anomaly_items_fall_back_to_metric_line_refs(conn, cfg):
    """A4：首页异常数据的 source_refs 不得在该有值时为空。"""
    load_full_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30))
    items = build_anomalies(conn, out.run_id)
    for item in items:
        if not any(rid.startswith("QUAL-") for rid in item.rule_ids):
            continue
        for metric in item.metrics.values():
            if metric.get("line_refs"):
                assert item.source_refs, item.rule_ids


def test_api_import_response_has_no_file_id(tmp_path):
    """/api/import 响应不得回传 DB file_id。"""
    import src.api as api_mod
    from src.auth import hash_password
    from src.ingest import import_rows

    users = tmp_path / "users.json"
    users.write_text(json.dumps({
        "schema": "wca-users-v1",
        "users": [{"username": "op1", "emp_id": "E-NEST", "roles": ["OP", "EM"],
                   "pw_hash": hash_password("pw-op1-2025")}],
    }, ensure_ascii=False), encoding="utf-8")
    cfg = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="sqlite", WCA_DB_PATH=str(tmp_path / "api.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
        WCA_DATA_DIR=str(tmp_path / "data"), WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"), WCA_USERS_PATH=str(users),
        WCA_UPLOAD_DIR=str(tmp_path / "uploads"), WCA_REGION_CODE="440300",
        WCA_RULE_PACK="rp-2026.11.gd-pilot-standard.v5",
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    cfg.ensure_dirs()
    conn = connect(cfg.db_path)
    init_db(conn)
    import_rows(conn, cfg, "org", [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""}],
                rel_path="inline://api-org")
    import_rows(conn, cfg, "employee", [{
        "emp_id": "E-NEST", "pseudonym": "嵌套路径员工", "job_code": "assembly_line",
        "org_id": "ORG-A", "region_code": "440300", "worktime_regime": "standard",
        "contract_approved_flex": 0, "normal_hourly_cents": 3000,
    }], rel_path="inline://api-emp")
    conn.commit()

    from fastapi.testclient import TestClient
    client = TestClient(api_mod.create_app(cfg))
    login = client.post("/login", data={"username": "op1", "password": "pw-op1-2025"},
                        follow_redirects=True)
    assert login.status_code == 200
    match = re.search(r'name="csrf-token" content="([^"]+)"', login.text)
    assert match, "登录后的页面没有下发 CSRF token"
    token = match.group(1)
    text = "emp_id,event_ts,punch_type,device_id\n" + \
           "E-NEST,2025-09-02T09:00:00+08:00,in,DEV-NEST\n" + \
           "E-NEST,2025-09-02T18:00:00+08:00,out,DEV-NEST\n"
    res = client.post("/api/import", json={"filename": "punch.csv", "content": text,
                                          "kind": "punch"},
                      headers={"X-CSRF-Token": token})
    assert res.status_code == 200, res.text[:300]
    payload = res.json()
    assert "file_id" not in json.dumps(payload)
    assert payload["rel_path"] == "uploads/punch.csv"


def _env(tmp_path: Path, cfg: Config) -> Path:
    path = tmp_path / "round9.env"
    path.write_text("\n".join([
        "WCA_DB_BACKEND=sqlite", f"WCA_DB_PATH={cfg.db_path}",
        f"WCA_DB_IDENTITY_PATH={cfg.db_identity_path}",
        f"WCA_DATA_DIR={cfg.data_dir}", f"WCA_REPORTS_DIR={cfg.reports_dir}",
        f"WCA_PACKAGES_DIR={cfg.packages_dir}", f"WCA_USERS_PATH={cfg.users_path}",
        f"WCA_UPLOAD_DIR={cfg.upload_dir}", "WCA_REGION_CODE=440300",
        "WCA_RULE_PACK=rp-2026.11.gd-pilot-standard.v5",
        "WCA_LLM_PROVIDER=stub", "WCA_EMBEDDING_BACKEND=bm25",
    ]) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("bad", [
    "../outside/data", "C:\\outside\\data", "\\\\server\\share\\data", "data/../outside",
])
def test_ingest_rejects_non_contract_paths(conn, cfg, tmp_path, capsys, bad):
    """A13：cwd 外/绝对/UNC/含 .. 一律非零退出 + 中文错误。"""
    from src import cli
    env = _env(tmp_path, cfg)
    rc = cli.main(["--env", str(env), "ingest", "--dir", bad])
    err = capsys.readouterr().err
    assert rc != 0, (bad, rc)
    assert ("当前工作目录" in err) or ("不允许" in err), err
    assert conn.execute("SELECT COUNT(*) AS n FROM raw_file").fetchone()["n"] == 0


def test_zip_exports_are_unique_and_never_overwrite(tmp_path):
    """附带 3：同一 run 连续导出生成不同文件，旧包保留。"""
    item = _build_dup(tmp_path / "dup-zip")
    first = Path(_export(item)["package_zip"])
    second = Path(_export(item)["package_zip"])
    assert first != second
    assert first.exists() and second.exists()
    assert first.stat().st_size > 0 and second.stat().st_size > 0


def test_manifest_discloses_approval_export(tmp_path):
    """附带 2：审批台账为数据库重导出，manifest 必须披露。"""
    item = _build_dup(tmp_path / "dup-approval")
    manifest = _export(item)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        raw = json.loads(zf.read("manifest.json").decode("utf-8"))
    doc = raw.get("inputs", {}).get("approval_export") or {}
    assert doc.get("mode") == "db_export"
    assert doc.get("encoding") == "utf-8"
    assert doc.get("bom") is False
    assert doc.get("line_endings") == "LF"
    assert doc.get("original_bytes_retained") is False
