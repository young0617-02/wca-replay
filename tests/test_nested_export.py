"""0.4.6：嵌套 rel_path 的导出、验算对账与导入边界。

覆盖审计方 F1–F4 与第九轮 A1/A2/A13 的软件面：
* 单层/两层/空格/中文目录、同名不同目录、跨子目录重复行；
* 缺源文件失败关闭，不留半成品；
* `..` 与绝对路径在导入期拒绝；
* verify 对账“input_files.csv 有、inputs/ 少”。
"""
from __future__ import annotations

import csv
import io
import json
import shutil
import zipfile
from datetime import date
from pathlib import Path

import pytest

from src import signing
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.package_verify import verify_package
from src.replay import replay

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
    data = work / "data"
    cfg = Config.load(
        env_path=work / "nonexistent.env",
        WCA_DB_BACKEND="sqlite", WCA_DB_PATH=str(work / "db.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(work / "db_target.json"),
        WCA_DATA_DIR=str(data), WCA_REPORTS_DIR=str(work / "reports"),
        WCA_PACKAGES_DIR=str(work / "packages"), WCA_USERS_PATH=str(work / "users.json"),
        WCA_UPLOAD_DIR=str(work / "uploads"), WCA_REGION_CODE="440300",
        WCA_RULE_PACK="rp-2026.11.gd-pilot-standard.v5",
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    cfg.ensure_dirs()
    return cfg


def _build(work: Path, *, punch_rels=("2025-09/punch.csv",)):
    if work.exists():
        shutil.rmtree(work)
    cfg = _cfg(work)
    data = Path(cfg.data_dir)
    _write_csv(data / "org.csv", ORG)
    _write_csv(data / "employee.csv", EMP)
    _write_csv(data / "schedule.csv", SCHEDULE)
    for rel in punch_rels:
        _write_csv(data / rel, [IN_ROW, OUT_ROW])
    conn = connect(cfg.db_path)
    init_db(conn)
    order = [("org.csv", "org"), ("employee.csv", "employee"), ("schedule.csv", "schedule")]
    order += [(rel, "punch") for rel in punch_rels]
    for rel, kind in order:
        import_csv_file(conn, cfg, data / rel, kind=kind, rel_path=rel)
    out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    key = signing.generate_keypair()
    return {"conn": conn, "cfg": cfg, "out": out, "key": key, "data": data}


def _export(item):
    return export_package(item["conn"], item["cfg"], item["out"].run_id,
                          signing_key=item["key"])


def _zip_names(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as zf:
        return zf.namelist()


def _verify(item, zip_path: Path) -> dict:
    pub = signing.public_key_b64(item["key"].verify_key.encode())
    return verify_package(zip_path, public_keys=[pub])


@pytest.mark.parametrize("sub", ["a", "2025-09/门店A", "dir with space", "中文目录"])
def test_nested_export_verify_and_replay(tmp_path, sub):
    item = _build(tmp_path / "nested", punch_rels=(f"{sub}/punch.csv",))
    manifest = _export(item)
    names = _zip_names(Path(manifest["package_zip"]))
    assert f"inputs/{sub}/punch.csv" in names
    result = _verify(item, Path(manifest["package_zip"]))
    assert result["checks"].get("inputs_completeness") == "OK", result["reason"]
    assert result["checks"]["inputs"] == "OK", result["reason"]
    rp = replay(Path(manifest["package_zip"]))
    assert rp["ok"], rp.get("reason")
    item["conn"].close()


def test_same_name_in_two_subdirs_not_overwritten(tmp_path):
    item = _build(tmp_path / "same-name", punch_rels=("a/punch.csv", "b/punch.csv"))
    manifest = _export(item)
    names = _zip_names(Path(manifest["package_zip"]))
    assert "inputs/a/punch.csv" in names and "inputs/b/punch.csv" in names
    item["conn"].close()


def test_cross_subdir_duplicate_order_stable(tmp_path):
    builds = []
    for tag, order in (("a-then-b", "a"), ("b-then-a", "b")):
        work = tmp_path / tag
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
        base = [("org.csv", "org"), ("employee.csv", "employee"), ("schedule.csv", "schedule")]
        punch = [("a/punch-a.csv", "punch"), ("b/punch-b.csv", "punch")]
        if order == "b":
            punch.reverse()
        for rel, kind in base + punch:
            import_csv_file(conn, cfg, data / rel, kind=kind, rel_path=rel)
        out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
        key = signing.generate_keypair()
        manifest = export_package(conn, cfg, out.run_id, signing_key=key)
        builds.append({"conn": conn, "out": out, "manifest": manifest})
    try:
        a, b = builds
        assert a["manifest"]["triple"]["conclusion_digest"] == \
            b["manifest"]["triple"]["conclusion_digest"]
        assert a["manifest"]["evidence_digest"] == b["manifest"]["evidence_digest"]
        assert a["manifest"]["inputs_digest"] == b["manifest"]["inputs_digest"]
        assert a["manifest"]["triple"]["input_fingerprint"] == \
            b["manifest"]["triple"]["input_fingerprint"]
        for item in builds:
            names = _zip_names(Path(item["manifest"]["package_zip"]))
            assert "inputs/a/punch-a.csv" in names
            assert "inputs/b/punch-b.csv" in names
    finally:
        for item in builds:
            item["conn"].close()


@pytest.mark.parametrize("rel", ["a/../punch.csv", "../punch.csv", "/abs/punch.csv",
                                 "C:/abs/punch.csv"])
def test_import_rejects_bad_rel_path(tmp_path, rel):
    work = tmp_path / "bad"
    cfg = _cfg(work)
    source = Path(cfg.data_dir) / "punch.csv"
    _write_csv(source, [IN_ROW, OUT_ROW])
    conn = connect(cfg.db_path)
    init_db(conn)
    try:
        with pytest.raises(ValueError, match="rel_path"):
            import_csv_file(conn, cfg, source, kind="punch", rel_path=rel)
    finally:
        conn.close()


def test_missing_input_fails_closed_without_zip(tmp_path):
    item = _build(tmp_path / "missing")
    (item["data"] / "2025-09" / "punch.csv").unlink()
    with pytest.raises(ValueError, match="拒绝生成残缺包"):
        _export(item)
    assert not any(Path(item["cfg"].packages_dir).glob("*.zip"))
    work = Path(item["cfg"].packages_dir) / item["out"].run_id
    assert not work.exists(), "失败后不得留下暂存目录"
    item["conn"].close()


def test_reexport_self_heals_nested_inputs_dir(tmp_path):
    item = _build(tmp_path / "heal")
    first = _export(item)
    work = Path(item["cfg"].packages_dir) / item["out"].run_id
    stale = work / "inputs" / "stale" / "dir"
    stale.mkdir(parents=True)
    (stale / "junk.txt").write_text("junk", encoding="utf-8")
    second = _export(item)
    assert Path(second["package_zip"]).is_file()
    assert Path(first["package_zip"]).is_file()
    item["conn"].close()


def _rezip_without(src: Path, dst: Path, member: str) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist() if name != member}
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


def test_package_confidence_uses_current_version(tmp_path):
    from src import ENGINE_VERSION
    item = _build(tmp_path / "confidence")
    manifest = _export(item)
    with zipfile.ZipFile(Path(manifest["package_zip"])) as zf:
        text = zf.read("policies/CONFIDENCE.md").decode("utf-8")
    assert f"本轮 {ENGINE_VERSION} 测试与干净环境验证" in text
    assert "0.4.2" not in text
    assert "{{ENGINE_VERSION}}" not in text
    item["conn"].close()


def test_verify_detects_missing_input_member(tmp_path):
    item = _build(tmp_path / "verify-missing", punch_rels=("a/punch.csv",))
    manifest = _export(item)
    broken = _rezip_without(Path(manifest["package_zip"]),
                            tmp_path / "broken.zip", "inputs/a/punch.csv")
    result = _verify(item, broken)
    assert result["checks"].get("inputs_completeness") == "FAIL", result
    assert "INPUTS COMPLETENESS FAIL" in result["reason"]
    assert "缺少 1 个" in result["reason"]
    item["conn"].close()
