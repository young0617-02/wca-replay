"""PostgreSQL 18 真实集成用例（默认跳过，需显式提供维护库连接）。

启用方式（口令只在本地环境变量/.env，不写进仓库）：

    $env:WCA_TEST_POSTGRES_URL = "postgresql://root:<本地口令>@127.0.0.1:5927/postgres"
    uv run python -m pytest tests/test_postgres_integration.py -q

每个用例创建独立的 `wca_test_<随机后缀>` 数据库，结束后删除；不会碰已有项目库。
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
import uuid
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

from conftest import load_full_facts, ORGS, EMPLOYEES, punch
from src.auth import User
from src.config import Config
from src.db import (DB_BACKEND_POSTGRES, DB_BACKEND_SQLITE, check_database_identity,
                    connect, ensure_database, get_meta, init_db, is_postgres, transaction)
from src.engine import run_check
from src.evidence import ExportBusyError, export_package, verify_chain
from src.ingest import import_csv_file, import_rows
from src.replay import replay
from src.rules.approval_docs import create_draft, publish_doc
from src.rules.approvals import upsert_approval
from src.rules.rulepack import RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6

TEST_URL = os.environ.get("WCA_TEST_POSTGRES_URL", "")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not TEST_URL,
                       reason="未设置 WCA_TEST_POSTGRES_URL（需要 PostgreSQL 18 维护库连接）"),
]


def _with_database(url: str, dbname: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{dbname}", parts.query, parts.fragment))


def _database_name(url: str) -> str:
    name = urlsplit(url).path.lstrip("/")
    if not name:
        raise ValueError("测试连接串必须带维护库名（建议 /postgres）")
    return name


def _admin_url(url: str) -> str:
    return _with_database(url, "postgres")


def _drop_database(url: str) -> None:
    import psycopg

    name = _database_name(url)
    with psycopg.connect(_admin_url(url), autocommit=True) as conn:
        conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()", (name,))
        conn.execute(f'DROP DATABASE IF EXISTS "{name}"')


def _admin_exec(url: str, statement: str, params: tuple = ()) -> None:
    import psycopg

    with psycopg.connect(_admin_url(url), autocommit=True) as conn:
        conn.execute(statement, params)


def _exec_on(url: str, statement: str, params: tuple = ()) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(statement, params)


@pytest.fixture
def pg(tmp_path: Path):
    base = f"wca_test_{uuid.uuid4().hex[:10]}"
    url = _with_database(TEST_URL, base)
    cfg = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
        WCA_DATABASE_URL=url,
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
        WCA_DATA_DIR=str(tmp_path / "data"),
        WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"),
        WCA_USERS_PATH=str(tmp_path / "users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
        WCA_REGION_CODE="440300",
        WCA_LLM_PROVIDER="stub",
        WCA_EMBEDDING_BACKEND="bm25",
    )
    chosen = ensure_database(cfg)
    assert chosen
    conn = connect(cfg)
    init_db(conn)
    try:
        yield cfg, conn
    finally:
        conn.close()
        _drop_database(cfg.database_url)


def test_postgres_empty_database_initialises_idempotently(pg):
    cfg, conn = pg
    assert is_postgres(conn)
    assert get_meta(conn, "schema_version") == "1"
    # 再跑两次不能重复建表/重复写 meta，也不能因 identity 列报错
    init_db(conn)
    init_db(conn)
    assert get_meta(conn, "schema_version") == "1"
    assert check_database_identity(conn) is True
    # 迭代开发：同一个项目库必须继续复用，不能每次启动又新建一个
    chosen = _database_name(cfg.database_url)
    assert ensure_database(cfg) == chosen


def test_existing_foreign_database_gets_a_suffix(tmp_path: Path):
    """目标库名被别的项目占用时：加后缀新建，原库一行不动。"""
    base = f"wca_test_occupied_{uuid.uuid4().hex[:8]}"
    url = _with_database(TEST_URL, base)
    _admin_exec(url, f'CREATE DATABASE "{base}"')
    foreign_url = _with_database(url, base)
    _exec_on(foreign_url, "CREATE TABLE public.foreign_table(id INTEGER PRIMARY KEY)")
    try:
        cfg = Config.load(
            env_path=tmp_path / "nonexistent.env",
            WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
            WCA_DATABASE_URL=url,
            WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
            WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
            WCA_DATA_DIR=str(tmp_path / "data"),
            WCA_REPORTS_DIR=str(tmp_path / "reports"),
            WCA_PACKAGES_DIR=str(tmp_path / "packages"),
            WCA_USERS_PATH=str(tmp_path / "users.json"),
            WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
            WCA_REGION_CODE="440300", WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        )
        chosen = ensure_database(cfg)
        assert chosen != base and chosen.startswith(base + "_")
        # 原库仍是别人的形状：没有本项目表，foreign_table 还在
        import psycopg
        with psycopg.connect(foreign_url, autocommit=True) as conn:
            assert conn.execute(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name='foreign_table'").fetchone()[0] == 1
            assert conn.execute(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name IN ('meta','raw_file')").fetchone()[0] == 0
        conn = connect(cfg)
        init_db(conn)
        assert check_database_identity(conn)
        conn.close()
        _drop_database(cfg.database_url)
    finally:
        _drop_database(foreign_url)


def test_postgres_idempotent_import_and_duplicate_punch(pg):
    cfg, conn = pg
    import_rows(conn, cfg, "org", ORGS, rel_path="inline://pg-org")
    import_rows(conn, cfg, "employee", EMPLOYEES, rel_path="inline://pg-emp")
    rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T19:00:00+08:00", "out")]

    first = import_rows(conn, cfg, "punch", rows, rel_path="inline://pg-punch")
    assert first.rows_accepted == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM raw_file WHERE rel_path = ?",
                        ("inline://pg-punch",)).fetchone()["c"] == 1
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2

    second = import_rows(conn, cfg, "punch", rows, rel_path="inline://pg-punch")
    assert second.rows_accepted == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM raw_file WHERE rel_path = ?",
                        ("inline://pg-punch",)).fetchone()["c"] == 1, \
        "同一文件重导必须复用 file_id，不能重复登记"
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2, \
        "同文件重导会先清派生行再重插，事实条数必须不变"

    # 换一个文件名重传同一批打卡：文件级幂等键不同，但内容唯一索引必须挡住第二份事实
    copy = import_rows(conn, cfg, "punch", rows, rel_path="inline://pg-punch-copy")
    assert copy.rows_accepted == 2
    assert conn.execute("SELECT COUNT(*) AS c FROM raw_file WHERE rel_path = ?",
                        ("inline://pg-punch-copy",)).fetchone()["c"] == 1
    assert conn.execute("SELECT COUNT(*) AS c FROM punch").fetchone()["c"] == 2, \
        "按内容唯一索引必须挡住跨文件/重传的重复打卡"
    assert conn.execute("SELECT COUNT(*) AS c FROM ingest_issue WHERE rule_id = 'QUAL-DUP'"
                        ).fetchone()["c"] >= 2


if TEST_URL:
    def test_postgres_copy_within_file_duplicate_is_rejected(pg, tmp_path):
        """COPY 路径的文件内重复行也必须按“首次保留、后续拒收”处理，且与 single 同三元组。"""
        import csv
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        path = cfg.data_dir / "dup.csv"
        row = punch("T-STD", "2025-09-02T09:00:00+08:00", "in")
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(row.keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows([row, dict(row)])

        copy_res = import_csv_file(conn, replace(cfg, import_write_mode="copy"), path,
                                   kind="punch", rel_path="dup.csv")
        assert (copy_res.rows_seen, copy_res.rows_accepted, copy_res.rows_rejected) == (2, 1, 1)
        assert any(i.rule_id == "QUAL-DUP" and i.field_name == "*" for i in copy_res.issues)
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 1
        first = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                          notes="copy within-file dup")

        single_res = import_csv_file(conn, replace(cfg, import_write_mode="single"), path,
                                     kind="punch", rel_path="dup.csv")
        assert (single_res.rows_seen, single_res.rows_accepted, single_res.rows_rejected) == (2, 1, 1)
        second = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                           notes="single within-file dup")
        assert first.input_fingerprint == second.input_fingerprint
        assert first.conclusion_digest == second.conclusion_digest
        assert len(first.findings) == len(second.findings)


def test_postgres_transaction_rolls_back(pg):
    cfg, conn = pg
    with pytest.raises(RuntimeError):
        with transaction(conn):
            conn.execute("INSERT INTO meta(key, value) VALUES(%s, %s)", ("tx-probe", "1"))
            raise RuntimeError("强制回滚")
    assert conn.execute("SELECT 1 FROM meta WHERE key = %s", ("tx-probe",)).fetchone() is None


def test_postgres_and_sqlite_produce_same_conclusion_digest(tmp_path):
    """同一批事实在两种后端上跑校验，三元组中的结论摘要必须逐字节一致。"""
    pg_cfg = Config.load(
        env_path=tmp_path / "none-pg.env",
        WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
        WCA_DATABASE_URL=_with_database(TEST_URL, f"wca_test_{uuid.uuid4().hex[:10]}"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "pg_target.json"),
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
        WCA_DATA_DIR=str(tmp_path / "pg-data"),
        WCA_REPORTS_DIR=str(tmp_path / "pg-reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "pg-packages"),
        WCA_USERS_PATH=str(tmp_path / "pg-users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "pg-uploads"),
        WCA_REGION_CODE="440300", WCA_RULE_PACK=RULE_PACK_V4,
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
    )
    ensure_database(pg_cfg)
    pg_conn = connect(pg_cfg)
    init_db(pg_conn)

    sqlite_cfg = Config.load(
        env_path=tmp_path / "none-sqlite.env",
        WCA_DB_BACKEND=DB_BACKEND_SQLITE,
        WCA_DB_PATH=str(tmp_path / "baseline.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "sqlite_target.json"),
        WCA_DATA_DIR=str(tmp_path / "sqlite-data"),
        WCA_REPORTS_DIR=str(tmp_path / "sqlite-reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "sqlite-packages"),
        WCA_USERS_PATH=str(tmp_path / "sqlite-users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "sqlite-uploads"),
        WCA_REGION_CODE="440300", WCA_RULE_PACK=RULE_PACK_V4,
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    sqlite_conn = connect(sqlite_cfg)
    init_db(sqlite_conn)
    try:
        load_full_facts(pg_conn, pg_cfg)
        load_full_facts(sqlite_conn, sqlite_cfg)
        pg_out = run_check(pg_conn, pg_cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                           notes="pg equivalence")
        sq_out = run_check(sqlite_conn, sqlite_cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                           notes="pg equivalence")
        assert pg_out.conclusion_digest == sq_out.conclusion_digest
        assert pg_out.counts == sq_out.counts
        assert len(pg_out.findings) == len(sq_out.findings)
        assert pg_out.input_fingerprint == sq_out.input_fingerprint
    finally:
        pg_conn.close()
        sqlite_conn.close()
        _drop_database(pg_cfg.database_url)


def test_postgres_epoch_transition_preserves_v4_chain(pg):
    """PG 单库切换：旧 v4 genesis 不变，v5 新段可验证，旧 v4 链仍可验证。"""
    cfg5, conn = pg
    cfg4 = replace(cfg5, rule_pack_id=RULE_PACK_V4)
    load_full_facts(conn, cfg4)
    run_check(conn, cfg4, start=date(2025, 9, 1), end=date(2025, 9, 30), notes="pg v4")
    old_genesis = get_meta(conn, "audit_genesis")
    out = run_check(conn, cfg5, start=date(2025, 9, 1), end=date(2025, 9, 30), notes="pg v5")
    assert out.run_id
    assert get_meta(conn, "audit_genesis") == old_genesis
    epoch = conn.execute(
        "SELECT epoch_id, prev_rule_pack_version, segment_start_prev_hash "
        "FROM rule_pack_epoch WHERE rule_pack_version = ?", (RULE_PACK_V5,)).fetchone()
    assert epoch is not None and epoch["prev_rule_pack_version"] == RULE_PACK_V4
    assert verify_chain(conn, cfg4).ok, "旧 v4 段仍须独立验证"
    assert verify_chain(conn, cfg5).ok, "v5 新段 + 旧段须组合验证"


def test_postgres_v5_and_sqlite_produce_same_conclusion_digest(tmp_path):
    """v5 四条新规则也必须双后端同摘要；两侧审批台账都为空，按“未覆盖”一致处理。"""
    pg_cfg = Config.load(
        env_path=tmp_path / "none-pg.env",
        WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
        WCA_DATABASE_URL=_with_database(TEST_URL, f"wca_test_{uuid.uuid4().hex[:10]}"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "pg_target.json"),
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
        WCA_DATA_DIR=str(tmp_path / "pg-data"),
        WCA_REPORTS_DIR=str(tmp_path / "pg-reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "pg-packages"),
        WCA_USERS_PATH=str(tmp_path / "pg-users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "pg-uploads"),
        WCA_REGION_CODE="440300", WCA_RULE_PACK=RULE_PACK_V5,
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
    )
    ensure_database(pg_cfg)
    pg_conn = connect(pg_cfg)
    init_db(pg_conn)

    sqlite_cfg = Config.load(
        env_path=tmp_path / "none-sqlite.env",
        WCA_DB_BACKEND=DB_BACKEND_SQLITE,
        WCA_DB_PATH=str(tmp_path / "baseline-v5.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "sqlite_target.json"),
        WCA_DATA_DIR=str(tmp_path / "sqlite-data"),
        WCA_REPORTS_DIR=str(tmp_path / "sqlite-reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "sqlite-packages"),
        WCA_USERS_PATH=str(tmp_path / "sqlite-users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "sqlite-uploads"),
        WCA_REGION_CODE="440300", WCA_RULE_PACK=RULE_PACK_V5,
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )
    sqlite_conn = connect(sqlite_cfg)
    init_db(sqlite_conn)
    try:
        load_full_facts(pg_conn, pg_cfg)
        load_full_facts(sqlite_conn, sqlite_cfg)
        approval = {
            "emp_id": "T-CMP", "doc_no": "深人社函〔2025〕PG-001号",
            "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
            "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
            "region_code": "440300", "attachment_sha256": "e" * 64,
            "recorded_at": "2025-01-02T00:00:00+08:00",
        }
        upsert_approval(pg_conn, approval)
        upsert_approval(sqlite_conn, approval)
        pg_out = run_check(pg_conn, pg_cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                           notes="pg v5 equivalence")
        sq_out = run_check(sqlite_conn, sqlite_cfg, start=date(2025, 9, 1),
                           end=date(2025, 11, 30), notes="pg v5 equivalence")
        assert pg_out.conclusion_digest == sq_out.conclusion_digest
        assert pg_out.input_fingerprint == sq_out.input_fingerprint
        assert pg_out.counts == sq_out.counts
        assert {"COMP-C01", "REG-01"} <= {f.rule_id for f in pg_out.findings}
        assert not any(f.rule_id == "REG-01" and f.emp_id == "T-CMP"
                       for f in pg_out.findings), "有效台账应消掉 T-CMP 的 REG-01"
    finally:
        pg_conn.close()
        sqlite_conn.close()
        _drop_database(pg_cfg.database_url)

if TEST_URL:
    def test_postgres_v6_self_contained_package(pg, tmp_path):
        """PG 上 v6：check → 自含 export → 独立 replay → verify.py，全链路一致。"""
        cfg, conn = pg
        cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
        cfg6 = replace(cfg, rule_pack_id=RULE_PACK_V6)
        cfg6.ensure_dirs()
        cfg6.data_dir.mkdir(parents=True, exist_ok=True)
        for name, kind, rows in (("org.csv", "org", ORGS), ("employee.csv", "employee", EMPLOYEES)):
            path = cfg6.data_dir / name
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            import_csv_file(conn, cfg6, path, kind=kind, rel_path=name)

        t0 = time.perf_counter()
        run_check(conn, cfg5, start=date(2025, 9, 2), end=date(2025, 9, 2), notes="pg v5 base")
        ad = User("ad-pg-v6", "T-STD", ("AD",), "ORG-A", "440300", "管理员")
        create_draft(
            conn, cfg6, ad, doc_no="PG-V6-DOC", title="PG v6 批文", issuer="人社局",
            regime="comprehensive_monthly", version_no=1,
            valid_from="2025-01-01", valid_to="2025-12-31",
            job_codes='["warehouse_shift"]', region_code="440300",
            attachment_sha256="a" * 64, scopes=[("employee", "T-CMP")])
        publish_doc(conn, cfg6, ad, "PG-V6-DOC")
        check_ms = round((time.perf_counter() - t0) * 1000, 1)
        out = run_check(conn, cfg6, start=date(2025, 9, 2), end=date(2025, 9, 2),
                        notes="pg v6 package")
        t1 = time.perf_counter()
        manifest = export_package(conn, cfg6, out.run_id)
        export_ms = round((time.perf_counter() - t1) * 1000, 1)
        package = Path(manifest["package_zip"])
        package_bytes = package.stat().st_size
        inputs_bytes = int(manifest["inputs"]["total_bytes"])
        assert manifest["inputs"]["approval_source"] == "v6-coverage"
        assert manifest["triple"]["rule_pack_version"] == RULE_PACK_V6

        res = replay(package)
        assert res["ok"], res["reason"]
        assert res["actual_triple"] == res["expected_triple"]
        assert res["findings_actual"] == res["findings_expected"]

        extracted = tmp_path / "pg-v6-verify"
        extracted.mkdir()
        with zipfile.ZipFile(package) as zf:
            zf.extractall(extracted)
        proc = subprocess.run([sys.executable, "verify.py"], cwd=extracted,
                              capture_output=True, text=True, encoding="utf-8", timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert "EPOCH OK" in proc.stdout
        assert "CHAIN OK" in proc.stdout
        assert "INPUTS OK" in proc.stdout and "missing_at_export= 0" in proc.stdout
        print(f"V6_PG inputs_bytes={inputs_bytes} package_bytes={package_bytes} "
              f"check_ms={check_ms} export_ms={export_ms} findings={len(out.findings)}")

if TEST_URL:
    def test_postgres_punch_executemany_and_copy_have_same_rows_and_triple(pg, tmp_path):
        """executemany 与 COPY 在同一 punch 文件上必须得到相同行数/指纹/结论。"""
        import csv
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch, schedule

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        rows_by_name = {
            "org.csv": ("org", ORGS),
            "employee.csv": ("employee", EMPLOYEES),
            "schedule.csv": ("schedule", [
                schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
                         "2025-09-02T19:00:00+08:00")]),
            "punch.csv": ("punch", [
                punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                punch("T-STD", "2025-09-02T19:00:00+08:00", "out")]),
        }
        for name, (_kind, data) in rows_by_name.items():
            path = cfg.data_dir / name
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
        for name in ("org.csv", "employee.csv", "schedule.csv"):
            import_csv_file(conn, cfg, cfg.data_dir / name, kind=rows_by_name[name][0],
                            rel_path=name)
        punch_csv = cfg.data_dir / "punch.csv"
        cfg_exec = replace(cfg, import_write_mode="executemany", import_batch_size=500)
        import_csv_file(conn, cfg_exec, punch_csv, kind="punch", rel_path="punch.csv")
        first = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                          notes="pg import executemany")
        counts1 = {t: int(conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"])
                   for t in ("employee", "punch", "shift_plan", "raw_file")}
        cfg_copy = replace(cfg, import_write_mode="copy")
        import_csv_file(conn, cfg_copy, punch_csv, kind="punch", rel_path="punch.csv")
        second = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                           notes="pg import copy")
        counts2 = {t: int(conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"])
                   for t in ("employee", "punch", "shift_plan", "raw_file")}
        assert counts1 == counts2 == {"employee": 6, "punch": 2, "shift_plan": 1,
                                      "raw_file": 4}
        assert first.input_fingerprint == second.input_fingerprint
        assert first.conclusion_digest == second.conclusion_digest
        assert len(first.findings) == len(second.findings)
        print(f"IMPORT_AB rows={counts1} fingerprint={first.input_fingerprint[:16]} "
              f"digest={first.conclusion_digest[:16]} findings={len(first.findings)}")

if TEST_URL:
    def test_postgres_import_temp_tables_are_cleaned(pg, tmp_path):
        """导入结束后 punch_stage / punch_seen / punch_seen_stage 不得残留。"""
        import csv
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        path = cfg.data_dir / "punch.csv"
        rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                punch("T-STD", "2025-09-02T18:00:00+08:00", "out")]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import_csv_file(conn, replace(cfg, import_write_mode="copy"), path,
                        kind="punch", rel_path="punch.csv")
        leftovers = conn.execute(
            "SELECT relname FROM pg_class WHERE relname IN "
            "('punch_stage','punch_seen','punch_seen_stage')").fetchall()
        assert not leftovers, leftovers

if TEST_URL:
    def test_postgres_copy_chunk_sizes_keep_same_triple(pg, tmp_path, caplog):
        """COPY 分块 1 / 5 / 大于总行数 / 超上限截断：行数与三元组必须一致。"""
        import csv
        import logging
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch
        from src.ingest import MAX_IMPORT_CHUNK_ROWS

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)

        rows = [punch("T-STD", f"2025-09-02T08:{i:02d}:00+08:00",
                      "in" if i % 2 == 0 else "out") for i in range(12)]
        path = cfg.data_dir / "punch.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

        triples = []
        for chunk in (1, 5, 20):
            cfg_copy = replace(cfg, import_write_mode="copy", import_batch_size=chunk)
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="src.ingest"):
                res = import_csv_file(conn, cfg_copy, path, kind="punch", rel_path="punch.csv")
            assert res.requested_write_mode == "copy"
            assert res.write_mode == "copy"
            assert res.degraded_from == ""
            assert res.chunk_rows == chunk
            assert res.rows_seen == res.rows_accepted == len(rows)
            assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == len(rows)
            out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                            notes=f"copy chunk {chunk}")
            triples.append((out.input_fingerprint, out.conclusion_digest, len(out.findings)))

        capped = replace(cfg, import_write_mode="copy",
                         import_batch_size=MAX_IMPORT_CHUNK_ROWS * 5)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="src.ingest"):
            res = import_csv_file(conn, capped, path, kind="punch", rel_path="punch.csv")
        assert res.chunk_rows == MAX_IMPORT_CHUNK_ROWS
        cap_logs = [r.getMessage() for r in caplog.records
                    if r.name == "src.ingest" and "超过分块上限" in r.getMessage()]
        assert len(cap_logs) == 1, cap_logs
        out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                        notes="copy chunk capped")
        triples.append((out.input_fingerprint, out.conclusion_digest, len(out.findings)))
        assert len(set(triples)) == 1, triples

if TEST_URL:
    def test_postgres_import_crash_rolls_back_raw_file_and_retry_matches(pg, tmp_path, monkeypatch):
        """COPY flush 后异常：punch/raw_file 必须一起回滚；重跑结果与正常导入一致。"""
        import csv
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch, schedule
        import src.ingest as ingest

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        rows_by_name = {
            "org.csv": ("org", ORGS),
            "employee.csv": ("employee", EMPLOYEES),
            "schedule.csv": ("schedule", [
                schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
                         "2025-09-02T19:00:00+08:00")]),
            # 故意放一条同时点、同类型、不同设备的打卡：OFF-01 的 metric 会写入
            # source file_id，用以验证回滚后重跑时 file_id 也必须稳定，摘要才不会漂移。
            "punch.csv": ("punch", [
                punch("T-STD", "2025-09-02T09:00:00+08:00", "in", "DEV-1"),
                punch("T-STD", "2025-09-02T19:00:00+08:00", "out", "DEV-1"),
                punch("T-STD", "2025-09-02T19:00:00+08:00", "out", "DEV-2")]),
        }
        for name, (_kind, data) in rows_by_name.items():
            path = cfg.data_dir / name
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
        for name in ("org.csv", "employee.csv", "schedule.csv"):
            import_csv_file(conn, cfg, cfg.data_dir / name, kind=rows_by_name[name][0],
                            rel_path=name)
        punch_csv = cfg.data_dir / "punch.csv"
        cfg_copy = replace(cfg, import_write_mode="copy")
        expected = import_csv_file(conn, cfg_copy, punch_csv, kind="punch",
                                   rel_path="punch.csv")
        expected_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                                 notes="pg crash expected")
        expected_file_id = expected.file_id
        file_id = int(conn.execute("SELECT file_id FROM raw_file WHERE rel_path = ?",
                                   ("punch.csv",)).fetchone()["file_id"])
        conn.execute("DELETE FROM punch WHERE source_file_id = ?", (file_id,))
        conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM raw_file WHERE file_id = ?", (file_id,))
        before_raw = int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"])

        original = ingest._write_punch_bulk

        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated crash after punch_stage flush")

        monkeypatch.setattr(ingest, "_write_punch_bulk", crash)
        with pytest.raises(RuntimeError, match="simulated crash"):
            import_csv_file(conn, cfg_copy, punch_csv, kind="punch", rel_path="punch.csv")
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 0
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw
        assert int(conn.execute(
            "SELECT COUNT(*) c FROM pg_class WHERE relname = 'punch_stage'").fetchone()["c"]) == 0
        monkeypatch.setattr(ingest, "_write_punch_bulk", original)
        retry = import_csv_file(conn, cfg_copy, punch_csv, kind="punch", rel_path="punch.csv")
        assert retry.reimported is False
        assert retry.file_id == expected_file_id, "回滚后重跑必须复用原来的 raw_file 主键"
        retry_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                              notes="pg crash retry")
        assert retry_out.input_fingerprint == expected_out.input_fingerprint
        assert retry_out.conclusion_digest == expected_out.conclusion_digest
        assert len(retry_out.findings) == len(expected_out.findings)
        assert retry_out.counts == expected_out.counts
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 3
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw + 1

    def test_postgres_first_v5_import_after_v4_chain_rolls_back_on_audit_failure(
            pg, tmp_path, monkeypatch):
        """v4 链切换到 v5 后的首次导入：epoch 创建必须在导入事务之外。

        否则 `ensure_audit_epoch` 会在导入事务内再开一个事务并 COMMIT，把 punch /
        raw_file 提前提交；之后即使抛异常，外层 ROLLBACK 也撤不回来。
        """
        import csv
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch
        import src.ingest as ingest

        cfg, conn = pg
        cfg4 = replace(cfg, rule_pack_id=RULE_PACK_V4)
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg4, p, kind=name.split(".")[0], rel_path=name)
        before_raw = int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"])

        rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in")]
        path = cfg.data_dir / "punch.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)

        original = ingest.append_audit

        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated crash after first v5 audit append")

        monkeypatch.setattr(ingest, "append_audit", crash)
        with pytest.raises(RuntimeError, match="simulated crash"):
            import_csv_file(conn, cfg5, path, kind="punch", rel_path="punch.csv")
        monkeypatch.setattr(ingest, "append_audit", original)
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 0
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw
        assert conn.execute(
            "SELECT COUNT(*) c FROM rule_pack_epoch WHERE rule_pack_version = ?",
            (RULE_PACK_V5,)).fetchone()["c"] == 0, "失败的首次切包不应留下 epoch"
        assert verify_chain(conn, cfg4).ok, "失败后仍应停留在可验证的 v4 链"

        retry = import_csv_file(conn, cfg5, path, kind="punch", rel_path="punch.csv")
        assert retry.rows_accepted == 1
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 1
        assert conn.execute(
            "SELECT COUNT(*) c FROM rule_pack_epoch WHERE rule_pack_version = ?",
            (RULE_PACK_V5,)).fetchone()["c"] == 1
        assert verify_chain(conn, cfg5).ok, "重跑成功后 v4/v5 组合链必须可验证"

    @pytest.mark.parametrize("failure", ["copy_disconnect", "bad_field_count"])
    def test_postgres_copy_midstream_failure_rolls_back_and_retry_matches(
            pg, tmp_path, monkeypatch, failure):
        """COPY 中途断连 / 字段数非法：punch、raw_file、stage 全部回滚，重跑三元组一致。"""
        import csv
        import psycopg
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch
        import src.ingest as ingest

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        rows = [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T12:00:00+08:00", "out"),
            punch("T-STD", "2025-09-02T13:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T18:00:00+08:00", "out"),
        ]
        path = cfg.data_dir / "punch.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

        cfg_copy = replace(cfg, import_write_mode="copy")
        expected = import_csv_file(conn, cfg_copy, path, kind="punch", rel_path="punch.csv")
        expected_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                                 notes=f"copy failure expected {failure}")
        file_id = int(conn.execute("SELECT file_id FROM raw_file WHERE rel_path = ?",
                                   ("punch.csv",)).fetchone()["file_id"])
        conn.execute("DELETE FROM punch WHERE source_file_id = ?", (file_id,))
        conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM raw_file WHERE file_id = ?", (file_id,))
        before_raw = int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"])

        cols = ", ".join(ingest._PUNCH_STAGE_COLUMNS)
        original = ingest._write_punch_bulk

        def partial(c, mode, batch, params):
            cursor = c.raw.cursor()
            try:
                with cursor.copy(f"COPY {ingest._PUNCH_STAGE}({cols}) FROM STDIN") as copy:
                    if failure == "copy_disconnect":
                        for row in params[:max(1, len(params) // 2)]:
                            copy.write_row(row)
                        raise psycopg.OperationalError("simulated COPY disconnect")
                    copy.write_row(params[0])
                    copy.write_row(tuple(params[0][:-1]))  # 字段数少一列
            finally:
                cursor.close()

        monkeypatch.setattr(ingest, "_write_punch_bulk", partial)
        with pytest.raises(Exception):
            import_csv_file(conn, cfg_copy, path, kind="punch", rel_path="punch.csv")
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 0
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw
        assert int(conn.execute("SELECT COUNT(*) c FROM ingest_issue").fetchone()["c"]) == 0
        assert int(conn.execute(
            "SELECT COUNT(*) c FROM pg_class WHERE relname = 'punch_stage'").fetchone()["c"]) == 0
        monkeypatch.setattr(ingest, "_write_punch_bulk", original)

        retry = import_csv_file(conn, cfg_copy, path, kind="punch", rel_path="punch.csv")
        assert retry.reimported is False
        assert retry.file_id == expected.file_id == file_id
        assert retry.rows_accepted == len(rows)
        retry_out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                              notes=f"copy failure retry {failure}")
        assert retry_out.input_fingerprint == expected_out.input_fingerprint
        assert retry_out.conclusion_digest == expected_out.conclusion_digest
        assert len(retry_out.findings) == len(expected_out.findings)
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == before_raw + 1

    def test_postgres_concurrent_agent_answers_serialize_audit(pg, tmp_path, monkeypatch):
        """agent 真实问答路径：两个并发 append 不得抢 audit_event 主键。"""
        import threading
        from conftest import load_base
        import src.agent as agent_module
        from src.agent import ComplianceAgent

        cfg, conn = pg
        load_base(conn, cfg)
        before_audit = int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])
        before_questions = int(conn.execute(
            "SELECT COUNT(*) c FROM question_log").fetchone()["c"])

        barrier = threading.Barrier(2)
        original = agent_module.append_audit

        def synchronized(c, *args, **kwargs):
            barrier.wait(timeout=10)
            return original(c, *args, **kwargs)

        monkeypatch.setattr(agent_module, "append_audit", synchronized)
        errors: list[str] = []
        answers = []

        def worker() -> None:
            c = connect(cfg, provision=False)
            try:
                answers.append(ComplianceAgent(c, cfg).ask(
                    "我 2025-09 加班多少小时", actor_emp_id="T-STD"))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, errors
        assert len(answers) == 2
        assert (int(conn.execute("SELECT COUNT(*) c FROM question_log").fetchone()["c"])
                == before_questions + 2)
        assert (int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])
                == before_audit + 2)
        assert verify_chain(conn, cfg).ok, "并发 agent 问答后审计链必须仍可验证"

    def test_postgres_same_run_concurrent_export_yields_one_complete_package(pg, tmp_path):
        """同一 run 并发导出：一个成功、一个明确“正在导出”；最终只有一个完整可验证包。"""
        import csv
        import threading
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        path = cfg.data_dir / "punch.csv"
        rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                punch("T-STD", "2025-09-02T18:00:00+08:00", "out")]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import_csv_file(conn, cfg, path, kind="punch", rel_path="punch.csv")
        out = run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                        notes="same run export")

        start = threading.Barrier(2)
        errors: list[str] = []
        successes = []
        busy: list[str] = []

        def worker() -> None:
            c = connect(cfg, provision=False)
            try:
                start.wait(timeout=10)
                successes.append(export_package(c, cfg, out.run_id))
            except ExportBusyError as exc:
                busy.append(str(exc))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors
        assert len(successes) == 1, (len(successes), busy)
        assert len(busy) == 1 and "正在导出" in busy[0], busy
        manifest = successes[0]
        package = Path(manifest["package_zip"])
        assert package.is_file() and zipfile.ZipFile(package).testzip() is None
        run_row = conn.execute("SELECT input_fingerprint, conclusion_digest FROM run "
                               "WHERE run_id = ?", (out.run_id,)).fetchone()
        assert manifest["triple"]["input_fingerprint"] == run_row["input_fingerprint"]
        assert manifest["triple"]["conclusion_digest"] == run_row["conclusion_digest"]
        assert int(manifest["counts"]["findings"]) == len(out.findings)

        extracted = tmp_path / "same-run-export"
        extracted.mkdir()
        with zipfile.ZipFile(package) as zf:
            zf.extractall(extracted)
        proc = subprocess.run([sys.executable, "verify.py"], cwd=extracted,
                              capture_output=True, text=True, encoding="utf-8", timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert "CHAIN OK" in proc.stdout
        assert "INPUTS OK" in proc.stdout and "missing_at_export= 0" in proc.stdout

    def test_postgres_concurrent_exports_serialize_audit(pg, tmp_path, monkeypatch):
        """export 真实导出路径：两个并发包登记 + append 不得冲突，链仍可验证。"""
        import csv
        import threading
        from conftest import EMPLOYEES, ORGS, punch
        import src.evidence as evidence_module
        from src.evidence import export_package

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        path = cfg.data_dir / "punch.csv"
        rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                punch("T-STD", "2025-09-02T18:00:00+08:00", "out")]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import_csv_file(conn, cfg, path, kind="punch", rel_path="punch.csv")
        runs = [run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                          notes=f"export setup {i}") for i in range(2)]
        before_audit = int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])
        before_packages = int(conn.execute(
            "SELECT COUNT(*) c FROM evidence_package").fetchone()["c"])

        barrier = threading.Barrier(2)
        original = evidence_module.append_audit

        def synchronized(c, *args, **kwargs):
            barrier.wait(timeout=10)
            return original(c, *args, **kwargs)

        monkeypatch.setattr(evidence_module, "append_audit", synchronized)
        errors: list[str] = []
        manifests = []

        def worker(run_id: str) -> None:
            c = connect(cfg, provision=False)
            try:
                manifests.append(export_package(c, cfg, run_id))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                c.close()

        threads = [threading.Thread(target=worker, args=(r.run_id,)) for r in runs]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors
        assert len(manifests) == 2
        assert (int(conn.execute("SELECT COUNT(*) c FROM evidence_package").fetchone()["c"])
                == before_packages + 2)
        assert (int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])
                == before_audit + 2)
        assert verify_chain(conn, cfg).ok, "并发导出后审计链必须仍可验证"

    def test_postgres_concurrent_checks_serialize_audit(pg, tmp_path):
        """两个并发 run_check：不得出现 audit_event 主键冲突，链仍可验证。"""
        import csv
        import threading
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        rows = [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T18:00:00+08:00", "out"),
        ]
        path = cfg.data_dir / "punch.csv"
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        import_csv_file(conn, cfg, path, kind="punch", rel_path="punch.csv")
        before_run = int(conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"])
        before_audit = int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])

        start = threading.Barrier(2)
        errors: list[str] = []
        outcomes = []

        def worker() -> None:
            c = connect(cfg, provision=False)
            try:
                start.wait(timeout=10)
                outcomes.append(run_check(c, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2),
                                          notes="concurrent check"))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, errors
        assert len(outcomes) == 2
        assert len({o.run_id for o in outcomes}) == 2
        assert int(conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"]) == before_run + 2
        assert (int(conn.execute("SELECT COUNT(*) c FROM audit_event").fetchone()["c"])
                == before_audit + 2)
        assert verify_chain(conn, cfg).ok, "并发 check 后审计链必须仍可验证"

    def test_postgres_same_file_concurrent_import_serializes(pg, tmp_path):
        """两个连接同文件并发：advisory lock 串行化，不抛 UniqueViolation，结果不翻倍。"""
        import csv
        import threading
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        path = cfg.data_dir / "punch.csv"
        rows = [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                punch("T-STD", "2025-09-02T19:00:00+08:00", "out")]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)
        cfg_copy = replace(cfg, import_write_mode="copy")
        barrier = threading.Barrier(2)
        errors: list[str] = []
        results = []

        def worker():
            c = connect(cfg, provision=False)
            try:
                barrier.wait(timeout=10)
                results.append(import_csv_file(c, cfg_copy, path, kind="punch",
                                               rel_path="punch.csv"))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                c.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, errors
        assert len(results) == 2
        assert sorted(r.reimported for r in results) == [False, True]
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 2
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == 3
        assert int(conn.execute(
            "SELECT COUNT(*) c FROM pg_class WHERE relname = 'punch_stage'").fetchone()["c"]) == 0
        assert verify_chain(conn, cfg).ok, "并发导入后审计链必须仍可验证"

    def test_postgres_different_file_concurrent_imports_get_distinct_file_ids(pg, tmp_path):
        """不同文件并发导入：raw_file 主键分配必须无冲突、无重复、无异常。

        这条钉住「按 MAX(file_id)+1 显式分配」的并发安全：两个事务同时读到同一个
        下一个 id 时，冲突的一方必须能重试拿到下一个 id，而不是抛 UniqueViolation。
        """
        import csv
        import threading
        from dataclasses import replace
        from conftest import EMPLOYEES, ORGS, punch

        cfg, conn = pg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("org.csv", ORGS), ("employee.csv", EMPLOYEES)):
            p = cfg.data_dir / name
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerows(data)
            import_csv_file(conn, cfg, p, kind=name.split(".")[0], rel_path=name)

        files = {}
        for rel, row in (
            ("punch-a.csv", punch("T-STD", "2025-09-02T09:00:00+08:00", "in")),
            ("punch-b.csv", punch("T-STD", "2025-09-02T19:00:00+08:00", "out")),
        ):
            p = cfg.data_dir / rel
            with p.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(row.keys()), lineterminator="\n")
                writer.writeheader()
                writer.writerow(row)
            files[rel] = p

        cfg_copy = replace(cfg, import_write_mode="copy")
        barrier = threading.Barrier(2)
        errors: list[str] = []
        results = []
        threads = []

        def worker(rel: str, path: Path) -> None:
            c = connect(cfg, provision=False)
            try:
                barrier.wait(timeout=10)
                results.append(import_csv_file(c, cfg_copy, path, kind="punch", rel_path=rel))
            except Exception as exc:
                errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            finally:
                c.close()

        for rel, path in files.items():
            t = threading.Thread(target=worker, args=(rel, path))
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, errors
        assert len(results) == 2
        assert all(r.reimported is False for r in results)
        assert len({r.file_id for r in results}) == 2, "两个文件必须拿到不同的 file_id"
        assert int(conn.execute("SELECT COUNT(*) c FROM raw_file").fetchone()["c"]) == 4
        assert int(conn.execute("SELECT COUNT(*) c FROM punch").fetchone()["c"]) == 2
        assert verify_chain(conn, cfg).ok, "不同文件并发导入后审计链必须仍可验证"

if TEST_URL:
    def test_postgres_report_cli_rc0_and_rows_match_anomalies(pg, tmp_path):
        """PG 方言回归：report 必须 rc=0，CSV 行数与 AnomalyItem 一致，rule_hit_counts 可执行。"""
        from conftest import load_full_facts
        from src import cli
        from src.anomaly import HEADER, build_anomalies, rule_hit_counts

        cfg, conn = pg
        load_full_facts(conn, cfg)
        out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                        notes="pg report regression")
        env = tmp_path / "report.env"
        env.write_text("\n".join([
            "WCA_DB_BACKEND=postgres",
            f"WCA_DATABASE_URL={cfg.database_url}",
            f"WCA_DB_IDENTITY_PATH={cfg.db_identity_path}",
            f"WCA_DB_PATH={cfg.db_path}",
            f"WCA_DATA_DIR={cfg.data_dir}",
            f"WCA_REPORTS_DIR={cfg.reports_dir}",
            f"WCA_PACKAGES_DIR={cfg.packages_dir}",
            f"WCA_USERS_PATH={cfg.users_path}",
            f"WCA_UPLOAD_DIR={cfg.upload_dir}",
            "WCA_REGION_CODE=440300",
            f"WCA_RULE_PACK={cfg.rule_pack_id}",
            "WCA_LLM_PROVIDER=stub",
            "WCA_EMBEDDING_BACKEND=bm25",
            "WCA_SQLITE_SYNCHRONOUS=OFF",
        ]) + "\n", encoding="utf-8")

        rc = cli.main(["--env", str(env), "report"])
        assert rc == 0
        report = Path(cfg.reports_dir) / f"异常报表-{out.run_id}.csv"
        assert report.is_file()
        with report.open("r", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == HEADER
        assert len(rows) == len(build_anomalies(conn, out.run_id)) + 1
        hits = rule_hit_counts(conn, out.run_id)
        assert sum(r["count"] for r in hits) == len(out.findings)
