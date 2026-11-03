"""旧审批台账迁移/对照工具测试（临时 SQLite，不碰活动库）。"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import load_base
from src.config import Config
from src.db_guard import validate_active_cutover
from src.engine import run_check
from src.rules.approval_migration import (ACTIVE_SQLITE_PATH, MigrationSafetyError,
                                          apply_migration, assert_connection_is_temporary,
                                          assert_no_widening, assert_temporary_database,
                                          compare_reg01, plan_migration)
from src.rules.rulepack import RULE_PACK_V5, RULE_PACK_V6

SHA_A = "a" * 64
SHA_B = "b" * 64
START = date(2025, 9, 1)
END = date(2025, 11, 30)


def _insert_legacy(conn, emp_id: str, doc_no: str, *, regime: str = "comprehensive_monthly",
                   valid_from: str = "2025-01-01", valid_to: str = "2025-12-31",
                   job_codes: str = '["warehouse_shift"]', region_code: str = "440300",
                   attachment_sha256: str = SHA_A,
                   recorded_at: str = "2025-01-02T00:00:00+08:00") -> None:
    conn.execute(
        "INSERT INTO worktime_approval(emp_id, doc_no, regime, valid_from, valid_to, "
        "job_codes, region_code, attachment_sha256, recorded_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (emp_id, doc_no, regime, valid_from, valid_to, job_codes, region_code,
         attachment_sha256, recorded_at))


def _insert_existing_doc(conn, doc_no: str, *, regime: str) -> None:
    conn.execute(
        "INSERT INTO approval_doc(doc_no, title, issuer, regime, status, current_version, "
        "created_at, updated_at, created_by, updated_by) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (doc_no, f"既有批文 {doc_no}", "p0-pilot", regime, "PUBLISHED", 1,
         "2025-01-01T00:00:00+08:00", "2025-01-01T00:00:00+08:00", "pilot", "pilot"))


def _table_counts(conn) -> dict[str, int]:
    return {
        table: int(conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])
        for table in ("approval_doc", "approval_doc_version", "approval_doc_scope",
                      "employee_approval_coverage")
    }


def _reg01_hits(out) -> set[str]:
    return {f.emp_id for f in out.findings if f.rule_id == "REG-01"}


@pytest.fixture
def migration_data(conn, cfg):
    """构造覆盖/丢弃/合并/既有文号四类旧台账，全部在临时库。"""
    load_base(conn, cfg)
    # 1) 合法覆盖：T-CMP 被 MIG-OK 覆盖
    _insert_legacy(conn, "T-CMP", "MIG-OK")
    # 2) 非法行：岗位范围为空、附件哈希缺失
    _insert_legacy(conn, "T-CMP", "MIG-BAD-JOB", job_codes="[]")
    _insert_legacy(conn, "T-NAPPR", "MIG-BAD-SHA", job_codes='["store_clerk"]',
                   attachment_sha256="")
    # 3) 同文号多工时制：保留 comprehensive_monthly，flexible 行丢弃
    _insert_legacy(conn, "T-CMP", "MIG-MULTI")
    _insert_legacy(conn, "T-NAPPR", "MIG-MULTI", regime="flexible",
                   job_codes='["store_clerk","warehouse_shift"]')
    # 4) 同文号同签名多员工：应合并为一个版本
    _insert_legacy(conn, "T-CMP", "MIG-MERGE", job_codes='["warehouse_shift"]')
    # 同签名第二行（T-NAPPR 岗位不在范围内，仅用于验证“合并”本身）
    _insert_legacy(conn, "T-NAPPR", "MIG-MERGE", job_codes='["warehouse_shift"]')
    # 5) 新表已有同文号：旧行必须丢弃，不能覆盖 P0 链
    _insert_existing_doc(conn, "MIG-EXISTING", regime="comprehensive_monthly")
    _insert_existing_doc(conn, "MIG-EXISTING-FLX", regime="flexible")
    _insert_legacy(conn, "T-NAPPR", "MIG-EXISTING", job_codes='["store_clerk"]')
    _insert_legacy(conn, "T-FLX", "MIG-EXISTING-FLX", regime="flexible",
                   job_codes='["senior_manager"]', attachment_sha256=SHA_B)
    return conn


def test_plan_is_read_only_and_explains_dropped_and_merged_rows(migration_data):
    conn = migration_data
    before = _table_counts(conn)
    plan = plan_migration(conn)
    after = _table_counts(conn)

    # dry-run 默认不写 P0 四表
    assert after == before
    assert plan.legacy_rows == 9
    assert plan.legacy_docs == 7
    assert plan.legacy_employee_ids == ["T-CMP", "T-FLX", "T-NAPPR"]
    assert len(plan.docs) == 3          # MIG-OK / MIG-MULTI / MIG-MERGE
    assert len(plan.versions) == 3
    assert len(plan.coverage) == 4      # T-CMP(MIG-OK) + T-CMP/T-NAPPR(MIG-MERGE) + ...
    assert plan.coverage_employee_ids == ["T-CMP", "T-NAPPR"]

    reasons = " | ".join(item["reason"] for item in plan.skipped)
    assert "审批岗位范围为空" in reasons
    assert "附件哈希缺失" in reasons
    assert "同文号存在多个工时制" in reasons
    assert "新表 approval_doc 已有文号 MIG-EXISTING" in reasons
    assert "新表 approval_doc 已有文号 MIG-EXISTING-FLX" in reasons
    assert len(plan.skipped) == 5
    assert len(plan.merged) == 1
    assert plan.merged[0]["doc_no"] == "MIG-MERGE"
    assert plan.merged[0]["employees"] == ["T-CMP", "T-NAPPR"]


def test_compare_reg01_marks_only_v6_when_migration_drops_covering_rows(migration_data):
    conn = migration_data
    plan = plan_migration(conn)
    reg01 = compare_reg01(conn, plan, START, END)
    # T-FLX / T-NAPPR 的既有文号行在 v5 能覆盖，迁移后丢弃 -> v6 更严格
    assert reg01["only_v5"] == []
    assert reg01["only_v6"] == ["T-FLX", "T-NAPPR"]
    assert reg01["legacy_employees_without_coverage"] == ["T-FLX"]
    assert reg01["v5_hits_count"] < reg01["v6_hits_count"]


def test_apply_writes_projection_and_v6_reg01_matches_prediction(migration_data, cfg):
    conn = migration_data
    plan = plan_migration(conn)
    before = _table_counts(conn)
    # fixture 先放了两份“既有批文”，迁移只能在它们之外新增
    assert before == {"approval_doc": 2, "approval_doc_version": 0,
                      "approval_doc_scope": 0, "employee_approval_coverage": 0}

    v5_out = run_check(conn, replace(cfg, rule_pack_id=RULE_PACK_V5),
                       start=START, end=END)
    v5_hits = _reg01_hits(v5_out)
    reg01_prediction = compare_reg01(conn, plan, START, END)
    assert v5_hits == set(reg01_prediction["v5_hits"])

    result = apply_migration(conn, replace(cfg, rule_pack_id=RULE_PACK_V5), plan)
    assert result["docs"] == 3
    assert result["versions"] == 3
    assert result["coverage"] == 4
    assert result["scopes"] == 4
    # 计划阶段已把“新表已有同文号”的旧行过滤成 skipped；apply 只做并发保护
    assert result["skipped_existing_docs"] == 0
    after = _table_counts(conn)
    assert after["approval_doc"] == before["approval_doc"] + 3
    assert after["approval_doc_version"] == 3
    assert after["approval_doc_scope"] == 4
    assert after["employee_approval_coverage"] == 4
    # 旧表必须保留，迁移不删除历史
    assert int(conn.execute("SELECT COUNT(*) AS c FROM worktime_approval")
               .fetchone()["c"]) == 9
    actions = [str(r["action"]) for r in conn.execute(
        "SELECT action FROM audit_event ORDER BY seq").fetchall()]
    assert "approval_doc.migrate" in actions

    v6_out = run_check(conn, replace(cfg, rule_pack_id=RULE_PACK_V6),
                       start=START, end=END)
    v6_hits = _reg01_hits(v6_out)
    assert v6_hits == set(reg01_prediction["v6_hits"])
    assert reg01_prediction["only_v5"] == []
    assert any("旧 worktime_approval 仍有" in w for w in v6_out.warnings)


def test_apply_is_idempotent(migration_data, cfg):
    conn = migration_data
    plan = plan_migration(conn)
    first = apply_migration(conn, replace(cfg, rule_pack_id=RULE_PACK_V5), plan)
    counts = _table_counts(conn)
    second = apply_migration(conn, replace(cfg, rule_pack_id=RULE_PACK_V5), plan)
    assert second["docs"] == 0
    assert second["versions"] == 0
    assert second["coverage"] == 0
    assert second["skipped_existing_docs"] == first["versions"]
    assert _table_counts(conn) == counts


def test_active_database_guard(tmp_path: Path, cfg: Config, monkeypatch):
    import src.db as db

    pg_active = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="postgres",
        WCA_DATABASE_URL="postgresql://root:local-pw@127.0.0.1:5927/wca_worktime",
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
    )
    with pytest.raises(MigrationSafetyError, match="wca_worktime"):
        assert_temporary_database(pg_active)

    identity = tmp_path / "db_target.json"
    identity.write_text(json.dumps({
        "schema": "wca-db-target-v1", "backend": "postgres",
        "host": "127.0.0.1", "port": 5927, "user": "root",
        "database": "wca_worktime",
    }), encoding="utf-8")
    pg_drill = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="postgres",
        WCA_DATABASE_URL="postgresql://root:local-pw@127.0.0.1:5927/wca_drill_v6_20261102",
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(identity),
    )
    assert_temporary_database(pg_drill)   # 临时演练库允许

    # 回归：provision=False 不得让 identity 把目标拉回活动库（首次 dry-run 事故边界）
    seen: dict[str, str] = {}

    def fake_connect(target):
        seen["url"] = target.database_url
        return object()

    monkeypatch.setattr(db, "_connect_postgres", fake_connect)
    db.connect(pg_drill, provision=False)
    assert pg_drill.database_url.endswith("/wca_drill_v6_20261102")
    assert seen["url"] == pg_drill.database_url

    with pytest.raises(MigrationSafetyError, match="活动 SQLite"):
        assert_temporary_database(replace(cfg, db_path=ACTIVE_SQLITE_PATH))
    assert_temporary_database(replace(cfg, db_path=tmp_path / "scratch.sqlite3"))


def test_connection_guard_rejects_actual_active_database(tmp_path: Path, monkeypatch):
    """配置写临时库、实际连接是活动库：连接后守卫必须拒绝（dry-run 也不许跑）。"""
    import src.cli as cli
    from src.config import Config

    class _Cursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchone(self):
            return self._rows[0] if self._rows else None

        def fetchall(self):
            return self._rows

    class _FakeConn:
        def __init__(self, dialect: str, rows):
            self.dialect = dialect
            self._rows = rows
            self.closed = False

        def execute(self, sql, params=None):
            if "current_database" in sql:
                return _Cursor(self._rows)
            if "PRAGMA database_list" in sql:
                return _Cursor(self._rows)
            raise AssertionError(f"守卫不应继续执行 SQL：{sql}")

        def close(self):
            self.closed = True

    cfg = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="postgres",
        WCA_DATABASE_URL="postgresql://root:local-pw@127.0.0.1:5927/wca_drill_guard",
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
    )
    with pytest.raises(MigrationSafetyError, match="活动库"):
        assert_connection_is_temporary(_FakeConn("postgres", [{"name": "wca_worktime"}]), cfg)

    fake = _FakeConn("postgres", [{"name": "wca_worktime"}])
    monkeypatch.setattr(cli, "connect", lambda target, provision=False: fake)
    monkeypatch.setattr(cli, "init_db", lambda conn: None)
    env = tmp_path / "guard.env"
    env.write_text("\n".join([
        "WCA_DB_BACKEND=postgres",
        "WCA_DATABASE_URL=postgresql://root:local-pw@127.0.0.1:5927/wca_drill_guard",
        f"WCA_DB_PATH={(tmp_path / 'unused.sqlite3').as_posix()}",
        f"WCA_DB_IDENTITY_PATH={(tmp_path / 'db_target.json').as_posix()}",
        f"WCA_DATA_DIR={(tmp_path / 'data').as_posix()}",
        f"WCA_REPORTS_DIR={(tmp_path / 'reports').as_posix()}",
        f"WCA_PACKAGES_DIR={(tmp_path / 'packages').as_posix()}",
        f"WCA_USERS_PATH={(tmp_path / 'users.json').as_posix()}",
        f"WCA_UPLOAD_DIR={(tmp_path / 'uploads').as_posix()}",
        "WCA_REGION_CODE=440300",
        "WCA_LLM_PROVIDER=stub",
        "WCA_EMBEDDING_BACKEND=bm25",
    ]) + "\n", encoding="utf-8")
    rc = cli.main(["--env", str(env), "approval-migrate", "--start", "2025-09-01",
                   "--end", "2025-09-30", "--report", str(tmp_path / "guard.json")])
    assert rc == 2
    assert fake.closed, "守卫拒绝后必须断开连接"
    assert not (tmp_path / "guard.json").exists(), "dry-run 也不得产出报告"

    fake_sqlite = _FakeConn("sqlite", [{"name": "main", "file": str(ACTIVE_SQLITE_PATH)}])
    sqlite_cfg = replace(cfg, db_backend="sqlite", db_path=ACTIVE_SQLITE_PATH)
    with pytest.raises(MigrationSafetyError, match="活动 SQLite"):
        assert_connection_is_temporary(fake_sqlite, sqlite_cfg)


def test_allow_active_guard_rejects_four_failure_paths_and_accepts_valid(tmp_path: Path):
    """allow-active 五个条件：备份缺失/校验失败/确认串不符/连错库拒绝，合法才放行。"""
    from src.util import sha256_hex

    backup = tmp_path / "wca_worktime_backup.dump"
    backup.write_bytes(b"fake-pg-dump-for-guard-test")
    digest = sha256_hex(backup.read_bytes())
    valid = validate_active_cutover(
        actual="wca_worktime", confirm_active="wca_worktime",
        backup_path=backup, backup_sha256=digest)
    assert valid == {"path": str(backup), "bytes": backup.stat().st_size, "sha256": digest}

    with pytest.raises(MigrationSafetyError, match="备份文件不存在"):
        validate_active_cutover(actual="wca_worktime", confirm_active="wca_worktime",
                                backup_path=tmp_path / "missing.dump",
                                backup_sha256=digest)
    with pytest.raises(MigrationSafetyError, match="备份校验失败"):
        validate_active_cutover(actual="wca_worktime", confirm_active="wca_worktime",
                                backup_path=backup, backup_sha256="0" * 64)
    with pytest.raises(MigrationSafetyError, match="不一致"):
        validate_active_cutover(actual="wca_worktime", confirm_active="wca_drill_x",
                                backup_path=backup, backup_sha256=digest)
    with pytest.raises(MigrationSafetyError, match="不是活动库"):
        validate_active_cutover(actual="wca_drill_x", confirm_active="wca_drill_x",
                                backup_path=backup, backup_sha256=digest)


def test_cli_allow_active_reaches_apply_only_with_all_confirmations(tmp_path: Path,
                                                                   monkeypatch):
    """allow-active 的允许路径：实际库名、确认串、备份哈希都对时才进入 apply。"""
    import src.cli as cli
    import src.rules.approval_migration as migration
    from src.rules.approval_migration import MigrationPlan
    from src.util import sha256_hex

    class _FakeConn:
        dialect = "postgres"
        closed = False

        def execute(self, sql, params=None):
            assert "current_database" in sql
            return type("C", (), {"fetchone": lambda self: {"name": "wca_worktime"}})()

        def close(self):
            self.closed = True

    backup = tmp_path / "backup.dump"
    backup.write_bytes(b"backup-bytes")
    digest = sha256_hex(backup.read_bytes())
    fake = _FakeConn()
    called: dict = {}

    monkeypatch.setattr(cli, "connect", lambda target, provision=False: fake)
    monkeypatch.setattr(cli, "init_db", lambda conn: None)
    monkeypatch.setattr(migration, "plan_migration", lambda conn: MigrationPlan())
    monkeypatch.setattr(migration, "build_report", lambda *a, **k: {
        "reg01": {"v5_hits_count": 0, "v6_hits_count": 0, "only_v5": [], "only_v6": []},
        "plan": {"legacy_rows": 1, "legacy_docs": 1, "skipped": [], "merged": []},
    })

    def fake_apply(conn, cfg, plan, *, actor="system:migration", allow_active=False):
        called["allow_active"] = allow_active
        return {"docs": 1, "versions": 1, "scopes": 1, "coverage": 1,
                "skipped_existing_docs": 0}

    monkeypatch.setattr(migration, "apply_migration", fake_apply)
    env = tmp_path / "active.env"
    env.write_text("\n".join([
        "WCA_DB_BACKEND=postgres",
        "WCA_DATABASE_URL=postgresql://root:local-pw@127.0.0.1:5927/wca_worktime",
        f"WCA_DB_PATH={(tmp_path / 'unused.sqlite3').as_posix()}",
        f"WCA_DB_IDENTITY_PATH={(tmp_path / 'db_target.json').as_posix()}",
        f"WCA_DATA_DIR={(tmp_path / 'data').as_posix()}",
        f"WCA_REPORTS_DIR={(tmp_path / 'reports').as_posix()}",
        f"WCA_PACKAGES_DIR={(tmp_path / 'packages').as_posix()}",
        f"WCA_USERS_PATH={(tmp_path / 'users.json').as_posix()}",
        f"WCA_UPLOAD_DIR={(tmp_path / 'uploads').as_posix()}",
        "WCA_REGION_CODE=440300", "WCA_LLM_PROVIDER=stub",
        "WCA_EMBEDDING_BACKEND=bm25",
    ]) + "\n", encoding="utf-8")
    rc = cli.main([
        "--env", str(env), "approval-migrate", "--apply", "--allow-active",
        "--confirm-apply", "wca_worktime", "--confirm-active", "wca_worktime",
        "--backup-path", str(backup), "--backup-sha256", digest,
        "--start", "2025-09-01", "--end", "2026-04-30",
        "--report", str(tmp_path / "active-report.json")])
    assert rc == 0
    assert called["allow_active"] is True
    assert fake.closed


def test_no_widening_guard_rejects_v6_broader_coverage():
    with pytest.raises(MigrationSafetyError, match="更宽松"):
        assert_no_widening({"only_v5": ["T-CMP"]})


def test_cli_dry_run_does_not_write(migration_data, cfg, tmp_path: Path, capsys):
    from src.cli import main

    conn = migration_data
    before = _table_counts(conn)
    env = tmp_path / "migration.env"
    env.write_text(
        "\n".join([
            "WCA_DB_BACKEND=sqlite",
            f"WCA_DB_PATH={cfg.db_path.as_posix()}",
            f"WCA_DB_IDENTITY_PATH={(tmp_path / 'db_target.json').as_posix()}",
            f"WCA_DATA_DIR={(tmp_path / 'data').as_posix()}",
            f"WCA_REPORTS_DIR={(tmp_path / 'reports').as_posix()}",
            f"WCA_PACKAGES_DIR={(tmp_path / 'packages').as_posix()}",
            f"WCA_USERS_PATH={(tmp_path / 'users.json').as_posix()}",
            f"WCA_UPLOAD_DIR={(tmp_path / 'uploads').as_posix()}",
            f"WCA_RULE_PACK={RULE_PACK_V5}",
            "WCA_REGION_CODE=440300",
            "WCA_LLM_PROVIDER=stub",
            "WCA_EMBEDDING_BACKEND=bm25",
            "WCA_SQLITE_SYNCHRONOUS=OFF",
        ]) + "\n", encoding="utf-8")
    report_path = tmp_path / "migration-report.json"
    rc = main(["--env", str(env), "approval-migrate", "--start", START.isoformat(),
               "--end", END.isoformat(), "--report", str(report_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "未写库" in out
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["mode"] == "dry-run"
    assert report["plan"]["legacy_rows"] == 9
    assert report["reg01"]["only_v5"] == []
    assert _table_counts(conn) == before

    # --apply 缺显式确认参数：必须拒绝，且不能产出/写任何东西
    apply_report = tmp_path / "must-not-exist.json"
    rc = main(["--env", str(env), "approval-migrate", "--apply",
               "--start", START.isoformat(), "--end", END.isoformat(),
               "--report", str(apply_report)])
    assert rc == 2
    assert "confirm-apply" in capsys.readouterr().err
    assert not apply_report.exists()
    assert _table_counts(conn) == before
