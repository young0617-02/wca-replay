"""数据库身份不符必须硬失败：不得自动改写配置 URL，不得回落到 identity 指向的库。

覆盖：
  * 配置 URL 指向 A、identity 指向 B：connect / ingest / check / export 全部拒绝，且不建连、不建库、不改 identity；
  * host/port/user 任一不符、identity 文件损坏（含 BOM）也拒绝；
  * 只有显式 `db-target --reset --confirm A` 之后才允许切到 A；
  * 既有 db_guard 的临时库白名单与活动库拒绝不变。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import cli
import src.db as db
from src.config import Config
from src.db import (DatabaseIdentityMismatch, connect, ensure_database,
                    reset_database_identity)
from src.db_guard import MigrationSafetyError, assert_temporary_database

SECRET = "wca-identity-secret-never-echo"
SCHEMA = "wca-db-target-v1"


def _identity_file(tmp_path: Path, database: str, **overrides) -> Path:
    payload = {
        "schema": SCHEMA, "backend": "postgres", "host": "127.0.0.1",
        "port": 5927, "user": "root", "database": database,
    }
    payload.update(overrides)
    path = tmp_path / "db_target.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _cfg(tmp_path: Path, configured: str, identity: str = "B", **overrides) -> Config:
    identity_path = _identity_file(tmp_path, identity,
                                   **{k: overrides.pop(k) for k in list(overrides)
                                      if k in {"host", "port", "user", "backend"}})
    values = {
        "WCA_DB_BACKEND": "postgres",
        "WCA_DATABASE_URL": f"postgresql://root:{SECRET}@127.0.0.1:5927/{configured}",
        "WCA_DB_IDENTITY_PATH": str(identity_path),
        "WCA_DB_PATH": str(tmp_path / "unused.sqlite3"),
        "WCA_DATA_DIR": str(tmp_path / "data"),
        "WCA_REPORTS_DIR": str(tmp_path / "reports"),
        "WCA_PACKAGES_DIR": str(tmp_path / "packages"),
        "WCA_USERS_PATH": str(tmp_path / "users.json"),
        "WCA_UPLOAD_DIR": str(tmp_path / "uploads"),
        "WCA_REGION_CODE": "440300",
        "WCA_RULE_PACK": "rp-2026.11.gd-pilot-standard.v5",
        "WCA_LLM_PROVIDER": "stub",
        "WCA_EMBEDDING_BACKEND": "bm25",
    }
    values.update(overrides)
    return Config.load(env_path=tmp_path / "nonexistent.env", **values)


def _env_file(cfg: Config, tmp_path: Path) -> Path:
    path = tmp_path / "identity.env"
    path.write_text("\n".join([
        f"WCA_DB_BACKEND={cfg.db_backend}",
        f"WCA_DATABASE_URL={cfg.database_url}",
        f"WCA_DB_IDENTITY_PATH={cfg.db_identity_path}",
        f"WCA_DB_PATH={cfg.db_path}",
        f"WCA_DATA_DIR={cfg.data_dir}",
        f"WCA_REPORTS_DIR={cfg.reports_dir}",
        f"WCA_PACKAGES_DIR={cfg.packages_dir}",
        f"WCA_USERS_PATH={cfg.users_path}",
        f"WCA_UPLOAD_DIR={cfg.upload_dir}",
        "WCA_REGION_CODE=440300",
        "WCA_RULE_PACK=rp-2026.11.gd-pilot-standard.v5",
        "WCA_LLM_PROVIDER=stub",
        "WCA_EMBEDDING_BACKEND=bm25",
    ]) + "\n", encoding="utf-8")
    return path


def _patch_pg(monkeypatch, names: set[str]) -> tuple[list[str], list[str]]:
    created: list[str] = []
    connected: list[str] = []
    monkeypatch.setattr(db, "_ENSURED", set())
    monkeypatch.setattr(db, "_database_names", lambda _url: set(names))
    monkeypatch.setattr(db, "_database_state", lambda _url, name: "ours" if name in names else "foreign")
    monkeypatch.setattr(db, "_create_database", lambda _url, name: created.append(name))
    monkeypatch.setattr(db, "_connect_postgres", lambda cfg: connected.append(cfg.safe_database_target) or object())
    return created, connected


def test_identity_database_mismatch_fails_hard_without_rewriting(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    created, connected = _patch_pg(monkeypatch, {"A", "B"})
    before = Path(cfg.db_identity_path).read_text(encoding="utf-8")

    with pytest.raises(DatabaseIdentityMismatch, match="身份不符"):
        connect(cfg)

    assert created == [] and connected == [], "身份不符时不得建库/建连"
    assert cfg.database_url.endswith("/A"), "不得把配置 URL 改写成 identity 的库"
    assert Path(cfg.db_identity_path).read_text(encoding="utf-8") == before, \
        "拒绝路径不得改写 identity"


@pytest.mark.parametrize("field,value", [
    ("host", "127.0.0.2"), ("port", 5928), ("user", "other"), ("backend", "sqlite"),
])
def test_identity_any_field_mismatch_fails_hard(tmp_path, monkeypatch, field, value):
    cfg = _cfg(tmp_path, configured="A", identity="A", **{field: value})
    created, connected = _patch_pg(monkeypatch, {"A"})
    with pytest.raises(DatabaseIdentityMismatch, match="身份不符"):
        connect(cfg)
    assert created == [] and connected == []


@pytest.mark.parametrize("payload", [
    b"{not-json",
    b"\xef\xbb\xbf" + json.dumps({"schema": SCHEMA, "backend": "postgres",
                                  "host": "127.0.0.1", "port": 5927,
                                  "user": "root", "database": "B"}).encode("utf-8"),
])
def test_corrupt_identity_is_not_silently_ignored(tmp_path, monkeypatch, payload):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    Path(cfg.db_identity_path).write_bytes(payload)
    created, connected = _patch_pg(monkeypatch, {"A", "B"})
    with pytest.raises(DatabaseIdentityMismatch, match="identity 文件"):
        connect(cfg)
    assert created == [] and connected == []


@pytest.mark.parametrize("argv", [["ingest"], ["check"], ["export"]])
def test_cli_import_check_export_all_reject_identity_mismatch(
        tmp_path, monkeypatch, capsys, argv):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    env = _env_file(cfg, tmp_path)
    created, connected = _patch_pg(monkeypatch, {"A", "B"})

    rc = cli.main(["--env", str(env), *argv])

    assert rc == 2
    err = capsys.readouterr().err
    assert "数据库身份不符" in err and "db-target --reset" in err
    assert created == [] and connected == [], "拒绝命令不得写任何库"
    assert cfg.database_url.endswith("/A")


def test_explicit_reset_allows_switch_and_then_creates_configured_database(
        tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    env = _env_file(cfg, tmp_path)

    rc = cli.main(["--env", str(env), "db-target", "--reset", "--confirm", "A"])
    assert rc == 0
    assert not Path(cfg.db_identity_path).exists()
    assert "已重置数据库 identity" in capsys.readouterr().out

    created, connected = _patch_pg(monkeypatch, {"B"})
    chosen = ensure_database(cfg)
    assert chosen == "A"
    assert created == ["A"]
    assert cfg.database_url.endswith("/A")
    marker = json.loads(Path(cfg.db_identity_path).read_text(encoding="utf-8"))
    assert marker["database"] == "A"


def test_reset_requires_exact_configured_database_and_keeps_marker_on_mismatch(
        tmp_path, capsys):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    env = _env_file(cfg, tmp_path)
    before = Path(cfg.db_identity_path).read_text(encoding="utf-8")

    rc = cli.main(["--env", str(env), "db-target", "--reset", "--confirm", "B"])

    assert rc == 2
    assert "确认串" in capsys.readouterr().err
    assert Path(cfg.db_identity_path).exists()
    assert Path(cfg.db_identity_path).read_text(encoding="utf-8") == before


def test_db_target_show_reports_mismatch_without_connecting(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, configured="A", identity="B")
    env = _env_file(cfg, tmp_path)
    created, connected = _patch_pg(monkeypatch, {"A", "B"})

    rc = cli.main(["--env", str(env), "db-target", "--show"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "配置库：A" in out and "identity：B" in out and "匹配：否" in out
    assert created == [] and connected == []


def test_active_database_guard_still_rejects(tmp_path):
    active = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="postgres",
        WCA_DATABASE_URL=f"postgresql://root:{SECRET}@127.0.0.1:5927/wca_worktime",
        WCA_DB_PATH=str(tmp_path / "unused.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "active_target.json"),
    )
    with pytest.raises(MigrationSafetyError, match="wca_worktime"):
        assert_temporary_database(active)


def test_reset_function_rejects_non_postgres(tmp_path):
    cfg = Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(tmp_path / "offline.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
    )
    with pytest.raises(ValueError, match="PostgreSQL"):
        reset_database_identity(cfg, confirm="offline")
