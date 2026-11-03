"""数据库后端迁移的离线约束：配置不泄密、方言差异集中、SQLite 基线不变、Web 端口一致。

PostgreSQL 真实连接用例在 `test_postgres_integration.py`，由 `WCA_TEST_POSTGRES_URL`
显式开启；这里跑的是无外部服务也能验证的结构性约束。
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest

from src import api_server
from src.api import serve
from src.config import DEFAULT_WEB_PORT, Config, redact_database_url
from src.db import (DB_BACKEND_POSTGRES, DB_BACKEND_SQLITE, DatabaseUnavailable, connect,
                    init_db, is_postgres, transaction)

ROOT = Path(__file__).resolve().parent.parent
SECRET = "wca-db-secret-should-never-leak"


def _cfg(tmp_path: Path, **overrides) -> Config:
    values = {
        "WCA_DB_BACKEND": DB_BACKEND_SQLITE,
        "WCA_DB_PATH": str(tmp_path / "test.sqlite3"),
        "WCA_DATA_DIR": str(tmp_path / "data"),
        "WCA_REPORTS_DIR": str(tmp_path / "reports"),
        "WCA_PACKAGES_DIR": str(tmp_path / "packages"),
        "WCA_USERS_PATH": str(tmp_path / "users.json"),
        "WCA_UPLOAD_DIR": str(tmp_path / "uploads"),
        "WCA_DB_IDENTITY_PATH": str(tmp_path / "db_target.json"),
        "WCA_REGION_CODE": "440300",
        "WCA_LLM_PROVIDER": "stub",
        "WCA_EMBEDDING_BACKEND": "bm25",
        "WCA_SQLITE_SYNCHRONOUS": "OFF",
    }
    values.update(overrides)
    return Config.load(env_path=tmp_path / "nonexistent.env", **values)


def test_explicit_sqlite_fallback_is_supported(tmp_path):
    cfg = _cfg(tmp_path)
    assert cfg.db_backend == DB_BACKEND_SQLITE
    assert cfg.safe_database_target.startswith("sqlite:")


def test_default_backend_is_postgres_and_requires_url(tmp_path):
    """默认后端必须是 PostgreSQL；没有 URL 时启动期报错，不再静默回落 SQLite。"""
    with pytest.raises(ValueError, match="WCA_DATABASE_URL"):
        Config.load(env_path=tmp_path / "nonexistent.env")


def test_no_explicit_config_does_not_read_existing_sqlite(tmp_path):
    """即使工作区有旧 SQLite 文件，没有显式 WCA 配置也不能悄悄采用它。"""
    legacy = tmp_path / "legacy.sqlite3"
    legacy.write_bytes(b"SQLite format 3\x00-legacy-worktime")
    with pytest.raises(ValueError, match="WCA_DATABASE_URL"):
        Config.load(env_path=tmp_path / "nonexistent.env", WCA_DB_PATH=str(legacy))


def test_env_example_and_readme_document_postgres_as_default():
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"^WCA_DB_BACKEND=postgres\s*$", env_example, re.M), \
        ".env.example 的活动默认后端必须是 postgres"
    assert "WCA_DATABASE_URL=" in env_example
    assert "SQLite" in env_example or "sqlite" in env_example, \
        ".env.example 必须说明 SQLite 只是显式回退"
    assert "PostgreSQL 18" in readme and "SQLite" in readme, \
        "README 必须说明 PostgreSQL 为默认、SQLite 为回退"


def test_config_never_renders_database_password(tmp_path):
    url = f"postgresql://root:{SECRET}@127.0.0.1:5927/wca_worktime"
    cfg = _cfg(tmp_path, WCA_DB_BACKEND=DB_BACKEND_POSTGRES, WCA_DATABASE_URL=url)

    assert SECRET not in repr(cfg)
    assert SECRET not in str(cfg)
    assert SECRET not in cfg.safe_database_target
    assert SECRET not in json.dumps(cfg.raw, ensure_ascii=False)
    assert "WCA_DATABASE_URL" not in cfg.raw, "原始配置快照不得把含口令的 URL 传给服务管理器"
    assert redact_database_url(url) == "postgresql://root@127.0.0.1:5927/wca_worktime"
    assert SECRET not in redact_database_url(f"{url}?password={SECRET}")


def test_postgres_backend_requires_url(tmp_path):
    with pytest.raises(ValueError, match="WCA_DATABASE_URL"):
        Config.load(env_path=tmp_path / "nonexistent.env", WCA_DB_BACKEND="postgres")


def test_connection_error_does_not_echo_password(tmp_path):
    cfg = _cfg(tmp_path, WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
               WCA_DATABASE_URL=f"postgresql://root:{SECRET}@127.0.0.1:1/wca_nope")
    with pytest.raises(DatabaseUnavailable) as exc:
        connect(cfg)
    assert SECRET not in str(exc.value)
    assert "127.0.0.1:1" in str(exc.value), "报错必须给可排查的 host:port，而不是只给异常类型"


def test_malformed_database_url_is_redacted_not_echoed(tmp_path):
    cfg = _cfg(tmp_path, WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
               WCA_DATABASE_URL=f"postgresql://root:{SECRET}@bad host/db")
    assert SECRET not in cfg.safe_database_target
    assert cfg.safe_database_target


def test_connection_is_postgres_flag_and_wal_checkpoint_is_skipped(tmp_path):
    from src.api import checkpoint_wal

    cfg = _cfg(tmp_path, WCA_DB_BACKEND=DB_BACKEND_POSTGRES,
               WCA_DATABASE_URL=f"postgresql://root:{SECRET}@127.0.0.1:5927/wca_worktime")
    assert not cfg.db_backend == DB_BACKEND_SQLITE
    assert checkpoint_wal(cfg) == "skip(postgresql)"


def test_sqlite_transaction_rolls_back_on_error(tmp_path):
    cfg = _cfg(tmp_path)
    conn = connect(cfg)
    try:
        init_db(conn)
        assert not is_postgres(conn)
        with pytest.raises(RuntimeError):
            with transaction(conn):
                conn.execute("INSERT INTO meta(key, value) VALUES(?, ?)", ("tx-probe", "1"))
                raise RuntimeError("强制回滚")
        assert conn.execute("SELECT 1 FROM meta WHERE key = ?", ("tx-probe",)).fetchone() is None
    finally:
        conn.close()


def test_schema_file_has_no_sqlite_only_constructs():
    """方言差异集中在 db.py；schema 本身必须两种后端都能执行。"""
    text = (ROOT / "src" / "schema.sql").read_text(encoding="utf-8")
    assert "PRAGMA" not in text, "PRAGMA 只能出现在 SQLite 连接路径，不能写进共享 schema"
    assert "IFNULL(" not in text, "IFNULL 是 SQLite 专有函数，共享 schema 用 COALESCE"
    assert not re.search(r"INSERT\s+OR\s+", text, re.I), \
        "INSERT OR IGNORE/REPLACE 是 SQLite 专有语法，统一改成 ON CONFLICT"

    for path in (ROOT / "src").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "INSERT OR IGNORE" not in source, f"{path} 仍在写 SQLite 专有 INSERT OR IGNORE"
        assert "INSERT OR REPLACE" not in source, f"{path} 仍在写 SQLite 专有 INSERT OR REPLACE"


def test_web_port_is_9763_everywhere():
    assert DEFAULT_WEB_PORT == 9763
    assert inspect.signature(serve).parameters["port"].default == 9763
    assert inspect.signature(api_server.main).parameters is not None
    source = inspect.getsource(api_server.main)
    assert "default=str(DEFAULT_WEB_PORT)" in source or "DEFAULT_WEB_PORT" in source

    services = json.loads((ROOT / "config" / "services.json").read_text(encoding="utf-8"))
    api = next(s for s in services["services"] if s["name"] == "api")
    assert api["port"] == 9763, f"services.json 里 api 端口仍是 {api['port']}"
