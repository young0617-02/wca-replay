"""临时库身份守卫：连接后按**实际连接的库**复核，不被配置/identity 自述绕过。

背景（REV-23）：`ensure_database` 的本地 identity 只比较 host/port/user，
会把“配置里指向临时库”的连接拉回活动库。只在连接前看配置库名，
无法发现这种回落；本模块要求在建立连接后读取：
  * PostgreSQL：`current_database()`；
  * SQLite：`PRAGMA database_list` 里 `main` 的实际文件路径。

白名单只用于迁移/演练/性能探针/导出类工具；活动库 `wca_worktime`
（SQLite 为 `var/worktime.sqlite3`）一律拒绝。
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlsplit

from .config import PROJECT_ROOT, Config
from .db import DB_BACKEND_POSTGRES, DB_BACKEND_SQLITE, Connection
from .util import sha256_hex

ACTIVE_DATABASE_NAME = "wca_worktime"
ACTIVE_SQLITE_PATH = PROJECT_ROOT / "var" / "worktime.sqlite3"
# 只允许临时/对照库；不要在这里加活动库。
TEMP_DATABASE_PREFIXES = ("wca_test_", "wca_perf_", "wca_migrate_", "wca_drill_", "wca_tmp_")
TEMP_DATABASE_NAMES = ("wca_worktime_v5",)
# SQLite 没有“库名”可读，只能按实际文件路径做临时库标记。
SQLITE_TEMP_MARKERS = ("pytest-", "tmp", "temp", "scratch", "test", "probe",
                       "migrate", "drill", "perf", "smoke", "dense", "v6")


class MigrationSafetyError(RuntimeError):
    """目标库不是白名单临时库；调用方必须断开连接并拒绝执行。"""


def _database_name(cfg: Config) -> str:
    if cfg.db_backend != DB_BACKEND_POSTGRES:
        return ""
    return unquote(urlsplit(cfg.database_url).path.lstrip("/"))


def assert_temporary_database(cfg: Config) -> None:
    """连接前的配置层预检（只做防呆，最终判定必须用 assert_connection_is_temporary）。"""
    if cfg.db_backend == DB_BACKEND_POSTGRES:
        name = _database_name(cfg)
        if name == ACTIVE_DATABASE_NAME:
            raise MigrationSafetyError(
                "拒绝在活动库 wca_worktime 上执行迁移/演练/导出工具（dry-run 也不允许）。")
        if not (name in TEMP_DATABASE_NAMES or name.startswith(TEMP_DATABASE_PREFIXES)):
            raise MigrationSafetyError(
                f"数据库 {name!r} 不在临时库白名单 "
                f"{list(TEMP_DATABASE_PREFIXES) + list(TEMP_DATABASE_NAMES)}；"
                "这些工具只允许临时/对照库。")
        return
    chosen = Path(cfg.db_path).resolve()
    if chosen == ACTIVE_SQLITE_PATH.resolve():
        raise MigrationSafetyError(
            f"拒绝在活动 SQLite 库 {ACTIVE_SQLITE_PATH} 上执行迁移/演练/导出工具"
            "（dry-run 也不允许）。")


def _sqlite_path_allowed(path: Path) -> bool:
    if path == ACTIVE_SQLITE_PATH.resolve():
        return False
    text = str(path).lower()
    return any(marker in text for marker in SQLITE_TEMP_MARKERS)


def actual_database_identity(conn: Connection) -> str:
    """读取实际连接的库身份；PG 返回库名，SQLite 返回 main 文件路径。"""
    if conn.dialect == DB_BACKEND_POSTGRES:
        row = conn.execute("SELECT current_database() AS name").fetchone()
        return str(row["name"])
    if conn.dialect == DB_BACKEND_SQLITE:
        rows = conn.execute("PRAGMA database_list").fetchall()
        for row in rows:
            if str(row["name"]) == "main":
                file = str(row["file"] or "")
                return str(Path(file).resolve()) if file else ":memory:"
        return ":memory:"
    return ""


def assert_connection_is_temporary(conn: Connection, cfg: Config) -> str:
    """连接后复核实际库身份；不是白名单就抛错，调用方负责 close。"""
    if cfg.db_backend != conn.dialect:
        raise MigrationSafetyError(
            f"配置后端 {cfg.db_backend!r} 与实际连接方言 {conn.dialect!r} 不一致；拒绝执行。")
    actual = actual_database_identity(conn)
    if conn.dialect == DB_BACKEND_POSTGRES:
        if actual == ACTIVE_DATABASE_NAME:
            raise MigrationSafetyError(
                f"实际连接的是活动库 {actual!r}（不是配置里的临时库），拒绝执行。")
        if not (actual in TEMP_DATABASE_NAMES or actual.startswith(TEMP_DATABASE_PREFIXES)):
            raise MigrationSafetyError(
                f"实际连接的数据库 {actual!r} 不在临时库白名单 "
                f"{list(TEMP_DATABASE_PREFIXES) + list(TEMP_DATABASE_NAMES)}；拒绝执行。")
        return actual
    if conn.dialect == DB_BACKEND_SQLITE:
        resolved = Path(actual).resolve() if actual != ":memory:" else Path(actual)
        if resolved == ACTIVE_SQLITE_PATH.resolve():
            raise MigrationSafetyError(
                f"实际连接的是活动 SQLite 库 {resolved}（不是配置里的临时库），拒绝执行。")
        if actual != ":memory:" and not _sqlite_path_allowed(resolved):
            raise MigrationSafetyError(
                f"实际 SQLite 路径 {resolved} 不是临时库白名单；拒绝执行。")
        return actual
    raise MigrationSafetyError(f"未知数据库方言 {conn.dialect!r}；拒绝执行。")


def validate_backup_file(path: str | Path | None, expected_sha256: str | None) -> dict:
    """活动库切换前必须验证备份文件存在、非空、SHA-256 与期望值一致。"""
    p = Path(str(path or ""))
    if not path or not p.is_file():
        raise MigrationSafetyError(f"活动库备份文件不存在：{path!r}；拒绝 allow-active")
    if p.stat().st_size <= 0:
        raise MigrationSafetyError(f"活动库备份文件为空：{p}；拒绝 allow-active")
    expected = str(expected_sha256 or "").strip().lower()
    if not expected:
        raise MigrationSafetyError("allow-active 必须提供备份文件的 --backup-sha256；拒绝执行")
    actual = sha256_hex(p.read_bytes())
    if actual != expected:
        raise MigrationSafetyError(
            f"活动库备份校验失败：实际 sha256={actual}，期望 {expected}；拒绝 allow-active")
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": actual}


def validate_active_cutover(*, actual: str, confirm_active: str,
                            backup_path: str | Path | None,
                            backup_sha256: str | None) -> dict:
    """allow-active 的唯一放行条件；实际库名必须命中活动库，确认串必须一致。"""
    if actual != ACTIVE_DATABASE_NAME:
        raise MigrationSafetyError(
            f"实际连接的是 {actual!r}，不是活动库 {ACTIVE_DATABASE_NAME!r}；拒绝 allow-active")
    if str(confirm_active or "").strip() != actual:
        raise MigrationSafetyError(
            f"--confirm-active={confirm_active!r} 与实际连接 {actual!r} 不一致；拒绝 allow-active")
    return validate_backup_file(backup_path, backup_sha256)


def ensure_config_matches_actual(cfg: Config, actual: str) -> None:
    """配置自述与连接后实际身份不一致时，明确报错而不是继续。"""
    if cfg.db_backend == DB_BACKEND_POSTGRES:
        configured = _database_name(cfg)
        if configured != actual:
            raise MigrationSafetyError(
                f"配置库名 {configured!r} 与实际连接 {actual!r} 不一致；"
                "identity 可能把目标改写了，拒绝执行。")
        return
    if cfg.db_backend == DB_BACKEND_SQLITE and actual != ":memory:":
        configured = Path(cfg.db_path).resolve()
        if configured != Path(actual).resolve():
            raise MigrationSafetyError(
                f"配置 SQLite 路径 {configured} 与实际连接 {actual} 不一致；拒绝执行。")
