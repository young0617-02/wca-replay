"""启动期 / 请求层演示口令闸门（M-01）。

演示账号本身保留，回环地址下的演示流程不受影响；但只要服务实际以非回环地址对外提供服务，
且账号仍能使用文档公开的 `wca-demo-*` 口令登录，就拒绝启动或拒绝服务，避免把可预测的管理员
凭据带到局域网/共享主机。

判定来源有两个，均只读、不写库：
  1. 配置里的账号文件（`config/users.json`）；
  2. 数据库 `app_user`：`sync_users` 写进去的旧行，即使配置删除、账号仍可登录。

`create_app` 阶段按传入 `bound_host` 判定一次；`uvicorn src.api:app --host 0.0.0.0` 这类直接
CLI 启动拿不到真实绑定地址，因此再加一层请求中间件：按请求 `Host` 头复检，非回环 Host 且仍
检出演示口令账号时返回 503。当前阶段**只认 `Host`**，不信任 `X-Forwarded-Host`（详见 README
与 docs/操作手册.md 的反向代理注意事项）。
"""

from __future__ import annotations

import os
import sqlite3
from functools import lru_cache
from pathlib import Path

from .auth import AuthError, load_users_file, verify_password
from .config import DEFAULT_WEB_HOST, Config
from .db import DB_BACKEND_SQLITE, Connection, DatabaseError, connect, table_exists

# 只看这些演示账号名；口令按文档公开的 `wca-demo-<用户名>` 规则推导，
# 不把口令明文再抄进源码，也不会在错误信息里回显。
DEMO_USERNAMES = frozenset({"ad1", "au1", "em1", "op1", "rv1"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class DemoCredentialError(RuntimeError):
    """非回环绑定下仍在使用演示口令；服务必须拒绝启动/拒绝服务。"""


def normalise_host(host: str) -> str:
    """把 `Host` 头规整成可比对的地址：去端口、去 IPv6 方括号、去尾点、转小写。"""
    value = str(host or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        value = value[1:end] if end != -1 else value[1:]
    elif value.count(":") == 1:
        host_part, _, port_part = value.rpartition(":")
        if port_part.isdigit():
            value = host_part
    return value.rstrip(".")


def is_loopback_host(host: str) -> bool:
    return normalise_host(host) in LOOPBACK_HOSTS


def resolve_bound_host(host: str | None = None) -> str:
    """显式传入的绑定地址优先；否则读服务管理器设置的 WCA_HOST，最后按默认回环。"""
    if host is not None and str(host).strip():
        return str(host).strip()
    return str(os.environ.get("WCA_HOST") or DEFAULT_WEB_HOST).strip()


@lru_cache(maxsize=256)
def _matches_demo_password(username: str, pw_hash: str) -> bool:
    """缓存“用户名 + 哈希 → 是否演示口令”的布尔结果，不缓存口令明文。"""
    if username not in DEMO_USERNAMES:
        return False
    try:
        return verify_password(f"wca-demo-{username}", pw_hash)
    except (AuthError, ValueError):
        # 哈希格式坏掉的账号会在登录期报错；这里不把它误判成演示口令。
        return False


def demo_credential_accounts(cfg: Config, users: list[dict] | None = None) -> list[str]:
    """返回配置账号文件里仍能用文档演示口令登录的账号名（只读，不查库）。"""
    configured = load_users_file(cfg) if users is None else users
    found: list[str] = []
    for user in configured:
        username = str(user.get("username") or "")
        if _matches_demo_password(username, str(user.get("pw_hash") or "")):
            found.append(username)
    return sorted(set(found))


def database_demo_credential_accounts(cfg: Config,
                                      conn: Connection | None = None) -> list[str]:
    """返回数据库 `app_user` 里仍能用文档演示口令登录的账号名（只读，不建表、不写库）。

    * SQLite 目标文件不存在时直接返回空，避免为了“检查”反而创建空库；
    * PostgreSQL 用 `connect(..., provision=False)`，不会触发建库/identity 改写；
    * 表还不存在（尚未 init）时按“没有账号”处理。
    """
    own_connection = conn is None
    if own_connection:
        if cfg.db_backend == DB_BACKEND_SQLITE and not Path(cfg.db_path).is_file():
            return []
        conn = connect(cfg, provision=False)
    try:
        if not table_exists(conn, "app_user"):
            return []
        rows = conn.execute("SELECT username, pw_hash FROM app_user").fetchall()
        found: list[str] = []
        for row in rows:
            username = str(row["username"] or "")
            if _matches_demo_password(username, str(row["pw_hash"] or "")):
                found.append(username)
        return sorted(set(found))
    finally:
        if own_connection and conn is not None:
            conn.close()


def assert_demo_credentials_safe(cfg: Config, bound_host: str | None = None, *,
                                 conn: Connection | None = None) -> None:
    """非回环绑定下，配置或数据库仍有演示口令账号 → 拒绝启动。

    数据库不可读时按“无法确认”处理（失败关闭），避免在检查不可用时静默放行；
    回环地址直接返回，保留既有演示流程。
    """
    host = resolve_bound_host(bound_host)
    if is_loopback_host(host):
        return

    configured = demo_credential_accounts(cfg)
    persisted: list[str] = []
    db_error: Exception | None = None
    try:
        persisted = database_demo_credential_accounts(cfg, conn)
    except (DatabaseError, sqlite3.Error, OSError) as exc:
        db_error = exc

    if configured or persisted:
        accounts = sorted(set(configured) | set(persisted))
        sources: list[str] = []
        if configured:
            sources.append(f"账号文件 {cfg.users_path}")
        if persisted:
            sources.append("数据库 app_user（配置删除后仍残留）")
        raise DemoCredentialError(
            f"拒绝启动：服务绑定非回环地址 {host!r}，但账号 {', '.join(accounts)} "
            "仍在使用文档公开的演示口令"
            f"（来源：{'；'.join(sources)}）。"
            "处置：用 `python -m src.cli users --username <账号> --emp <员工> "
            "--roles <角色> --password <新口令>` 改口令并重启（该命令会同步数据库账号），"
            "或把服务绑回 127.0.0.1/localhost；演示账号与回环演示流程保持不变。")

    if db_error is not None:
        raise DemoCredentialError(
            f"拒绝启动：服务绑定非回环地址 {host!r}，但无法读取数据库 app_user 的账号状态"
            f"（{type(db_error).__name__}），不能确认演示口令是否已清理。"
            "处置：确认数据库可连接且已执行 `python -m src.cli init` 后重试，"
            "或把服务绑回 127.0.0.1/localhost。") from db_error
