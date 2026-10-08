"""服务端身份与会话（US-UI-05 / NFR-15 / NFR-16）。

三条硬规矩，都是为了让"界面藏起来"不被当成权限：
  * 口令只用标准库 `hashlib.scrypt` 存哈希，仓库与库里都不出现明文；密钥不进日志（NFR-15）。
  * 会话是随机令牌 + 库里存哈希（可撤销、可过期），Cookie 为 HttpOnly + SameSite=Strict。
  * **提问主体只能来自会话**。HTTP 层不再接受 `as_emp` 这类由调用方自报的身份，
    否则任何登录者都能冒充他人读其工时结论（这是基线里 `/ask?as_emp=` 的真实缺陷）。

账号来源是 `config/users.json`（管理员配置，US-AD-02）。文件缺失或为空时登录一律拒绝，
不内置默认口令、不静默放行。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .config import Config
from .util import CN_TZ

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
COOKIE_NAME = "wca_session"
SESSION_TTL_MINUTES = 120
ROLES = ("OP", "RV", "EM", "AD")   # 与需求 §2 角色码一致
_TOKEN_RE = re.compile(r"^[0-9a-zA-Z_-]{16,128}$")


class AuthError(Exception):
    pass


def hash_password(password: str) -> str:
    """scrypt 哈希，格式自描述：scrypt$N,r,p$salt$hash。"""
    if not password or len(password) < 8:
        raise AuthError("口令至少 8 位（演示账号也不能用空口令）")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                            p=SCRYPT_P, maxmem=64 * 1024 * 1024)
    return f"scrypt${SCRYPT_N},{SCRYPT_R},{SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, params, salt_hex, hash_hex = str(stored).split("$")
        n, r, p = (int(x) for x in params.split(","))
    except ValueError as exc:
        raise AuthError(f"口令哈希格式无法识别：{stored!r:.40s}") from exc
    if algo != "scrypt":
        raise AuthError(f"不支持的口令算法：{algo}")
    digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=n, r=r, p=p,
                            maxmem=64 * 1024 * 1024)
    return hmac.compare_digest(digest.hex(), hash_hex)


# ------------------------------------------------------------------ 账号来源（配置文件）
def load_users_file(cfg: Config) -> list[dict[str, Any]]:
    path = Path(cfg.users_path)
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    users = data.get("users") if isinstance(data, dict) else data
    if not isinstance(users, list):
        raise AuthError(f"{path} 里必须有 users 列表")
    for u in users:
        for key in ("username", "emp_id", "roles", "pw_hash"):
            if not u.get(key):
                raise AuthError(f"账号 {u.get('username', '?')} 缺字段 {key}（{path}）")
        bad = [r for r in u["roles"] if r not in ROLES]
        if bad:
            raise AuthError(f"账号 {u['username']} 含未知角色 {bad}，可用：{list(ROLES)}")
        if not str(u["pw_hash"]).startswith("scrypt$"):
            raise AuthError(
                f"账号 {u['username']} 的 pw_hash 不是 scrypt 格式：库里不允许出现明文或弱哈希口令")
    return users


def sync_users(conn: sqlite3.Connection, cfg: Config, *, actor: str = "system:auth") -> dict:
    """把配置文件里的账号落到库里（幂等）。口令哈希原样存，不做任何可逆处理。"""
    from .evidence import append_audit

    users = load_users_file(cfg)
    known_emp = {r["emp_id"] for r in conn.execute("SELECT emp_id FROM employee")}
    added, updated, skipped = [], [], []
    for u in users:
        if u["emp_id"] not in known_emp:
            skipped.append(f"{u['username']}→{u['emp_id']}（员工主数据里查无此人）")
            continue
        existing = conn.execute("SELECT user_id, pw_hash, roles FROM app_user WHERE username = ?",
                                (u["username"],)).fetchone()
        roles = json.dumps(sorted(u["roles"]), ensure_ascii=False)
        if existing is None:
            conn.execute(
                "INSERT INTO app_user(username, emp_id, roles, pw_hash, algo, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (u["username"], u["emp_id"], roles, u["pw_hash"], "scrypt",
                 datetime.now(CN_TZ).isoformat()))
            added.append(u["username"])
        elif existing["pw_hash"] != u["pw_hash"] or existing["roles"] != roles:
            conn.execute("UPDATE app_user SET pw_hash = ?, roles = ?, algo = ? WHERE username = ?",
                         (u["pw_hash"], roles, "scrypt", u["username"]))
            updated.append(u["username"])
    if added or updated:
        append_audit(conn, run_id=None, actor=actor, action="auth.users.sync",
                     payload={"added": added, "updated": updated, "skipped": skipped,
                              "source": str(cfg.users_path)},
                     ts=datetime.now(CN_TZ).isoformat(), cfg=cfg)
    return {"added": added, "updated": updated, "skipped": skipped, "configured": len(users)}


# ------------------------------------------------------------------ 会话
def start_session(conn: sqlite3.Connection, cfg: Config, username: str,
                  password: str) -> tuple[str, "User"]:
    """口令校验 + 签发会话令牌。失败原因不区分「用户不存在/口令错」，避免账号枚举。"""
    row = conn.execute("SELECT * FROM app_user WHERE username = ?", (username,)).fetchone()
    if row is None:
        # 仍然做一次同量级的哈希计算，避免"用户不存在"响应明显更快
        hash_password(password or "x" * 8)
        raise AuthError("登录失败：用户名或口令不正确")
    if not verify_password(password, row["pw_hash"]):
        raise AuthError("登录失败：用户名或口令不正确")
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO app_session(token_hash, username, created_at, expires_at, last_seen_at) "
        "VALUES(?,?,?,?,?)",
        (sha256_token(token), username, datetime.now(CN_TZ).isoformat(),
         (datetime.now(CN_TZ) + timedelta(minutes=SESSION_TTL_MINUTES)).isoformat(),
         datetime.now(CN_TZ).isoformat()))
    return token, user_of(conn, username)


def sha256_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def user_of(conn: sqlite3.Connection, username: str) -> "User":
    row = conn.execute("SELECT * FROM app_user WHERE username = ?", (username,)).fetchone()
    if row is None:
        raise AuthError(f"会话指向不存在的账号：{username}")
    emp = conn.execute("SELECT emp_id, pseudonym, org_id, region_code FROM employee WHERE emp_id = ?",
                       (row["emp_id"],)).fetchone()
    if emp is None:
        raise AuthError(f"账号 {username} 指向的员工主数据不存在：{row['emp_id']}")
    return User(username=row["username"], emp_id=row["emp_id"], roles=tuple(json.loads(row["roles"])),
                org_id=emp["org_id"], region_code=emp["region_code"],
                pseudonym=emp["pseudonym"])


def resolve_session(conn: sqlite3.Connection, token: str | None) -> User | None:
    if not token or not _TOKEN_RE.match(token):
        return None
    row = conn.execute(
        "SELECT username, expires_at FROM app_session WHERE token_hash = ?",
        (sha256_token(token),)).fetchone()
    if row is None:
        return None
    if str(row["expires_at"]) < datetime.now(CN_TZ).isoformat():
        conn.execute("DELETE FROM app_session WHERE token_hash = ?", (sha256_token(token),))
        return None
    conn.execute("UPDATE app_session SET last_seen_at = ? WHERE token_hash = ?",
                 (datetime.now(CN_TZ).isoformat(), sha256_token(token)))
    return user_of(conn, row["username"])


def end_session(conn: sqlite3.Connection, token: str | None) -> bool:
    if not token:
        return False
    cur = conn.execute("DELETE FROM app_session WHERE token_hash = ?", (sha256_token(token),))
    return cur.rowcount > 0


@dataclass(frozen=True)
class User:
    username: str
    emp_id: str
    roles: tuple[str, ...]
    org_id: str
    region_code: str
    pseudonym: str

    def has(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)

    def as_dict(self) -> dict:
        return {"username": self.username, "emp_id": self.emp_id, "roles": list(self.roles),
                "org_id": self.org_id, "region_code": self.region_code}
