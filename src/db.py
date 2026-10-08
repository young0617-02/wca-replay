"""SQLite access layer: connection, schema bootstrap, meta, small query helpers."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import Config
from .util import sha256_hex

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
SCHEMA_VERSION = "1"


VALID_SYNCHRONOUS = ("OFF", "NORMAL", "FULL", "EXTRA")


def connect(db_path: Path | str, synchronous: str = "FULL") -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = synchronous.upper()
    if mode not in VALID_SYNCHRONOUS:
        raise ValueError(f"synchronous 只能是 {VALID_SYNCHRONOUS}，收到 {synchronous!r}")
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA synchronous = {mode}")  # 默认 FULL：审计链写入必须落盘，性能让位于可举证
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def schema_digest() -> str:
    return sha256_hex(SCHEMA_PATH.read_bytes())


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate_review_amount(conn)
    set_meta(conn, "schema_version", SCHEMA_VERSION)
    set_meta(conn, "schema_digest", schema_digest())


def init_db_for(cfg: Config) -> sqlite3.Connection:
    cfg.ensure_dirs()
    conn = connect(cfg.db_path, cfg.sqlite_synchronous)
    init_db(conn)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def insert_many(conn: sqlite3.Connection, sql: str, rows: Iterable[Iterable[Any]]) -> int:
    seq = list(rows)
    if not seq:
        return 0
    conn.execute("BEGIN")
    try:
        conn.executemany(sql, [tuple(r) for r in seq])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return len(seq)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN")
    try:
        yield
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def table_rows(conn: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    _assert_ident(table)
    return conn.execute(f"SELECT * FROM {table}").fetchall()


def count(conn: sqlite3.Connection, table: str) -> int:
    _assert_ident(table)
    return int(conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])


def _assert_ident(name: str) -> None:
    """表名来自代码常量而非用户输入；仍做白名单校验，防注入也防手滑。"""
    if not name.replace("_", "").isalnum():
        raise ValueError(f"非法表名: {name!r}")


def _migrate_review_amount(conn: sqlite3.Connection) -> None:
    """给已存在的库补上"人工录入金额"列（需求 D-03：金额只能由人录入，不由引擎产出）。

    只加列、不改任何既有行的判定值；老库的复核记录该列保持 NULL，表示"未录入"。
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(review_item)")}
    if "amount_cents_input" not in cols:
        conn.execute("ALTER TABLE review_item ADD COLUMN amount_cents_input INTEGER")
        conn.execute("ALTER TABLE review_item ADD COLUMN amount_entered_by TEXT")
        conn.execute("ALTER TABLE review_item ADD COLUMN amount_entered_at TEXT")
