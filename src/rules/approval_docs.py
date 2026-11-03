"""审批台账 P0：批文主表 + 版本 + 范围 + 员工覆盖投影。

与旧的 `worktime_approval` 静默 UPSERT 不同，这一条链路：
  * 批文按 doc_no 唯一，版本不可覆盖；发布才生成 `employee_approval_coverage`；
  * 所有写操作先做角色检查，AU 只读；
  * CSV 导入整批校验、整批提交，任何一行失败都不留半份数据；
  * 附件只登记 SHA-256，不保存原件；
  * 每次草稿/导入/发布都写审计事件，发布前做员工覆盖冲突检测。
"""

from __future__ import annotations

import csv
import json
import re
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

from ..auth import User
from ..config import Config
from ..db import DB_BACKEND_POSTGRES, Connection, transaction
from ..evidence import append_audit, set_genesis
from ..util import CN_TZ, canonical_json, sha256_hex

APPROVAL_READ_ROLES = ("AD", "AU")
APPROVAL_WRITE_ROLES = ("AD",)
VALID_REGIMES = ("comprehensive_monthly", "comprehensive_quarterly",
                 "comprehensive_yearly", "flexible")
VALID_SCOPE_TYPES = ("org", "employee")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CSV_FIELDS = ("doc_no", "title", "issuer", "regime", "version_no", "valid_from",
              "valid_to", "job_codes", "region_code", "attachment_sha256",
              "scope_type", "scope_value", "change_note")


class ApprovalConflictError(ValueError):
    """批文/版本/员工覆盖冲突；调用方必须显式处理，不允许静默覆盖。"""


def _now() -> str:
    return datetime.now(CN_TZ).isoformat()


def _require(user: User, roles: Iterable[str]) -> None:
    if not user.has(*roles):
        raise PermissionError(f"账号 {user.username} 没有审批台账写权限（需要 {list(roles)}）")


def require_read(user: User) -> None:
    if not user.has(*APPROVAL_READ_ROLES):
        raise PermissionError(f"账号 {user.username} 没有审批台账读权限（需要 {list(APPROVAL_READ_ROLES)}）")


def require_write(user: User) -> None:
    _require(user, APPROVAL_WRITE_ROLES)


def _parse_date(value: str, field: str) -> date:
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} 无法解析为 YYYY-MM-DD：{value!r}") from exc


def _job_codes(raw: str | list[str]) -> list[str]:
    if isinstance(raw, list):
        values = [str(x).strip() for x in raw if str(x).strip()]
    else:
        text = str(raw or "").strip()
        if not text:
            values = []
        else:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = [part.strip() for part in text.split(",") if part.strip()]
            values = [str(x).strip() for x in parsed if str(x).strip()] \
                if isinstance(parsed, list) else []
    if not values:
        raise ValueError("job_codes 至少要有一项")
    return sorted(dict.fromkeys(values))


def _validate_version(version: dict) -> dict:
    doc_no = str(version.get("doc_no") or "").strip()
    title = str(version.get("title") or "").strip()
    issuer = str(version.get("issuer") or "").strip()
    regime = str(version.get("regime") or "").strip()
    if not doc_no:
        raise ValueError("doc_no 不能为空")
    if not title:
        raise ValueError("title 不能为空")
    if not issuer:
        raise ValueError("issuer 不能为空")
    if regime not in VALID_REGIMES:
        raise ValueError(f"regime {regime!r} 不在允许范围 {list(VALID_REGIMES)}")
    try:
        version_no = int(version.get("version_no"))
    except (TypeError, ValueError) as exc:
        raise ValueError("version_no 必须是正整数") from exc
    if version_no <= 0:
        raise ValueError("version_no 必须是正整数")
    start = _parse_date(version.get("valid_from"), "valid_from")
    end = _parse_date(version.get("valid_to"), "valid_to")
    if start > end:
        raise ValueError(f"审批期限起点 {start} 晚于终点 {end}")
    codes = _job_codes(version.get("job_codes"))
    region = str(version.get("region_code") or "").strip()
    if not region:
        raise ValueError("region_code 不能为空")
    sha = str(version.get("attachment_sha256") or "").strip()
    if not _SHA256_RE.match(sha):
        raise ValueError("attachment_sha256 必须是 64 位十六进制 sha256")
    return {"doc_no": doc_no, "title": title, "issuer": issuer, "regime": regime,
            "version_no": version_no, "valid_from": start.isoformat(),
            "valid_to": end.isoformat(), "job_codes": canonical_json(codes),
            "region_code": region, "attachment_sha256": sha,
            "change_note": str(version.get("change_note") or "").strip()}


def _normalise_scopes(scopes: Iterable[dict | tuple[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for scope in scopes:
        if isinstance(scope, dict):
            kind, value = str(scope.get("scope_type") or ""), str(scope.get("scope_value") or "")
        else:
            kind, value = str(scope[0]), str(scope[1])
        kind, value = kind.strip(), value.strip()
        if kind not in VALID_SCOPE_TYPES:
            raise ValueError(f"scope_type {kind!r} 不在 {list(VALID_SCOPE_TYPES)}")
        if not value:
            raise ValueError("scope_value 不能为空")
        out.append((kind, value))
    if not out:
        raise ValueError("至少需要一个审批范围（org 或 employee）")
    return sorted(dict.fromkeys(out))


def _ensure_scope_targets(conn: Connection, scopes: list[tuple[str, str]]) -> None:
    for kind, value in scopes:
        if kind == "employee":
            if conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (value,)).fetchone() is None:
                raise ValueError(f"审批范围指向不存在的员工：{value}")
        else:
            if conn.execute("SELECT 1 FROM org_unit WHERE org_id = ?", (value,)).fetchone() is None:
                raise ValueError(f"审批范围指向不存在的组织：{value}")


def refresh_org_paths(conn: Connection) -> None:
    """按 parent_id 重算物化路径；检测环，不猜层级。"""
    rows = [dict(r) for r in conn.execute(
        "SELECT org_id, parent_id FROM org_unit ORDER BY org_id").fetchall()]
    parents = {r["org_id"]: (str(r["parent_id"]) if r["parent_id"] else "") for r in rows}
    paths: dict[str, str] = {}
    levels: dict[str, int] = {}
    visiting: set[str] = set()

    def walk(org_id: str) -> None:
        if org_id in paths:
            return
        if org_id in visiting:
            raise ValueError(f"组织层级存在环：{org_id}")
        visiting.add(org_id)
        parent = parents.get(org_id, "")
        if parent and parent in parents:
            walk(parent)
            paths[org_id] = f"{paths[parent]}{org_id}/"
            levels[org_id] = levels[parent] + 1
        else:
            paths[org_id] = f"/{org_id}/"
            levels[org_id] = 0
        visiting.remove(org_id)

    for org_id in parents:
        walk(org_id)
    for org_id, path in paths.items():
        conn.execute("UPDATE org_unit SET org_path = ?, org_level = ? WHERE org_id = ?",
                     (path, levels[org_id], org_id))


_LIKE_ESCAPE_TABLE = str.maketrans({"\\": "\\\\", "%": "\\%", "_": "\\_"})


def _like_literal_prefix(prefix: str) -> str:
    """把物化路径转成字面前缀模式：`%`/`_`/`\\` 不再具有通配符语义。"""
    return str(prefix).translate(_LIKE_ESCAPE_TABLE) + "%"


def _scope_employees(conn: Connection, version_id: int) -> list[str]:
    refresh_org_paths(conn)
    version = conn.execute(
        "SELECT job_codes, region_code FROM approval_doc_version WHERE version_id = ?",
        (version_id,)).fetchone()
    if version is None:
        raise ValueError(f"审批版本不存在：{version_id}")
    codes = json.loads(version["job_codes"])
    placeholders = ",".join("?" * len(codes))
    scopes = conn.execute(
        "SELECT scope_type, scope_value FROM approval_doc_scope WHERE version_id = ? "
        "ORDER BY scope_type, scope_value", (version_id,)).fetchall()
    employees: set[str] = set()
    for scope in scopes:
        if scope["scope_type"] == "employee":
            row = conn.execute(
                f"SELECT emp_id FROM employee WHERE emp_id = ? AND region_code = ? "
                f"AND job_code IN ({placeholders})",
                (str(scope["scope_value"]), str(version["region_code"]), *codes)).fetchone()
            if row is not None:
                employees.add(str(row["emp_id"]))
            continue
        org = conn.execute("SELECT org_path FROM org_unit WHERE org_id = ?",
                           (str(scope["scope_value"]),)).fetchone()
        if org is None:
            raise ValueError(f"审批范围指向不存在的组织：{scope['scope_value']}")
        prefix = str(org["org_path"])
        # M-04：org_id 可含 `%`/`_`，不转义会把兄弟组织误纳入审批覆盖。
        for row in conn.execute(
                f"SELECT e.emp_id FROM employee e JOIN org_unit o ON o.org_id = e.org_id "
                f"WHERE o.org_path LIKE ? ESCAPE '\\' AND e.region_code = ? "
                f"AND e.job_code IN ({placeholders}) ORDER BY e.emp_id",
                (_like_literal_prefix(prefix), str(version["region_code"]), *codes)).fetchall():
            employees.add(str(row["emp_id"]))
    return sorted(employees)


def _doc_row(conn: Connection, doc_no: str) -> dict | None:
    row = conn.execute("SELECT * FROM approval_doc WHERE doc_no = ?", (doc_no,)).fetchone()
    return dict(row) if row else None


def _insert_draft_in_tx(conn: Connection, actor: str, version: dict,
                        scopes: list[tuple[str, str]]) -> dict:
    doc = _doc_row(conn, version["doc_no"])
    now = _now()
    if doc is None:
        cur = conn.execute(
            "INSERT INTO approval_doc(doc_no, title, issuer, regime, status, current_version, "
            "created_at, updated_at, created_by, updated_by) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "RETURNING doc_id",
            (version["doc_no"], version["title"], version["issuer"], version["regime"],
             "DRAFT", None, now, now, actor, actor))
        doc_id = int(cur.fetchone()["doc_id"])
    else:
        if (doc["title"] != version["title"] or doc["issuer"] != version["issuer"]
                or doc["regime"] != version["regime"]):
            raise ApprovalConflictError(
                f"批文 {version['doc_no']} 已存在且标题/发文机关/工时制不同；"
                "版本链不允许改写批文主数据")
        doc_id = int(doc["doc_id"])
    existing = conn.execute(
        "SELECT 1 FROM approval_doc_version WHERE doc_id = ? AND version_no = ?",
        (doc_id, version["version_no"])).fetchone()
    if existing is not None:
        raise ApprovalConflictError(
            f"批文 {version['doc_no']} 的版本 {version['version_no']} 已存在；"
            "版本不可覆盖，请递增版本号")
    cur = conn.execute(
        "INSERT INTO approval_doc_version(doc_id, version_no, valid_from, valid_to, job_codes, "
        "region_code, attachment_sha256, change_note, status, published_at, published_by, "
        "created_at, created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING version_id",
        (doc_id, version["version_no"], version["valid_from"], version["valid_to"],
         version["job_codes"], version["region_code"], version["attachment_sha256"],
         version["change_note"], "DRAFT", None, None, now, actor))
    version_id = int(cur.fetchone()["version_id"])
    for kind, value in scopes:
        conn.execute(
            "INSERT INTO approval_doc_scope(version_id, scope_type, scope_value) VALUES(?,?,?)",
            (version_id, kind, value))
    return {"doc_id": doc_id, "version_id": version_id, "doc_no": version["doc_no"],
            "version_no": version["version_no"]}


def create_draft(conn: Connection, cfg: Config, user: User, *,
                 doc_no: str, title: str, issuer: str, regime: str, version_no: int,
                 valid_from: str, valid_to: str, job_codes: str | list[str],
                 region_code: str, attachment_sha256: str,
                 scopes: Iterable[dict | tuple[str, str]], change_note: str = "") -> dict:
    """创建批文/版本草稿；同名同版本冲突即拒绝，绝不静默覆盖。"""
    require_write(user)
    version = _validate_version({
        "doc_no": doc_no, "title": title, "issuer": issuer, "regime": regime,
        "version_no": version_no, "valid_from": valid_from, "valid_to": valid_to,
        "job_codes": job_codes, "region_code": region_code,
        "attachment_sha256": attachment_sha256, "change_note": change_note,
    })
    scopes_norm = _normalise_scopes(scopes)
    _ensure_scope_targets(conn, scopes_norm)
    set_genesis(conn, cfg)
    with transaction(conn):
        result = _insert_draft_in_tx(conn, user.username, version, scopes_norm)
        append_audit(conn, run_id=None, actor=f"human:{user.username}",
                     action="approval_doc.draft",
                     payload={"doc_no": version["doc_no"], "version_no": version["version_no"],
                              "regime": version["regime"], "scopes": scopes_norm},
                     ts=_now(), cfg=cfg)
    return result


def update_draft(conn: Connection, cfg: Config, user: User, doc_no: str, version_no: int,
                 *, valid_from: str, valid_to: str, job_codes: str | list[str],
                 region_code: str, attachment_sha256: str,
                 scopes: Iterable[dict | tuple[str, str]], change_note: str = "") -> dict:
    """只编辑仍为 DRAFT 的版本；已发布/已替代版本不可改写。"""
    require_write(user)
    doc = _doc_row(conn, doc_no)
    if doc is None:
        raise ValueError(f"批文不存在：{doc_no}")
    row = conn.execute(
        "SELECT * FROM approval_doc_version WHERE doc_id = ? AND version_no = ?",
        (int(doc["doc_id"]), int(version_no))).fetchone()
    if row is None:
        raise ValueError(f"批文 {doc_no} 没有版本 {version_no}")
    version = dict(row)
    if version["status"] != "DRAFT":
        raise ApprovalConflictError(
            f"批文 {doc_no} 版本 {version_no} 状态为 {version['status']}，只有 DRAFT 可编辑")
    validated = _validate_version({
        "doc_no": doc_no, "title": doc["title"], "issuer": doc["issuer"],
        "regime": doc["regime"], "version_no": version_no,
        "valid_from": valid_from, "valid_to": valid_to, "job_codes": job_codes,
        "region_code": region_code, "attachment_sha256": attachment_sha256,
        "change_note": change_note,
    })
    scopes_norm = _normalise_scopes(scopes)
    _ensure_scope_targets(conn, scopes_norm)
    now = _now()
    set_genesis(conn, cfg)
    with transaction(conn, immediate=True):
        # 与 publish 共用同一把数据库锁，避免“编辑范围/期限”与“发布展开”竞争。
        if conn.dialect == DB_BACKEND_POSTGRES:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('wca.approval.publish'))")
        conn.execute(
            "UPDATE approval_doc_version SET valid_from = ?, valid_to = ?, job_codes = ?, "
            "region_code = ?, attachment_sha256 = ?, change_note = ? WHERE version_id = ?",
            (validated["valid_from"], validated["valid_to"], validated["job_codes"],
             validated["region_code"], validated["attachment_sha256"],
             validated["change_note"], int(version["version_id"])))
        conn.execute("DELETE FROM approval_doc_scope WHERE version_id = ?",
                     (int(version["version_id"]),))
        for kind, value in scopes_norm:
            conn.execute(
                "INSERT INTO approval_doc_scope(version_id, scope_type, scope_value) "
                "VALUES(?,?,?)", (int(version["version_id"]), kind, value))
        conn.execute("UPDATE approval_doc SET updated_at = ?, updated_by = ? WHERE doc_id = ?",
                     (now, user.username, int(doc["doc_id"])))
        append_audit(conn, run_id=None, actor=f"human:{user.username}",
                     action="approval_doc.draft.edit",
                     payload={"doc_no": doc_no, "version_no": int(version_no),
                              "valid_from": validated["valid_from"],
                              "valid_to": validated["valid_to"],
                              "scopes": scopes_norm},
                     ts=now, cfg=cfg)
    return {"doc_no": doc_no, "version_no": int(version_no),
            "scopes": scopes_norm}


def import_drafts_csv(conn: Connection, cfg: Config, user: User, path: Path | str) -> dict:
    """原子导入草稿 CSV：先全量校验，再单事务写入；任一行失败回滚全部。"""
    require_write(user)
    p = Path(path)
    with p.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        missing = [f for f in CSV_FIELDS if f not in header]
        if missing:
            raise ValueError(f"审批草稿 CSV 缺列：{missing}")
        rows = [{k: str(row.get(k) or "") for k in CSV_FIELDS} for row in reader]
    if not rows:
        raise ValueError("审批草稿 CSV 没有数据行")

    versions: dict[tuple[str, int], dict] = {}
    scopes_by_version: dict[tuple[str, int], list[tuple[str, str]]] = {}
    for line_no, row in enumerate(rows, start=2):
        try:
            version = _validate_version(row)
            scope = _normalise_scopes([(row["scope_type"], row["scope_value"])])[0]
        except ValueError as exc:
            raise ValueError(f"第 {line_no} 行：{exc}") from exc
        key = (version["doc_no"], version["version_no"])
        if key in versions:
            prev = versions[key]
            for field in ("title", "issuer", "regime", "valid_from", "valid_to",
                          "job_codes", "region_code", "attachment_sha256"):
                if prev[field] != version[field]:
                    raise ApprovalConflictError(
                        f"第 {line_no} 行：同一批文/版本的 {field} 与前面的行不一致")
        else:
            versions[key] = version
            scopes_by_version[key] = []
        scopes_by_version[key].append(scope)
    for key, scopes in scopes_by_version.items():
        scopes_by_version[key] = sorted(dict.fromkeys(scopes))
        _ensure_scope_targets(conn, scopes_by_version[key])

    written: list[dict] = []
    set_genesis(conn, cfg)
    with transaction(conn):
        for key in sorted(versions.keys()):
            written.append(_insert_draft_in_tx(conn, user.username, versions[key],
                                               scopes_by_version[key]))
        append_audit(conn, run_id=None, actor=f"human:{user.username}",
                     action="approval_doc.import",
                     payload={"file_sha256": sha256_hex(p.read_bytes()),
                              "rows": len(rows),
                              "docs": len({k[0] for k in versions}),
                              "doc_nos": sorted({k[0] for k in versions}),
                              "versions": len(versions)},
                     ts=_now(), cfg=cfg)
    return {"rows": len(rows), "docs": len({k[0] for k in versions}),
            "versions": len(versions), "written": written}


def publish_doc(conn: Connection, cfg: Config, user: User, doc_no: str,
                version_no: int | None = None) -> dict:
    """发布一个草稿版本，生成员工覆盖投影；冲突检测在写入前完成。"""
    require_write(user)
    doc = _doc_row(conn, doc_no)
    if doc is None:
        raise ValueError(f"批文不存在：{doc_no}")
    if version_no is None:
        row = conn.execute(
            "SELECT * FROM approval_doc_version WHERE doc_id = ? AND status = 'DRAFT' "
            "ORDER BY version_no DESC LIMIT 1", (int(doc["doc_id"]),)).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM approval_doc_version WHERE doc_id = ? AND version_no = ?",
            (int(doc["doc_id"]), int(version_no))).fetchone()
    if row is None:
        raise ValueError(f"批文 {doc_no} 没有可发布的草稿版本")
    version = dict(row)
    version["regime"] = str(doc["regime"])
    if version["status"] != "DRAFT":
        raise ApprovalConflictError(
            f"批文 {doc_no} 版本 {version['version_no']} 状态为 {version['status']}，"
            "只有 DRAFT 可以发布")

    now = _now()
    employees: list[str] = []
    set_genesis(conn, cfg)
    # 数据库级保护：SQLite 用 BEGIN IMMEDIATE 先拿写锁；PG 用事务级 advisory lock。
    # 冲突检测与写入放进同一个锁区间，避免“先查后写”被另一个发布者穿透。
    with transaction(conn, immediate=True):
        if conn.dialect == DB_BACKEND_POSTGRES:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('wca.approval.publish'))")
        employees = _scope_employees(conn, int(version["version_id"]))
        if not employees:
            raise ApprovalConflictError(
                f"批文 {doc_no} 版本 {version['version_no']} 展开后没有员工")
        conflicts: list[dict] = []
        for emp_id in employees:
            hit = conn.execute(
                "SELECT doc_no, version_no, valid_from, valid_to FROM employee_approval_coverage "
                "WHERE emp_id = ? AND regime = ? AND doc_id <> ? "
                "AND valid_from <= ? AND valid_to >= ? LIMIT 1",
                (emp_id, version["regime"], int(doc["doc_id"]),
                 version["valid_to"], version["valid_from"])).fetchone()
            if hit is not None:
                conflicts.append({"emp_id": emp_id, "doc_no": hit["doc_no"],
                                  "version_no": int(hit["version_no"]),
                                  "valid_from": hit["valid_from"], "valid_to": hit["valid_to"]})
        if conflicts:
            raise ApprovalConflictError(
                f"批文 {doc_no} 版本 {version['version_no']} 与已发布覆盖冲突：{conflicts[:5]}")

        conn.execute(
            "UPDATE approval_doc_version SET status = 'SUPERSEDED' "
            "WHERE doc_id = ? AND status = 'PUBLISHED'", (int(doc["doc_id"]),))
        conn.execute("DELETE FROM employee_approval_coverage WHERE doc_id = ?",
                     (int(doc["doc_id"]),))
        conn.execute(
            "UPDATE approval_doc_version SET status = 'PUBLISHED', published_at = ?, "
            "published_by = ? WHERE version_id = ?",
            (now, user.username, int(version["version_id"])))
        conn.execute(
            "UPDATE approval_doc SET status = 'PUBLISHED', current_version = ?, updated_at = ?, "
            "updated_by = ? WHERE doc_id = ?",
            (int(version["version_no"]), now, user.username, int(doc["doc_id"])))
        for emp_id in employees:
            conn.execute(
                "INSERT INTO employee_approval_coverage(emp_id, doc_id, version_id, doc_no, "
                "version_no, regime, valid_from, valid_to, job_codes, region_code, "
                "attachment_sha256, published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (emp_id, int(doc["doc_id"]), int(version["version_id"]), doc_no,
                 int(version["version_no"]), version["regime"], version["valid_from"],
                 version["valid_to"], version["job_codes"], version["region_code"],
                 version["attachment_sha256"], now))
        append_audit(conn, run_id=None, actor=f"human:{user.username}",
                     action="approval_doc.publish",
                     payload={"doc_no": doc_no, "version_no": int(version["version_no"]),
                              "coverage_employees": len(employees),
                              "regime": version["regime"],
                              "valid_from": version["valid_from"],
                              "valid_to": version["valid_to"]},
                     ts=now, cfg=cfg)
    return {"doc_no": doc_no, "version_no": int(version["version_no"]),
            "coverage_employees": len(employees)}


def list_docs(conn: Connection, user: User) -> list[dict]:
    """AU/AD 可读；只返回批文主表，不返回附件内容。"""
    require_read(user)
    return [dict(r) for r in conn.execute(
        "SELECT doc_id, doc_no, title, issuer, regime, status, current_version, "
        "created_at, updated_at, created_by, updated_by FROM approval_doc "
        "ORDER BY doc_no").fetchall()]


def list_docs_summary(conn: Connection, user: User) -> list[dict]:
    """只读列表：批文状态、文号、生效期、版本数；供网页列表使用。"""
    require_read(user)
    rows = conn.execute(
        "SELECT d.doc_id, d.doc_no, d.title, d.issuer, d.regime, d.status, "
        "d.current_version, d.created_at, d.updated_at, "
        "COUNT(v.version_id) AS version_count, "
        "MIN(v.valid_from) AS valid_from, MAX(v.valid_to) AS valid_to "
        "FROM approval_doc d LEFT JOIN approval_doc_version v ON v.doc_id = d.doc_id "
        "GROUP BY d.doc_id, d.doc_no, d.title, d.issuer, d.regime, d.status, "
        "d.current_version, d.created_at, d.updated_at "
        "ORDER BY d.doc_no").fetchall()
    return [dict(r) for r in rows]


def coverage_for(conn: Connection, user: User, emp_id: str) -> list[dict]:
    """AU/AD 可读某员工的已发布覆盖投影。"""
    require_read(user)
    return [dict(r) for r in conn.execute(
        "SELECT emp_id, doc_no, version_no, regime, valid_from, valid_to, "
        "attachment_sha256, published_at FROM employee_approval_coverage "
        "WHERE emp_id = ? ORDER BY valid_from DESC, doc_no", (emp_id,)).fetchall()]


def version_chain(conn: Connection, user: User, doc_no: str) -> dict:
    """AU/AD 可读某批文的版本链与范围；不返回附件原件。"""
    require_read(user)
    doc = _doc_row(conn, doc_no)
    if doc is None:
        raise ValueError(f"批文不存在：{doc_no}")
    versions = [dict(r) for r in conn.execute(
        "SELECT version_id, version_no, status, valid_from, valid_to, job_codes, region_code, "
        "attachment_sha256, change_note, published_at, published_by, created_at, created_by "
        "FROM approval_doc_version WHERE doc_id = ? ORDER BY version_no",
        (int(doc["doc_id"]),)).fetchall()]
    for version in versions:
        scopes = [dict(r) for r in conn.execute(
            "SELECT scope_type, scope_value FROM approval_doc_scope WHERE version_id = ? "
            "ORDER BY scope_type, scope_value", (int(version["version_id"]),)).fetchall()]
        version["scopes"] = scopes
        version.pop("version_id", None)
    return {"doc": doc, "versions": versions}
