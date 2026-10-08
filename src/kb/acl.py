"""F-009 权限模型：把 ACL 编译成 SQL 谓词，交给检索层下推。

红线（A3）：权限判断必须发生在候选集构造阶段（WHERE / JOIN），
不允许「先把全部文档召回、再在 Python 里过滤掉无权看的」——后者一旦上游缓存、
日志或异常分支漏掉过滤步骤，越权内容就已经进入模型上下文，无法事后收回。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

ACL_PUBLIC = "public"
ACL_OWN_ORG = "own_org"
ACL_OWN_ORG_MANAGER = "own_org_manager"
ACL_SELF = "self"
ACL_SCOPES = (ACL_PUBLIC, ACL_OWN_ORG, ACL_OWN_ORG_MANAGER, ACL_SELF)


@dataclass(frozen=True)
class Principal:
    """提问主体。姓名一律用化名，权限只取决于组织/角色/本人三个维度。"""

    emp_id: str
    org_id: str
    is_manager: bool = False
    region_code: str = "440300"
    roles: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_db(cls, conn: sqlite3.Connection, emp_id: str) -> "Principal":
        row = conn.execute(
            "SELECT emp_id, org_id, is_manager, region_code FROM employee WHERE emp_id = ?",
            (emp_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"主体不存在: {emp_id}")
        return cls(emp_id=row["emp_id"], org_id=row["org_id"],
                   is_manager=bool(row["is_manager"]), region_code=row["region_code"])


# 别名，方便检索层与工具层共用同一个主体对象
Subject = Principal


def acl_predicate(principal: Principal, alias: str = "d") -> tuple[str, list]:
    """返回 (SQL 片段, 参数列表)。片段必须以括号开头，可直接拼进 WHERE。

    注意参数全部走占位符，绝不做字符串拼接 —— 提问内容不进入 SQL 文本。
    """
    parts = [f"{alias}.acl_scope = ?"]
    params: list = [ACL_PUBLIC]

    parts.append(
        f"({alias}.acl_scope IN (?, ?) AND EXISTS (SELECT 1 FROM kb_doc_org k "
        f"WHERE k.doc_id = {alias}.doc_id AND k.org_id = ?))"
    )
    params += [ACL_OWN_ORG, ACL_OWN_ORG_MANAGER, principal.org_id]

    parts.append(f"({alias}.acl_scope = ? AND {alias}.acl_emp_id = ?)")
    params += [ACL_SELF, principal.emp_id]

    if principal.is_manager:
        # 主管可见「本组织内成员的考勤汇总」，但薪酬明细仍是 self
        parts.append(
            f"({alias}.acl_scope = ? AND {alias}.doc_type = 'personnel_data' "
            f"AND {alias}.category = 'attendance_summary' AND EXISTS "
            f"(SELECT 1 FROM kb_doc_org k WHERE k.doc_id = {alias}.doc_id AND k.org_id = ?))"
        )
        params += [ACL_SELF, principal.org_id]

    return "(" + " OR ".join(parts) + ")", params


def can_view(principal: Principal, doc: dict) -> bool:
    """与 SQL 谓词等价 Python 版：只用于测试里做交叉验证，不参与检索路径。"""
    scope = doc.get("acl_scope", ACL_PUBLIC)
    orgs = set(doc.get("acl_org_ids") or [])
    if scope == ACL_PUBLIC:
        return True
    if scope in (ACL_OWN_ORG, ACL_OWN_ORG_MANAGER):
        return principal.org_id in orgs
    if scope == ACL_SELF:
        if doc.get("acl_emp_id") == principal.emp_id:
            return True
        return bool(principal.is_manager and doc.get("category") == "attendance_summary"
                    and principal.org_id in orgs)
    return False


def parse_acl_orgs(raw: str | list | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    text = str(raw).strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [p.strip() for p in text.split(",") if p.strip()]
    return [str(x) for x in data]
