"""旧审批台账迁移/对照工具：`worktime_approval` → P0 批文/版本/范围/覆盖投影。

设计边界（与需求一致）：
  * **默认 dry-run**：`plan_migration` 只读，不写四张新表；
  * 只有显式 `apply_migration` 才落库，且只允许临时库（活动库 `wca_worktime` 一律拒绝）；
  * 旧表**不删除、不改写**，迁移只新增 P0 投影，保留历史证据；
  * 迁移不修改 `employee.contract_approved_flex`，也不改变 `regime.decide` 的生效口径；
  * 不把旧行“修正”成合法行：字段不全/文号内工时制冲突/新表已有同文号时，显式丢弃并记录原因，
    只会让 v6 REG-01 更严格，不会凭空扩大审批覆盖；
  * 附件仍只保留 SHA-256，不保存原件、路径或 BLOB；
  * REG-01 对照只调用与引擎同一套 `evaluate_approval_evidence`，不另写一套判据。

对应测试：`tests/test_approval_migration.py`。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from ..config import Config
from ..db import Connection, transaction
from ..db_guard import (ACTIVE_DATABASE_NAME, ACTIVE_SQLITE_PATH, MigrationSafetyError,
                        TEMP_DATABASE_NAMES, TEMP_DATABASE_PREFIXES,
                        actual_database_identity, assert_connection_is_temporary,
                        assert_temporary_database, ensure_config_matches_actual)
from ..util import CN_TZ, canonical_json, sha256_hex
from .approvals import VALID_APPROVAL_REGIMES, evaluate_approval_evidence
from .regime import REGIME_STANDARD

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class MigrationPlan:
    """一次 dry-run 的完整迁移计划；不包含任何写库动作。"""

    legacy_rows: int = 0
    legacy_docs: int = 0
    legacy_employee_ids: list[str] = field(default_factory=list)
    docs: list[dict] = field(default_factory=list)
    versions: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    merged: list[dict] = field(default_factory=list)
    plan_digest: str = ""

    @property
    def coverage_employee_ids(self) -> list[str]:
        return sorted({str(row["emp_id"]) for row in self.coverage})

    def summary(self) -> dict:
        return {
            "legacy_rows": self.legacy_rows,
            "legacy_docs": self.legacy_docs,
            "legacy_employees": len(self.legacy_employee_ids),
            "docs": len(self.docs),
            "versions": len(self.versions),
            "coverage_rows": len(self.coverage),
            "coverage_employees": len(self.coverage_employee_ids),
            "skipped_rows": len(self.skipped),
            "merged_groups": len(self.merged),
            "plan_digest": self.plan_digest,
        }


def _now() -> str:
    return datetime.now(CN_TZ).isoformat()


def _as_date(value: object) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _job_codes(raw: object) -> list[str]:
    """旧表 job_codes 是 JSON 列表（历史脏数据也接受逗号分隔）。"""
    if isinstance(raw, list):
        values = [str(x).strip() for x in raw if str(x).strip()]
    else:
        text = str(raw or "").strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = [part.strip() for part in text.split(",") if part.strip()]
        values = [str(x).strip() for x in parsed if str(x).strip()] \
            if isinstance(parsed, list) else []
    return sorted(dict.fromkeys(values))


def _legacy_rows(conn: Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT approval_id, emp_id, doc_no, regime, valid_from, valid_to, job_codes, "
        "region_code, attachment_sha256, recorded_at FROM worktime_approval "
        "ORDER BY doc_no, emp_id").fetchall()
    return [dict(row) for row in rows]


def _validate_legacy_row(row: dict, *, employee_ids: set[str],
                         existing_docs: set[str]) -> list[str]:
    """迁移前的逐行校验；错误只用于“丢弃并说明原因”，不做静默修补。"""
    errors: list[str] = []
    emp_id = str(row.get("emp_id") or "")
    doc_no = str(row.get("doc_no") or "")
    if not emp_id:
        errors.append("员工 emp_id 为空")
    elif emp_id not in employee_ids:
        errors.append(f"员工 {emp_id} 不在 employee 主数据")
    if not doc_no:
        errors.append("审批文号为空")
    elif doc_no in existing_docs:
        errors.append(f"新表 approval_doc 已有文号 {doc_no}，迁移不覆盖新链路")
    regime = str(row.get("regime") or "")
    if regime not in VALID_APPROVAL_REGIMES:
        errors.append(f"工时制 {regime!r} 不在 {list(VALID_APPROVAL_REGIMES)}")
    start = _as_date(row.get("valid_from"))
    end = _as_date(row.get("valid_to"))
    if start is None or end is None:
        errors.append("审批期限缺失或无法解析（需要 YYYY-MM-DD）")
    elif start > end:
        errors.append(f"审批期限起点 {start} 晚于终点 {end}")
    if not _job_codes(row.get("job_codes")):
        errors.append("审批岗位范围为空（新模型版本必须有 job_codes）")
    if not str(row.get("region_code") or "").strip():
        errors.append("审批城市为空")
    if not _SHA256_RE.match(str(row.get("attachment_sha256") or "")):
        errors.append("附件哈希缺失或不是 64 位十六进制 sha256")
    if not str(row.get("recorded_at") or "").strip():
        errors.append("登记时间 recorded_at 为空")
    return errors


def _signature(row: dict) -> tuple[str, str, str, str, str, str]:
    """版本级字段签名：同签名旧行合并为一个版本，不同签名拆成多个版本。"""
    return (
        str(row["regime"]),
        (_as_date(row["valid_from"]) or date.min).isoformat(),
        (_as_date(row["valid_to"]) or date.max).isoformat(),
        canonical_json(_job_codes(row["job_codes"])),
        str(row["region_code"]),
        str(row["attachment_sha256"]),
    )


def plan_migration(conn: Connection) -> MigrationPlan:
    """只读计划：把旧表行按批文/版本/员工范围重新组织，不写任何表。"""
    legacy = _legacy_rows(conn)
    employee_ids = {str(r["emp_id"]) for r in conn.execute(
        "SELECT emp_id FROM employee ORDER BY emp_id").fetchall()}
    existing_docs = {str(r["doc_no"]) for r in conn.execute(
        "SELECT doc_no FROM approval_doc ORDER BY doc_no").fetchall()}

    by_doc: dict[str, list[dict]] = {}
    for row in legacy:
        by_doc.setdefault(str(row["doc_no"]), []).append(row)

    docs: list[dict] = []
    versions: list[dict] = []
    coverage: list[dict] = []
    skipped: list[dict] = []
    merged: list[dict] = []

    for doc_no in sorted(by_doc):
        rows = by_doc[doc_no]
        valid_rows: list[dict] = []
        for row in rows:
            errors = _validate_legacy_row(row, employee_ids=employee_ids,
                                          existing_docs=existing_docs)
            if errors:
                skipped.append({"emp_id": str(row["emp_id"]), "doc_no": doc_no,
                                "reason": "；".join(errors)})
            else:
                valid_rows.append(row)
        if not valid_rows:
            continue

        # 新模型批文级只能有一个工时制；同文号多工时制无法安全表达。
        regime_counts: dict[str, int] = {}
        for row in valid_rows:
            regime_counts[str(row["regime"])] = regime_counts.get(str(row["regime"]), 0) + 1
        primary_regime = sorted(regime_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        kept: list[dict] = []
        for row in valid_rows:
            if str(row["regime"]) != primary_regime:
                skipped.append({
                    "emp_id": str(row["emp_id"]), "doc_no": doc_no,
                    "reason": (f"同文号存在多个工时制，批文级 regime 只能取 "
                               f"{primary_regime!r}；本行 {row['regime']!r} 无法进入同一批文"),
                })
            else:
                kept.append(row)

        # 同员工同批文重复行（旧 schema 有 UNIQUE，历史库可能没有约束）：
        # 只保留 recorded_at 最新的一行，其余显式丢弃，避免 COVERAGE UNIQUE 冲突。
        by_emp: dict[str, list[dict]] = {}
        for row in kept:
            by_emp.setdefault(str(row["emp_id"]), []).append(row)
        deduped: list[dict] = []
        for emp_id in sorted(by_emp):
            candidates = sorted(by_emp[emp_id],
                                key=lambda r: str(r["recorded_at"]), reverse=True)
            deduped.append(candidates[0])
            for duplicate in candidates[1:]:
                skipped.append({
                    "emp_id": emp_id, "doc_no": doc_no,
                    "reason": ("同员工同批文存在重复旧行，保留 recorded_at 最新的一行，"
                               "其余丢弃"),
                })

        groups: dict[tuple[str, str, str, str, str, str], list[dict]] = {}
        for row in deduped:
            groups.setdefault(_signature(row), []).append(row)
        ordered_groups = sorted(
            groups.items(),
            key=lambda kv: (kv[0][1], kv[0][2], kv[0][3], kv[0][4], kv[0][0]))

        doc_versions: list[dict] = []
        for version_no, (signature, group_rows) in enumerate(ordered_groups, start=1):
            regime, valid_from, valid_to, job_codes_json, region_code, attachment = signature
            published_at = max(str(r["recorded_at"]) for r in group_rows)
            emp_ids = sorted({str(r["emp_id"]) for r in group_rows})
            version = {
                "doc_no": doc_no, "version_no": version_no, "regime": regime,
                "valid_from": valid_from, "valid_to": valid_to,
                "job_codes": job_codes_json, "region_code": region_code,
                "attachment_sha256": attachment,
                "change_note": "从旧 worktime_approval 迁移",
                "published_at": published_at,
                "employee_ids": emp_ids,
            }
            doc_versions.append(version)
            versions.append(version)
            if len(group_rows) > 1:
                merged.append({
                    "doc_no": doc_no, "version_no": version_no,
                    "legacy_rows": len(group_rows), "employees": emp_ids,
                    "reason": "同文号同工时制/期限/岗位/城市/附件，合并为一个版本",
                })
            for row in group_rows:
                coverage.append({
                    "emp_id": str(row["emp_id"]),
                    "doc_no": doc_no,
                    "version_no": version_no,
                    "regime": regime,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "job_codes": job_codes_json,
                    "region_code": region_code,
                    "attachment_sha256": attachment,
                    "published_at": published_at,
                })
        docs.append({
            "doc_no": doc_no,
            "title": f"迁移批文 {doc_no}",
            "issuer": "legacy-worktime_approval",
            "regime": primary_regime,
            # 多版本批文没有单一“当前版本”，显式留空，避免 UI 误读。
            "current_version": (1 if len(doc_versions) == 1 else None),
            "versions": len(doc_versions),
        })

    plan = MigrationPlan(
        legacy_rows=len(legacy),
        legacy_docs=len(by_doc),
        legacy_employee_ids=sorted({str(r["emp_id"]) for r in legacy}),
        docs=docs,
        versions=versions,
        coverage=coverage,
        skipped=skipped,
        merged=merged,
    )
    plan.plan_digest = sha256_hex(canonical_json({
        "legacy_rows": plan.legacy_rows,
        "legacy_employee_ids": plan.legacy_employee_ids,
        "docs": plan.docs,
        "versions": plan.versions,
        "coverage": plan.coverage,
        "skipped": plan.skipped,
        "merged": plan.merged,
    }))
    return plan


def compare_reg01(conn: Connection, plan: MigrationPlan, start: date,
                  end: date) -> dict:
    """用与引擎相同的 REG-01 证据评估函数，对比 v5 旧表与迁移后 v6 覆盖投影。"""
    employees = [dict(r) for r in conn.execute(
        "SELECT emp_id, job_code, region_code, worktime_regime FROM employee "
        "ORDER BY emp_id").fetchall()]
    legacy_by_emp: dict[str, list[dict]] = {}
    for row in _legacy_rows(conn):
        legacy_by_emp.setdefault(str(row["emp_id"]), []).append(row)
    coverage_by_emp: dict[str, list[dict]] = {}
    for row in plan.coverage:
        coverage_by_emp.setdefault(str(row["emp_id"]), []).append(row)

    v5_hits: list[str] = []
    v6_hits: list[str] = []
    detail: dict[str, dict] = {}
    for emp in employees:
        emp_id = str(emp["emp_id"])
        declared = str(emp["worktime_regime"])
        if declared == REGIME_STANDARD or declared not in VALID_APPROVAL_REGIMES:
            continue
        legacy_rows = legacy_by_emp.get(emp_id, [])
        coverage_rows = coverage_by_emp.get(emp_id, [])
        v5 = evaluate_approval_evidence(
            declared_regime=declared, job_code=str(emp["job_code"]),
            region_code=str(emp["region_code"]), approvals=legacy_rows,
            start=start, end=end)
        v6 = evaluate_approval_evidence(
            declared_regime=declared, job_code=str(emp["job_code"]),
            region_code=str(emp["region_code"]), approvals=coverage_rows,
            start=start, end=end)
        if not v5.covered:
            v5_hits.append(emp_id)
        if not v6.covered:
            v6_hits.append(emp_id)
        if v5.covered != v6.covered:
            detail[emp_id] = {
                "emp_id": emp_id,
                "declared_regime": declared,
                "v5_covered": v5.covered,
                "v6_covered": v6.covered,
                "v5_reasons": v5.reasons,
                "v6_reasons": v6.reasons,
                "legacy_rows": len(legacy_rows),
                "migrated_rows": len(coverage_rows),
            }

    v5_set, v6_set = set(v5_hits), set(v6_hits)
    only_v5 = sorted(v5_set - v6_set)   # v6 比 v5 更宽松：迁移凭空扩大了覆盖，必须阻止
    only_v6 = sorted(v6_set - v5_set)   # v6 比 v5 更严格：迁移丢弃了旧证据，允许但须报告
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "evaluated_employees": len([
            e for e in employees
            if str(e["worktime_regime"]) != REGIME_STANDARD
            and str(e["worktime_regime"]) in VALID_APPROVAL_REGIMES
        ]),
        "v5_hits": v5_hits,
        "v6_hits": v6_hits,
        "v5_hits_count": len(v5_hits),
        "v6_hits_count": len(v6_hits),
        "same_hits": sorted(v5_set & v6_set),
        "only_v5": only_v5,
        "only_v6": only_v6,
        "differences": [detail[emp_id] for emp_id in sorted(detail)],
        "legacy_employee_ids": plan.legacy_employee_ids,
        "migrated_employee_ids": plan.coverage_employee_ids,
        "legacy_employees_without_coverage": sorted(
            set(plan.legacy_employee_ids) - set(plan.coverage_employee_ids)),
    }


def assert_no_widening(reg01: dict) -> None:
    """迁移不得让 v6 审批覆盖比 v5 更宽松；出现 only_v5 立即拒绝 apply。"""
    if reg01.get("only_v5"):
        raise MigrationSafetyError(
            "迁移后 v6 REG-01 覆盖比 v5 更宽松（v5 命中但 v6 未命中）："
            f"{reg01['only_v5'][:10]}；拒绝落库，先核对迁移计划。")


def apply_migration(conn: Connection, cfg: Config, plan: MigrationPlan, *,
                    actor: str = "system:migration", allow_active: bool = False) -> dict:
    """把 dry-run 计划写入 P0 四表；默认只允许临时库，旧表不动。

    `allow_active=True` 只用于显式批准的活动库切换；仍要求连接后实际库名为
    `wca_worktime`，且配置自述与实际一致。备份/确认串由 CLI 在调用前校验。
    """
    from ..evidence import append_audit, set_genesis

    if allow_active:
        actual = actual_database_identity(conn)
        if actual != ACTIVE_DATABASE_NAME:
            raise MigrationSafetyError(
                f"allow-active 实际连接 {actual!r}，不是活动库 {ACTIVE_DATABASE_NAME!r}；拒绝执行")
        ensure_config_matches_actual(cfg, actual)
    else:
        assert_temporary_database(cfg)
        actual = assert_connection_is_temporary(conn, cfg)
        ensure_config_matches_actual(cfg, actual)
    now = _now()
    written = {"docs": 0, "versions": 0, "scopes": 0, "coverage": 0,
               "skipped_existing_docs": 0}
    set_genesis(conn, cfg)
    with transaction(conn):
        # 事务内再查一次，避免两个人同时 apply 时重复建批文。
        current_docs = {str(r["doc_no"]) for r in conn.execute(
            "SELECT doc_no FROM approval_doc").fetchall()}
        for doc in plan.docs:
            doc_no = str(doc["doc_no"])
            if doc_no in current_docs:
                written["skipped_existing_docs"] += int(doc["versions"])
                continue
            cur = conn.execute(
                "INSERT INTO approval_doc(doc_no, title, issuer, regime, status, "
                "current_version, created_at, updated_at, created_by, updated_by) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING doc_id",
                (doc_no, doc["title"], doc["issuer"], doc["regime"], "PUBLISHED",
                 doc["current_version"], now, now, actor, actor))
            doc_id = int(cur.fetchone()["doc_id"])
            written["docs"] += 1
            for version in plan.versions:
                if str(version["doc_no"]) != doc_no:
                    continue
                cur = conn.execute(
                    "INSERT INTO approval_doc_version(doc_id, version_no, valid_from, "
                    "valid_to, job_codes, region_code, attachment_sha256, change_note, "
                    "status, published_at, published_by, created_at, created_by) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING version_id",
                    (doc_id, int(version["version_no"]), version["valid_from"],
                     version["valid_to"], version["job_codes"], version["region_code"],
                     version["attachment_sha256"], version["change_note"], "PUBLISHED",
                     version["published_at"], actor, now, actor))
                version_id = int(cur.fetchone()["version_id"])
                written["versions"] += 1
                for emp_id in version["employee_ids"]:
                    conn.execute(
                        "INSERT INTO approval_doc_scope(version_id, scope_type, scope_value) "
                        "VALUES(?,?,?)", (version_id, "employee", emp_id))
                    written["scopes"] += 1
                    conn.execute(
                        "INSERT INTO employee_approval_coverage(emp_id, doc_id, version_id, "
                        "doc_no, version_no, regime, valid_from, valid_to, job_codes, "
                        "region_code, attachment_sha256, published_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (emp_id, doc_id, version_id, doc_no, int(version["version_no"]),
                         version["regime"], version["valid_from"], version["valid_to"],
                         version["job_codes"], version["region_code"],
                         version["attachment_sha256"], version["published_at"]))
                    written["coverage"] += 1
        append_audit(conn, run_id=None, actor=actor, action="approval_doc.migrate",
                     payload={"source_table": "worktime_approval",
                              "legacy_rows": plan.legacy_rows,
                              "docs": written["docs"],
                              "versions": written["versions"],
                              "coverage": written["coverage"],
                              "skipped_rows": len(plan.skipped),
                              "merged_groups": len(plan.merged),
                              "plan_digest": plan.plan_digest},
                     ts=now, cfg=cfg)
    return {**written, "plan_digest": plan.plan_digest, "actor": actor}


def build_report(conn: Connection, cfg: Config, plan: MigrationPlan, start: date,
                 end: date, *, mode: str) -> dict:
    """生成 JSON 差异报告：行数、员工集合、丢弃/合并原因、REG-01 对照。"""
    reg01 = compare_reg01(conn, plan, start, end)
    return {
        "generated_at": _now(),
        "mode": mode,
        "database": cfg.safe_database_target,
        "rule_pack_id": cfg.rule_pack_id,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "plan": {
            # summary() 里保留 docs/versions/merged_groups 的**计数**，
            # 明细另用 *_details，避免报告消费者把数组误当行数。
            **plan.summary(),
            "doc_details": plan.docs,
            "version_details": plan.versions,
            "skipped": plan.skipped,
            "merged_details": plan.merged,
            "coverage_employee_ids": plan.coverage_employee_ids,
        },
        "reg01": reg01,
    }


def write_report(report: dict, path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                 encoding="utf-8")
    return p


def latest_run_window(conn: Connection) -> tuple[date, date] | None:
    """dry-run 未显式给区间时，沿用最近一次 run 的校验区间，保证 REG-01 对照同口径。"""
    row = conn.execute(
        "SELECT scope_json FROM run ORDER BY started_at DESC LIMIT 1").fetchone()
    if row is None:
        return None
    try:
        scope = json.loads(str(row["scope_json"]))
        return date.fromisoformat(str(scope["start"])), date.fromisoformat(str(scope["end"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


