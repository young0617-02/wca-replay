"""两层指纹中的“投影指纹”：只覆盖规则/引擎实际读取的字段。

为什么需要它：
  * `input_fingerprint` 绑定原始输入整包的 sha/row_count，适合证明“同一批原始字节”；
  * 但它也让任何导出副本字段裁剪都改变指纹，导致新包 replay 对不上；
  * `projection_fingerprint` 只取规则/引擎读取的字段，按固定顺序/规范化后取哈希，
    因此可以安全地把明确不读的字段从导出副本剪掉，而仍能复算结论。
  * 原始字节完整性由 `inputs_digest` + 签名负责；投影指纹不承担字节不变职责。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .db import Connection, table_exists
from .util import canonical_json, iso_minute, parse_date, parse_timestamp, sha256_hex

PROJECTION_SPEC = "wca-projection-v1"

# 字段清单依据（2026-11-03 grep/阅读证据）：
#   employee:        src/engine.py:63-85（build_scope 读取 emp_id/job_code/org_id/region_code/
#                    worktime_regime/contract_approved_flex）
#   punch:           src/rules/dayfacts.py:138-145,209-232（event_ts/punch_type/device_id）
#   punch_correction:src/rules/dayfacts.py:154-160（claimed_ts/claimed_type/approved）；
#                    reason 经 src/ingest.py:877 的 QUAL-EMPTY 进入
#                    src/rules/rulepack.py:510-531 的 QUAL-01 结论（间接字段）
#   leave_record:    src/rules/dayfacts.py:177-184
#   trip_record:     src/rules/dayfacts.py:186-192,300
#   shift_plan:      src/rules/dayfacts.py:167-172,263-265
#   worktime_approval / employee_approval_coverage: src/rules/approvals.py:37-43,176-183
#   ingest_issue:    src/engine.py:106-110；src/rules/rulepack.py:510-555
#
# 未覆盖（engine SELECT 但未参与结论，故不进投影）：
#   employee.pseudonym、normal_hourly_cents、pay_base_*、is_manager、acl_scope；
#   approval.recorded_at/version_no/published_at、org_unit.parent_id/org_name；
#   raw_file.file_id / ingest_issue.file_id 是数据库分配序号，不作为业务字段；
#   QUAL-01/02 的 line_refs 改用包内 rel_path + line_no，OFF-01 conflicts.sources 同样
#   不再暴露 file_id；DB file_id 只留在 source_refs/内部查询，不进 canonical。
PROJECTION_TABLE_FIELDS: dict[str, tuple[str, ...]] = {
    "employee": ("emp_id", "job_code", "org_id", "region_code", "worktime_regime",
                 "contract_approved_flex"),
    "punch": ("emp_id", "event_ts", "punch_type", "device_id"),
    "punch_correction": ("emp_id", "claimed_ts", "claimed_type", "reason", "approved"),
    "leave_record": ("emp_id", "leave_kind", "start_ts", "end_ts", "approved"),
    "trip_record": ("emp_id", "start_ts", "end_ts"),
    "shift_plan": ("emp_id", "work_date", "planned_start", "planned_end", "rest_minutes"),
    "worktime_approval": ("emp_id", "doc_no", "regime", "valid_from", "valid_to",
                          "job_codes", "region_code", "attachment_sha256"),
    "employee_approval_coverage": ("emp_id", "doc_no", "regime", "valid_from", "valid_to",
                                   "job_codes", "region_code", "attachment_sha256"),
    "ingest_issue": ("rule_id", "severity", "emp_id", "work_date", "field_name",
                     "raw_value", "line_no"),
}

# 排序不是“字段列表”的一部分，但必须固定，否则同数据不同插入顺序会导致不同指纹。
PROJECTION_TABLE_ORDER = {
    "employee": "emp_id",
    "punch": "emp_id, event_ts, punch_type, COALESCE(device_id, '')",
    "punch_correction": "emp_id, claimed_ts, claimed_type, COALESCE(reason, ''), approved",
    "leave_record": "emp_id, leave_kind, start_ts, end_ts, approved",
    "trip_record": "emp_id, start_ts, end_ts",
    "shift_plan": "emp_id, work_date, planned_start, planned_end, rest_minutes",
    "worktime_approval": "emp_id, doc_no, regime, valid_from, valid_to",
    "employee_approval_coverage": "emp_id, doc_no, version_no, regime, valid_from, valid_to",
    "ingest_issue": "COALESCE(line_no, -1), rule_id, field_name",
}

PROJECTION_TIME_FIELDS = {
    ("punch", "event_ts"),
    ("punch_correction", "claimed_ts"),
    ("leave_record", "start_ts"), ("leave_record", "end_ts"),
    ("trip_record", "start_ts"), ("trip_record", "end_ts"),
    ("shift_plan", "planned_start"), ("shift_plan", "planned_end"),
}
PROJECTION_DATE_FIELDS = {
    ("shift_plan", "work_date"),
    ("worktime_approval", "valid_from"), ("worktime_approval", "valid_to"),
    ("employee_approval_coverage", "valid_from"), ("employee_approval_coverage", "valid_to"),
}
PROJECTION_INT_FIELDS = {
    ("employee", "contract_approved_flex"),
    ("punch_correction", "approved"), ("leave_record", "approved"),
    ("shift_plan", "rest_minutes"),
    ("ingest_issue", "line_no"),
}
PROJECTION_JSON_LIST_FIELDS = {
    ("worktime_approval", "job_codes"),
    ("employee_approval_coverage", "job_codes"),
}
PROJECTION_SHA_FIELDS = {
    ("worktime_approval", "attachment_sha256"),
    ("employee_approval_coverage", "attachment_sha256"),
}

# 字段清单无法只用“直接 SQL 读取”覆盖的间接字段；标记用于测试/文档核对。
PROJECTION_INDIRECT_FIELDS = {
    ("punch_correction", "reason"): "QUAL-EMPTY",
}

# 输入文件 kind -> 投影列。用于拒绝“把投影字段从导出副本剪掉”。
PROJECTION_INPUT_FIELDS: dict[str, set[str]] = {
    "employee": set(PROJECTION_TABLE_FIELDS["employee"]),
    "punch": set(PROJECTION_TABLE_FIELDS["punch"]),
    "punch_correction": set(PROJECTION_TABLE_FIELDS["punch_correction"]),
    "leave": set(PROJECTION_TABLE_FIELDS["leave_record"]),
    "trip": set(PROJECTION_TABLE_FIELDS["trip_record"]),
    "correction": set(PROJECTION_TABLE_FIELDS["punch_correction"]),
    "schedule": set(PROJECTION_TABLE_FIELDS["shift_plan"]),
    "org": {"org_id"},
    "approval": (set(PROJECTION_TABLE_FIELDS["worktime_approval"])
                 | set(PROJECTION_TABLE_FIELDS["employee_approval_coverage"])),
}

# 当前导入器真正可选的字段。其余“非投影字段”仍被导入校验/表结构要求，不能剪。
OMITTABLE_FIELDS = {("leave", "paid")}
OMITTED_REASON = "非投影字段；导入可选，不影响规则结论"


def normalize_omit_fields(values: Any) -> tuple[tuple[str, str], ...]:
    """接受 {"leave:paid"} / ("leave.csv:paid",) 等；只允许当前可安全裁剪的字段。"""
    out: set[tuple[str, str]] = set()
    for raw in values or ():
        text = str(raw).strip()
        if ":" not in text:
            raise ValueError(f"omit_fields 格式应为 kind:field（例如 leave:paid）：{raw!r}")
        kind, field = (part.strip() for part in text.split(":", 1))
        if kind.endswith(".csv"):
            kind = kind[:-4]
        if kind not in PROJECTION_INPUT_FIELDS:
            raise ValueError(f"未知输入种类：{kind}")
        if field in PROJECTION_INPUT_FIELDS[kind]:
            raise ValueError(
                f"投影字段不能从导出副本裁剪：{kind}.{field}（删掉会让 replay 的投影指纹变化）")
        if (kind, field) not in OMITTABLE_FIELDS:
            raise ValueError(
                f"字段 {kind}.{field} 当前不能安全裁剪：导入器仍要求该列或会影响回放；"
                f"请先改导入/指纹设计")
        out.add((kind, field))
    return tuple(sorted(out))


def _normalize_value(table: str, field: str, value: Any) -> Any:
    if value is None:
        return None
    if (table, field) in PROJECTION_TIME_FIELDS:
        return iso_minute(parse_timestamp(value))
    if (table, field) in PROJECTION_DATE_FIELDS:
        return parse_date(value).isoformat()
    if (table, field) in PROJECTION_INT_FIELDS:
        return int(value)
    if (table, field) in PROJECTION_JSON_LIST_FIELDS:
        parsed = json.loads(str(value))
        if not isinstance(parsed, list):
            raise ValueError(f"{table}.{field} 不是 JSON 数组")
        return sorted(str(x) for x in parsed)
    if (table, field) in PROJECTION_SHA_FIELDS:
        return str(value).strip().lower()
    return str(value)


FILE_LINKED_TABLES = {
    "punch": "source_file_id",
    "punch_correction": "source_file_id",
    "leave_record": "source_file_id",
    "trip_record": "source_file_id",
    "shift_plan": "source_file_id",
    "ingest_issue": "file_id",
}
EMP_FILTERED_TABLES = {
    "employee", "worktime_approval", "employee_approval_coverage",
}


def _table_rows(conn: Connection, table: str, rel_paths: set[str] | None,
                emp_ids: list[str] | None) -> list[list[Any]]:
    fields = PROJECTION_TABLE_FIELDS[table]
    order = PROJECTION_TABLE_ORDER[table]
    clauses: list[str] = []
    params: list[Any] = []
    if rel_paths is not None:
        paths = sorted(str(p) for p in rel_paths)
        if table in FILE_LINKED_TABLES:
            link = FILE_LINKED_TABLES[table]
            clauses.append(
                f"{link} IN (SELECT file_id FROM raw_file WHERE rel_path IN ("
                + ",".join("?" * len(paths)) + "))")
            params.extend(paths)
    if emp_ids is not None and table in EMP_FILTERED_TABLES:
        ids = sorted({str(x) for x in emp_ids if str(x)})
        if ids:
            clauses.append("emp_id IN (" + ",".join("?" * len(ids)) + ")")
            params.extend(ids)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT {', '.join(fields)} FROM {table}{where} ORDER BY {order}",
        tuple(params)).fetchall()
    return [[_normalize_value(table, field, row[field]) for field in fields] for row in rows]


def _active_tables(rule_pack_version: str) -> set[str]:
    """只投影当前规则包实际读取的审批表；避免 v6 把旧 worktime_approval 也算进去。"""
    from .rules.rulepack import RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6

    tables = set(PROJECTION_TABLE_FIELDS)
    if rule_pack_version == RULE_PACK_V6:
        tables.discard("worktime_approval")
    elif rule_pack_version == RULE_PACK_V5:
        tables.discard("employee_approval_coverage")
    elif rule_pack_version == RULE_PACK_V4:
        tables.discard("worktime_approval")
        tables.discard("employee_approval_coverage")
    return tables


def projection_payload(conn: Connection, scope: dict, rule_pack_version: str,
                       *, rel_paths: set[str] | None = None,
                       emp_ids: list[str] | None = None) -> dict:
    """投影的规范结构；排序/时间/空值都在这里固定。

    `rel_paths` 限定本次包内输入文件（按 raw_file.rel_path 关联事实/质量表）；
    `emp_ids` 限定本次 run 员工（employee/审批表）。两者都不传时取全库，仅供
    单测/无 run 场景；导出/重放必须显式传入，避免把其他 run 的行算进投影。
    """
    tables: dict[str, list[list[Any]]] = {}
    for table in _active_tables(rule_pack_version):
        if table_exists(conn, table):
            tables[table] = _table_rows(conn, table, rel_paths, emp_ids)
    return {
        "spec": PROJECTION_SPEC,
        "rule_pack_version": str(rule_pack_version),
        "scope": scope,
        "tables": tables,
    }


def projection_fingerprint(conn: Connection, scope: dict, rule_pack_version: str,
                           *, rel_paths: set[str] | None = None,
                           emp_ids: list[str] | None = None) -> str:
    return sha256_hex(canonical_json(projection_payload(
        conn, scope, rule_pack_version, rel_paths=rel_paths, emp_ids=emp_ids)))


def projection_input_fields(kind: str) -> set[str]:
    return set(PROJECTION_INPUT_FIELDS.get(kind, set()))
