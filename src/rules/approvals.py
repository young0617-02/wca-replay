"""特殊工时审批台账（v5 REG-01 的最小证据读取与核验）。

台账只回答“有没有可核验的审批证据”，不改变 `regime.decide` 的 effective_regime：
缺文号/过期/岗位不符/城市不符一律最多「需复核」，不产生违规、倍数或金额。
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from ..db import Connection, transaction
from ..util import canonical_json, csv_safe_cell, csv_unescape_cell, sha256_hex
from .regime import CYCLE_DAYS, REGIME_FLEXIBLE

APPROVAL_FIELDS = ("emp_id", "doc_no", "regime", "valid_from", "valid_to", "job_codes",
                   "region_code", "attachment_sha256", "recorded_at")
COVERAGE_FIELDS = ("emp_id", "doc_no", "version_no", "regime", "valid_from", "valid_to",
                   "job_codes", "region_code", "attachment_sha256", "published_at")
VALID_APPROVAL_REGIMES = tuple(CYCLE_DAYS) + (REGIME_FLEXIBLE,)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class ApprovalEvidence:
    covered: bool
    reasons: list[str] = field(default_factory=list)
    selected: dict[str, Any] = field(default_factory=dict)
    checked: int = 0


def load_approvals(conn: Connection, emp_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT approval_id, emp_id, doc_no, regime, valid_from, valid_to, job_codes, "
        "region_code, attachment_sha256, recorded_at FROM worktime_approval "
        "WHERE emp_id = ? ORDER BY valid_to DESC, doc_no", (emp_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def _ledger_rows(conn: Connection, emp_ids: list[str]) -> list[dict]:
    ids = sorted({str(e) for e in emp_ids if str(e)})
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    fetched = conn.execute(
        f"SELECT {', '.join(APPROVAL_FIELDS)} FROM worktime_approval "
        f"WHERE emp_id IN ({placeholders}) ORDER BY emp_id, doc_no, regime",
        ids,
    ).fetchall()
    return [{k: r[k] for k in APPROVAL_FIELDS} for r in fetched]


def _ledger_digest_of(rows: list[dict]) -> str:
    return sha256_hex(canonical_json({"approval_ledger": rows}))


def approval_ledger_digest(conn: Connection, emp_ids: list[str]) -> str:
    """审批台账指纹：v5 的结论依赖它，输入指纹必须能感知台账变化。"""
    return _ledger_digest_of(_ledger_rows(conn, emp_ids))


def validate_approval_record(record: dict) -> list[str]:
    """最小录入校验：文号、期限、岗位范围、城市、附件哈希与工时制都要可核验。"""
    errors: list[str] = []
    if not str(record.get("emp_id") or "").strip():
        errors.append("员工 emp_id 不能为空")
    if not str(record.get("doc_no") or "").strip():
        errors.append("审批文号缺失")
    regime = str(record.get("regime") or "").strip()
    if regime not in VALID_APPROVAL_REGIMES:
        errors.append(f"审批工时制 {regime!r} 不在允许范围 {list(VALID_APPROVAL_REGIMES)}")
    start = _as_date(record.get("valid_from"))
    end = _as_date(record.get("valid_to"))
    if start is None or end is None:
        errors.append("审批期限缺失或无法解析（需要 YYYY-MM-DD）")
    elif start > end:
        errors.append(f"审批期限起点 {start} 晚于终点 {end}")
    if not _job_scope(record.get("job_codes")):
        errors.append("审批岗位范围缺失（job_codes 至少一项）")
    if not str(record.get("region_code") or "").strip():
        errors.append("审批城市缺失")
    sha = str(record.get("attachment_sha256") or "").strip()
    if not _SHA256_RE.match(sha):
        errors.append("审批附件哈希缺失或不是 64 位十六进制 sha256")
    if not str(record.get("recorded_at") or "").strip():
        errors.append("审批登记时间缺失")
    return errors


def upsert_approval(conn: Connection, record: dict) -> dict:
    errors = validate_approval_record(record)
    if errors:
        raise ValueError("审批台账校验失败：" + "；".join(errors))
    conn.execute(
        "INSERT INTO worktime_approval(emp_id, doc_no, regime, valid_from, valid_to, "
        "job_codes, region_code, attachment_sha256, recorded_at) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(emp_id, doc_no) DO UPDATE SET regime = excluded.regime, "
        "valid_from = excluded.valid_from, valid_to = excluded.valid_to, "
        "job_codes = excluded.job_codes, region_code = excluded.region_code, "
        "attachment_sha256 = excluded.attachment_sha256, recorded_at = excluded.recorded_at",
        tuple(str(record.get(k) or "") for k in APPROVAL_FIELDS),
    )
    return {k: record.get(k) for k in APPROVAL_FIELDS}


def export_approval_csv(conn: Connection, emp_ids: list[str], path: Path) -> dict:
    """把本次 run 范围内的审批台账导出为确定性 CSV（不含 approval_id）。"""
    rows = _ledger_rows(conn, emp_ids)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(APPROVAL_FIELDS), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: csv_safe_cell(row[k]) for k in APPROVAL_FIELDS})
    data = path.read_bytes()
    return {"path": path, "rows": len(rows), "sha256": sha256_hex(data),
            "bytes": len(data), "digest": _ledger_digest_of(rows)}


def import_approval_csv(conn: Connection, path: Path | str, *,
                        unescape_formula: bool = False) -> int:
    """校验后整批导入；任一行不合法即拒绝全部，不写半份台账。

    `unescape_formula` 只由举证包重放显式开启：包内 CSV 按导出约定加了 `'` 防护前缀，
    重放时必须还原为原始台账值，否则输入指纹会变。用户上传路径保持默认 False。
    """
    p = Path(path)
    with p.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        missing = [f for f in APPROVAL_FIELDS if f not in header]
        if missing:
            raise ValueError(f"审批台账 CSV 缺列：{missing}")
        records, errors = [], []
        for line_no, row in enumerate(reader, start=2):
            record = {k: str(row.get(k) or "") for k in APPROVAL_FIELDS}
            if unescape_formula:
                record = {k: str(csv_unescape_cell(v)) for k, v in record.items()}
            row_errors = validate_approval_record(record)
            if row_errors:
                errors.append(f"第 {line_no} 行：" + "；".join(row_errors))
            records.append(record)
    if errors:
        raise ValueError("审批台账 CSV 校验失败：" + " | ".join(errors))
    with transaction(conn):
        for record in records:
            upsert_approval(conn, record)
    return len(records)


def _coverage_rows(conn: Connection, emp_ids: list[str]) -> list[dict]:
    ids = sorted({str(e) for e in emp_ids if str(e)})
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    fetched = conn.execute(
        f"SELECT {', '.join(COVERAGE_FIELDS)} FROM employee_approval_coverage "
        f"WHERE emp_id IN ({placeholders}) "
        f"ORDER BY emp_id, doc_no, version_no, valid_from",
        ids,
    ).fetchall()
    return [{k: r[k] for k in COVERAGE_FIELDS} for r in fetched]


def coverage_ledger_digest(conn: Connection, emp_ids: list[str]) -> str:
    """v6 输入指纹：覆盖投影按员工/批文/版本/生效期/范围/附件/发布时间确定性摘要。"""
    return sha256_hex(canonical_json({"approval_coverage": _coverage_rows(conn, emp_ids)}))


def load_coverage_approvals(conn: Connection, emp_id: str) -> list[dict]:
    """v6 REG-01 只读 P0 覆盖投影，映射成与旧台账相同的 evidence 字段。"""
    rows = conn.execute(
        f"SELECT {', '.join(COVERAGE_FIELDS)} FROM employee_approval_coverage "
        f"WHERE emp_id = ? ORDER BY valid_to DESC, doc_no, version_no", (emp_id,)
    ).fetchall()
    return [{**{k: r[k] for k in COVERAGE_FIELDS}, "recorded_at": r["published_at"]}
            for r in rows]


def export_coverage_csv(conn: Connection, emp_ids: list[str], path: Path) -> dict:
    """v6 包内 inputs/000-approval.csv：来源是覆盖投影，不是旧 worktime_approval。"""
    rows = _coverage_rows(conn, emp_ids)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(COVERAGE_FIELDS), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: csv_safe_cell(row[k]) for k in COVERAGE_FIELDS})
    data = path.read_bytes()
    return {"path": path, "rows": len(rows), "sha256": sha256_hex(data),
            "bytes": len(data),
            "digest": sha256_hex(canonical_json({"approval_coverage": rows}))}


def import_coverage_csv(conn: Connection, path: Path | str, *,
                        unescape_formula: bool = False) -> int:
    """v6 重放：从覆盖 CSV 重建批文/版本/员工覆盖投影。

    `unescape_formula` 语义同 `import_approval_csv`：只由包内重放显式开启。
    """
    p = Path(path)
    with p.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        missing = [f for f in COVERAGE_FIELDS if f not in header]
        if missing:
            raise ValueError(f"覆盖投影 CSV 缺列：{missing}")
        rows = [{k: str(row.get(k) or "") for k in COVERAGE_FIELDS} for row in reader]
    if unescape_formula:
        rows = [{k: str(csv_unescape_cell(v)) for k, v in row.items()} for row in rows]
    if not rows:
        raise ValueError("覆盖投影 CSV 没有数据行")
    now = rows[0]["published_at"] or "replay"
    with transaction(conn):
        for line_no, row in enumerate(rows, start=2):
            errors: list[str] = []
            if not row["emp_id"] or not row["doc_no"]:
                errors.append("emp_id/doc_no 不能为空")
            if row["regime"] not in VALID_APPROVAL_REGIMES:
                errors.append(f"regime {row['regime']!r} 不合法")
            if _as_date(row["valid_from"]) is None or _as_date(row["valid_to"]) is None:
                errors.append("valid_from/valid_to 无法解析")
            if not _SHA256_RE.match(row["attachment_sha256"]):
                errors.append("attachment_sha256 不是 64 位 sha256")
            if not row["published_at"]:
                errors.append("published_at 缺失")
            if errors:
                raise ValueError(f"第 {line_no} 行：" + "；".join(errors))
            doc = conn.execute("SELECT doc_id, regime FROM approval_doc WHERE doc_no = ?",
                               (row["doc_no"],)).fetchone()
            if doc is None:
                cur = conn.execute(
                    "INSERT INTO approval_doc(doc_no, title, issuer, regime, status, "
                    "current_version, created_at, updated_at, created_by, updated_by) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING doc_id",
                    (row["doc_no"], f"重放覆盖投影 {row['doc_no']}", "replay", row["regime"],
                     "PUBLISHED", int(row["version_no"]), now, now, "replay", "replay"))
                doc_id = int(cur.fetchone()["doc_id"])
            else:
                doc_id = int(doc["doc_id"])
                if str(doc["regime"]) != row["regime"]:
                    raise ValueError(f"第 {line_no} 行：批文 {row['doc_no']} 的工时制不一致")
            ver = conn.execute(
                "SELECT version_id FROM approval_doc_version WHERE doc_id = ? AND version_no = ?",
                (doc_id, int(row["version_no"]))).fetchone()
            if ver is None:
                cur = conn.execute(
                    "INSERT INTO approval_doc_version(doc_id, version_no, valid_from, valid_to, "
                    "job_codes, region_code, attachment_sha256, change_note, status, "
                    "published_at, published_by, created_at, created_by) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING version_id",
                    (doc_id, int(row["version_no"]), row["valid_from"], row["valid_to"],
                     row["job_codes"], row["region_code"], row["attachment_sha256"],
                     "replay coverage", "PUBLISHED", row["published_at"], "replay", now, "replay"))
                version_id = int(cur.fetchone()["version_id"])
            else:
                version_id = int(ver["version_id"])
            conn.execute(
                "INSERT INTO employee_approval_coverage(emp_id, doc_id, version_id, doc_no, "
                "version_no, regime, valid_from, valid_to, job_codes, region_code, "
                "attachment_sha256, published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["emp_id"], doc_id, version_id, row["doc_no"], int(row["version_no"]),
                 row["regime"], row["valid_from"], row["valid_to"], row["job_codes"],
                 row["region_code"], row["attachment_sha256"], row["published_at"]))
            conn.execute(
                "INSERT INTO approval_doc_scope(version_id, scope_type, scope_value) "
                "VALUES(?,?,?) ON CONFLICT(version_id, scope_type, scope_value) DO NOTHING",
                (version_id, "employee", row["emp_id"]))
    return len(rows)


def _as_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _job_scope(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [str(x).strip() for x in data] if isinstance(data, list) else []


def _reasons_for(row: dict, *, declared_regime: str, job_code: str, region_code: str,
                 start: date, end: date) -> list[str]:
    reasons: list[str] = []
    if not str(row.get("doc_no") or "").strip():
        reasons.append("审批文号缺失")
    if str(row.get("regime") or "") != declared_regime:
        reasons.append(f"审批工时制 {row.get('regime')!r} 与申报 {declared_regime!r} 不一致")
    valid_from = _as_date(row.get("valid_from"))
    valid_to = _as_date(row.get("valid_to"))
    if valid_from is None or valid_to is None:
        reasons.append("审批期限缺失或无法解析")
    elif valid_from > start or valid_to < end:
        reasons.append(
            f"审批期限 {valid_from}~{valid_to} 未完整覆盖本次校验区间 {start}~{end}")
    scopes = _job_scope(row.get("job_codes"))
    if not scopes:
        reasons.append("审批岗位范围未登记")
    elif job_code not in scopes:
        reasons.append(f"岗位 {job_code} 不在审批岗位范围 {scopes}")
    approval_region = str(row.get("region_code") or "").strip()
    if not approval_region:
        reasons.append("审批城市未登记")
    elif approval_region != region_code:
        reasons.append(f"审批城市 {approval_region} 与员工城市 {region_code} 不符")
    if not str(row.get("attachment_sha256") or "").strip():
        reasons.append("审批附件哈希缺失，无法核验原件")
    return reasons


def evaluate_approval_evidence(declared_regime: str, job_code: str, region_code: str,
                               approvals: list[dict], start: date | None,
                               end: date | None) -> ApprovalEvidence:
    """逐行核验；任一行完整通过即视为已覆盖，否则返回最接近的一行的问题清单。"""
    if declared_regime == "standard":
        return ApprovalEvidence(True, [], {}, 0)
    if start is None or end is None:
        return ApprovalEvidence(False, ["校验区间缺失，无法核对审批期限覆盖"], {}, 0)
    if not approvals:
        return ApprovalEvidence(
            False,
            ["审批台账缺失：未登记文号、期限、岗位范围、城市、附件哈希"],
            {}, 0,
        )
    evaluated = []
    for row in approvals:
        reasons = _reasons_for(row, declared_regime=declared_regime, job_code=job_code,
                               region_code=region_code, start=start, end=end)
        if not reasons:
            return ApprovalEvidence(True, [], row, len(approvals))
        evaluated.append((row, reasons))
    # 选择 valid_to 最晚的一行解释问题；没有合法日期时用最后一行，保证确定性
    best_row, best_reasons = evaluated[0]
    best_to = _as_date(best_row.get("valid_to")) or date.min
    for row, reasons in evaluated[1:]:
        row_to = _as_date(row.get("valid_to")) or date.min
        if row_to > best_to:
            best_row, best_reasons, best_to = row, reasons, row_to
    return ApprovalEvidence(False, best_reasons, best_row, len(approvals))
