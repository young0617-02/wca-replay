"""F-003 导入器 + F-004 数据质量门禁。

三条硬规矩（auscult ISS-031 的教训直接迁过来）：
  1. 每一行都带 (file_id, line_no) 与文件 sha256，任何结论都能反查到原始行（A7）；
  2. 非字符串入参（None / int / bytes / dict / float('nan') / 布尔）绝不允许把导入流程打崩，
     只能落成一条 QUAL-ENC 记录并被跳过；
  3. 幂等键 = (rel_path, sha256)：同一个文件重复导入不会产生重复事实，只留一条重跑痕迹。
"""

from __future__ import annotations

import csv
import io
import sqlite3
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping

from .config import Config
from .db import transaction
from .evidence import append_audit
from .rules.dayfacts import _anchor_day
from .util import CN_TZ, parse_date, parse_timestamp, sha256_hex, iso_minute

KINDS = ("org", "employee", "punch", "leave", "trip", "correction", "schedule")

REQUIRED_COLUMNS: dict[str, list[str]] = {
    "org": ["org_id", "org_name"],
    "punch": ["emp_id", "event_ts", "punch_type"],
    "leave": ["emp_id", "leave_kind", "start_ts", "end_ts"],
    "trip": ["emp_id", "destination", "start_ts", "end_ts"],
    "correction": ["emp_id", "claimed_ts", "claimed_type", "reason"],
    "schedule": ["emp_id", "work_date", "planned_start", "planned_end"],
    "employee": ["emp_id", "pseudonym", "job_code", "org_id", "region_code",
                 "worktime_regime", "normal_hourly_cents"],
}

SEV_REJECT = "REJECT"
SEV_DEFENSIBLE = "DEFENSIBLE"
SEV_REVIEW = "REVIEW"


@dataclass
class Issue:
    rule_id: str
    severity: str
    line_no: int | None
    field_name: str
    raw_value: str
    detail: str
    emp_id: str = ""          # O-2：导入期尽力归属；归属不了的留空，由引擎出「未归属」结论
    work_date: str = ""

    def as_row(self, file_id: int, created_at: str) -> tuple:
        return (file_id, self.line_no if self.line_no is not None else 0, self.rule_id,
                self.emp_id, self.work_date, self.severity, self.field_name, self.raw_value,
                self.detail, created_at)


@dataclass
class ImportResult:
    file_id: int
    rel_path: str
    sha256: str
    kind: str
    rows_seen: int = 0
    rows_accepted: int = 0
    rows_rejected: int = 0
    issues: list[Issue] = field(default_factory=list)
    reimported: bool = False
    unattributed: int = 0
    idempotency_key: str = ""

    def summary(self) -> dict:
        return {
            "file": self.rel_path, "kind": self.kind, "sha256": self.sha256[:16],
            "rows_seen": self.rows_seen, "accepted": self.rows_accepted,
            "rejected": self.rows_rejected, "issues": len(self.issues),
            "reimported": self.reimported, "unattributed": self.unattributed,
        }


# ------------------------------------------------------------------ 畸形入参守卫
def _cell(value: Any, *, field_name: str) -> tuple[str, Issue | None]:
    """把任意 Python 对象安全地取成字符串。永远不抛异常打断导入。"""
    if value is None:
        return "", Issue("QUAL-EMPTY", SEV_REJECT, None, field_name, "None", "单元格为 None，视为缺失")
    if isinstance(value, str):
        return value.strip(), None
    if isinstance(value, bool):
        # bool 是 int 的子类，必须先判 bool，否则 True 会被当成 1 写进时间字段
        return "true" if value else "false", Issue(
            "QUAL-ENC", SEV_REJECT, None, field_name, repr(value), "布尔值不是合法的文本单元格")
    if isinstance(value, float):
        if value != value:  # NaN
            return "", Issue("QUAL-ENC", SEV_REJECT, None, field_name, "nan", "NaN 入参已拒绝")
        if value in (float("inf"), float("-inf")):
            return "", Issue("QUAL-ENC", SEV_REJECT, None, field_name, repr(value), "无穷大入参已拒绝")
        return repr(value), Issue("QUAL-ENC", SEV_DEFENSIBLE, None, field_name, repr(value),
                                  "浮点单元格：判定链不使用浮点，此处仅原样留痕")
    if isinstance(value, int):
        return str(value), None
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8").strip(), None
        except UnicodeDecodeError:
            return "", Issue("QUAL-ENC", SEV_REJECT, None, field_name,
                             repr(value[:32]), "非 UTF-8 字节序列，已拒绝")
    return "", Issue("QUAL-ENC", SEV_REJECT, None, field_name, f"<{type(value).__name__}>",
                     f"非字符串/非数字类型 {type(value).__name__}，已拒绝且不中断导入")


def _ts_of(value: str, *, field_name: str, line_no: int) -> tuple[str, list[Issue]]:
    issues: list[Issue] = []
    text, cell_issue = _cell(value, field_name=field_name)
    if cell_issue:
        cell_issue.line_no = line_no
        return "", [cell_issue]
    if not text:
        issues.append(Issue("QUAL-EMPTY", SEV_REJECT, line_no, field_name, "", "时间字段为空"))
        return "", issues
    naive = "T" not in text and ("+" not in text and "Z" not in text and "-" not in text[10:])
    try:
        dt = parse_timestamp(text)
    except (ValueError, TypeError) as exc:
        issues.append(Issue("QUAL-TS", SEV_REJECT, line_no, field_name, text, f"时间格式无法识别：{exc}"))
        return "", issues
    if naive:
        issues.append(Issue("QUAL-TZ", SEV_DEFENSIBLE, line_no, field_name, text,
                            "时间戳无时区标记，按 +08:00（北京时间）补齐后入库"))
    return iso_minute(dt), issues


# ------------------------------------------------------------------ 文件入口
def import_csv_file(conn: sqlite3.Connection, cfg: Config, path: Path | str, *,
                    kind: str | None = None, actor: str = "system:ingest",
                    created_at: str | None = None) -> ImportResult:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"待导入文件不存在: {p}")
    raw = p.read_bytes()
    text = raw.decode("utf-8-sig", errors="replace")
    digest = sha256_hex(raw)
    rel = _rel_path(p, cfg)
    kind = kind or _guess_kind(rel)
    if kind not in KINDS:
        raise ValueError(f"未知数据类型 kind={kind!r}，可选 {KINDS}")

    reader = csv.DictReader(io.StringIO(text))
    header = list(reader.fieldnames or [])
    header_digest = sha256_hex("|".join(header).encode("utf-8"))
    created_at = created_at or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")

    missing = [c for c in REQUIRED_COLUMNS[kind] if c not in header]
    file_id = _register_file(conn, rel, digest, kind, header_digest, created_at, len(header))
    if missing:
        issue = Issue("QUAL-HDR", SEV_REJECT, 1, "header", ",".join(missing),
                      f"表头缺少必需列 {missing}，整个文件被拒收")
        issue.emp_id = ""  # 文件级问题，归属不到人
        _record_issues(conn, file_id, [issue], created_at)
        append_audit(conn, run_id=None, actor=actor, action="ingest.reject_file",
                     payload={"rel_path": rel, "sha256": digest, "reason": "missing_columns",
                              "columns": missing}, cfg=cfg)
        return ImportResult(file_id=file_id, rel_path=rel, sha256=digest, kind=kind,
                            rows_seen=0, rows_rejected=0, issues=[issue])

    rows: list[dict[str, Any]] = []
    for r in reader:
        rows.append(r)
    result = _ingest_rows(conn, cfg, file_id=file_id, kind=kind, rows=rows, actor=actor,
                          rel_path=rel, digest=digest, created_at=created_at, start_line=2)
    return result


def import_rows(conn: sqlite3.Connection, cfg: Config, kind: str, rows: Iterable[Mapping[str, Any]],
                *, rel_path: str = "inline://adhoc", actor: str = "system:ingest",
                created_at: str | None = None,
                header: list[str] | None = None) -> ImportResult:
    """程序化入口（测试与 API 走这里）。与 CSV 入口共用同一套门禁，不额外放宽。"""
    if kind not in KINDS:
        raise ValueError(f"未知数据类型 kind={kind!r}")
    seq = list(rows)
    digest = sha256_hex(_safe_repr(seq))
    created_at = created_at or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    header_digest = sha256_hex("|".join(header or (list(seq[0].keys()) if seq else [])).encode())
    file_id = _register_file(conn, rel_path, digest, kind, header_digest, created_at, len(seq))
    return _ingest_rows(conn, cfg, file_id=file_id, kind=kind, rows=seq, actor=actor,
                        rel_path=rel_path, digest=digest, created_at=created_at, start_line=1)


def _safe_repr(seq: list) -> bytes:
    buf = []
    for r in seq:
        buf.append({k: (v if isinstance(v, (str, int)) else type(v).__name__ + ":" + str(v))
                    for k, v in dict(r).items()})
    return repr(sorted(buf, key=lambda x: str(x))).encode("utf-8", errors="replace")


def _guess_kind(rel: str) -> str:
    low = Path(rel).name.lower()
    for kind in KINDS:
        if kind in low or low.startswith(kind):
            return kind
    raise ValueError(f"无法从文件名推断数据类型：{rel}；请显式传 kind={KINDS}")


def _rel_path(p: Path, cfg: Config) -> str:
    try:
        return p.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return p.name


def _register_file(conn: sqlite3.Connection, rel: str, digest: str, kind: str,
                   header_digest: str, created_at: str, row_count: int) -> int:
    """幂等键 (rel_path, sha256)：命中则复用 file_id 并清空派生行，绝不重复登记事实。"""
    existing = conn.execute(
        "SELECT file_id FROM raw_file WHERE rel_path = ? AND sha256 = ?", (rel, digest)
    ).fetchone()
    if existing:
        file_id = int(existing["file_id"])
        _purge_file_rows(conn, file_id)
        conn.execute("UPDATE raw_file SET row_count = ?, imported_at = ? WHERE file_id = ?",
                     (row_count, created_at, file_id))
        return file_id
    cur = conn.execute(
        "INSERT INTO raw_file(rel_path, sha256, kind, row_count, header_sha256, imported_at) "
        "VALUES(?,?,?,?,?,?)",
        (rel, digest, kind, row_count, header_digest, created_at),
    )
    return int(cur.lastrowid)


def _purge_file_rows(conn: sqlite3.Connection, file_id: int) -> None:
    table_by_kind = {
        "punch": "punch", "leave": "leave_record", "trip": "trip_record",
        "correction": "punch_correction", "schedule": "shift_plan",
    }
    # org / employee 是主数据：重复导入走 UPSERT，不做级联删除
    for table in table_by_kind.values():
        conn.execute(f"DELETE FROM {table} WHERE source_file_id = ?", (file_id,))
    conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
    # employee 是主数据，重复导入直接 UPSERT，不做删除（避免级联清掉历史事实）


def _ingest_rows(conn: sqlite3.Connection, cfg: Config, *, file_id: int, kind: str,
                 rows: list, actor: str, rel_path: str, digest: str, created_at: str,
                 start_line: int) -> ImportResult:
    result = ImportResult(file_id=file_id, rel_path=rel_path, sha256=digest, kind=kind,
                          idempotency_key=f"{rel_path}#{digest[:16]}")
    handler = {
        "org": _row_org,
        "punch": _row_punch, "leave": _row_leave, "trip": _row_trip,
        "correction": _row_correction, "schedule": _row_schedule, "employee": _row_employee,
    }[kind]

    seen_keys: set[tuple] = set()
    with transaction(conn):
        for offset, raw in enumerate(rows):
            line_no = start_line + offset
            result.rows_seen += 1
            issues: list[Issue] = []
            try:
                payload, row_issues = handler(conn, cfg, raw, line_no, seen_keys, file_id)
            except Exception as exc:  # 兜底：任何一行都不允许打断整个导入
                payload, row_issues = None, [Issue("QUAL-CRASH", SEV_REJECT, line_no, "*",
                                                   f"<{type(raw).__name__}>",
                                                   f"该行处理异常已隔离：{type(exc).__name__}: {exc}")]
            issues.extend(row_issues)
            owner = str(raw.get("emp_id") or "").strip() if isinstance(raw, dict) else ""
            if payload is None:
                result.rows_rejected += 1
                if owner and _emp_exists(conn, owner):
                    for iss in issues:
                        iss.emp_id = iss.emp_id or owner
                else:
                    result.unattributed += sum(1 for iss in issues if not iss.emp_id)
            else:
                result.rows_accepted += 1
                cur = conn.execute(payload[0], payload[1])
                # O-3：内容已存在（INSERT OR IGNORE 未插入）-> 记重复，而不是静默丢弃
                if kind == "punch" and cur.rowcount == 0:
                    dup = Issue("QUAL-DUP", SEV_DEFENSIBLE, line_no, "(db-unique)",
                                f"{owner}|{payload[1][1]}|{payload[1][5]}",
                                "与已有打卡事实内容完全相同（跨文件/跨重传），"
                                "按内容唯一索引未二次入账")
                    dup.emp_id = owner
                    dup.work_date = payload[1][3]
                    issues.append(dup)
            if issues:
                result.issues.extend(issues)
                _record_issues(conn, file_id, issues, created_at)

    append_audit(conn, run_id=None, actor=actor, action="ingest.file",
                 payload={"rel_path": rel_path, "sha256": digest, "kind": kind,
                          "rows_seen": result.rows_seen, "accepted": result.rows_accepted,
                          "rejected": result.rows_rejected, "issues": len(result.issues)},
                 ts=created_at, cfg=cfg)
    return result


def _get(raw: Mapping[str, Any], key: str, *, field_name: str, line_no: int
         ) -> tuple[str, Issue | None]:
    value = raw.get(key)
    text, issue = _cell(value, field_name=field_name)
    if issue is not None:
        issue.line_no = line_no
    return text, issue


def _collect(raw: Mapping[str, Any], key: str, *, field_name: str, line_no: int,
             issues: list[Issue]) -> str:
    text, issue = _get(raw, key, field_name=field_name, line_no=line_no)
    if issue:
        issues.append(issue)
    return text


# ------------------------------------------------------------------ 各类型行处理
def _row_org(conn, cfg: Config, raw: Mapping[str, Any], line_no: int, seen: set[tuple],
             file_id: int) -> tuple[tuple[str, tuple] | None, list[Issue]]:
    """组织主数据：员工表对外键引用它，必须先导入。"""
    issues: list[Issue] = []
    org_id = _collect(raw, "org_id", field_name="org_id", line_no=line_no, issues=issues)
    org_name = _collect(raw, "org_name", field_name="org_name", line_no=line_no, issues=issues)
    parent = _collect(raw, "parent_id", field_name="parent_id", line_no=line_no, issues=issues)
    if not org_id or issues_fatal(issues):
        return None, issues
    sql = ("INSERT INTO org_unit(org_id, org_name, parent_id) VALUES(?,?,?) "
           "ON CONFLICT(org_id) DO UPDATE SET org_name = excluded.org_name, parent_id = excluded.parent_id")
    return (sql, (org_id, org_name or org_id, parent or None)), issues


def _row_punch(conn, cfg: Config, raw: Mapping[str, Any], line_no: int, seen: set[tuple],
               file_id: int) -> tuple[tuple[str, tuple] | None, list[Issue]]:
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    ts, ts_issues = _ts_of(raw.get("event_ts", ""), field_name="event_ts", line_no=line_no)
    issues.extend(ts_issues)
    raw_type = raw.get("punch_type", "")
    ptype, _ = _get(raw, "punch_type", field_name="punch_type", line_no=line_no)
    device, dev_issue = _get(raw, "device_id", field_name="device_id", line_no=line_no)
    if dev_issue is not None and dev_issue.severity == SEV_REJECT:
        # 可选字段畸形不毁掉整行事实：置空 + 降级留痕（必填字段畸形仍然整行拒收）
        dev_issue.severity = SEV_DEFENSIBLE
        dev_issue.detail += "（device_id 为可选字段，已置空保留该行打卡事实）"
        issues.append(dev_issue)
    ptype = _normalize_punch_type(ptype)

    if not emp_id or not ts or issues_fatal(issues):
        return None, issues
    if not conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (emp_id,)).fetchone():
        issues.append(Issue("QUAL-EMP", SEV_REJECT, line_no, "emp_id", emp_id, "员工主数据不存在"))
        return None, issues
    if ptype == "unknown":
        issues.append(Issue("QUAL-TYPE", SEV_REVIEW, line_no, "punch_type", str(raw_type),
                            "打卡类型无法识别，按 unknown 入库并要求复核（不参与配对）"))

    dt = parse_timestamp(ts)
    if dt > datetime.now(CN_TZ) + timedelta(hours=8):
        issues.append(Issue("QUAL-FUTURE", SEV_REVIEW, line_no, "event_ts", ts,
                            "打卡时间晚于当前时间 8 小时以上，可能是时钟错乱或合成数据边界"))
    anchor = _anchor_day(dt, cfg.cross_day_cut_hour).isoformat()
    key = (emp_id, ts, ptype, device)
    if key in seen:
        issues.append(Issue("QUAL-DUP", SEV_DEFENSIBLE, line_no, "*", f"{emp_id}|{ts}|{ptype}|{device}",
                            "完全重复的打卡行：只保留首次出现，重复行不进入事实表"
                            "（可申辩：终端重复上传或补录）"))
        return None, issues
    seen.add(key)

    sql = ("INSERT OR IGNORE INTO punch(emp_id, event_ts, event_minute, day_anchor, device_id, "
           "punch_type, raw_text, source_file_id, source_line_no) VALUES(?,?,?,?,?,?,?,?,?)")
    params = (emp_id, ts, 0, anchor, device or None, ptype,
              _raw_text_of(raw, emp_id=emp_id, ts=ts, ptype=ptype, device=device), file_id, line_no)
    for i in issues:
        i.emp_id = i.emp_id or emp_id          # O-2：导入期就把问题挂到人身上
        i.work_date = i.work_date or anchor
    return (sql, params), issues


_PUNCH_IN = {"in", "i", "上班", "on", "1"}
_PUNCH_OUT = {"out", "o", "下班", "off", "2"}


def _normalize_punch_type(value: str) -> str:
    low = str(value).strip().lower()
    if low in _PUNCH_IN:
        return "in"
    if low in _PUNCH_OUT:
        return "out"
    return "unknown"


def _raw_text_of(raw: Mapping[str, Any], **normalized) -> str:
    """保留原始行内容，供举证包反查（超过 512 字符截断，避免 DB 膨胀）。"""
    try:
        text = "|".join(f"{k}={v}" for k, v in dict(raw).items())
    except Exception:
        text = repr(raw)
    return text[:512]


def _row_leave(conn, cfg, raw, line_no, seen, file_id):
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    kind = _collect(raw, "leave_kind", field_name="leave_kind", line_no=line_no, issues=issues)
    start, i1 = _ts_of(raw.get("start_ts", ""), field_name="start_ts", line_no=line_no)
    end, i2 = _ts_of(raw.get("end_ts", ""), field_name="end_ts", line_no=line_no)
    issues += i1 + i2
    approved, _ = _get(raw, "approved", field_name="approved", line_no=line_no)
    paid, _ = _get(raw, "paid", field_name="paid", line_no=line_no)
    if not emp_id or not start or not end or issues_fatal(issues):
        return None, issues
    if parse_timestamp(end) <= parse_timestamp(start):
        issues.append(Issue("QUAL-ORDER", SEV_REJECT, line_no, "end_ts", end, "请假结束时间不晚于开始时间"))
        return None, issues
    sql = ("INSERT INTO leave_record(emp_id, leave_kind, start_ts, end_ts, approved, paid, "
           "source_file_id, source_line_no) VALUES(?,?,?,?,?,?,?,?)")
    return (sql, (emp_id, kind or "unspecified", start, end, 1 if approved in ("", "1", "true", "yes") else 0,
                  1 if paid in ("", "1", "true", "yes") else 0, file_id, line_no)), issues


def _row_trip(conn, cfg, raw, line_no, seen, file_id):
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    dest = _collect(raw, "destination", field_name="destination", line_no=line_no, issues=issues)
    start, i1 = _ts_of(raw.get("start_ts", ""), field_name="start_ts", line_no=line_no)
    end, i2 = _ts_of(raw.get("end_ts", ""), field_name="end_ts", line_no=line_no)
    issues += i1 + i2
    if not emp_id or not start or not end or issues_fatal(issues):
        return None, issues
    if parse_timestamp(end) <= parse_timestamp(start):
        issues.append(Issue("QUAL-ORDER", SEV_REJECT, line_no, "end_ts", end, "出差结束时间不晚于开始时间"))
        return None, issues
    sql = ("INSERT INTO trip_record(emp_id, destination, start_ts, end_ts, source_file_id, "
           "source_line_no) VALUES(?,?,?,?,?,?)")
    return (sql, (emp_id, dest or "unknown", start, end, file_id, line_no)), issues


def _row_correction(conn, cfg, raw, line_no, seen, file_id):
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    ts, i1 = _ts_of(raw.get("claimed_ts", ""), field_name="claimed_ts", line_no=line_no)
    issues += i1
    ctype, _ = _get(raw, "claimed_type", field_name="claimed_type", line_no=line_no)
    reason, _ = _get(raw, "reason", field_name="reason", line_no=line_no)
    approved, _ = _get(raw, "approved", field_name="approved", line_no=line_no)
    if not emp_id or not ts or issues_fatal(issues):
        return None, issues
    if not reason:
        issues.append(Issue("QUAL-EMPTY", SEV_REVIEW, line_no, "reason", "", "补卡缺理由，要求复核"))
    ctype_norm = "in" if ctype.lower() in ("in", "i", "上班") else ("out" if ctype.lower() in ("out", "o", "下班") else "")
    if not ctype_norm:
        issues.append(Issue("QUAL-TYPE", SEV_REJECT, line_no, "claimed_type", ctype, "补卡类型非法"))
        return None, issues
    sql = ("INSERT INTO punch_correction(emp_id, claimed_ts, claimed_type, reason, approved, "
           "source_file_id, source_line_no) VALUES(?,?,?,?,?,?,?)")
    return (sql, (emp_id, ts, ctype_norm, reason or "（未填写理由）",
                  1 if approved in ("1", "true", "yes") else 0, file_id, line_no)), issues


def _row_schedule(conn, cfg, raw, line_no, seen, file_id):
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    work_date = _collect(raw, "work_date", field_name="work_date", line_no=line_no, issues=issues)
    start, i1 = _ts_of(raw.get("planned_start", ""), field_name="planned_start", line_no=line_no)
    end, i2 = _ts_of(raw.get("planned_end", ""), field_name="planned_end", line_no=line_no)
    issues += i1 + i2
    rest = _collect(raw, "rest_minutes", field_name="rest_minutes", line_no=line_no, issues=issues)
    if not emp_id or not work_date or not start or not end or issues_fatal(issues):
        return None, issues
    try:
        wd = parse_date(work_date)
        rest_minutes = int(rest or 0)
    except ValueError as exc:
        issues.append(Issue("QUAL-FMT", SEV_REJECT, line_no, "work_date/rest_minutes",
                            f"{work_date}/{rest}", f"格式错误：{exc}"))
        return None, issues
    s, e = parse_timestamp(start), parse_timestamp(end)
    crosses = int(e.date() > s.date() or (e.date() == s.date() and e <= s))
    if e <= s and not crosses:
        issues.append(Issue("QUAL-ORDER", SEV_REJECT, line_no, "planned_end", end, "班次结束不晚于开始"))
        return None, issues
    if crosses:
        issues.append(Issue("QUAL-XDAY", SEV_REVIEW, line_no, "planned_end", end,
                            "班次跨 00:00：工时归属依赖 cut_hour 切分口径，已标注待人工确认"))
    sql = ("INSERT INTO shift_plan(emp_id, work_date, planned_start, planned_end, crosses_midnight, "
           "rest_minutes, source_file_id, source_line_no) VALUES(?,?,?,?,?,?,?,?) "
           "ON CONFLICT(emp_id, work_date) DO UPDATE SET planned_start = excluded.planned_start, "
           "planned_end = excluded.planned_end, crosses_midnight = excluded.crosses_midnight, "
           "rest_minutes = excluded.rest_minutes, source_file_id = excluded.source_file_id, "
           "source_line_no = excluded.source_line_no")
    return (sql, (emp_id, wd.isoformat(), start, end, crosses, rest_minutes, file_id, line_no)), issues


def _row_employee(conn, cfg, raw, line_no, seen, file_id):
    issues: list[Issue] = []
    emp_id = _collect(raw, "emp_id", field_name="emp_id", line_no=line_no, issues=issues)
    pseudo = _collect(raw, "pseudonym", field_name="pseudonym", line_no=line_no, issues=issues)
    job = _collect(raw, "job_code", field_name="job_code", line_no=line_no, issues=issues)
    org = _collect(raw, "org_id", field_name="org_id", line_no=line_no, issues=issues)
    region = _collect(raw, "region_code", field_name="region_code", line_no=line_no, issues=issues)
    regime = _collect(raw, "worktime_regime", field_name="worktime_regime", line_no=line_no, issues=issues)
    hourly = _collect(raw, "normal_hourly_cents", field_name="normal_hourly_cents", line_no=line_no, issues=issues)
    approved_flex = _collect(raw, "contract_approved_flex", field_name="contract_approved_flex",
                             line_no=line_no, issues=issues)
    if not emp_id or issues_fatal(issues):
        return None, issues
    try:
        hourly_cents = int(hourly)
    except ValueError:
        issues.append(Issue("QUAL-FMT", SEV_REJECT, line_no, "normal_hourly_cents", hourly,
                            "小时工资必须是整数分"))
        return None, issues
    if hourly_cents <= 0:
        issues.append(Issue("QUAL-RANGE", SEV_REJECT, line_no, "normal_hourly_cents", hourly,
                            "小时工资必须为正整数分，否则加班测算基数无意义"))
        return None, issues
    valid_regimes = ("standard", "comprehensive_monthly", "comprehensive_quarterly",
                     "comprehensive_yearly", "flexible")
    if regime not in valid_regimes:
        issues.append(Issue("QUAL-REGIME", SEV_REJECT, line_no, "worktime_regime", regime,
                            f"工时制必须属于 {valid_regimes}"))
        return None, issues
    if org and not conn.execute("SELECT 1 FROM org_unit WHERE org_id = ?", (org,)).fetchone():
        issues.append(Issue("QUAL-ORG", SEV_REVIEW, line_no, "org_id", org, "组织单元不存在，已按缺省组织入库"))
    sql = ("INSERT INTO employee(emp_id, pseudonym, job_code, org_id, region_code, worktime_regime, "
           "contract_approved_flex, pay_base_cents, pay_base_hourly_cents, normal_hourly_cents, "
           "is_manager, acl_scope) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
           "ON CONFLICT(emp_id) DO UPDATE SET pseudonym = excluded.pseudonym, job_code = excluded.job_code, "
           "org_id = excluded.org_id, region_code = excluded.region_code, "
           "worktime_regime = excluded.worktime_regime, "
           "contract_approved_flex = excluded.contract_approved_flex, "
           "normal_hourly_cents = excluded.normal_hourly_cents")
    return (sql, (emp_id, pseudo or emp_id, job or "unknown", org or "ORG-DEFAULT",
                  region or cfg.region_code, regime, 1 if approved_flex in ("1", "true", "yes") else 0,
                  hourly_cents * 174, hourly_cents, hourly_cents,
                  1 if job == "senior_manager" else 0,
                  "own_org" if job == "senior_manager" else "self")), issues


def _emp_exists(conn: sqlite3.Connection, emp_id: str) -> bool:
    return conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (emp_id,)).fetchone() is not None


def issues_fatal(issues: list[Issue]) -> bool:
    return any(i.severity == SEV_REJECT for i in issues)


def _record_issues(conn: sqlite3.Connection, file_id: int, issues: list[Issue], created_at: str) -> None:
    conn.executemany(
        "INSERT INTO ingest_issue(file_id, line_no, rule_id, emp_id, work_date, severity, field_name, "
        "raw_value, detail, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        [i.as_row(file_id, created_at) for i in issues],
    )


def quality_report(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT i.rule_id, i.severity, COUNT(*) AS c FROM ingest_issue i GROUP BY i.rule_id, i.severity "
        "ORDER BY c DESC"
    ).fetchall()
    return [{"rule_id": r["rule_id"], "severity": r["severity"], "count": int(r["c"])} for r in rows]
