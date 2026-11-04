"""F-003 导入器 + F-004 数据质量门禁。

三条硬规矩（auscult ISS-031 的教训直接迁过来）：
  1. 每一行都带 (file_id, line_no) 与文件 sha256，任何结论都能反查到原始行（A7）；
  2. 非字符串入参（None / int / bytes / dict / float('nan') / 布尔）绝不允许把导入流程打崩，
     只能落成一条 QUAL-ENC 记录并被跳过；
  3. 幂等键 = (rel_path, sha256)：同一个文件重复导入不会产生重复事实，只留一条重跑痕迹。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Mapping

from .config import Config
from .db import DB_BACKEND_POSTGRES, Connection, transaction
from .evidence import append_audit
from .package_inputs import validate_input_rel_path
from .rules.dayfacts import _anchor_day
from .util import CN_TZ, parse_date, parse_timestamp, sha256_hex, iso_minute

logger = logging.getLogger(__name__)

IMPORT_WRITE_MODES = ("single", "executemany", "copy")
# 分块行数硬上限：防止把 WCA_IMPORT_BATCH_SIZE 配成整文件大小，重新把全部 payload
# 拉回内存。默认 5,000；超过上限时截断并告警，不静默接受。
MAX_IMPORT_CHUNK_ROWS = 20_000
# 流式哈希/读取块：1 MiB；内存只按块增长，不随手文件体积线性增长。
STREAM_READ_CHUNK_BYTES = 1 << 20
_PUNCH_STAGE = "punch_stage"
_PUNCH_STAGE_COLUMNS = ("emp_id", "event_ts", "event_minute", "day_anchor", "device_id",
                        "punch_type", "raw_text", "source_file_id", "source_line_no")
_PUNCH_STAGE_DDL = (
    "emp_id TEXT, event_ts TEXT, event_minute INTEGER, day_anchor TEXT, device_id TEXT, "
    "punch_type TEXT, raw_text TEXT, source_file_id INTEGER, source_line_no INTEGER")
_PUNCH_INSERT = ("INSERT INTO punch(emp_id, event_ts, event_minute, day_anchor, device_id, "
                 "punch_type, raw_text, source_file_id, source_line_no) "
                 "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING")
# 文件内“完全重复打卡”的临时唯一键表：把 O(行数) 的 Python set 换成 DB 临时表，
# 让内存不随文件大小增长。只保留每个键首次出现的行号。
_PUNCH_SEEN = "punch_seen"
_PUNCH_SEEN_STAGE = "punch_seen_stage"
_PUNCH_SEEN_COLUMNS = ("emp_id", "event_ts", "punch_type", "device_id", "source_line_no")
_PUNCH_SEEN_DDL = (
    "emp_id TEXT, event_ts TEXT, punch_type TEXT, device_id TEXT, source_line_no INTEGER, "
    "PRIMARY KEY(emp_id, event_ts, punch_type, device_id)")
_PUNCH_SEEN_STAGE_DDL = (
    "emp_id TEXT, event_ts TEXT, punch_type TEXT, device_id TEXT, source_line_no INTEGER")

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
    # 跨文件重复行的行级引用按包内 rel_path 字典序确定；写入 DB 时覆盖当前导入文件。
    file_id_override: int | None = None
    # 同一重复内容的全部来源文件；仅用于把输入文件都带进包，不进入 canonical。
    related_file_ids: list[int] = field(default_factory=list)

    def as_row(self, file_id: int, created_at: str) -> tuple:
        target_file_id = self.file_id_override if self.file_id_override is not None else file_id
        detail = self.detail
        if self.related_file_ids:
            ids = ",".join(str(x) for x in sorted(set(self.related_file_ids)))
            detail = f"{detail}; related_file_ids={ids}"
        return (target_file_id, self.line_no if self.line_no is not None else 0, self.rule_id,
                self.emp_id, self.work_date, self.severity, self.field_name, self.raw_value,
                detail, created_at)


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
    # 写入方式可观测：SQLite 请求批量时会降级为 single，不能静默假装用了批量。
    requested_write_mode: str = "single"
    write_mode: str = "single"
    degraded_from: str = ""
    chunk_rows: int = 0

    def summary(self) -> dict:
        return {
            "file": self.rel_path, "kind": self.kind, "sha256": self.sha256[:16],
            "rows_seen": self.rows_seen, "accepted": self.rows_accepted,
            "rejected": self.rows_rejected, "issues": len(self.issues),
            "reimported": self.reimported, "unattributed": self.unattributed,
            "write_mode": self.write_mode, "requested_write_mode": self.requested_write_mode,
            "degraded_from": self.degraded_from, "chunk_rows": self.chunk_rows,
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
def _hash_stream(fh, chunk_size: int = STREAM_READ_CHUNK_BYTES) -> str:
    """按块读已打开的二进制流并算 sha256。"""
    hasher = hashlib.sha256()
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def _stream_sha256(path: Path, chunk_size: int = STREAM_READ_CHUNK_BYTES) -> str:
    """按块读文件并算 sha256；与 `sha256_hex(path.read_bytes())` 逐字节一致。"""
    with path.open("rb") as fh:
        return _hash_stream(fh, chunk_size)


def import_csv_file(conn: Connection, cfg: Config, path: Path | str, *,
                    kind: str | None = None, actor: str = "system:ingest",
                    created_at: str | None = None,
                    rel_path: str | None = None) -> ImportResult:
    """导入一个 CSV。`rel_path` 只在**外部重放**时显式给：包里的文件落在临时目录，
    但输入指纹按原始 `rel_path` 计算，不复现就比不回来。默认仍按当前工作目录推导。
    """
    p = Path(path)
    if rel_path is None:
        # 先做纯字符串校验，避免 UNC/网络路径在 is_file() 阶段触发系统调用。
        _reject_unreconstructable_path(p)
    if not p.is_file():
        raise FileNotFoundError(f"待导入文件不存在: {p}")
    rel = rel_path if rel_path else _rel_path(p, cfg)
    rel = validate_input_rel_path(rel)
    kind = kind or _guess_kind(rel)
    if kind not in KINDS:
        raise ValueError(f"未知数据类型 kind={kind!r}，可选 {KINDS}")

    # 同一个打开句柄两遍流式读：第一遍只哈希，第二遍 seek(0) 后解码交给 CSV。
    # 不再把 raw bytes / 解码文本整体留在内存；同一句柄也降低“路径被替换”的竞态。
    with p.open("rb") as binary:
        digest = _hash_stream(binary)
        binary.seek(0)
        # newline='\\n' 与旧实现 io.StringIO(text) 一致（只按 \\n 分行、保留原始行尾与裸 \\r）。
        text_file = io.TextIOWrapper(binary, encoding="utf-8-sig", errors="replace",
                                     newline="\n")
        reader = csv.DictReader(text_file)
        header = list(reader.fieldnames or [])
        header_digest = sha256_hex("|".join(header).encode("utf-8"))
        created_at = created_at or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")

        missing = [c for c in REQUIRED_COLUMNS[kind] if c not in header]
        # 整个文件（raw_file 登记/purge + 派生行 + 审计）必须在同一事务里；
        # 否则进程中断会把 raw_file 留在库中，punch 却已回滚。
        with transaction(conn, immediate=True):
            _acquire_import_lock(conn, rel, digest)
            # CSV 通道只有读到数据行后才知道真实行数；先登记 0，读完再更新。
            # 不能用 len(header)：那是列数，会让 raw_file.row_count / input_fingerprint
            # 与导出 input_files.csv 的 row_count 语义错位。
            file_id, reimported = _register_file(
                conn, rel, digest, kind, header_digest, created_at, 0)
            if missing:
                issue = Issue("QUAL-HDR", SEV_REJECT, 1, "header", ",".join(missing),
                              f"表头缺少必需列 {missing}，整个文件被拒收")
                issue.emp_id = ""  # 文件级问题，归属不到人
                _record_issues(conn, file_id, [issue], created_at)
                append_audit(conn, run_id=None, actor=actor, action="ingest.reject_file",
                             payload={"rel_path": rel, "sha256": digest,
                                      "reason": "missing_columns", "columns": missing}, cfg=cfg)
                return ImportResult(file_id=file_id, rel_path=rel, sha256=digest, kind=kind,
                                    rows_seen=0, rows_rejected=0, issues=[issue],
                                    reimported=reimported)

            # reader 由 _ingest_rows 按块消费，不再预读成 dict 列表。
            result = _ingest_rows(conn, cfg, file_id=file_id, kind=kind, rows=reader,
                                  actor=actor, rel_path=rel, digest=digest,
                                  created_at=created_at, start_line=2,
                                  manage_transaction=False)
            conn.execute("UPDATE raw_file SET row_count = ? WHERE file_id = ?",
                         (result.rows_seen, file_id))
            result.reimported = reimported
            return result


def import_rows(conn: Connection, cfg: Config, kind: str, rows: Iterable[Mapping[str, Any]],
                *, rel_path: str = "inline://adhoc", actor: str = "system:ingest",
                created_at: str | None = None,
                header: list[str] | None = None) -> ImportResult:
    """程序化入口（测试与 API 走这里）。与 CSV 入口共用同一套门禁，不额外放宽。"""
    if kind not in KINDS:
        raise ValueError(f"未知数据类型 kind={kind!r}")
    rel_path = validate_input_rel_path(rel_path)
    seq = list(rows)
    digest = sha256_hex(_safe_repr(seq))
    created_at = created_at or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    header_digest = sha256_hex("|".join(header or (list(seq[0].keys()) if seq else [])).encode())
    with transaction(conn, immediate=True):
        _acquire_import_lock(conn, rel_path, digest)
        file_id, reimported = _register_file(
            conn, rel_path, digest, kind, header_digest, created_at, len(seq))
        result = _ingest_rows(conn, cfg, file_id=file_id, kind=kind, rows=seq, actor=actor,
                              rel_path=rel_path, digest=digest, created_at=created_at,
                              start_line=1, manage_transaction=False)
        result.reimported = reimported
        return result


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


def _reject_unreconstructable_path(raw: object) -> None:
    """导入期契约：必须能按 `rel_path` 原样还原到包内。

    含 `..`、绝对路径、盘符、UNC 的路径会丢失目录信息，一律中文报错，
    不做静默压平（第九轮 A13）。
    """
    text = str(raw).replace("\\", "/")
    if text.startswith("//"):
        raise ValueError(
            f"导入路径不允许 UNC/网络路径（无法在包内还原）：{raw}；"
            "请先把文件复制到当前工作目录下再导入")
    if text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        raise ValueError(
            f"导入路径不允许绝对路径（无法在包内还原）：{raw}；"
            "请使用当前工作目录内的相对路径，或 cd 到数据根目录后再导入")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise ValueError(
            f"导入路径不允许包含 ..（无法在包内还原）：{raw}；"
            "请把文件放在当前工作目录内，用相对路径导入")


def _rel_path(p: Path, cfg: Config) -> str:
    _reject_unreconstructable_path(p)
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(
            f"导入文件必须位于当前工作目录内（否则包内无法按 rel_path 还原）：{p}；"
            "请 cd 到数据根目录，或把文件放入工作目录下的 data/raw") from exc


def _acquire_import_lock(conn: Connection, rel: str, digest: str) -> None:
    """同一文件（rel_path+sha256）的导入串行化；PG advisory xact lock 随事务释放。"""
    if conn.dialect == DB_BACKEND_POSTGRES:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))",
                     (f"wca.import:{rel}#{digest}",))


def _register_file(conn: Connection, rel: str, digest: str, kind: str,
                   header_digest: str, created_at: str, row_count: int) -> tuple[int, bool]:
    """幂等键 (rel_path, sha256)：命中则复用 file_id 并清空派生行，绝不重复登记事实。

    返回 (file_id, 是否重导)；登记/purge 必须由调用方放进导入事务。
    """
    existing = conn.execute(
        "SELECT file_id FROM raw_file WHERE rel_path = ? AND sha256 = ?", (rel, digest)
    ).fetchone()
    if existing:
        file_id = int(existing["file_id"])
        _purge_file_rows(conn, file_id)
        conn.execute("UPDATE raw_file SET row_count = ?, imported_at = ? WHERE file_id = ?",
                     (row_count, created_at, file_id))
        return file_id, True
    # 显式取号（MAX+1）而不是 autoincrement：回滚会连同 raw_file 行一起撤销，
    # 下一次重跑仍拿到同一个 file_id。file_id 只用于内部查询与 source_refs 行级反查，
    # 不进入 metric/canonical；用序列取号仍会因回滚跳号，影响 source_refs 的稳定排序。
    # 并发不同文件可能同时取到同一个 id，ON CONFLICT DO NOTHING 让后到者重取。
    for _ in range(8):
        next_id = int(conn.execute(
            "SELECT COALESCE(MAX(file_id), 0) + 1 AS next_id FROM raw_file").fetchone()["next_id"])
        cur = conn.execute(
            "INSERT INTO raw_file(file_id, rel_path, sha256, kind, row_count, header_sha256, "
            "imported_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING RETURNING file_id",
            (next_id, rel, digest, kind, row_count, header_digest, created_at),
        )
        got = cur.fetchone()
        if got is not None:
            return int(got["file_id"]), False
        # 冲突有两种：同一文件已被并发事务登记（幂等命中），或 id 被其他文件占用。
        existing = conn.execute(
            "SELECT file_id FROM raw_file WHERE rel_path = ? AND sha256 = ?", (rel, digest)
        ).fetchone()
        if existing:
            file_id = int(existing["file_id"])
            _purge_file_rows(conn, file_id)
            conn.execute("UPDATE raw_file SET row_count = ?, imported_at = ? WHERE file_id = ?",
                         (row_count, created_at, file_id))
            return file_id, True
    raise RuntimeError("raw_file 主键分配连续冲突 8 次，请检查并发导入")


def _purge_file_rows(conn: Connection, file_id: int) -> None:
    table_by_kind = {
        "punch": "punch", "leave": "leave_record", "trip": "trip_record",
        "correction": "punch_correction", "schedule": "shift_plan",
    }
    # org / employee 是主数据：重复导入走 UPSERT，不做级联删除
    for table in table_by_kind.values():
        conn.execute(f"DELETE FROM {table} WHERE source_file_id = ?", (file_id,))
    conn.execute("DELETE FROM ingest_issue WHERE file_id = ?", (file_id,))
    # employee 是主数据，重复导入直接 UPSERT，不做删除（避免级联清掉历史事实）


@dataclass(slots=True)
class _DupGroup:
    """按员工聚合的 QUAL-DUP 元数据；逐行 Issue 已落库，汇总时再删除。"""

    emp_id: str
    count: int = 0
    line_min: int | None = None
    line_max: int | None = None
    summary_key: tuple[str, int] | None = None
    summary_raw: str = ""
    # day -> [count, samples[:3], refs[:5]]；refs = (rel_path, line_no, file_id)
    days: dict[str, list] = field(default_factory=dict)
    related_file_ids: set[int] = field(default_factory=set)
    canonical_file_ids: set[int] = field(default_factory=set)

    def add(self, issue: Issue, file_id: int, rel_paths: dict[int, str]) -> None:
        line_no = int(issue.line_no or 0)
        day = str(issue.work_date or "")
        key = (day, line_no)
        if self.summary_key is None or key < self.summary_key:
            self.summary_key = key
            self.summary_raw = str(issue.raw_value or "")
        self.count += 1
        if self.line_min is None or line_no < self.line_min:
            self.line_min = line_no
        if self.line_max is None or line_no > self.line_max:
            self.line_max = line_no
        target_file_id = (issue.file_id_override
                          if issue.file_id_override is not None else file_id)
        self.related_file_ids.update(issue.related_file_ids)
        self.related_file_ids.add(target_file_id)
        self.canonical_file_ids.add(target_file_id)
        rel_path = rel_paths.get(target_file_id, "")
        meta = self.days.get(day)
        if meta is None:
            meta = [0, [], []]
            self.days[day] = meta
        meta[0] += 1
        if len(meta[1]) < 3:
            meta[1].append(str(issue.raw_value or ""))
        if len(meta[2]) < 5:
            meta[2].append((rel_path, line_no, target_file_id))

    @property
    def file_ids(self) -> set[int]:
        return set(self.canonical_file_ids)

    def summary(self, file_id: int) -> Issue:
        days = {}
        for day, meta in self.days.items():
            refs = sorted(meta[2], key=lambda x: (x[0], x[1], x[2]))
            days[day] = {
                "count": meta[0], "samples": meta[1],
                # 行引用按包内相对路径排序；同一文件时与旧行为一致，跨文件时与导入顺序无关。
                "line_refs": [[ref[2], ref[1]] for ref in refs],
            }
        detail = json.dumps({
            "qual_dup_summary": True,
            "count": self.count,
            "line_min": int(self.line_min or 0),
            "line_max": int(self.line_max or 0),
            "days": days,
            "related_file_ids": sorted(self.related_file_ids),
        }, ensure_ascii=False, sort_keys=True)
        first_refs = sorted(
            [ref for meta in self.days.values() for ref in meta[2]],
            key=lambda x: (x[0], x[1], x[2]))
        first = first_refs[0] if first_refs else ("", int(self.line_min or 0), file_id)
        issue = Issue("QUAL-DUP", SEV_DEFENSIBLE, int(first[1]), "(db-unique)",
                      self.summary_raw, detail, file_id_override=int(first[2]))
        issue.emp_id = self.emp_id
        return issue


def _clear_temp_table(conn: Connection, table: str) -> None:
    """清空块级临时表。PG 用 TRUNCATE 及时释放页，避免 DELETE 死元组随文件行数膨胀。"""
    if conn.dialect == DB_BACKEND_POSTGRES:
        conn.execute(f"TRUNCATE TABLE {table}")
    else:
        conn.execute(f"DELETE FROM {table}")


def _param_chunks(values: list[str], size: int = 100) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _load_db_duplicate_issues(conn: Connection, file_ids: set[int],
                              emp_ids: list[str]) -> dict[str, list[Issue]]:
    """按员工取回未汇总的逐行 QUAL-DUP；只在需要返回明细的组上查。"""
    grouped: dict[str, list[Issue]] = {}
    if not file_ids:
        return grouped
    ordered = sorted(int(x) for x in file_ids)
    file_marks = ",".join("?" * len(ordered))
    for chunk in _param_chunks(emp_ids):
        marks = ",".join("?" * len(chunk))
        rows = conn.execute(
            "SELECT line_no, rule_id, severity, field_name, raw_value, detail, emp_id, work_date "
            f"FROM ingest_issue WHERE file_id IN ({file_marks}) AND rule_id = 'QUAL-DUP' "
            f"AND field_name = '(db-unique)' AND emp_id IN ({marks}) ORDER BY line_no",
            (*ordered, *chunk),
        ).fetchall()
        for r in rows:
            issue = Issue(str(r["rule_id"]), str(r["severity"]), int(r["line_no"]),
                          str(r["field_name"]), str(r["raw_value"]), str(r["detail"]),
                          emp_id=str(r["emp_id"]), work_date=str(r["work_date"] or ""))
            grouped.setdefault(str(r["emp_id"]), []).append(issue)
    return grouped


def _delete_db_duplicate_issues(conn: Connection, file_ids: set[int],
                                emp_ids: list[str]) -> None:
    if not file_ids:
        return
    ordered = sorted(int(x) for x in file_ids)
    file_marks = ",".join("?" * len(ordered))
    for chunk in _param_chunks(emp_ids):
        marks = ",".join("?" * len(chunk))
        conn.execute(
            f"DELETE FROM ingest_issue WHERE file_id IN ({file_marks}) AND rule_id = 'QUAL-DUP' "
            f"AND field_name = '(db-unique)' AND emp_id IN ({marks})",
            (*ordered, *chunk),
        )


def _ingest_rows(conn: Connection, cfg: Config, *, file_id: int, kind: str,
                 rows: Iterable[Any], actor: str, rel_path: str, digest: str, created_at: str,
                 start_line: int, manage_transaction: bool = True) -> ImportResult:
    result = ImportResult(file_id=file_id, rel_path=rel_path, sha256=digest, kind=kind,
                          idempotency_key=f"{rel_path}#{digest[:16]}")
    handler = {
        "org": _row_org,
        "punch": _row_punch, "leave": _row_leave, "trip": _row_trip,
        "correction": _row_correction, "schedule": _row_schedule, "employee": _row_employee,
    }[kind]

    requested = str(getattr(cfg, "import_write_mode", "single")).strip().lower()
    if requested not in IMPORT_WRITE_MODES:
        raise ValueError(f"未知导入写入方式 {requested!r}，可用 {list(IMPORT_WRITE_MODES)}")
    requested_chunk = int(getattr(cfg, "import_batch_size", 5_000))
    chunk_rows = max(1, min(requested_chunk, MAX_IMPORT_CHUNK_ROWS))
    if requested_chunk > MAX_IMPORT_CHUNK_ROWS:
        logger.warning("WCA_IMPORT_BATCH_SIZE=%s 超过分块上限 %s，按 %s 行执行（%s）",
                       requested_chunk, MAX_IMPORT_CHUNK_ROWS, MAX_IMPORT_CHUNK_ROWS, rel_path)
    result.requested_write_mode = requested
    result.chunk_rows = chunk_rows

    # 写入方式只在 punch 上有批量路径；其他 kind 本来就是逐行 UPSERT。
    mode = "single"
    if kind == "punch" and requested in ("executemany", "copy"):
        if conn.dialect == DB_BACKEND_POSTGRES:
            mode = requested
        else:
            result.degraded_from = requested
            logger.warning("导入写入方式 %s 需要 PostgreSQL，SQLite 已自动降级为 single（%s）",
                           requested, rel_path)
    result.write_mode = mode

    bulk_punch = kind == "punch" and mode in ("executemany", "copy")
    known_employees = ({str(r["emp_id"]) for r in conn.execute(
        "SELECT emp_id FROM employee").fetchall()} if bulk_punch else None)
    seen_keys: set[tuple] = set()
    dup_groups: dict[str, _DupGroup] = {}
    limit = max(0, int(getattr(cfg, "qual_dup_aggregate_threshold", 20)))

    tx = transaction(conn) if manage_transaction else nullcontext()
    with tx:
        rel_paths = {int(r["file_id"]): str(r["rel_path"]) for r in conn.execute(
            "SELECT file_id, rel_path FROM raw_file").fetchall()}
        if bulk_punch:
            conn.execute(f"CREATE TEMP TABLE {_PUNCH_STAGE} "
                         f"({_PUNCH_STAGE_DDL}) ON COMMIT DROP")
        if kind == "punch":
            if conn.dialect == DB_BACKEND_POSTGRES:
                conn.execute(f"CREATE TEMP TABLE {_PUNCH_SEEN_STAGE} "
                             f"({_PUNCH_SEEN_STAGE_DDL}) ON COMMIT DROP")
                conn.execute(f"CREATE TEMP TABLE {_PUNCH_SEEN} "
                             f"({_PUNCH_SEEN_DDL}) ON COMMIT DROP")
            else:
                # SQLite 不支持 ON COMMIT DROP；连接内复用前先清掉上一轮遗留。
                conn.execute(f"DROP TABLE IF EXISTS {_PUNCH_SEEN_STAGE}")
                conn.execute(f"DROP TABLE IF EXISTS {_PUNCH_SEEN}")
                conn.execute(f"CREATE TEMP TABLE {_PUNCH_SEEN_STAGE}({_PUNCH_SEEN_STAGE_DDL})")
                conn.execute(f"CREATE TEMP TABLE {_PUNCH_SEEN}({_PUNCH_SEEN_DDL})")
        iterator = iter(rows)
        offset = 0
        while True:
            chunk = list(islice(iterator, chunk_rows))
            if not chunk:
                break
            chunk_issues: list[Issue] = []
            chunk_dups: list[Issue] = []
            bulk_params: list[tuple] = []
            bulk_meta: list[tuple[int, str, tuple]] = []
            punch_candidates: list[tuple[int, str, tuple, list[Issue]]] = []
            for local_idx, raw in enumerate(chunk):
                line_no = start_line + offset + local_idx
                result.rows_seen += 1
                issues: list[Issue] = []
                try:
                    if kind == "punch":
                        payload, row_issues = handler(
                            conn, cfg, raw, line_no, seen_keys, file_id,
                            known_employees=known_employees, check_seen=False)
                    else:
                        payload, row_issues = handler(conn, cfg, raw, line_no, seen_keys, file_id)
                except Exception as exc:  # 兜底：任何一行都不允许打断整个导入
                    payload, row_issues = None, [Issue(
                        "QUAL-CRASH", SEV_REJECT, line_no, "*", f"<{type(raw).__name__}>",
                        f"该行处理异常已隔离：{type(exc).__name__}: {exc}")]
                issues.extend(row_issues)
                owner = str(raw.get("emp_id") or "").strip() if isinstance(raw, dict) else ""
                if payload is None:
                    result.rows_rejected += 1
                    owner_known = (owner in known_employees if known_employees is not None
                                   else _emp_exists(conn, owner))
                    if owner and owner_known:
                        for iss in issues:
                            iss.emp_id = iss.emp_id or owner
                    else:
                        result.unattributed += sum(1 for iss in issues if not iss.emp_id)
                    if issues:
                        result.issues.extend(issues)
                        chunk_issues.extend(issues)
                elif kind == "punch":
                    # 先收集候选；块级临时唯一表判完“文件内重复”后再计 accepted。
                    punch_candidates.append((line_no, owner, payload, issues))
                else:
                    result.rows_accepted += 1
                    cur = conn.execute(payload[0], payload[1])
                    if issues:
                        result.issues.extend(issues)
                        chunk_issues.extend(issues)

            if kind == "punch":
                new_lines = _mark_seen_lines(
                    conn, mode, punch_candidates, start_line + offset,
                    start_line + offset + len(chunk) - 1)
                for line_no, owner, payload, issues in punch_candidates:
                    if line_no not in new_lines:
                        params = payload[1]
                        issues.append(_seen_duplicate_issue(
                            line_no, (params[0], params[1], params[5], params[4] or "")))
                        result.rows_rejected += 1
                        for iss in issues:
                            iss.emp_id = iss.emp_id or owner
                        if issues:
                            result.issues.extend(issues)
                            chunk_issues.extend(issues)
                        continue
                    result.rows_accepted += 1
                    if issues:
                        result.issues.extend(issues)
                        chunk_issues.extend(issues)
                    if bulk_punch:
                        bulk_params.append(payload[1])
                        bulk_meta.append((line_no, owner, payload[1]))
                    else:
                        cur = conn.execute(payload[0], payload[1])
                        # O-3：内容已存在（ON CONFLICT DO NOTHING 未插入）-> 记重复，不静默丢弃
                        if cur.rowcount == 0:
                            chunk_dups.append(_duplicate_punch_issue(
                                conn, rel_paths, line_no, owner, payload[1]))

            if bulk_punch:
                inserted_lines = _write_punch_bulk(conn, mode, chunk_rows, bulk_params)
                for line_no, owner, params in bulk_meta:
                    if line_no not in inserted_lines:
                        chunk_dups.append(_duplicate_punch_issue(
                            conn, rel_paths, line_no, owner, params))
                _clear_temp_table(conn, _PUNCH_STAGE)
            if chunk_issues:
                _record_issues(conn, file_id, chunk_issues, created_at)
            if chunk_dups:
                _record_issues(conn, file_id, chunk_dups, created_at)
                for issue in chunk_dups:
                    group = dup_groups.get(issue.emp_id)
                    if group is None:
                        group = _DupGroup(issue.emp_id)
                        dup_groups[issue.emp_id] = group
                    group.add(issue, file_id, rel_paths)
            offset += len(chunk)
        if kind == "punch":
            conn.execute(f"DROP TABLE IF EXISTS {_PUNCH_SEEN_STAGE}")
            conn.execute(f"DROP TABLE IF EXISTS {_PUNCH_SEEN}")

        if dup_groups:
            blocked = {str(i.emp_id) for i in result.issues if i.emp_id}
            aggregate_emps = sorted(
                emp for emp, group in dup_groups.items()
                if limit > 0 and group.count > limit and emp not in blocked)
            aggregate_set = set(aggregate_emps)
            keep_emps = [emp for emp in sorted(dup_groups) if emp not in aggregate_set]
            loaded: dict[str, list[Issue]] = {}
            for emp in keep_emps:
                loaded.update(_load_db_duplicate_issues(
                    conn, dup_groups[emp].file_ids, [emp]))
            summary_by_emp = {emp: dup_groups[emp].summary(file_id)
                              for emp in aggregate_emps}
            for emp in aggregate_emps:
                _delete_db_duplicate_issues(conn, dup_groups[emp].file_ids, [emp])
            final_dup: list[Issue] = []
            for emp in sorted(dup_groups):
                if emp in aggregate_set:
                    final_dup.append(summary_by_emp[emp])
                else:
                    final_dup.extend(loaded.get(emp, []))
            result.issues.extend(final_dup)
            if summary_by_emp:
                _record_issues(conn, file_id, list(summary_by_emp.values()), created_at)

    append_audit(conn, run_id=None, actor=actor, action="ingest.file",
                 payload={"rel_path": rel_path, "sha256": digest, "kind": kind,
                          "rows_seen": result.rows_seen, "accepted": result.rows_accepted,
                          "rejected": result.rows_rejected, "issues": len(result.issues),
                          "write_mode": result.write_mode, "chunk_rows": result.chunk_rows},
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


def _seen_duplicate_issue(line_no: int, key: tuple) -> Issue:
    """文件内完全重复行（key = emp_id, ts, ptype, device）。"""
    return Issue("QUAL-DUP", SEV_DEFENSIBLE, line_no, "*",
                 f"{key[0]}|{key[1]}|{key[2]}|{key[3]}",
                 "完全重复的打卡行：只保留首次出现，重复行不进入事实表"
                 "（可申辩：终端重复上传或补录）")


def _mark_seen_lines(conn: Connection, mode: str, candidates: list[tuple],
                     line_lo: int, line_hi: int) -> set[int]:
    """把本块候选打卡的键写入临时唯一表，返回“首次出现”的行号集合。

    `ON CONFLICT DO NOTHING` 让同一键的后续行不落库；再按本块行号区间回查，
    首次出现的行号会被返回，重复行不会。这样无需在 Python 里保存全文件 key。
    """
    keys = [(p[1][0], p[1][1], p[1][5], p[1][4] or "", line_no)
            for line_no, _owner, p, _issues in candidates]
    if not keys:
        return set()
    cols = ", ".join(_PUNCH_SEEN_COLUMNS)
    if mode == "copy":
        cursor = conn.raw.cursor()
        try:
            with cursor.copy(f"COPY {_PUNCH_SEEN_STAGE}({cols}) FROM STDIN") as copy:
                for row in keys:
                    copy.write_row(row)
        finally:
            cursor.close()
    else:
        conn.executemany(
            f"INSERT INTO {_PUNCH_SEEN_STAGE}({cols}) VALUES(?,?,?,?,?)", keys)
    # 同一块内重复 key 只保留最小行号；先落块级无索引暂存表，再批量进唯一表，
    # 避免逐行更新唯一索引。已存在于前块的 key 会 ON CONFLICT 跳过。
    conn.execute(
        f"INSERT INTO {_PUNCH_SEEN}({cols}) "
        f"SELECT emp_id, event_ts, punch_type, device_id, MIN(source_line_no) "
        f"FROM {_PUNCH_SEEN_STAGE} WHERE TRUE "
        "GROUP BY emp_id, event_ts, punch_type, device_id "
        "ON CONFLICT DO NOTHING")
    _clear_temp_table(conn, _PUNCH_SEEN_STAGE)
    rows = conn.execute(
        f"SELECT source_line_no FROM {_PUNCH_SEEN} "
        "WHERE source_line_no BETWEEN ? AND ?", (line_lo, line_hi)).fetchall()
    return {int(r["source_line_no"]) for r in rows}


def _duplicate_punch_issue(conn: Connection, rel_paths: dict[int, str],
                           line_no: int, owner: str, params: tuple) -> Issue:
    """跨文件/重传重复行：行级引用按 `rel_path` 字典序确定，不跟随导入顺序。

    同一内容可能在两个文件各有一行；只留“幸存”行会让 QUAL 摘要随谁先导入而翻转。
    这里把两处来源都取出，按 `(rel_path,line_no)` 排序后取第一个作为 canonical 引用，
    其余来源写入 detail，便于人工反查；不改变 issue_count，也不改变重复行事实。
    """
    key = (params[0], params[1], params[5], params[4] or "")
    existing = conn.execute(
        "SELECT source_file_id, source_line_no FROM punch "
        "WHERE emp_id = ? AND event_ts = ? AND punch_type = ? "
        "AND COALESCE(device_id, '') = ? ORDER BY punch_id LIMIT 1", key
    ).fetchone()
    refs: list[tuple[str, int, int]] = []
    if existing is not None and existing["source_file_id"] is not None:
        fid = int(existing["source_file_id"])
        refs.append((str(rel_paths.get(fid, "")), int(existing["source_line_no"] or 0), fid))
    if params[7] is not None:
        fid = int(params[7])
        refs.append((str(rel_paths.get(fid, "")), int(line_no), fid))
    refs = sorted(set(refs), key=lambda x: (x[0], x[1], x[2]))
    canonical = refs[0] if refs else ("", line_no, None)
    sources = ", ".join(f"{rel}:{line}" for rel, line, _fid in refs)
    detail = ("与已有打卡事实内容完全相同（跨文件/跨重传），按内容唯一索引未二次入账；"
              f"来源: {sources}（按 rel_path 字典序取首个为行级引用）")
    dup = Issue("QUAL-DUP", SEV_DEFENSIBLE, int(canonical[1]), "(db-unique)",
                f"{owner}|{params[1]}|{params[5]}", detail,
                file_id_override=canonical[2],
                related_file_ids=sorted({fid for _rel, _line, fid in refs}))
    dup.emp_id = owner
    dup.work_date = params[3]
    return dup


def _write_punch_bulk(conn: Connection, mode: str, batch_size: int,
                      params: list[tuple]) -> set[int]:
    """把已校验的 punch 行写入暂存表，再统一 ON CONFLICT 入正式表。

    executemany 与 copy 走同一个暂存表/同一条最终 INSERT；差别只在暂存写入方式。
    返回成功入正式表的 source_line_no 集合，用于精确识别 QUAL-DUP。
    """
    cols = ", ".join(_PUNCH_STAGE_COLUMNS)
    if not params:
        return set()
    if mode == "executemany":
        for start in range(0, len(params), batch_size):
            conn.executemany(
                f"INSERT INTO {_PUNCH_STAGE}({cols}) VALUES(?,?,?,?,?,?,?,?,?)",
                params[start:start + batch_size])
    elif mode == "copy":
        cursor = conn.raw.cursor()
        try:
            with cursor.copy(f"COPY {_PUNCH_STAGE}({cols}) FROM STDIN") as copy:
                for row in params:
                    copy.write_row(row)
        finally:
            cursor.close()
    else:
        raise ValueError(f"未知批量写入方式 {mode!r}")
    cur = conn.execute(
        f"INSERT INTO punch({cols}) SELECT {cols} FROM {_PUNCH_STAGE} "
        f"ORDER BY source_line_no ON CONFLICT DO NOTHING RETURNING source_line_no")
    return {int(r["source_line_no"]) for r in cur.fetchall()}


def _row_punch(conn, cfg: Config, raw: Mapping[str, Any], line_no: int, seen: set[tuple],
               file_id: int, *, known_employees: set[str] | None = None,
               check_seen: bool = True
               ) -> tuple[tuple[str, tuple] | None, list[Issue]]:
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
    exists = (emp_id in known_employees if known_employees is not None
              else conn.execute("SELECT 1 FROM employee WHERE emp_id = ?",
                                (emp_id,)).fetchone() is not None)
    if not exists:
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
    if check_seen:
        if key in seen:
            issues.append(_seen_duplicate_issue(line_no, key))
            return None, issues
        seen.add(key)

    sql = _PUNCH_INSERT
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


def _emp_exists(conn: Connection, emp_id: str) -> bool:
    return conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (emp_id,)).fetchone() is not None


def issues_fatal(issues: list[Issue]) -> bool:
    return any(i.severity == SEV_REJECT for i in issues)


def _record_issues(conn: Connection, file_id: int, issues: list[Issue], created_at: str) -> None:
    conn.executemany(
        "INSERT INTO ingest_issue(file_id, line_no, rule_id, emp_id, work_date, severity, field_name, "
        "raw_value, detail, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        [i.as_row(file_id, created_at) for i in issues],
    )


def quality_report(conn: Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT i.rule_id, i.severity, COUNT(*) AS c FROM ingest_issue i GROUP BY i.rule_id, i.severity "
        "ORDER BY c DESC"
    ).fetchall()
    return [{"rule_id": r["rule_id"], "severity": r["severity"], "count": int(r["c"])} for r in rows]
