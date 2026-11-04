"""F-007 举证包：不可篡改审计日志（hash 链）+ 三元组导出。

hash 链口径：
    entry_hash = sha256( prev_hash || seq || actor || action || ts || payload_sha256 )
    genesis prev_hash = sha256( engine_version || rule_pack_version )
链条只追加、不更新；任何一条被改写，verify_chain 会报出第一个断裂点。

三元组 = 规则版本 + 输入指纹 + 结论摘要。重跑同一三元组必须得到同一结论摘要（A8）。
"""

from __future__ import annotations

import csv
import json
import logging
import os
import shutil
import threading
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import ENGINE_VERSION, producer, projection, signing
from .config import Config, PROJECT_ROOT
from .db import (DB_BACKEND_POSTGRES, Connection, column_exists, get_meta, set_meta,
                 table_exists, transaction_if_needed)
from .evidence_digest import evidence_digest as compute_evidence_digest
from .package_inputs import input_arcnames, redact_issue_detail
from .quality_batch import (batch_id_from_sources, date_from_raw_value,
                            detail_physical_sources, repeat_sources)
from .rules.approvals import export_approval_csv, export_coverage_csv
from .rules.rulepack import RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6
from .util import (CN_TZ, CSV_FORMULA_ESCAPE, EVIDENCE_PACKAGE_SCHEMA,
                   EVIDENCE_PACKAGE_SCHEMA_V3, MANIFEST_CHECKSUM_FIELD, SIGNATURE_FIELD,
                   canonical_json, csv_safe_row, digest_of, manifest_checksum, sha256_hex)

logger = logging.getLogger(__name__)

# 同 run 导出锁：进程内线程锁 + PG session advisory lock；SQLite 用包目录原子锁文件。
_EXPORT_LOCK_GUARD = threading.Lock()
_EXPORT_LOCKS: dict[str, threading.Lock] = {}


class ExportBusyError(RuntimeError):
    """同一 run 已有导出在运行；明确拒绝，不并发写同一 zip。"""


@contextmanager
def _export_run_lock(conn: Connection, cfg: Config, run_id: str):
    key = f"wca.export:{run_id}"
    with _EXPORT_LOCK_GUARD:
        local = _EXPORT_LOCKS.setdefault(run_id, threading.Lock())
    if not local.acquire(blocking=False):
        raise ExportBusyError(f"该 run 正在导出：{run_id}（另一个导出正在进行），请稍后重试")
    pg_locked = False
    file_lock: Path | None = None
    try:
        if conn.dialect == DB_BACKEND_POSTGRES:
            row = conn.execute(
                "SELECT pg_try_advisory_lock(hashtext(?)) AS ok", (key,)).fetchone()
            if not bool(row["ok"]):
                raise ExportBusyError(
                    f"该 run 正在导出：{run_id}（另一个导出正在进行），请稍后重试")
            pg_locked = True
        else:
            cfg.packages_dir.mkdir(parents=True, exist_ok=True)
            lock_name = ".export-" + sha256_hex(run_id.encode("utf-8"))[:32] + ".lock"
            file_lock = cfg.packages_dir / lock_name
            try:
                fd = os.open(file_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError as exc:
                file_lock = None
                raise ExportBusyError(
                    f"该 run 正在导出：{run_id}（另一个导出正在进行），请稍后重试") from exc
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"pid={os.getpid()} run_id={run_id}\n")
        yield
    finally:
        if pg_locked:
            try:
                conn.execute("SELECT pg_advisory_unlock(hashtext(?))", (key,))
            except Exception:  # 连接已关闭时 PG 会自动释放 session lock
                logger.warning("释放导出 advisory lock 失败：%s", run_id, exc_info=True)
        if file_lock is not None:
            try:
                file_lock.unlink(missing_ok=True)
            except OSError:
                logger.warning("清理导出锁文件失败：%s", file_lock, exc_info=True)
        local.release()


GENESES = "wca-audit-chain-v1"
EPOCH_ACTION = "rule_pack.epoch.start"
LEGACY_RULE_PACK = "legacy"


def _chain_hash(prev: str, seq: int, actor: str, action: str, ts: str, payload_sha: str) -> str:
    return sha256_hex(f"{prev}|{seq}|{actor}|{action}|{ts}|{payload_sha}")


def genesis_hash(cfg: Config) -> str:
    return sha256_hex(f"{GENESES}|{ENGINE_VERSION}|{cfg.rule_pack_id}")


def _stored_rule_pack(conn: Connection) -> str:
    value = get_meta(conn, "rule_pack_version")
    if value:
        return value
    row = conn.execute("SELECT rule_pack_version FROM run ORDER BY started_at DESC LIMIT 1"
                       ).fetchone()
    return str(row["rule_pack_version"]) if row and row["rule_pack_version"] else LEGACY_RULE_PACK


def audit_epoch(conn: Connection, rule_pack_version: str) -> dict | None:
    """返回某规则包的纪元行；旧库/未切库时返回 None。"""
    if not table_exists(conn, "rule_pack_epoch"):
        return None
    row = conn.execute(
        "SELECT epoch_id, rule_pack_version, prev_rule_pack_version, prev_head_hash, "
        "activation_event_seq, segment_start_seq, segment_start_prev_hash, switched_at "
        "FROM rule_pack_epoch WHERE rule_pack_version = ? "
        "ORDER BY activation_event_seq DESC LIMIT 1", (rule_pack_version,)
    ).fetchone()
    return dict(row) if row else None


def _insert_event(conn: Connection, *, seq: int, run_id: str | None, actor: str, action: str,
                  ts: str, payload_sha: str, prev: str, entry: str,
                  rule_pack_version: str, segment_id: str | None) -> None:
    conn.execute(
        "INSERT INTO audit_event(seq, run_id, actor, action, ts, payload_sha256, prev_hash, "
        "entry_hash, rule_pack_version, segment_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (seq, run_id, actor, action, ts, payload_sha, prev, entry,
         rule_pack_version, segment_id),
    )


def ensure_audit_epoch(conn: Connection, cfg: Config) -> dict | None:
    """v5 首次写入旧 v4 链时，追加显式切换事件并建立新审计段。

    绝不重置 `audit_genesis`、绝不删除旧事件；切换事件留在旧段，段起点指回它的 entry_hash。
    """
    if cfg.rule_pack_id not in (RULE_PACK_V5, RULE_PACK_V6):
        return None
    existing = audit_epoch(conn, cfg.rule_pack_id)
    if existing:
        return existing
    stored = get_meta(conn, "audit_genesis")
    if not stored or stored == genesis_hash(cfg):
        return None
    old_pack = _stored_rule_pack(conn)
    if old_pack == cfg.rule_pack_id:
        raise RuntimeError(
            "审计链起点与当前 engine/rule_pack 不一致，且无法确定旧规则包纪元；"
            "拒绝写入，不重置旧链")
    # 已在导入/审批事务内时复用外层事务：再 BEGIN 会让 SQLite 报错，
    # 而 PG 的 COMMIT 会把外层业务写入提前提交，回滚补偿随之失效。
    with transaction_if_needed(conn):
        # 多个进程/连接同时首次切包时，epoch 的 seq/epoch_id 只能有一个赢家；
        # 与 append_audit 共用同一把事务级锁，串行化后再复查。
        if conn.dialect == DB_BACKEND_POSTGRES:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("wca.audit.append",))
        again = audit_epoch(conn, cfg.rule_pack_id)
        if again:
            return again
        old_epoch = audit_epoch(conn, old_pack)
        last = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1"
                            ).fetchone()
        prev = str(last["entry_hash"]) if last is not None else stored
        prev_seq = int(last["seq"]) if last is not None else 0
        seq = prev_seq + 1
        epoch_id = f"epoch-{cfg.rule_pack_id}-{seq}"
        ts = datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
        payload = {
            "epoch_id": epoch_id, "from_rule_pack": old_pack,
            "to_rule_pack": cfg.rule_pack_id, "prev_segment_head": prev,
            "prev_segment_head_seq": prev_seq,
        }
        payload_sha = sha256_hex(canonical_json(payload))
        entry = _chain_hash(prev, seq, "system:audit", EPOCH_ACTION, ts, payload_sha)
        _insert_event(conn, seq=seq, run_id=None, actor="system:audit", action=EPOCH_ACTION,
                      ts=ts, payload_sha=payload_sha, prev=prev, entry=entry,
                      rule_pack_version=old_pack,
                      segment_id=(old_epoch["epoch_id"] if old_epoch else None))
        conn.execute(
            "INSERT INTO rule_pack_epoch(epoch_id, rule_pack_version, prev_rule_pack_version, "
            "prev_head_hash, activation_event_seq, segment_start_seq, segment_start_prev_hash, "
            "switched_at) VALUES(?,?,?,?,?,?,?,?)",
            (epoch_id, cfg.rule_pack_id, old_pack, prev, seq, seq + 1, entry, ts),
        )
        return {
            "epoch_id": epoch_id, "rule_pack_version": cfg.rule_pack_id,
            "prev_rule_pack_version": old_pack, "prev_head_hash": prev,
            "activation_event_seq": seq, "segment_start_seq": seq + 1,
            "segment_start_prev_hash": entry, "switched_at": ts,
        }


def _audit_context(conn: Connection, cfg: Config | None) -> tuple[str, int, str | None, str | None]:
    """(prev_hash, next_seq, rule_pack_version, segment_id) for the next append."""
    if cfg is None:
        if any(audit_epoch(conn, p) for p in (RULE_PACK_V5, RULE_PACK_V6)):
            raise ValueError("审计纪元切换后追加事件必须传 cfg，不能猜段")
        last = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1"
                            ).fetchone()
        if last is None:
            raise ValueError("链首事件必须传 cfg 以派生 genesis")
        return str(last["entry_hash"]), int(last["seq"]) + 1, None, None

    package = cfg.rule_pack_id
    if package in (RULE_PACK_V5, RULE_PACK_V6):
        if package == RULE_PACK_V5 and audit_epoch(conn, RULE_PACK_V6):
            raise RuntimeError("v5 审计段已封闭（库已进入 v6 纪元），拒绝把新 v5 事件接在旧段上")
        epoch = ensure_audit_epoch(conn, cfg)
        if epoch:
            last = conn.execute(
                "SELECT entry_hash, seq FROM audit_event WHERE segment_id = ? "
                "ORDER BY seq DESC LIMIT 1", (epoch["epoch_id"],)).fetchone()
            prev = str(last["entry_hash"]) if last is not None else epoch["segment_start_prev_hash"]
            seq = int(last["seq"]) + 1 if last is not None else int(epoch["segment_start_seq"])
            return prev, seq, package, epoch["epoch_id"]
        last = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1"
                            ).fetchone()
        if last is None:
            return genesis_of(conn, cfg), 1, package, None
        return str(last["entry_hash"]), int(last["seq"]) + 1, package, None

    if package == RULE_PACK_V4:
        if audit_epoch(conn, RULE_PACK_V5) or audit_epoch(conn, RULE_PACK_V6):
            raise RuntimeError("v4 审计段已封闭（库已进入新规则包纪元），拒绝把新 v4 事件接在旧段上")
        last = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1"
                            ).fetchone()
        if last is None:
            return genesis_of(conn, cfg), 1, package, None
        return str(last["entry_hash"]), int(last["seq"]) + 1, package, None

    raise RuntimeError(f"不支持的规则包版本：{package}")


def append_audit(conn: Connection, *, run_id: str | None, actor: str, action: str,
                 payload: object, ts: str | None = None, cfg: Config | None = None) -> tuple[int, str]:
    """追加一条审计事件。payload 走规范 JSON，禁止浮点。

    审计链是单链表：seq/prev_hash 由「当前链头」推导，并发追加必须串行化，
    否则两个事务会各自读到同一个链头并抢同一个 seq。这里统一用
    `transaction_if_needed` 包住 append：调用方已在事务内就复用，否则自开一个，
    PG advisory lock 因而总能持有到提交；业务侧不需要再各自记得包事务。
    """
    with transaction_if_needed(conn):
        if conn.dialect == DB_BACKEND_POSTGRES:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("wca.audit.append",))
        prev, seq, pack, segment = _audit_context(conn, cfg)
        ts = ts or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
        payload_sha = sha256_hex(canonical_json(payload))
        entry = _chain_hash(prev, seq, actor, action, ts, payload_sha)
        _insert_event(conn, seq=seq, run_id=run_id, actor=actor, action=action, ts=ts,
                      payload_sha=payload_sha, prev=prev, entry=entry,
                      rule_pack_version=pack or "", segment_id=segment)
        return seq, entry


def genesis_of(conn: Connection, cfg: Config) -> str:
    stored = get_meta(conn, "audit_genesis")
    if not stored:
        g = genesis_hash(cfg)
        set_meta(conn, "audit_genesis", g)
        return g
    epoch = audit_epoch(conn, cfg.rule_pack_id)
    if epoch:
        return str(epoch["segment_start_prev_hash"])
    if stored != genesis_hash(cfg):
        raise RuntimeError("审计链起点与当前 engine/rule_pack 不一致，拒绝写入（防止历史被替换）")
    return stored


def set_genesis(conn: Connection, cfg: Config) -> None:
    """确保当前规则包有可用的审计上下文；v5/v6 首次写旧库会显式建立纪元。"""
    if cfg.rule_pack_id in (RULE_PACK_V5, RULE_PACK_V6):
        if cfg.rule_pack_id == RULE_PACK_V5 and audit_epoch(conn, RULE_PACK_V6):
            raise RuntimeError("v5 审计段已封闭（库已进入 v6 纪元），拒绝新的 v5 运行")
        ensure_audit_epoch(conn, cfg)
        if audit_epoch(conn, cfg.rule_pack_id):
            return
    elif audit_epoch(conn, RULE_PACK_V5) or audit_epoch(conn, RULE_PACK_V6):
        raise RuntimeError("v4 审计段已封闭（库已进入新规则包纪元），拒绝新的 v4 运行")
    genesis_of(conn, cfg)


@dataclass
class ChainVerification:
    length: int
    ok: bool
    broken_at_seq: int | None = None
    reason: str = ""
    head_hash: str = ""

    def as_dict(self) -> dict:
        return {
            "length": self.length,
            "ok": self.ok,
            "broken_at_seq": self.broken_at_seq,
            "reason": self.reason,
            "head_hash": self.head_hash,
        }


def _verify_rows(rows: list, start_prev: str) -> ChainVerification:
    if not rows:
        return ChainVerification(0, True, None, "空链条", start_prev)
    prev = start_prev
    for r in rows:
        expected = _chain_hash(prev, int(r["seq"]), r["actor"], r["action"], r["ts"],
                               r["payload_sha256"])
        if r["prev_hash"] != prev:
            return ChainVerification(len(rows), False, int(r["seq"]),
                                     "prev_hash 与前一条 entry_hash 不衔接",
                                     str(rows[-1]["entry_hash"]))
        if r["entry_hash"] != expected:
            return ChainVerification(len(rows), False, int(r["seq"]),
                                     "entry_hash 与内容重算不一致（疑似改写）",
                                     str(rows[-1]["entry_hash"]))
        prev = str(r["entry_hash"])
    return ChainVerification(len(rows), True, None, "", prev)


def verify_chain(conn: Connection, cfg: Config, *, upto_seq: int | None = None,
                 segment: dict | None = None, legacy_only: bool = False
                 ) -> ChainVerification:
    """校验链/段。

    * 给 `segment`：只验证该 v5 审计段，从该段起点前哈希开始；
    * `legacy_only`：只验证 v4 legacy 段（用于旧 v4 run 导出）；
    * 默认：有 v5 纪元时同时验证旧 v4 链与 v5 新段；没有纪元时验证整条链。
    """
    cols = ("seq, actor, action, ts, payload_sha256, prev_hash, entry_hash, "
            "rule_pack_version, segment_id")
    if segment is not None:
        where, params = "WHERE segment_id = ?", (segment["epoch_id"],)
        if upto_seq is not None:
            where += " AND seq <= ?"
            params = params + (int(upto_seq),)
        rows = conn.execute(f"SELECT {cols} FROM audit_event {where} ORDER BY seq",
                            params).fetchall()
        return _verify_rows(rows, str(segment["segment_start_prev_hash"]))

    epoch = audit_epoch(conn, cfg.rule_pack_id) if not legacy_only else None
    has_v5_epoch = audit_epoch(conn, RULE_PACK_V5)
    has_v6_epoch = audit_epoch(conn, RULE_PACK_V6)
    if legacy_only or (cfg.rule_pack_id == RULE_PACK_V4 and (has_v5_epoch or has_v6_epoch)):
        where, params = "WHERE segment_id IS NULL", ()
        if upto_seq is not None:
            where += " AND seq <= ?"
            params = (int(upto_seq),)
        rows = conn.execute(f"SELECT {cols} FROM audit_event {where} ORDER BY seq",
                            params).fetchall()
        start = get_meta(conn, "audit_genesis") or genesis_hash(cfg)
        return _verify_rows(rows, start)

    if epoch and cfg.rule_pack_id in (RULE_PACK_V5, RULE_PACK_V6):
        legacy_where, legacy_params = "WHERE segment_id IS NULL", ()
        if upto_seq is not None:
            legacy_where += " AND seq <= ?"
            legacy_params = (int(upto_seq),)
        legacy = conn.execute(
            f"SELECT {cols} FROM audit_event {legacy_where} ORDER BY seq",
            legacy_params).fetchall()
        start = get_meta(conn, "audit_genesis") or genesis_hash(cfg)
        legacy_ver = _verify_rows(legacy, start)
        if not legacy_ver.ok:
            return legacy_ver
        seg_where, seg_params = "WHERE segment_id = ?", (epoch["epoch_id"],)
        if upto_seq is not None:
            seg_where += " AND seq <= ?"
            seg_params = seg_params + (int(upto_seq),)
        seg_rows = conn.execute(
            f"SELECT {cols} FROM audit_event {seg_where} ORDER BY seq", seg_params).fetchall()
        seg_ver = _verify_rows(seg_rows, str(epoch["segment_start_prev_hash"]))
        if not seg_ver.ok:
            return seg_ver
        return ChainVerification(len(legacy) + len(seg_rows), True, None, "", seg_ver.head_hash)

    where, params = "WHERE 1=1", ()
    if upto_seq is not None:
        where += " AND seq <= ?"
        params = (int(upto_seq),)
    rows = conn.execute(f"SELECT {cols} FROM audit_event {where} ORDER BY seq",
                        params).fetchall()
    start = get_meta(conn, "audit_genesis") or genesis_hash(cfg)
    return _verify_rows(rows, start)


def tamper_check_report(ver: ChainVerification) -> str:
    return "链完整" if ver.ok else f"链在 seq={ver.broken_at_seq} 处断裂：{ver.reason}"


# ------------------------------------------------------------------ 输入指纹 / 结论摘要
def input_fingerprint(conn: Connection, scope: dict,
                      file_ids: set[int] | None = None) -> str:
    """输入指纹 = 本次校验**实际引用到**的输入文件集合 + 范围与口径参数。

    O-11a：旧实现把库里登记过的**所有**文件都算进来，于是导入一个与本次范围无关的文件
    也会改变指纹，"同一输入可复现"这句话就变得难解释。改成按引用集合计算后，
    无关文件的增删不再影响指纹，而范围/口径/规则版本变化仍会如实改变它。
    """
    if file_ids is None:
        where, params = "", ()
    else:
        ids = sorted(int(i) for i in file_ids)
        if not ids:
            return sha256_hex(canonical_json({"files": [], "scope": scope}))
        where = f"WHERE file_id IN ({','.join('?' * len(ids))})"
        params = tuple(ids)
    files = conn.execute(
        f"SELECT rel_path, sha256, row_count, kind FROM raw_file {where}", params,
    ).fetchall()
    # 排序放在 Python 里按 UTF-8 字节序完成：不依赖 SQLite/PG 的文本 collation，
    # 同一批输入在任一后端都必须得到逐字节相同的 input_fingerprint（0.4.8）。
    files.sort(key=lambda f: (str(f["rel_path"]).encode("utf-8"), str(f["sha256"])))
    payload = {
        "files": [
            {"rel_path": f["rel_path"], "sha256": f["sha256"], "rows": int(f["row_count"]),
             "kind": f["kind"]}
            for f in files
        ],
        "scope": scope,
        "fingerprint_scope": "referenced_files" if file_ids is not None else "all_registered_files",
    }
    return sha256_hex(canonical_json(payload))


def conclusion_digest(findings: list) -> str:
    return digest_of([f.canonical() for f in sorted(findings, key=_finding_sort_key)])


def _finding_sort_key(f) -> tuple:
    return (f.emp_id, f.work_date or "", f.period_key or "", f.rule_id, f.severity)


# ------------------------------------------------------------------ 举证包导出
PACKAGE_README = (
    "本举证包由 worktime-compliance-agent 生成。\r\n"
    "三元组（规则版本 / 输入指纹 / 结论摘要）用于复核：在相同输入与相同规则版本下重跑，"
    "结论摘要必须逐字节一致。\r\n"
    "本包不含任何应付金额：引擎只输出小时数与法定倍数档位，金额由 HR 负责人在复核台具名录入。\r\n"
    "包内 inputs/ 带本次结论真正依赖的原始 CSV；v5 另带审批台账 approval_ledger.csv，"
    "选择规则见 manifest.inputs.selection_rule。"
    "注意：approval_ledger.csv / approval_coverage.csv 由数据库确定性重导出"
    "（UTF-8 无 BOM、LF），不是原始上传字节，原始字节未随包保留；"
    "该事实记录在 manifest.inputs.approval_export。"
    "audit_chain.jsonl 是本次 run 的链前缀"
    "（到该 run 最后一条事件），边界见 manifest.audit_window。"
    "包内 verify.py 只是便利脚本，**不是信任依据**；正式验收应使用发行 wheel 的 "
    "wca-verify（独立实现，不执行包内代码），再用 wca replay 重放引擎比对三元组。\r\n"
    "v3 包带 manifest.signature（Ed25519）与 artifact_sha256/artifacts_digest/"
    "verify_script_sha256：包内公钥只能证明包内自洽；`--public-key` 只表示与供给的公钥 pin 匹配，"
    "来源身份仍需双方通过独立渠道核验 key_id。验签需要 PyNaCl，版本见 "
    "verify-requirements.txt。\r\n"
    "包内 policies/ 含规则包定义、条文/稳定引用、口径声明、13 项存疑与 CONFIDENCE；"
    "不把整份 docs/ 打包。\r\n"
    "摘要边界：conclusion_digest 只覆盖 rule_id/rule_version/emp_id/work_date/period_key/"
    "severity/metric/citations/explanation 九个规范字段；source_rel_path、source_line_no、"
    "severity_label 由 artifact_sha256[findings.csv] 负责。单个 FINDINGS DIGEST OK "
    "不等于整张 findings.csv 未变，必须同时看 ARTIFACTS OK。\r\n"
    "evidence_digest 单独覆盖全部 finding 的 evidence 块（tables/window/rules/"
    "aggregation，固定字段序、空值 null、路径 /），不进入 conclusion_digest；"
    "只补/改证据定位注释时，只有 evidence_digest 变化。正式验收必须用包外 "
    "--expect-evidence-digest 或单包 anchor 文件的 evidence_digest 锚定；"
    "签名者可能作恶或私钥失窃，不能只看包内 manifest。\r\n"
    "input_fingerprint 是内容与范围指纹（输入文件内容/引用范围/规则参数），"
    "inputs_digest 是包内 inputs/ 实际文件字节（不含 run_id 与 DB file_id；"
    "文件名由 rel_path 推导）；同一批输入跨 run/跨库导包时 inputs_digest 应稳定一致。"
    "注意：manifest.json 顶层另有 run_id 字段，只用于把包回指到库内 run 与审计段，"
    "不参与 inputs_digest、conclusion_digest、evidence_digest、artifacts_digest 或"
    "input_fingerprint 的任何计算；四联值本身不含 run_id。\r\n"
    "rule_version 是单条规则版本，不等于 rule pack 版本；v5 包可同时有 v4/v5 规则，"
    "分布见 manifest.counts.rule_versions 与包内 policies/RULE-PACK.md。\r\n"
)


# ---------------------------------------------------------------- 责任与未覆盖（US-EX-02 / US-EX-03 / US-RV-01）
NOT_COVERED_REL = "config/not_covered.json"
# 配置路径一律相对仓库根解析，不依赖进程当前目录（换目录 export 必须仍可读）。
NOT_COVERED_PATH = PROJECT_ROOT / NOT_COVERED_REL


def not_covered_block(cfg: Config) -> dict:
    """未覆盖清单：外部接收方最怕的是"缺项＝造假"，所以缺什么必须自己说清楚。

    覆盖城市来自档位表（配置，不写死），其余来自 `config/not_covered.json`。
    """
    raw = Path(NOT_COVERED_PATH)
    data = json.loads(raw.read_text(encoding="utf-8")) if raw.is_file() else {}
    profile = getattr(cfg, "region_profile", None)
    data["scope"]["cities_covered"] = profile.codes() if profile else [cfg.region_code]
    data["scope"]["cities_covered_labels"] = ([profile.label(c) for c in profile.codes()]
                                              if profile else [cfg.region_label])
    data["generated_from"] = NOT_COVERED_REL
    return data


def responsibility_block(conn: Connection, cfg: Config, run_id: str) -> dict:
    """谁参与了什么：机器只做解释与检索，数值出自确定性引擎，对外结论必须有人签名。"""
    rows = conn.execute(
        "SELECT f.finding_id, f.rule_id, f.emp_id, f.work_date, f.period_key, f.severity, "
        "       r.status, r.reviewer, r.decided_at, r.note, r.amount_cents_input, "
        "       r.amount_entered_by, r.amount_entered_at "
        "FROM finding f LEFT JOIN review_item r "
        "  ON r.run_id = f.run_id AND r.source_type = 'finding' "
        " AND (f.rule_id || ':' || f.emp_id || ':' || COALESCE(f.work_date, f.period_key, 'None') = r.source_id "
        "      OR f.rule_id || ':' || f.emp_id || ':' || COALESCE(f.work_date, f.period_key, '') = r.source_id) "
        "WHERE f.run_id = ?", (run_id,)).fetchall()
    # responsibility.json 的行序同样不能依赖 SQL 的 NULL 排序（0.4.8）。
    rows.sort(key=lambda x: (
        str(x["emp_id"]).encode("utf-8"), x["work_date"] or "", x["period_key"] or "",
        str(x["rule_id"]).encode("utf-8"),
    ))
    confirmed, pending = [], []
    for x in rows:
        entry = {"rule_id": x["rule_id"], "emp_id": x["emp_id"],
                 "work_date": x["work_date"], "period_key": x["period_key"],
                 "severity": x["severity"]}
        if x["status"] and x["status"] != "OPEN":
            entry.update({"decision": x["status"], "confirmed_by": x["reviewer"],
                          "confirmed_at": x["decided_at"], "note": x["note"],
                          "amount_cents_input": x["amount_cents_input"],
                          "amount_entered_by": x["amount_entered_by"]})
            confirmed.append(entry)
        else:
            pending.append(entry)

    # 问答留痕只导出关联到本 run 的记录；旧库/升级前的行 run_id 为 NULL，
    # 宁可少带也不把其他 run 的问答元数据混进本次举证包。
    ai_rows = (conn.execute(
        "SELECT qid, asked_at, actor_emp_id, question, intent, gate_decision, citation_ids, "
        "       numeric_tokens, allowed_numbers, provider, model, needs_review "
        "FROM question_log WHERE run_id = ?", (run_id,)).fetchall()
        if _has_table(conn, "question_log") and _has_column(conn, "question_log", "run_id")
        else [])
    # 不用 SQL ORDER BY asked_at：同一时间戳的并列行在库里无显式顺序，会让
    # responsibility.json 的问答留痕顺序随后端变化（0.4.8）。
    ai_rows.sort(key=lambda a: (str(a["asked_at"] or "").encode("utf-8"),
                                str(a["qid"] or "").encode("utf-8")))
    ai = [{"qid": a["qid"], "asked_at": a["asked_at"], "actor_emp_id": a["actor_emp_id"],
           "intent": a["intent"], "provider": a["provider"], "model": a["model"],
           "gate_decision": a["gate_decision"],
           "citations": json.loads(a["citation_ids"] or "[]"),
           "numeric_tokens": json.loads(a["numeric_tokens"] or "[]"),
           "escalated_to_human": bool(int(a["needs_review"] or 0))}
          for a in ai_rows]
    signs = conn.execute(
        "SELECT seq, actor, ts, payload_sha256 FROM audit_event "
        "WHERE action = 'evidence.sign' AND run_id = ? ORDER BY seq", (run_id,)).fetchall()
    return {
        "principle": "数值一律由确定性规则引擎计算；AI 只做意图归类与已有事实的叙述，"
                     "且出口有数字白名单与重大事项拒诺两道闸；对外结论必须由具名人工确认。",
        "engine_only_outputs": ["分钟数", "法定倍数档位（千分位）", "规则 ID", "条文号", "原始行号"],
        "never_output": ["应付金额", "赔偿数额", "违法定性"],
        "ai_participation_scope_note": "问答留痕仅本 run 关联记录（question_log.run_id；历史 NULL 行不导出）",
        "ai_participation": ai,
        "ai_participation_count": len(ai),
        "human_confirmations": confirmed,
        "human_confirmed_findings": len(confirmed),
        "unsigned_findings_excluded_from_conclusions": len(pending),
        "pending_findings": [p["rule_id"] + ":" + p["emp_id"] for p in pending][:200],
        "signed_by": [{"seq": int(x["seq"]), "actor": x["actor"], "ts": x["ts"]} for x in signs],
        "signed": bool(signs),
    }


def _has_table(conn: Connection, name: str) -> bool:
    return table_exists(conn, name)


def _has_column(conn: Connection, table: str, column: str) -> bool:
    return column_exists(conn, table, column)


def record_delivery_event(conn: Connection, cfg: Config, run_id: str,
                          recorded_by: str) -> dict:
    """登记交付事件：把“谁登记了这次交付”追加进审计链，不改写历史。

    这不是密码学签名，也不提供签名信任根；`evidence.sign` 动作名与 payload
    （`run_id`、`signed_by`）保持不变，改名只改函数/CLI 文案，审计事件字节不变。
    """
    if not recorded_by.strip():
        raise ValueError("登记人不能为空")
    seq, entry_hash = append_audit(
        conn, run_id=run_id, actor=f"human:{recorded_by}", action="evidence.sign",
        payload={"run_id": run_id, "signed_by": recorded_by}, cfg=cfg)
    return {"review_id": None, "audit_seq": seq, "entry_hash": entry_hash,
            "signed_by": recorded_by}


def sign_package(conn: Connection, cfg: Config, run_id: str, signed_by: str) -> dict:
    """迁移期旧别名；等价于 `record_delivery_event`，不做密码学签名。"""
    return record_delivery_event(conn, cfg, run_id, recorded_by=signed_by)


# 导出产物最小化：金额与录入人只留在库/复核台，不进入举证包。
EXPORT_REDACTED_REVIEW_FIELDS = ("amount_cents_input", "amount_entered_by")


def _minimized_responsibility(resp: dict) -> dict:
    """复制责任区块并去掉包内不应出现的金额/录入人字段；原 dict/数据库不动。"""
    doc = dict(resp)
    doc["human_confirmations"] = [
        {k: v for k, v in item.items() if k not in EXPORT_REDACTED_REVIEW_FIELDS}
        for item in resp["human_confirmations"]
    ]
    return doc


def _trim_input_entry(entry: dict, fields: set[str], work: Path) -> None:
    """把登记表中的可裁剪列从导出副本移除；只允许已显式列入 omit_fields 的列。"""
    source = Path(entry["source"])
    target = work / entry["arcname"]
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        missing = sorted(fields - set(header))
        if missing:
            raise ValueError(f"输入 {entry['rel_path']} 缺列，无法裁剪：{missing}")
        keep = [name for name in header if name not in fields]
        with target.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=keep, lineterminator="\n")
            writer.writeheader()
            for row in reader:
                writer.writerow({name: row.get(name, "") for name in keep})
    data = target.read_bytes()
    entry["source_sha256"] = entry["sha256"]
    entry["sha256"] = sha256_hex(data)
    entry["bytes"] = len(data)
    entry["trimmed"] = True


def _apply_omissions(collected: dict, work: Path,
                     omit_fields: tuple[tuple[str, str], ...]) -> list[dict]:
    """按 kind 分组裁剪；请求的 kind/field 必须实际存在，否则失败关闭。"""
    if not omit_fields:
        return []
    by_kind: dict[str, set[str]] = {}
    for kind, field in omit_fields:
        by_kind.setdefault(kind, set()).add(field)
    entries = collected["entries"]
    touched: dict[str, int] = {kind: 0 for kind in by_kind}
    for entry in entries:
        kind = str(entry.get("kind") or "")
        fields = by_kind.get(kind)
        if not fields:
            continue
        _trim_input_entry(entry, fields, work)
        touched[kind] += 1
    absent = sorted(kind for kind, count in touched.items() if count == 0)
    if absent:
        raise ValueError(f"请求裁剪的输入种类在本次包内没有文件：{absent}")
    collected["total_bytes"] = sum(int(e["bytes"]) for e in entries)
    meta = [{"kind": kind, "field": field, "reason": projection.OMITTED_REASON}
            for kind, field in omit_fields]
    return meta


def _write_conclusions_csv(path: Path, rows: list[dict]) -> None:
    """对外结论集：**只收已登记人工结论的条目**（US-RV-01★：无人工结论的异常不得进入）。"""
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rule_id", "emp_id", "work_date", "period_key", "severity",
                    "decision", "confirmed_by", "confirmed_at", "note"])
        for x in rows:
            w.writerow(csv_safe_row([
                x["rule_id"], x["emp_id"], x["work_date"], x["period_key"], x["severity"],
                x["decision"], x["confirmed_by"], x["confirmed_at"], x.get("note"),
            ]))




def _write_package_confidence(path, *, findings_count: int, final_count: int,
                              signed: bool, findings_batched: int = 0,
                              issues_total: int | None = None) -> None:
    """把本包真实计数写进已签名工件，避免静态 CONFIDENCE 把 confirmed 包写成 0 条。"""
    base = path.read_text(encoding="utf-8").rstrip()
    role = "含已确认结论" if final_count else "engine-only（无已确认结论）"
    issues_total = findings_count if issues_total is None else issues_total
    block = (
        "\n\n## 本包计数（导出时生成）\n\n"
        f"- 发现（未签认）：{findings_count} 条\n"
        f"- 其中批次 finding：{findings_batched} 条（每批代表多条重复问题）\n"
        f"- 按问题条数计：{issues_total} 条"
        "（= finding 条数 - 批次 finding 条数 + 各批 batch_size 合计）\n"
        f"- 已确认结论：{final_count} 条\n"
        f"- responsibility.signed：{'true' if signed else 'false'}\n"
        f"- 本包角色：{role}\n"
        "- 三处口径应一致：本文件、`manifest.counts`、`未覆盖清单.md`；"
        "若不一致，以 manifest 为准并视为导出缺陷。\n"
    )
    path.write_text(base + block, encoding="utf-8")


def _aggregate_findings(findings) -> list[dict]:
    """带 evidence 定位元数据的结论（第四轮实测 24 条：6 VIOLATION + 17 REVIEW + 1 DEFENSIBLE）。

    筛选依据是 evidence 块非空，而不是严重级别或“有没有行号”；这样 QUAL/REG/SCOPE
    这类同样没有单行来源、但事实来自台账/主数据的结论不会被误算进周期聚合清单。
    """
    out: list[dict] = []
    for f in findings:
        evidence = json.loads(f["evidence_json"] or "{}")
        if not evidence:
            continue
        window = evidence.get("window") if isinstance(evidence.get("window"), dict) else {}
        out.append({
            "severity": str(f["severity"]),
            "rule_id": str(f["rule_id"]),
            "emp_id": str(f["emp_id"]),
            "period_key": str(f["period_key"] or f["work_date"] or ""),
            "tables": evidence.get("tables") or [],
            "start": window.get("start"),
            "end": window.get("end"),
            "rules": evidence.get("rules") or [],
            "aggregation": evidence.get("aggregation") or "",
        })
    return out


def _not_covered_markdown(nc: dict, *, findings_count: int = 0,
                          final_count: int = 0,
                          rule_versions: dict[str, int] | None = None,
                          aggregate_findings: list[dict] | None = None,
                          findings_batched: int = 0,
                          issues_total: int | None = None) -> str:
    """把未覆盖清单渲染成给人读的 Markdown（数据来自 config/not_covered.json，不写死在代码里）。"""
    NL = chr(10)
    scope = nc["scope"]
    labels = list(scope.get("cities_covered_labels") or [])
    codes = [str(code) for code in (scope.get("cities_covered") or [])]
    if labels and codes and len(labels) == len(codes):
        city_text = "、".join(f"{label}（{code}）" for label, code in zip(labels, codes))
    elif labels:
        city_text = "、".join(labels)
    elif codes:
        city_text = "、".join(codes)
    else:
        city_text = "无"
    out = [
        "# 未覆盖清单（本期不做 / 未验证）",
        "",
        f"- 本轮包内：发现（未签认）{findings_count} 条 / 已确认结论 {final_count} 条"
        f"；其中批次 finding {findings_batched} 条，按问题条数计 "
        f"{findings_count if issues_total is None else issues_total} 条"
        "（以 manifest.counts.findings_total / findings_batched / issues_total / "
        "final_conclusions 为准）",
        "- 单条规则版本分布：" + (", ".join(
            f"{k}={v}" for k, v in sorted((rule_versions or {}).items())) or "无")
        + "。`rule_version` 是单条规则版本，不等于 rule pack 版本；v5 包内保留未改判据的 v4 规则是预期。",
        "- 覆盖工时制：" + str(scope["worktime_regimes_covered"]),
        "- 不覆盖工时制：" + str(scope["worktime_regimes_excluded"]),
        "  - 原因：" + str(scope["excluded_reason"]),
        "- 覆盖城市：" + city_text,
        "- 金额：" + str(scope["money_outputs"]),
        "",
        "## 摘除的判据",
        "",
    ]
    out += [f"- `{r['rule_id']}`：{r['why']}" for r in nc["rules_excluded"]]
    out += ["", "## 已知局限", ""]
    out += [f"- {x}" for x in nc["known_limitations"]]
    out += ["", "## 未测项（不得当成已达成）", ""]
    out += [f"- {x}" for x in nc["not_tested"]]
    out += ["", "## 证据定位（非单行结论）", ""]
    if aggregate_findings:
        counts = {severity: 0 for severity in ("VIOLATION", "REVIEW", "DEFENSIBLE")}
        for item in aggregate_findings:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        out.append(
            f"- 共 {len(aggregate_findings)} 条：VIOLATION {counts['VIOLATION']} / "
            f"REVIEW {counts['REVIEW']} / DEFENSIBLE {counts['DEFENSIBLE']}。"
            "以下每条都有 evidence 定位元数据，但仍是周期聚合/跨行事实，"
            "无法定位到单行；复算须按下列表、区间与规则进行。")
        for item in aggregate_findings:
            out.append(
                f"- `{item['severity']} / {item['rule_id']} / {item['emp_id']} / "
                f"{item['period_key']}`：该结论为周期聚合，无法定位到单行；"
                f"复算口径：表 {'/'.join(item['tables']) or '未知'}，"
                f"区间 {item['start'] or '未知'}..{item['end'] or '未知'}，"
                f"关联规则 {'/'.join(item['rules']) or item['rule_id']}；"
                f"{item['aggregation'] or '按 metric_json 聚合值复算'}。")
    else:
        out.append("- 无：本轮没有带 evidence 定位元数据的结论。")
    return NL.join(out) + NL


# ------------------------------------------------- 输入自含与外部重放（US-EX-01 / A8）
# 受控实验：3,000 员工月密集数据实测需要 10,881,370 字节；8 MiB 会阻断自含导出。
# 12 MiB 仍保持单包、不分卷；这是实验值，不是最终 SLA。
EXPORT_INPUTS_MAX_BYTES = 12 * 1024 * 1024
# 第一档告警线：3,000 行台账规模下的常态提示（不拒绝导出）。
EXPORT_INPUTS_WARN_BYTES = 11_010_048   # 10.5 MiB
# 第二档临界线：更接近硬上限，manifest/CLI/日志升级为“需人工确认”，仍不拒绝导出。
EXPORT_INPUTS_CRITICAL_BYTES = 12_058_624   # 11.5 MiB
INPUTS_DIRNAME = "inputs"
INPUTS_MANIFEST_NAME = f"{INPUTS_DIRNAME}/manifest.json"
README_FILE = "README.txt"
VERIFY_REQUIREMENTS_FILE = "verify-requirements.txt"


def input_budget_status(total_bytes: int, cap_bytes: int | None = None,
                        warn_bytes: int | None = None,
                        critical_bytes: int | None = None) -> str:
    """返回 "ok" / "warning" / "critical"；超过上限直接拒绝，等于上限放行。

    三档口径（写死，避免调用方各自解释）：
      * < 10.5 MiB：ok；
      * 10.5 MiB <= total < 11.5 MiB：warning（常态提示，仍允许导出）；
      * 11.5 MiB <= total <= 12 MiB：critical（接近硬上限，需人工确认，仍允许导出）；
      * > 12 MiB：ValueError（拒绝，不静默截断）。
    """
    cap = EXPORT_INPUTS_MAX_BYTES if cap_bytes is None else cap_bytes
    warn = EXPORT_INPUTS_WARN_BYTES if warn_bytes is None else warn_bytes
    critical = EXPORT_INPUTS_CRITICAL_BYTES if critical_bytes is None else critical_bytes
    if total_bytes > cap:
        raise ValueError(
            f"待打包输入 {total_bytes:,} 字节，超过预算 {cap:,} 字节；"
            "确认没必要自含时可用 --no-inputs 导出不带原始数据的包")
    if total_bytes >= critical:
        return "critical"
    if total_bytes >= warn:
        return "warning"
    return "ok"


def check_input_budget(total_bytes: int, cap_bytes: int | None = None,
                       critical_bytes: int | None = None) -> str:
    """输入体积预算的唯一判据；等于上限放行，超过 1 字节即拒绝。"""
    return input_budget_status(total_bytes, cap_bytes=cap_bytes,
                               critical_bytes=critical_bytes)


def _run_input_file_ids(conn: Connection, run_id: str) -> set[int]:
    """本次结论**实际依赖**的输入文件 = 主数据 ∪ 引用集合 ∪ 结论溯源里的文件 ∪ 未归属质量问题的文件。

    三个并集都必要：
      * 主数据（org/employee）不出现在 `source_refs` 里，但没有它连"这个员工存在"都不成立；
      * 只取输入指纹的引用集合也不够——`QUAL-02` 那类"归属不到人"的质量结论扫的是全库
        `ingest_issue`，产生它的文件可能不在引用集合里，却确实改变了结论摘要。
    漏掉任何一个，重放摘要就对不上，而那会被误读成"引擎不可复现"。
    """
    ids: set[int] = set()
    for r in conn.execute("SELECT file_id FROM raw_file WHERE kind IN ('org','employee')"
                          " ORDER BY file_id").fetchall():
        ids.add(int(r["file_id"]))
    if _has_column(conn, "run", "referenced_file_ids"):
        row = conn.execute("SELECT referenced_file_ids FROM run WHERE run_id = ?",
                           (run_id,)).fetchone()
        if row is not None and row["referenced_file_ids"]:
            ids |= {int(x) for x in json.loads(row["referenced_file_ids"])}
    for f in conn.execute("SELECT source_refs FROM finding WHERE run_id = ?",
                          (run_id,)).fetchall():
        for ref in json.loads(f["source_refs"] or "[]"):
            if isinstance(ref, dict) and ref.get("file_id") is not None:
                ids.add(int(ref["file_id"]))
    for r in conn.execute(
        "SELECT DISTINCT file_id FROM ingest_issue "
        "WHERE emp_id = '' OR emp_id NOT IN (SELECT emp_id FROM employee)"
    ).fetchall():
        ids.add(int(r["file_id"]))
    return ids


def _run_chain_prefix(conn: Connection, run_id: str, rule_pack_version: str
                      ) -> tuple[list, int | None, dict | None]:
    """本次 run 的链前缀；v5 纪元只取新段，v4 run 只取 legacy 段。"""
    epoch = audit_epoch(conn, rule_pack_version) if rule_pack_version in (
        RULE_PACK_V5, RULE_PACK_V6) else None
    legacy_closed = (audit_epoch(conn, RULE_PACK_V5) or audit_epoch(conn, RULE_PACK_V6)) \
        if rule_pack_version == RULE_PACK_V4 else None
    if epoch:
        where, params = "WHERE segment_id = ?", (epoch["epoch_id"],)
    elif legacy_closed:
        where, params = "WHERE segment_id IS NULL", ()
    else:
        where, params = "WHERE 1=1", ()
    row = conn.execute(
        f"SELECT MAX(seq) AS max_seq FROM audit_event {where} AND run_id = ?",
        params + (run_id,)).fetchone()
    max_seq = int(row["max_seq"]) if row and row["max_seq"] is not None else None
    if max_seq is None:
        # 旧 run 可能没有 run_id 事件：退回该段当前链头，保证链仍可验证
        row = conn.execute(f"SELECT MAX(seq) AS max_seq FROM audit_event {where}",
                           params).fetchone()
        max_seq = int(row["max_seq"]) if row and row["max_seq"] is not None else None
    if max_seq is None:
        return [], None, epoch
    rows = conn.execute(
        f"SELECT seq, run_id, actor, action, ts, payload_sha256, prev_hash, entry_hash, "
        f"rule_pack_version, segment_id FROM audit_event {where} AND seq <= ? ORDER BY seq",
        params + (max_seq,)
    ).fetchall()
    return rows, max_seq, epoch


def _select_raw_files(conn: Connection, ids: set[int]) -> list:
    if not ids:
        return []
    ordered = sorted(int(x) for x in ids)
    placeholders = ",".join("?" * len(ordered))
    rows = conn.execute(
        f"SELECT file_id, rel_path, sha256, kind, row_count FROM raw_file "
        f"WHERE file_id IN ({placeholders})", tuple(ordered)
    ).fetchall()
    # 文本排序在 Python 中按 UTF-8 字节序完成，跨 SQLite/PG 一致（0.4.8）。
    rows.sort(key=lambda r: (str(r["rel_path"]).encode("utf-8"), str(r["sha256"])))
    return rows


def _select_issues(conn: Connection, ids: set[int]) -> list:
    if not ids:
        return []
    ordered = sorted(int(x) for x in ids)
    placeholders = ",".join("?" * len(ordered))
    rows = conn.execute(
        f"SELECT i.*, f.rel_path FROM ingest_issue i JOIN raw_file f "
        f"ON f.file_id = i.file_id WHERE i.file_id IN ({placeholders})", tuple(ordered)
    ).fetchall()
    # 不再按 DB file_id 排：file_id 是自增值，跨库/换导入顺序都会漂移。
    # 统一按包内相对路径字节序 + 行号 + 规则/字段/原值确定行序（0.4.8）。
    rows.sort(key=lambda r: (
        str(r["rel_path"]).encode("utf-8"), int(r["line_no"] or 0),
        str(r["rule_id"]).encode("utf-8"), str(r["field_name"] or "").encode("utf-8"),
        str(r["raw_value"] or "").encode("utf-8"), str(r["detail"] or "").encode("utf-8"),
    ))
    return rows


def _aggregate_export_issues(issues: list, file_paths: dict[int, str]) -> list[dict]:
    """QUAL-DUP 按 (员工, 实际发生日) 聚成 1 行/批；detail 内列全部来源。

    批次只包含“重复行”（首次出现行仍是事实表中的那一条，不进批次），
    与 findings.csv 的 batch_size / batch_id / sources 完全同源：
    batch_id 由重复行集合内容派生，quality_issues.csv 与结论可逐字节互相核对。
    """
    plain: list[dict] = []
    groups: dict[tuple[str, str], dict] = {}

    def add_source(group: dict, bucket: str, rel_path: object, line_no: object) -> None:
        rel = str(rel_path or "")
        if not rel or line_no is None:
            return
        group[bucket].add((rel, int(line_no)))

    def add_group(emp_id: str, day: str, severity: str, raw_value: str,
                  sources: list[tuple[object, object]],
                  first: list[tuple[object, object]] | None = None) -> None:
        key = (str(emp_id or ""), str(day or ""))
        group = groups.get(key)
        if group is None:
            group = {"emp_id": key[0], "day": key[1], "severity": severity,
                     "raw_value": str(raw_value or ""), "sources": set(),
                     "first": set()}
            groups[key] = group
        for rel_path, line_no in sources:
            add_source(group, "sources", rel_path, line_no)
        for rel_path, line_no in (first or []):
            if rel_path:
                add_source(group, "first", rel_path, line_no)

    for issue in issues:
        if str(issue["rule_id"]) != "QUAL-DUP":
            plain.append(dict(issue))
            continue
        payload: dict = {}
        detail = str(issue["detail"] or "")
        if detail.startswith("{"):
            try:
                payload = json.loads(detail)
            except (TypeError, ValueError):
                payload = {}
        if payload.get("qual_dup_summary"):
            for day, meta in sorted((payload.get("days") or {}).items()):
                day_text = str(day or "")
                if not day_text:
                    day_text = date_from_raw_value(
                        (list(meta.get("samples") or []) or [""])[0])
                refs = [(file_paths.get(int(file_id), ""), line_no)
                        for file_id, line_no in (meta.get("line_refs") or [])]
                first = [(file_paths.get(int(file_id), ""), line_no)
                         for file_id, line_no in (meta.get("first_refs") or [])]
                # 汇总 payload 的 line_refs 全是重复行，first_refs 只用于反查。
                add_group(str(issue["emp_id"]), day_text, str(issue["severity"]),
                          str(issue["raw_value"] or ""), refs, first)
        else:
            day_text = str(issue["work_date"] or "") or date_from_raw_value(
                issue["raw_value"])
            physical = detail_physical_sources(issue["detail"])
            repeats = repeat_sources(issue["rel_path"], issue["line_no"],
                                     issue["detail"])
            add_group(str(issue["emp_id"]), day_text, str(issue["severity"]),
                      str(issue["raw_value"] or ""),
                      [(ref["rel_path"], ref["line_no"]) for ref in repeats],
                      physical[:1])

    out: list[dict] = list(plain)
    for (_emp, day), group in sorted(groups.items()):
        sources = sorted(group["sources"], key=lambda x: (x[0].encode("utf-8"), x[1]))
        refs = [{"rel_path": rel_path, "line_no": line_no} for rel_path, line_no in sources]
        batch_id = batch_id_from_sources(refs)
        source_text = "; ".join(f"{rel_path}:{line_no}" for rel_path, line_no in sources)
        first = sorted(group["first"], key=lambda x: (x[0].encode("utf-8"), x[1]))
        first_text = "; ".join(f"{rel_path}:{line_no}" for rel_path, line_no in first)
        detail = (f"重复批次：batch_size={len(sources)}；batch_id={batch_id}；"
                  f"重复行来源：{source_text}")
        if first_text:
            detail += f"；首次出现行（不重复计）：{first_text}"
        out.append({
            "rel_path": sources[0][0] if sources else "",
            "line_no": sources[0][1] if sources else 0,
            "rule_id": "QUAL-DUP",
            "severity": group["severity"],
            "field_name": "(batch)",
            "raw_value": group["raw_value"],
            "detail": detail,
            "work_date": day,
        })
    return out


def _batch_stats(findings: list) -> tuple[int, int]:
    """返回 (批次 finding 条数, 批次内问题条数合计)。"""
    batched = 0
    issues_total = 0
    for finding in findings:
        if str(finding["rule_id"]) != "QUAL-01":
            continue
        try:
            metric = json.loads(finding["metric_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if "batch_id" not in metric:
            continue
        batched += 1
        issues_total += int(metric.get("batch_size") or 0)
    return batched, issues_total


def _run_employee_ids(conn: Connection, scope: dict) -> list[str]:
    ids = scope.get("emp_ids")
    if ids:
        return sorted({str(x) for x in ids}, key=lambda x: x.encode("utf-8"))
    rows = conn.execute("SELECT emp_id FROM employee").fetchall()
    return sorted((str(r["emp_id"]) for r in rows), key=lambda x: x.encode("utf-8"))


def _resolve_input_path(rel_path: str, cfg: Config) -> Path | None:
    """按几个常见落点找原始文件；找不到就返回 None，由调用方如实记成缺项，不猜。"""
    if rel_path.startswith("inline://"):
        return None
    p = Path(rel_path)
    candidates = [p if p.is_absolute() else PROJECT_ROOT / p, Path.cwd() / p,
                  cfg.data_dir / p, cfg.data_dir / p.name,
                  cfg.upload_dir / p, cfg.upload_dir / p.name]
    for c in candidates:
        if c.is_file():
            return c
    return None


def collect_package_inputs(conn: Connection, cfg: Config, run_id: str,
                           *, file_ids: set[int] | None = None) -> dict:
    """挑出可打包的输入文件，并按字节预算把关（超预算直接报错，不静默截断）。"""
    entries: list[dict] = []
    missing: list[str] = []
    ids = set(file_ids) if file_ids is not None else _run_input_file_ids(conn, run_id)
    if not ids:
        return {"entries": [], "missing": [], "total_bytes": 0,
                "reason": "本次运行没有记录引用文件（旧库或空引用），包内不含 inputs/"}
    rows = _select_raw_files(conn, ids)
    for r in rows:
        src = _resolve_input_path(r["rel_path"], cfg)
        if src is None:
            missing.append(r["rel_path"])
            continue
        data = src.read_bytes()
        if sha256_hex(data) != r["sha256"]:
            # 库里登记的指纹与磁盘现状不一致：说明文件在导入后被改过，必须让接收方看得见
            missing.append(f"{r['rel_path']}（磁盘内容已与登记 sha256 不一致，拒绝打包）")
            continue
        entries.append({"file_id": int(r["file_id"]), "rel_path": r["rel_path"],
                        "kind": r["kind"], "sha256": r["sha256"], "bytes": len(data),
                        "row_count": int(r["row_count"]), "source": str(src)})
    total = sum(e["bytes"] for e in entries)
    status = check_input_budget(total)
    note = ""
    if not _has_column(conn, "run", "referenced_file_ids"):
        note = ("旧库没有 run.referenced_file_ids 列（本次运行当时未记录引用集合），"
                "已按主数据 + 结论溯源 + 未归属质量问题文件打包")
    elif not conn.execute("SELECT referenced_file_ids FROM run WHERE run_id = ?",
                          (run_id,)).fetchone()["referenced_file_ids"]:
        note = "该 run 未记录引用文件集合（升级前的旧 run），已按主数据 + 溯源引用打包"
    return {"entries": entries, "missing": missing, "total_bytes": total, "reason": note,
            "warning": status in ("warning", "critical"),
            "warn_bytes": EXPORT_INPUTS_WARN_BYTES,
            "critical": status == "critical",
            "critical_bytes": EXPORT_INPUTS_CRITICAL_BYTES}


def export_package(conn: Connection, cfg: Config, run_id: str, *,
                   include_inputs: bool = True, signing_key=None,
                   omit_fields: set[str] | tuple[str, ...] | None = None) -> dict:
    """导出举证包（zip + manifest），返回清单字典。同 run 并发导出会明确拒绝。

    `signing_key` 为 PyNaCl `SigningKey` 时写 v3 + Ed25519 签名；为 None 时保持
    既有 v2 无签名行为。私钥不进入包。
    `omit_fields` 默认空（不裁剪）；显式传 `{"leave:paid"}` 时按投影字段清单校验后
    只裁剪导入器可选的非投影列。
    """
    if conn.execute("SELECT 1 FROM run WHERE run_id = ?", (run_id,)).fetchone() is None:
        raise ValueError(f"未知 run_id: {run_id}")
    omit = projection.normalize_omit_fields(omit_fields)
    cfg.ensure_dirs()
    with _export_run_lock(conn, cfg, run_id):
        try:
            return _export_package_locked(conn, cfg, run_id, include_inputs=include_inputs,
                                          signing_key=signing_key, omit_fields=omit)
        except Exception:
            # 失败关闭：不把半成品暂存目录留给下一次导出。
            shutil.rmtree(cfg.packages_dir / run_id, ignore_errors=True)
            raise


def _export_package_locked(conn: Connection, cfg: Config, run_id: str, *,
                           include_inputs: bool = True, signing_key=None,
                           omit_fields: tuple[tuple[str, str], ...] = ()) -> dict:
    """在持有同 run 导出锁时执行的实际导出。1000 行内应控制在数秒级（设计值）。"""
    run = conn.execute("SELECT * FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if run is None:
        raise ValueError(f"未知 run_id: {run_id}")
    scope_json = json.loads(run["scope_json"])
    input_ids = _run_input_file_ids(conn, run_id)
    files = _select_raw_files(conn, input_ids)
    file_paths = {int(f["file_id"]): str(f["rel_path"]) for f in files}
    # 0.4.8：重复批次在包内只输出 1 行，detail 列出全部来源；不再逐行堆叠或只留前 5 条。
    issues = _aggregate_export_issues(_select_issues(conn, input_ids), file_paths)
    chain, chain_max_seq, chain_epoch = _run_chain_prefix(
        conn, run_id, str(run["rule_pack_version"]))
    activation_event = None
    if chain_epoch:
        row = conn.execute(
            "SELECT seq, run_id, actor, action, ts, payload_sha256, prev_hash, entry_hash, "
            "rule_pack_version, segment_id FROM audit_event WHERE seq = ?",
            (int(chain_epoch["activation_event_seq"]),)).fetchone()
        if row is not None:
            activation_event = {
                "seq": int(row["seq"]), "run_id": row["run_id"], "actor": row["actor"],
                "action": row["action"], "ts": row["ts"],
                "payload_sha256": row["payload_sha256"], "prev_hash": row["prev_hash"],
                "entry_hash": row["entry_hash"],
                "rule_pack_version": row["rule_pack_version"], "segment_id": row["segment_id"],
            }

    cfg.ensure_dirs()
    work = cfg.packages_dir / run_id
    # 每次导出都从干净暂存目录重建：上次失败留下的半成品（含 inputs/ 子目录）
    # 必须先整体清掉，否则 rerun 会卡在旧目录上。
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    policy_source = PROJECT_ROOT / "policies"
    policy_files = sorted(policy_source.glob("*.md")) if policy_source.is_dir() else []
    if not policy_files:
        raise RuntimeError("缺少 policies/ 对外规则/条文材料，无法导出可实质审查的举证包")
    policies_dir = work / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    for policy in policy_files:
        if policy.name == "CONFIDENCE.md":
            text = policy.read_text(encoding="utf-8").replace(
                "{{ENGINE_VERSION}}", ENGINE_VERSION)
            (policies_dir / policy.name).write_text(text, encoding="utf-8")
        else:
            shutil.copy2(policy, policies_dir / policy.name)

    findings = conn.execute(
        "SELECT * FROM finding WHERE run_id = ?", (run_id,)
    ).fetchall()
    # findings.csv 的行序必须是纯内容函数：work_date/period_key 都可空，
    # SQL 的 NULL 排序在 SQLite 与 PG 上不同（SQLite NULL 在前、PG 在后）。
    # 统一在 Python 里用 (work_date or "", period_key or "") 排序（0.4.8）。
    findings.sort(key=lambda f: (
        str(f["emp_id"]).encode("utf-8"), f["work_date"] or "", f["period_key"] or "",
        str(f["rule_id"]).encode("utf-8"), str(f["rule_version"]).encode("utf-8"),
        str(f["severity"]).encode("utf-8"), str(f["metric_json"] or "").encode("utf-8"),
        str(f["explanation"] or "").encode("utf-8"),
    ))
    evidence_digest_value = compute_evidence_digest(
        {"rule_id": f["rule_id"], "rule_version": f["rule_version"],
         "emp_id": f["emp_id"], "work_date": f["work_date"],
         "period_key": f["period_key"],
         "evidence": json.loads(f["evidence_json"] or "{}")}
        for f in findings)

    approval_source = "none"
    approval_meta: dict | None = None
    if include_inputs and str(run["rule_pack_version"]) in (RULE_PACK_V5, RULE_PACK_V6):
        employee_ids = _run_employee_ids(conn, scope_json)
        approval_path = work / "approval_ledger.csv"
        if str(run["rule_pack_version"]) == RULE_PACK_V6:
            approval_source = "v6-coverage"
            approval_meta = export_coverage_csv(conn, employee_ids, approval_path)
            expected = str(scope_json.get("approval_coverage_sha256") or "")
        else:
            approval_source = "v5-ledger"
            approval_meta = export_approval_csv(conn, employee_ids, approval_path)
            expected = str(scope_json.get("approval_ledger_sha256") or "")
        if expected and approval_meta["digest"] != expected:
            raise ValueError(
                "审批台账在 run 之后发生变化，导出的包无法与 run 的 input_fingerprint 对齐；"
                "请重新执行校验后再导出，不要用当前台账冒充历史输入")

    # 1) 结论明细 CSV（行级来源反查链：finding -> source_refs -> (rel_path, line_no)）
    findings_csv = work / "findings.csv"
    _write_findings_csv(findings_csv, findings, file_paths)

    # 2) 输入清单（只列本次 run 引用集合；审批台账作为 v5 合成输入追加）
    manifest_files = work / "input_files.csv"
    with manifest_files.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rel_path", "sha256", "row_count", "kind"])
        for f in files:
            w.writerow(csv_safe_row([f["rel_path"], f["sha256"], int(f["row_count"]),
                                     f["kind"]]))
        if approval_meta is not None:
            w.writerow(csv_safe_row(["approval_ledger.csv", approval_meta["sha256"],
                                     int(approval_meta["rows"]), "approval"]))

    # 3) 审计链快照 + 独立校验器
    chain_json = work / "audit_chain.jsonl"
    with chain_json.open("w", encoding="utf-8", newline="") as fh:
        for c in chain:
            fh.write(canonical_json({
                "seq": int(c["seq"]), "run_id": c["run_id"], "actor": c["actor"], "action": c["action"],
                "ts": c["ts"], "payload_sha256": c["payload_sha256"], "prev_hash": c["prev_hash"],
                "entry_hash": c["entry_hash"], "rule_pack_version": c["rule_pack_version"],
                "segment_id": c["segment_id"],
            }) + "\n")

    # 4) 数据质量报表
    issues_csv = work / "quality_issues.csv"
    with issues_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rel_path", "line_no", "rule_id", "severity", "field", "raw_value", "detail"])
        for i in issues:
            w.writerow(csv_safe_row([
                i["rel_path"], int(i["line_no"]), i["rule_id"], i["severity"],
                i["field_name"], i["raw_value"], redact_issue_detail(i["detail"]),
            ]))

    # 5) 对外结论集：只收"已登记人工结论"的条目（US-RV-01★）
    resp = responsibility_block(conn, cfg, run_id)
    # 导出副本去掉金额/录入人；库内 resp 仍保留，供复核台与责任审计使用。
    export_resp = _minimized_responsibility(resp)
    conclusions_csv = work / "conclusions_final.csv"
    _write_conclusions_csv(conclusions_csv, export_resp["human_confirmations"])

    # 6) 责任区块（US-EX-02★）：机器做了什么、人确认了什么、谁签的字
    resp_path = work / "responsibility.json"
    resp_doc = dict(export_resp)
    resp_path.write_text(canonical_json(resp_doc) + chr(10), encoding="utf-8")

    # 7) 未覆盖清单（US-EX-03）：不覆盖什么，自己先说
    nc = not_covered_block(cfg)
    nc_path = work / "not_covered.json"
    nc_path.write_text(canonical_json(nc) + chr(10), encoding="utf-8")
    nc_md = work / "未覆盖清单.md"
    findings_batched, batched_issue_rows = _batch_stats(findings)
    findings_total = len(findings)
    # 批次 finding 在 CSV 里是 1 行，但代表 batch_size 条问题；
    # issues_total 是把批次展开后的实际条数，三者关系在各包文档里写清。
    issues_total = findings_total - findings_batched + batched_issue_rows
    nc_md.write_text(_not_covered_markdown(
        nc, findings_count=findings_total, final_count=len(resp["human_confirmations"]),
        rule_versions=_rule_version_counts(findings),
        aggregate_findings=_aggregate_findings(findings),
        findings_batched=findings_batched, issues_total=issues_total))
    confidence_path = policies_dir / "CONFIDENCE.md"
    if not confidence_path.is_file():
        raise RuntimeError("缺少 policies/CONFIDENCE.md，无法生成按包计数")
    _write_package_confidence(
        confidence_path, findings_count=findings_total,
        final_count=len(resp["human_confirmations"]), signed=bool(resp["signed"]),
        findings_batched=findings_batched, issues_total=issues_total)

    # 8) 输入自含（US-EX-01）：把本次结论真正依赖的原始 CSV 一起打包，让重放不需要另外索要数据
    inputs_dir = work / INPUTS_DIRNAME
    inputs_dir.mkdir(exist_ok=True)
    if include_inputs:
        collected = collect_package_inputs(conn, cfg, run_id, file_ids=input_ids)
        fatal = [m for m in collected["missing"] if not str(m).startswith("inline://")]
        if fatal:
            raise ValueError(
                f"导出失败：本 run 引用 {len(input_ids)} 个输入，其中 {len(fatal)} 个无法按 "
                f"rel_path 定位：{'; '.join(fatal)}；拒绝生成残缺包")
        if approval_meta is not None:
            collected["entries"].append({
                "file_id": 0, "rel_path": "approval_ledger.csv", "kind": "approval",
                "sha256": approval_meta["sha256"], "bytes": approval_meta["bytes"],
                "row_count": int(approval_meta["rows"]),
                "source": str(approval_meta["path"]),
            })
            collected["total_bytes"] += approval_meta["bytes"]
            collected["approval_rows"] = approval_meta["rows"]
            collected["approval_sha256"] = approval_meta["sha256"]
        # 包内输入文件名只由 rel_path 推导，不再依赖数据库 file_id；
        # 这样换空库重导同一批 CSV 时，inputs_digest 不会因 file_id 不同而漂移。
        for entry, arc in zip(collected["entries"], input_arcnames(collected["entries"])):
            entry["arcname"] = arc
        omitted_fields = _apply_omissions(collected, work, omit_fields)
        status = input_budget_status(collected["total_bytes"])
        collected["warning"] = status in ("warning", "critical")
        collected["critical"] = status == "critical"
        collected["warn_bytes"] = EXPORT_INPUTS_WARN_BYTES
        collected["critical_bytes"] = EXPORT_INPUTS_CRITICAL_BYTES
        collected["warning_message"] = ""
        collected["critical_message"] = ""
        if status == "warning":
            collected["warning_message"] = (
                f"自含输入 {collected['total_bytes']:,} 字节已超过告警线 "
                f"{EXPORT_INPUTS_WARN_BYTES:,} 字节（上限 {EXPORT_INPUTS_MAX_BYTES:,} 字节），"
                "接近上限但仍在预算内；导出照常成功")
            logger.warning("举证包导出接近输入上限：%s", collected["warning_message"])
        elif status == "critical":
            collected["warning_message"] = (
                f"自含输入 {collected['total_bytes']:,} 字节已超过告警线 "
                f"{EXPORT_INPUTS_WARN_BYTES:,} 字节（上限 {EXPORT_INPUTS_MAX_BYTES:,} 字节）")
            collected["critical_message"] = (
                f"自含输入 {collected['total_bytes']:,} 字节已超过临界线 "
                f"{EXPORT_INPUTS_CRITICAL_BYTES:,} 字节（硬上限 {EXPORT_INPUTS_MAX_BYTES:,} 字节），"
                "接近硬上限，需人工确认；导出照常成功")
            logger.error("举证包导出接近硬上限：%s", collected["critical_message"])
    else:
        collected = {"entries": [], "missing": [], "total_bytes": 0,
                     "reason": "调用方指定 --no-inputs：本包不含原始输入，接收方无法离线重放",
                     "warning": False, "warn_bytes": EXPORT_INPUTS_WARN_BYTES,
                     "critical": False, "critical_bytes": EXPORT_INPUTS_CRITICAL_BYTES,
                     "warning_message": "", "critical_message": ""}
        omitted_fields = _apply_omissions(collected, work, omit_fields)
    inputs_manifest = work / INPUTS_MANIFEST_NAME
    approval_export_doc = {
        "mode": "db_export",
        "encoding": "utf-8",
        "bom": False,
        "line_endings": "LF",
        "original_bytes_retained": False,
        "normalized_bytes": int(approval_meta["bytes"]) if approval_meta else 0,
        "note": ("approval_ledger.csv / approval_coverage.csv 由数据库确定性重导出，"
                 "不是原始上传字节；原始字节未随包保留，重放以包内重导出文件为准。"),
        # 第十轮复测要求的逐字节披露：0.4.7 实测的 approval_ledger.csv 为仅表头文件。
        # 原上传 97 字节 = 表头 92 + UTF-8 BOM 3 + CRLF 2；
        # 规范化 93 字节 = 表头 92 + LF 1；差异 4 字节 = BOM 3 + CRLF→LF 1。
        # 原始上传字节已不可得（仓库与历史产物中均无该 97 字节副本）。
        "ledger_97_to_93": {
            "original_bytes": 97,
            "normalized_bytes": 93,
            "difference_bytes": 4,
            "breakdown": "UTF-8 BOM 3 字节 + CRLF→LF 1 字节（仅表头、无数据行）",
            "arithmetic": "97 = 92（表头）+ 3（BOM）+ 2（CRLF）；93 = 92 + 1（LF）",
            "original_bytes_recovered": False,
            "reason": "原文件是临时上传，未保留 raw 副本；包内只保留确定性重导出结果",
        },
    }
    inputs_doc = {"schema": "wca-package-inputs-v1",
                  "csv_formula_escape": CSV_FORMULA_ESCAPE,
                  "cap_bytes": EXPORT_INPUTS_MAX_BYTES,
                  "warn_bytes": EXPORT_INPUTS_WARN_BYTES,
                  "critical_bytes": EXPORT_INPUTS_CRITICAL_BYTES,
                  "warning": bool(collected.get("warning", False)),
                  "warning_message": str(collected.get("warning_message") or ""),
                  "critical": bool(collected.get("critical", False)),
                  "critical_message": str(collected.get("critical_message") or ""),
                  "selection_rule": ("主数据(org/employee) ∪ 引用集合 ∪ 结论溯源引用 ∪ "
                                     "未归属质量问题所在文件 ∪ " +
                                     ("v6 覆盖投影" if approval_source == "v6-coverage"
                                      else "v5 审批台账")),
                  "total_bytes": collected["total_bytes"], "missing": collected["missing"],
                  "reason": collected["reason"],
                  "approval_rows": int(collected.get("approval_rows", 0)),
                  "approval_source": approval_source,
                  "path_rule": ("inputs/<rel_path>；同一规范化路径重复时按 entries 顺序追加 -2/-3"),
                  **({"omitted_fields": omitted_fields} if omit_fields else {}),
                  "entries": [{k: e[k] for k in ("rel_path", "kind", "sha256",
                                                 "bytes", "row_count") if k in e}
                              for e in collected["entries"]]}
    inputs_manifest.write_text(canonical_json(inputs_doc) + chr(10), encoding="utf-8")
    for e in collected["entries"]:
        if e.get("trimmed"):
            continue
        target = work / e["arcname"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(e["source"], target)

    # 工件逐文件哈希：把包根 CSV/JSON/MD 与 README/verify 依赖绑定到 manifest。
    # 这些字段会被 manifest_checksum 覆盖；新签名包还会把它们放进签名载荷。
    artifact_sha256 = {
        p.name: sha256_hex(p.read_bytes()) for p in (
            findings_csv, manifest_files, issues_csv, conclusions_csv,
            resp_path, nc_path, nc_md)
    }
    artifact_sha256[README_FILE] = sha256_hex(PACKAGE_README.encode("utf-8"))
    artifact_sha256[VERIFY_REQUIREMENTS_FILE] = sha256_hex(
        VERIFY_REQUIREMENTS.encode("utf-8"))
    artifact_sha256.update({
        f"policies/{p.name}": sha256_hex((policies_dir / p.name).read_bytes())
        for p in policy_files
    })
    verify_script_sha256 = sha256_hex(VERIFY_SNIPPET.encode("utf-8"))
    artifacts_digest = signing.artifact_digest(artifact_sha256)
    # 输入摘要覆盖 inputs/ 下实际存在的每个文件（含 inputs/manifest.json 本身），
    # 在签名前算好并写入 manifest；签名 payload 会覆盖它，避免“只换输入不换 manifest”。
    inputs_digest = signing.compute_inputs_digest_from_dir(work) if signing_key else ""
    # 投影指纹只在受控裁剪开启时计算/写入；默认导出保持既有字段与 replay 语义。
    projection_fp = (projection.projection_fingerprint(
        conn, scope_json, str(run["rule_pack_version"]),
        rel_paths={str(f["rel_path"]) for f in files},
        emp_ids=scope_json.get("emp_ids")) if omit_fields else "")

    if chain_epoch:
        verification = verify_chain(conn, cfg, upto_seq=chain_max_seq, segment=chain_epoch)
    elif str(run["rule_pack_version"]) == RULE_PACK_V4 and audit_epoch(conn, RULE_PACK_V5):
        verification = verify_chain(conn, cfg, upto_seq=chain_max_seq, legacy_only=True)
    else:
        verification = verify_chain(conn, cfg, upto_seq=chain_max_seq)
    triple = {
        "rule_pack_version": run["rule_pack_version"],
        "input_fingerprint": run["input_fingerprint"],
        "conclusion_digest": run["conclusion_digest"],
    }
    manifest = {
        "schema": EVIDENCE_PACKAGE_SCHEMA_V3 if signing_key else EVIDENCE_PACKAGE_SCHEMA,
        "run_id": run_id,
        "engine_version": run["engine_version"],
        "producer": producer.producer_info(cfg.rule_pack_id),
        "artifact_sha256": artifact_sha256,
        "artifacts_digest": artifacts_digest,
        "verify_script_sha256": verify_script_sha256,
        "triple": triple,
        **({"projection_spec": projection.PROJECTION_SPEC,
            "projection_fingerprint": projection_fp,
            "omitted_fields": omitted_fields} if omit_fields else {}),
        "scope_json": scope_json,
        "audit_window": {"mode": "prefix_through_last_run_event",
                         "max_seq": chain_max_seq,
                         "segment_id": chain_epoch["epoch_id"] if chain_epoch else None},
        **({"audit_segment": {
            "epoch_id": chain_epoch["epoch_id"],
            "rule_pack_version": chain_epoch["rule_pack_version"],
            "prev_rule_pack_version": chain_epoch["prev_rule_pack_version"],
            "prev_head_hash": chain_epoch["prev_head_hash"],
            "activation_event_seq": int(chain_epoch["activation_event_seq"]),
            "segment_start_seq": int(chain_epoch["segment_start_seq"]),
            "segment_start_prev_hash": chain_epoch["segment_start_prev_hash"],
            "switched_at": chain_epoch["switched_at"],
            "activation_event": activation_event,
        }} if chain_epoch else {}),
        "counts": {
            "findings": len(findings),
            # 0.4.8 批次口径：findings_total 是 CSV 行数；findings_batched 是其中
            # 代表多条的批次 finding 数；issues_total = findings_total - findings_batched
            # + 各批 batch_size 合计，供消费方不要按 CSV 行数误算重复问题。
            "findings_total": findings_total,
            "findings_batched": findings_batched,
            "issues_total": issues_total,
            "input_files": len(files) + (1 if approval_meta is not None else 0),
            "audit_events": len(chain),
            "quality_issues": len(issues),
            "approval_rows": int(collected.get("approval_rows", 0)),
            # 对外结论集只含已人工确认的条目；未确认的仍留在 findings.csv 里等处置
            "final_conclusions": len(resp["human_confirmations"]),
            "unsigned_pending": resp["unsigned_findings_excluded_from_conclusions"],
            "ai_answered_questions": resp["ai_participation_count"],
            # rule_version 是“单条规则版本”，不等于 rule pack 版本；v5 包里可以同时有
            # 未改判据的 v4 规则与 v5 规则。把分布写进 manifest，避免被误读成版本漂移。
            "rule_versions": _rule_version_counts(findings),
        },
        "chain_verification": verification.as_dict(),
        "responsibility": {k: resp[k] for k in
                           ("principle", "engine_only_outputs", "never_output", "signed",
                            "signed_by", "human_confirmed_findings",
                            "unsigned_findings_excluded_from_conclusions", "ai_participation_count")},
        "not_covered": {"regimes_excluded": nc["scope"]["worktime_regimes_excluded"],
                        "cities_covered": nc["scope"].get("cities_covered"),
                        "rules_excluded": [r["rule_id"] for r in nc["rules_excluded"]],
                        "not_tested_count": len(nc["not_tested"])},
        # 输入自含（US-EX-01）：接收方拿着这个包就能自己重跑，不必再回头索要原始数据
        "inputs": {"packed": len(collected["entries"]),
                   "csv_formula_escape": CSV_FORMULA_ESCAPE,
                   "total_bytes": collected["total_bytes"],
                   "cap_bytes": EXPORT_INPUTS_MAX_BYTES,
                   "warn_bytes": EXPORT_INPUTS_WARN_BYTES,
                   "critical_bytes": EXPORT_INPUTS_CRITICAL_BYTES,
                   "warning": bool(collected.get("warning", False)),
                   "warning_message": str(collected.get("warning_message") or ""),
                   "critical": bool(collected.get("critical", False)),
                   "critical_message": str(collected.get("critical_message") or ""),
                   "selection_rule": inputs_doc["selection_rule"],
                   "approval_rows": int(collected.get("approval_rows", 0)),
                   "approval_sha256": str(collected.get("approval_sha256") or ""),
                   "approval_source": approval_source,
                   "approval_export": approval_export_doc,
                   **({"omitted_fields": omitted_fields} if omit_fields else {}),
                   "missing": collected["missing"],
                   "reason": collected["reason"],
                   "replay_command": "python -m src.cli replay <本包.zip 或解包目录>"},
        "approval_source": approval_source,
        "evidence_digest": evidence_digest_value,
        **({"inputs_digest": inputs_digest} if signing_key else {}),
        "artifacts": [p.name for p in (findings_csv, manifest_files, chain_json, issues_csv,
                                       conclusions_csv, resp_path, nc_path, nc_md)]
                      + [README_FILE, VERIFY_REQUIREMENTS_FILE, "verify.py"]
                      + [f"policies/{p.name}" for p in policy_files]
                      + [INPUTS_MANIFEST_NAME] + [e["arcname"] for e in collected["entries"]],
        "disclaimer": "本包不产出应付金额（需求 D-03）；金额是 HR 负责人具名录入的人工结论，不属于引擎输出；"
                      "数据为合成数据，非任何真实个人信息。",
    }
    if signing_key:
        # 结论集文件哈希也放进 manifest；它被自校验和覆盖，进而被签名覆盖。
        # 这样“只改 conclusions_final.csv、不动 manifest”能被 verify 的 ARTIFACT 检查发现。
        manifest["conclusions_sha256"] = sha256_hex(conclusions_csv.read_bytes())
    # 自校验和覆盖 manifest.json 内除自身与 signature 外的全部字段；它是
    # “防单点改动”的自洽检查，不是签名——能重算校验和的人仍可伪造。
    manifest[MANIFEST_CHECKSUM_FIELD] = manifest_checksum(manifest)
    if signing_key:
        # 签名 payload 覆盖 schema/triple/manifest_checksum/实际链头；signature
        # 自身不参与 checksum，避免“先校验和再签名”的循环。
        manifest[SIGNATURE_FIELD] = signing.create_signature(
            manifest, signing_key, verification.head_hash)
    manifest_path = work / "manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    # manifest 自身的哈希，用于「重跑后比对包是否等价」
    manifest_sha = sha256_hex(manifest_path.read_bytes())

    stamp = datetime.now(CN_TZ).strftime("%Y%m%dT%H%M%S")
    zip_path = cfg.packages_dir / f"{run_id}-{stamp}-{os.urandom(3).hex()}.zip"
    if zip_path.exists():
        raise ValueError(f"导出失败：目标包已存在，拒绝覆盖：{zip_path}")
    tmp_zip = cfg.packages_dir / f".{zip_path.name}.{os.getpid()}.tmp"
    try:
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(README_FILE, PACKAGE_README.encode("utf-8"))
            for p in (manifest_path, findings_csv, manifest_files, chain_json, issues_csv,
                      conclusions_csv, resp_path, nc_path, nc_md):
                zf.write(p, arcname=p.name)
            for policy in policy_files:
                zf.write(policies_dir / policy.name, arcname=f"policies/{policy.name}")
            zf.write(inputs_manifest, arcname=INPUTS_MANIFEST_NAME)
            for e in collected["entries"]:
                zf.write(work / e["arcname"], arcname=e["arcname"])
            zf.writestr("verify.py", VERIFY_SNIPPET.encode("utf-8"))
            zf.writestr(VERIFY_REQUIREMENTS_FILE, VERIFY_REQUIREMENTS.encode("utf-8"))
        os.replace(tmp_zip, zip_path)
    except Exception:
        tmp_zip.unlink(missing_ok=True)
        raise

    # 包登记与审计事件同事务；zip/文件已落盘，DB 失败时包可能残留，
    # 但不会出现“登记了包、审计链里没有这次导出”的情况。
    with transaction_if_needed(conn):
        conn.execute(
            "INSERT INTO evidence_package(package_id, run_id, created_at, rule_pack_version, "
            "input_fingerprint, conclusion_digest, manifest_sha256, package_dir, row_count) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(package_id) DO UPDATE SET created_at = excluded.created_at, "
            "manifest_sha256 = excluded.manifest_sha256, package_dir = excluded.package_dir",
            (
                f"pkg-{run_id}", run_id,
                datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00"),
                triple["rule_pack_version"], triple["input_fingerprint"],
                triple["conclusion_digest"], manifest_sha, str(zip_path), len(findings),
            ),
        )
        append_audit(
            conn, run_id=run_id, actor="system:evidence", action="evidence.export",
            payload={"triple": triple, "manifest_sha256": manifest_sha, "zip": zip_path.name},
            cfg=cfg,
        )
    manifest["manifest_sha256"] = manifest_sha
    manifest["package_zip"] = str(zip_path)
    return manifest


def _write_findings_csv(path: Path, findings, file_paths: dict[int, str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow([
            "rule_id", "rule_version", "emp_id", "work_date", "period_key", "severity",
            "severity_label", "citations", "metric_json", "evidence_json", "source_rel_path",
            "source_line_no", "explanation",
        ])
        for f in findings:
            refs = json.loads(f["source_refs"])
            loc = _source_loc(refs, file_paths)
            try:
                evidence_json = f["evidence_json"]
            except (KeyError, IndexError):
                evidence_json = "{}"
            w.writerow(csv_safe_row([
                f["rule_id"], f["rule_version"], f["emp_id"], f["work_date"], f["period_key"],
                f["severity"], _sev_label(f["severity"]), f["citation_ids"], f["metric_json"],
                evidence_json, loc[0], loc[1], f["explanation"],
            ]))


def _source_loc(refs: list[dict], file_paths: dict[int, str]) -> tuple[str, str]:
    paths: list[str] = []
    lines: list[str] = []
    for r in refs:
        fid = r.get("file_id")
        if fid is None:
            continue
        path = file_paths.get(int(fid))
        if path:
            paths.append(path)
            lines.append(str(r.get("line_no")))
    return (";".join(dict.fromkeys(paths))), (";".join(lines))


def _sev_label(sev: str) -> str:
    return {"DEFENSIBLE": "可申辩", "REVIEW": "需复核", "VIOLATION": "明显违规"}.get(sev, sev)


def _rule_version_counts(findings) -> dict[str, int]:
    """单条规则版本分布；它不等于 rule pack 版本，必须原样公开。"""
    out: dict[str, int] = {}
    for f in findings:
        version = str(f["rule_version"])
        out[version] = out.get(version, 0) + 1
    return dict(sorted(out.items()))


VERIFY_REQUIREMENTS = (
    "# 仅包内 verify.py 验签需要；不验签（旧 v1/v2 包）时只用标准库。\n"
    "pynacl==1.6.2\n"
)


VERIFY_SNIPPET = r'''"""包内便利复核脚本（不是信任依据）；正式验收请用发行 wheel 的 wca-verify。

本脚本只用标准库重算 hash 链、校验包内输入与结论集哈希；签名存在时用 PyNaCl 验签。
它不校验工件绑定与 findings 反算摘要，且运行在已解压目录上；不要把它的 OK 当成独立验收。

用法：unzip pkg-<run_id>.zip && python verify.py
可选外部锚点：python verify.py --expect-triple rp,input_fp,conclusion_digest
（也可用环境变量 WCA_EXPECT_TRIPLE）；不传时仍按包内自洽规则校验。
可选签名约束：--public-key <公钥文件或Base64>（可重复）作为外部 pin；--require-signature。
签名验签依赖 PyNaCl（见包内 verify-requirements.txt）；未安装且包内有签名时失败关闭。
期望输出：EPOCH OK + MANIFEST CHECKSUM OK + CHAIN OK + INPUTS OK + ARTIFACT OK + SIGNATURE OK。
SIGNATURE OK 只表示签名有效：pinned 只表示“与供给公钥副本匹配”，不代表来源身份已核验；
来源身份必须由双方独立渠道核验 key_id。package self-check 仅包内自洽，必须打印
NOT source trust。
任一校验失败都会打印 RESULT FAIL 并返回非零退出码；链、输入与签名一致仍不代表结论正确，
结论是否一致要重跑引擎（`python -m src.cli replay <包>`）。
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

GENESES = "wca-audit-chain-v1"
MANIFEST_CHECKSUM_FIELD = "manifest_checksum"
SIGNATURE_FIELD = "signature"
SIGNATURE_ALG = "Ed25519"
SIGNATURE_REQUIRED_FIELDS = ("alg", "key_id", "created_at", "public_key_b64",
                             "signature_b64")
TRIPLE_KEYS = ("rule_pack_version", "input_fingerprint", "conclusion_digest")
EVIDENCE_SCHEMA_RE = re.compile(r"^wca-evidence-package-v(\d+)$")


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def schema_version(doc):
    """解析 wca-evidence-package-vN；缺失/未知返回 None（调用方失败关闭）。"""
    raw = doc.get("schema")
    if not isinstance(raw, str):
        return None
    match = EVIDENCE_SCHEMA_RE.match(raw)
    return int(match.group(1)) if match else None


def checksum_of(doc):
    """与导出方同口径：排除 manifest_checksum 与 signature 后做规范 JSON + SHA-256。"""
    payload = {k: v for k, v in doc.items()
               if k not in (MANIFEST_CHECKSUM_FIELD, SIGNATURE_FIELD)}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return h(raw)


def decode_b64(value, label, length=None):
    try:
        raw = base64.b64decode(str(value).strip(), validate=True)
    except Exception:
        raise ValueError(label + " 不是合法 Base64")
    if length is not None and len(raw) != length:
        raise ValueError(label + " 长度应为 %d 字节，实际 %d" % (length, len(raw)))
    return raw


def key_id_for_public_key(public):
    return "ed25519:" + digest_bytes(public)


INPUTS_DIRNAME = "inputs"
INPUT_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_input_path(path):
    """包内相对路径统一为 `/`；不折叠大小写，`..` 直接拒绝。"""
    text = str(path).replace(chr(92), "/")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts:
        raise ValueError("输入文件路径为空")
    if any(p == ".." for p in parts):
        raise ValueError("输入文件路径不允许包含 ..：" + str(path))
    return "/".join(parts)


def compute_inputs_digest(root):
    """重算 inputs_digest：[[path, sha256], ...] 按路径字节序排序后 canonical JSON + SHA-256。"""
    base = safe_path(root, INPUTS_DIRNAME)
    if not base.is_dir():
        raise ValueError("包内没有 inputs/ 目录")
    entries = []
    seen = set()
    for path in base.rglob("*"):
        if path.is_symlink():
            raise ValueError("输入目录包含符号链接：" + str(path))
        if not path.is_file():
            continue
        rel = normalize_input_path(path.relative_to(root).as_posix())
        digest = digest_bytes(path.read_bytes())
        if not INPUT_SHA256_RE.match(digest):
            raise ValueError("输入文件 sha256 非法：" + rel)
        if rel in seen:
            raise ValueError("输入文件路径重复（规范化后）：" + rel)
        seen.add(rel)
        entries.append([rel, digest])
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    return h(json.dumps(entries, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def signature_payload(manifest, audit_chain_head):
    triple = manifest.get("triple") or {}
    payload = {
        "schema": manifest.get("schema"),
        "rule_pack_version": triple.get("rule_pack_version"),
        "input_fingerprint": triple.get("input_fingerprint"),
        "conclusion_digest": triple.get("conclusion_digest"),
        "inputs_digest": manifest.get("inputs_digest"),
        "manifest_checksum": manifest.get("manifest_checksum"),
        "audit_chain_head": audit_chain_head,
    }
    if "artifacts_digest" in manifest or "verify_script_sha256" in manifest:
        payload["artifacts_digest"] = manifest.get("artifacts_digest")
        payload["verify_script_sha256"] = manifest.get("verify_script_sha256")
    if "evidence_digest" in manifest:
        payload["evidence_digest"] = manifest.get("evidence_digest")
    return payload


def verify_signature(manifest, audit_chain_head, pinned_public_keys):
    """返回 present/ok/trust/key_id/reason；缺字段/坏签名/pin 不匹配都失败关闭。"""
    block = manifest.get(SIGNATURE_FIELD)
    result = {"present": isinstance(block, dict), "ok": False,
              "trust": "none", "key_id": "", "reason": ""}
    if not isinstance(block, dict):
        result["reason"] = "缺少 manifest.signature"
        return result
    missing = [k for k in SIGNATURE_REQUIRED_FIELDS
               if not isinstance(block.get(k), str) or not block.get(k)]
    if missing:
        result["reason"] = "manifest.signature 缺字段或为空：" + ",".join(missing)
        return result
    if block["alg"] != SIGNATURE_ALG:
        result["reason"] = "不支持的签名算法：" + str(block["alg"])
        return result
    try:
        public = decode_b64(block["public_key_b64"], "public_key_b64", 32)
        signature = decode_b64(block["signature_b64"], "signature_b64", 64)
    except ValueError as exc:
        result["reason"] = str(exc)
        return result
    key_id = key_id_for_public_key(public)
    result["key_id"] = key_id
    if block["key_id"] != key_id:
        result["reason"] = "key_id 与包内公钥指纹不一致"
        return result
    if pinned_public_keys:
        matched = [p for p in pinned_public_keys
                   if key_id_for_public_key(p) == key_id]
        if not matched:
            result["reason"] = "签名 key_id 不在外部 pin 公钥集合中"
            return result
        if matched[0] != public:
            result["reason"] = "包内公钥与 pin 公钥字节不一致"
            return result
        public = matched[0]
        result["trust"] = "pinned"
    else:
        result["trust"] = "package-self-check"
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except Exception:
        result["reason"] = "未安装 PyNaCl，无法验签（见 verify-requirements.txt）"
        return result
    payload = json.dumps(signature_payload(manifest, audit_chain_head), sort_keys=True,
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        VerifyKey(public).verify(payload, signature)
    except BadSignatureError:
        result["reason"] = "Ed25519 签名校验失败（manifest/链头/公钥不匹配或签名被改）"
        return result
    except Exception as exc:
        result["reason"] = "验签异常：%s: %s" % (type(exc).__name__, exc)
        return result
    result["ok"] = True
    result["reason"] = "签名有效"
    return result


ANCHOR_KEYS = ("schema_version", "rule_pack_version", "input_fingerprint",
               "conclusion_digest", "projection_fingerprint")


def anchor_schema_version(value):
    """外部锚点第一段：接受 2 / v2 / wca-evidence-package-v2。"""
    text = str(value).strip()
    if re.match(r"^(?:v|V)?\d+$", text):
        return int(text.lstrip("vV"))
    raw = text
    if isinstance(raw, str) and EVIDENCE_SCHEMA_RE.match(raw):
        return int(EVIDENCE_SCHEMA_RE.match(raw).group(1))
    return None


def parse_anchor(raw):
    parts = [p.strip() for p in str(raw).split(",")]
    if len(parts) not in (4, 5) or any(not p for p in parts):
        raise ValueError("期望四元组或五元组格式非法（需要 schema_version,rule_pack_version,"
                         "input_fingerprint,conclusion_digest，最后一段可选 projection_fingerprint）")
    version = anchor_schema_version(parts[0])
    if version is None:
        raise ValueError("schema_version 无法识别：" + parts[0])
    result = {"schema_version": version, "rule_pack_version": parts[1],
              "input_fingerprint": parts[2], "conclusion_digest": parts[3]}
    if len(parts) == 5:
        result["projection_fingerprint"] = parts[4]
    return result


def load_pinned_public_keys(values):
    """--public-key 支持文件路径或裸 Base64；多把用于轮换期并存。"""
    out = []
    for value in values or []:
        path = Path(str(value))
        try:
            raw_text = path.read_text(encoding="utf-8") if path.is_file() else str(value)
            out.append(decode_b64(raw_text, "公钥", 32))
        except (OSError, ValueError) as exc:
            raise ValueError("公钥读取失败（%s）：%s" % (value, exc))
    return out


def expected_anchors_from_args():
    """解析锚点与签名参数；无四元组时回退 --expect-triple。"""
    parser = argparse.ArgumentParser(
        description="独立复核举证包；可选传入包外记录的三/四/五元组作为外部锚点，"
                    "以及外部固定公钥做签名 pin。")
    parser.add_argument(
        "--expect-anchor",
        help="外部期望四元组或五元组：schema_version,rule_pack_version,input_fingerprint,"
             "conclusion_digest[,projection_fingerprint]；也可用环境变量 WCA_EXPECT_ANCHOR")
    parser.add_argument(
        "--expect-triple",
        help="外部期望三元组：rule_pack_version,input_fingerprint,conclusion_digest"
             "（不约束 schema）；也可用环境变量 WCA_EXPECT_TRIPLE")
    parser.add_argument(
        "--public-key", action="append", default=None, dest="public_keys",
        help="外部固定公钥（文件路径或 Base64），可重复传入以支持轮换；"
             "也可用环境变量 WCA_PUBLIC_KEY（逗号分隔）。不传时只做包内自洽验签")
    parser.add_argument(
        "--require-signature", action="store_true",
        help="旧 v1/v2 包没有签名也判失败；v3 缺签名始终失败。"
             "也可用环境变量 WCA_REQUIRE_SIGNATURE=1")
    args = parser.parse_args()
    raw_anchor = args.expect_anchor if args.expect_anchor is not None \
        else os.environ.get("WCA_EXPECT_ANCHOR")
    raw_triple = args.expect_triple if args.expect_triple is not None \
        else os.environ.get("WCA_EXPECT_TRIPLE")
    pinned_values = list(args.public_keys or [])
    env_public = os.environ.get("WCA_PUBLIC_KEY")
    if env_public:
        pinned_values.extend(p.strip() for p in env_public.split(",") if p.strip())
    require_signature = bool(args.require_signature) or str(
        os.environ.get("WCA_REQUIRE_SIGNATURE") or "").strip().lower() in (
            "1", "true", "yes", "on")
    try:
        pinned = load_pinned_public_keys(pinned_values)
    except ValueError as exc:
        return None, None, "PIN FAIL " + str(exc), [], require_signature
    if raw_anchor:
        try:
            return parse_anchor(raw_anchor), None, None, pinned, require_signature
        except ValueError as exc:
            return None, None, "ANCHOR FAIL " + str(exc), pinned, require_signature
    if raw_triple:
        parts = [p.strip() for p in str(raw_triple).split(",")]
        if len(parts) != 3 or any(not p for p in parts):
            return (None, None, "TRIPLE FAIL 期望三元组格式非法（需要三段逗号分隔的非空值）",
                    pinned, require_signature)
        return None, dict(zip(TRIPLE_KEYS, parts)), None, pinned, require_signature
    return None, None, None, pinned, require_signature


def safe_path(root, arcname):
    """包内相对路径约束：拒绝空值、绝对路径、UNC、驱动器号、.. 与解析后越界。"""
    if not isinstance(arcname, str) or not arcname.strip():
        raise ValueError("包内路径非法：arcname 为空")
    normalized = arcname.replace(chr(92), "/")
    if normalized.startswith("/"):
        raise ValueError("包内路径非法（绝对路径/UNC）：" + arcname)
    if re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("包内路径非法（含驱动器号）：" + arcname)
    parts = PurePosixPath(normalized).parts
    if not parts or ".." in parts:
        raise ValueError("包内路径非法（包含上级目录 ..）：" + arcname)
    root_resolved = root.resolve()
    target = root_resolved.joinpath(*parts).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError("包内路径越界（不在包根目录内）：" + arcname)
    return target


def input_arcnames(entries):
    """0.4.3 包内输入名由 rel_path 推导；旧包仍优先使用 arcname。"""
    used, out = set(), []
    for entry in entries:
        rel = str(entry.get("rel_path") or "").replace(chr(92), "/")
        parts = [part for part in rel.split("/") if part not in ("", ".")]
        if not parts or ".." in parts:
            raise ValueError("inputs/manifest.json rel_path 非法：" + rel)
        rel = "/".join(parts)
        base = "inputs/" + rel
        candidate, serial = base, 2
        while candidate in used:
            if "." in rel:
                stem, ext = rel.rsplit(".", 1)
                candidate = "inputs/" + stem + "-" + str(serial) + "." + ext
            else:
                candidate = base + "-" + str(serial)
            serial += 1
        used.add(candidate)
        out.append(candidate)
    return out


def require(manifest, key, where):
    value = manifest.get(key)
    if value is None:
        raise ValueError(where + " 缺字段：" + key)
    return value


def main():
    root = Path(__file__).resolve().parent
    try:
        manifest = json.loads(safe_path(root, "manifest.json").read_text(encoding="utf-8"))
    except Exception as exc:
        print("MANIFEST FAIL", type(exc).__name__, str(exc))
        print("RESULT FAIL")
        return 1
    if not isinstance(manifest, dict):
        print("MANIFEST FAIL manifest 不是对象")
        print("RESULT FAIL")
        return 1

    schema_ver = schema_version(manifest)
    if schema_ver is None:
        print("MANIFEST FAIL manifest.schema 缺失或无法识别：",
              repr(manifest.get("schema")))
        print("RESULT FAIL")
        return 1
    print("MANIFEST SCHEMA v" + str(schema_ver), "OK")
    producer = manifest.get("producer")
    if isinstance(producer, dict):
        print("PRODUCER", producer.get("version"), producer.get("commit"),
              "python=" + str(producer.get("python")),
              "rule_pack=" + str(producer.get("rule_pack_version")))

    checksum_present = MANIFEST_CHECKSUM_FIELD in manifest
    if schema_ver >= 2 and not checksum_present:
        print("MANIFEST FAIL 新 schema v" + str(schema_ver) + " 包缺少 manifest_checksum")
        print("RESULT FAIL")
        return 1
    if checksum_present:
        try:
            stored = manifest.get(MANIFEST_CHECKSUM_FIELD)
            if not isinstance(stored, str) or stored != checksum_of(manifest):
                print("MANIFEST FAIL manifest_checksum 不一致（字段被改动或校验和未同步重算）")
                print("RESULT FAIL")
                return 1
            print("MANIFEST CHECKSUM OK")
        except Exception as exc:
            print("MANIFEST FAIL 无法计算 manifest_checksum：", type(exc).__name__, str(exc))
            print("RESULT FAIL")
            return 1
    else:
        print("MANIFEST CHECKSUM MISSING")

    try:
        engine = require(manifest, "engine_version", "manifest")
        triple = require(manifest, "triple", "manifest")
        if not isinstance(triple, dict):
            raise ValueError("manifest.triple 不是对象")
        for key in ("rule_pack_version", "input_fingerprint", "conclusion_digest"):
            value = triple.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError("manifest.triple 缺字段或为空：" + key)
        require(manifest, "run_id", "manifest")
        for key in ("scope_json", "counts", "chain_verification"):
            if not isinstance(require(manifest, key, "manifest"), dict):
                raise ValueError("manifest." + key + " 不是对象")
    except Exception as exc:
        print("MANIFEST FAIL", str(exc))
        print("RESULT FAIL")
        return 1

    expected_anchor, expected, expected_error, pinned_keys, require_signature = \
        expected_anchors_from_args()
    if expected_error:
        print(expected_error)
        print("RESULT FAIL")
        return 1

    segment = manifest.get("audit_segment") or {}
    prev = segment.get("segment_start_prev_hash") or h(
        f"{GENESES}|{engine}|" + triple["rule_pack_version"])
    epoch_ok = True
    activation = segment.get("activation_event") or {}
    if activation:
        try:
            expect_act = h(f"{activation['prev_hash']}|{activation['seq']}|{activation['actor']}"
                           f"|{activation['action']}|{activation['ts']}|{activation['payload_sha256']}")
            epoch_ok = (activation["entry_hash"] == expect_act
                        and activation["entry_hash"] == segment["segment_start_prev_hash"]
                        and activation["prev_hash"] == segment["prev_head_hash"])
        except Exception:
            epoch_ok = False
    print("EPOCH", "OK" if epoch_ok else "FAIL")

    ok = True
    n = 0
    try:
        with safe_path(root, "audit_chain.jsonl").open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                e = json.loads(line)
                expect = h(f"{prev}|{e['seq']}|{e['actor']}|{e['action']}|{e['ts']}|"
                           f"{e['payload_sha256']}")
                if e["prev_hash"] != prev or e["entry_hash"] != expect:
                    ok = False
                    print("BROKEN at seq", e.get("seq"))
                    break
                prev = e["entry_hash"]
                n += 1
    except Exception as exc:
        ok = False
        print("CHAIN FAIL 无法读取 audit_chain.jsonl：", type(exc).__name__, str(exc))
    chain_head = prev
    print("CHAIN", "OK" if ok and epoch_ok else "FAIL", "events=", n,
          "segment=", segment.get("epoch_id", "legacy"))
    print("TRIPLE", json.dumps(triple, sort_keys=True))

    triple_ok = True
    anchor_ok = True
    if expected_anchor:
        mismatched = []
        if expected_anchor["schema_version"] != schema_ver:
            mismatched.append("schema_version")
        for key in TRIPLE_KEYS:
            if expected_anchor[key] != triple.get(key):
                mismatched.append(key)
        expected_projection = expected_anchor.get("projection_fingerprint")
        package_projection = manifest.get("projection_fingerprint")
        if expected_projection is not None:
            if not isinstance(package_projection, str) or not package_projection:
                mismatched.append("projection_fingerprint")
                print("ANCHOR FAIL 包内无 projection_fingerprint，第五段无法校验")
            elif package_projection != expected_projection:
                mismatched.append("projection_fingerprint")
        if mismatched:
            anchor_ok = False
            print("ANCHOR FAIL 外部锚点与包内不一致：", ",".join(mismatched))
            for key in mismatched:
                expected_value = expected_anchor[key]
                if key == "schema_version":
                    actual_value = schema_ver
                elif key == "projection_fingerprint":
                    actual_value = package_projection or "（包内无）"
                else:
                    actual_value = triple.get(key)
                print("  ", key, "期望", expected_value, "包内", str(actual_value))
        else:
            print("ANCHOR CHECK OK")
    elif expected:
        mismatched = [k for k in TRIPLE_KEYS if expected[k] != triple.get(k)]
        if mismatched:
            triple_ok = False
            print("TRIPLE FAIL 外部期望三元组与包内不一致：", ",".join(mismatched))
            for key in mismatched:
                print("  ", key, "期望", expected[key], "包内", str(triple.get(key)))
        else:
            print("TRIPLE CHECK OK")
    scope = manifest.get("scope_json") or {}
    if scope.get("rule_pack_id") and scope["rule_pack_id"] != triple["rule_pack_version"]:
        triple_ok = False
        print("TRIPLE FAIL 包内 triple.rule_pack_version 与 scope_json.rule_pack_id 不一致")
    if (segment.get("rule_pack_version")
            and segment["rule_pack_version"] != triple["rule_pack_version"]):
        triple_ok = False
        print("TRIPLE FAIL 包内 triple.rule_pack_version 与 audit_segment.rule_pack_version 不一致")

    declared_counts = manifest.get("counts") or {}
    if declared_counts.get("audit_events") is not None:
        try:
            if int(declared_counts["audit_events"]) != n:
                ok = False
                print("CHAIN FAIL manifest.counts.audit_events 与实际事件数不一致")
        except (TypeError, ValueError):
            ok = False
            print("CHAIN FAIL manifest.counts.audit_events 不是整数")

    inputs_ok = True
    inputs_manifest = safe_path(root, "inputs/manifest.json")
    if inputs_manifest.is_file():
        try:
            im = json.loads(inputs_manifest.read_text(encoding="utf-8"))
            entries = im["entries"]
            if not isinstance(entries, list):
                raise ValueError("inputs/manifest.json entries 不是数组")
            missing = im["missing"]
            total_bytes = im["total_bytes"]
            selection_rule = im["selection_rule"]
            bad, checked = [], 0
            derived_arcnames = input_arcnames(entries)
            for entry, derived in zip(entries, derived_arcnames):
                arc = entry.get("arcname") or derived
                try:
                    path = safe_path(root, arc)
                except Exception as exc:
                    bad.append(str(exc))
                    continue
                if not path.is_file():
                    bad.append(str(arc) + " (缺失)")
                    continue
                with path.open("rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                checked += 1
                if digest != entry.get("sha256"):
                    bad.append(str(entry.get("rel_path", arc)) + " (哈希不一致)")
            print("INPUTS", "OK" if not bad else "FAIL", "checked=", checked,
                  "packed=", len(entries), "missing_at_export=", len(missing))
            for b in bad:
                print("  BAD", b)
            print("INPUT_BYTES", total_bytes, "SELECTION", selection_rule)
            inputs_ok = not bad
            declared_inputs = manifest.get("inputs") or {}
            if "inputs" not in manifest:
                inputs_ok = False
                print("INPUTS FAIL manifest 缺字段：inputs")
            elif declared_inputs.get("packed") is not None:
                if int(declared_inputs["packed"]) != len(entries):
                    inputs_ok = False
                    print("INPUTS FAIL manifest.inputs.packed 与包内 entries 数量不一致")
            if declared_inputs.get("total_bytes") is not None:
                if int(declared_inputs["total_bytes"]) != int(total_bytes):
                    inputs_ok = False
                    print("INPUTS FAIL manifest.inputs.total_bytes 与 inputs/manifest 不一致")
        except Exception as exc:
            inputs_ok = False
            print("INPUTS FAIL 无法读取 inputs/manifest.json：", type(exc).__name__, str(exc))
    else:
        print("INPUTS NONE（本包未自含原始数据，无法离线重放）")
        declared_inputs = manifest.get("inputs") or {}
        try:
            if int(declared_inputs.get("packed") or 0) > 0:
                inputs_ok = False
                print("INPUTS FAIL manifest 声明有输入，但包内没有 inputs/manifest.json")
        except (TypeError, ValueError):
            inputs_ok = False
            print("INPUTS FAIL manifest.inputs.packed 不是整数")

    # 输入摘要：v3 必须覆盖 inputs/ 下实际每个文件（含 inputs/manifest.json），
    # 这样单独跑 verify.py 也能发现“整批换输入并同步改登记表”的伪造。
    inputs_digest_bound = False
    declared_inputs_digest = manifest.get("inputs_digest")
    if declared_inputs_digest is None:
        if schema_ver >= 3:
            inputs_ok = False
            print("INPUTS FAIL v3 包缺少 manifest.inputs_digest")
        else:
            print("INPUTS DIGEST NONE（本包未声明输入摘要）")
    else:
        try:
            actual_inputs_digest = compute_inputs_digest(root)
            if not isinstance(declared_inputs_digest, str) \
                    or actual_inputs_digest != declared_inputs_digest:
                inputs_ok = False
                print("INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致")
            else:
                inputs_digest_bound = True
                print("INPUTS DIGEST OK", actual_inputs_digest)
        except Exception as exc:
            inputs_ok = False
            print("INPUTS FAIL 无法计算输入摘要：", type(exc).__name__, str(exc))

    # 结论集字节哈希：导出时写进 manifest（进而进 checksum 与签名），
    # 这里必须重算，才能发现“只改 conclusions_final.csv、不动 manifest”的伪造。
    artifact_ok = True
    declared_artifact = manifest.get("conclusions_sha256")
    if declared_artifact is None:
        if schema_ver >= 3:
            artifact_ok = False
            print("ARTIFACT FAIL v3 包缺少 manifest.conclusions_sha256")
        else:
            print("ARTIFACT NONE（本包未声明结论集哈希）")
    else:
        try:
            actual_artifact = digest_bytes(
                safe_path(root, "conclusions_final.csv").read_bytes())
            if not isinstance(declared_artifact, str) or actual_artifact != declared_artifact:
                artifact_ok = False
                print("ARTIFACT FAIL conclusions_final.csv 与 manifest.conclusions_sha256 不一致")
            else:
                print("ARTIFACT OK conclusions_final.csv")
        except Exception as exc:
            artifact_ok = False
            print("ARTIFACT FAIL 无法校验结论集：", type(exc).__name__, str(exc))

    # 签名覆盖 schema/triple/manifest_checksum 与实际链头；包内公钥只做自洽，
    # 外部 pin 才证明来源。任何“有签名但验不过”都不允许降级成旧包路径。
    signature = verify_signature(manifest, chain_head, pinned_keys)
    signature_ok = True
    if signature["present"]:
        if signature["ok"]:
            if signature["trust"] == "pinned":
                print("SIGNATURE OK (pinned key_id=%s)" % signature["key_id"])
            else:
                print("SIGNATURE OK (package self-check; NOT source trust, key_id=%s)"
                      % signature["key_id"])
        else:
            signature_ok = False
            print("SIGNATURE FAIL", signature["reason"])
    elif schema_ver >= 3:
        signature_ok = False
        print("SIGNATURE FAIL v3 包缺少 manifest.signature")
    elif require_signature:
        signature_ok = False
        print("SIGNATURE FAIL 本包无签名，且 --require-signature 要求必须有签名")
    else:
        print("SIGNATURE NONE（旧包无签名，仅包内自洽；来源不可证明）")

    if inputs_digest_bound and signature["present"] and signature["ok"]:
        print("INPUTS SIGNED OK (inputs_digest bound by signature)")
    elif inputs_digest_bound:
        print("INPUTS SELF-CHECK OK (inputs_digest matches manifest; NOT signed)")

    result_ok = (epoch_ok and ok and triple_ok and anchor_ok and inputs_ok
                 and artifact_ok and signature_ok)
    print("RESULT", "OK" if result_ok else "FAIL")
    return 0 if result_ok else 1


if __name__ == "__main__":
    sys.exit(main())
'''
