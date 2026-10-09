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
import shutil
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import ENGINE_VERSION
from .config import Config, PROJECT_ROOT
from .db import get_meta, set_meta
from .util import CN_TZ, canonical_json, digest_of, sha256_hex

GENESES = "wca-audit-chain-v1"


def _chain_hash(prev: str, seq: int, actor: str, action: str, ts: str, payload_sha: str) -> str:
    return sha256_hex(f"{prev}|{seq}|{actor}|{action}|{ts}|{payload_sha}")


def genesis_hash(cfg: Config) -> str:
    return sha256_hex(f"{GENESES}|{ENGINE_VERSION}|{cfg.rule_pack_id}")


def append_audit(conn: sqlite3.Connection, *, run_id: str | None, actor: str, action: str,
                 payload: object, ts: str | None = None, cfg: Config | None = None) -> tuple[int, str]:
    """追加一条审计事件。payload 走规范 JSON，禁止浮点。"""
    last = conn.execute("SELECT entry_hash, seq FROM audit_event ORDER BY seq DESC LIMIT 1").fetchone()
    if last is not None:
        prev = str(last["entry_hash"])
        seq = int(last["seq"]) + 1
    else:
        if cfg is None:
            raise ValueError("链首事件必须传 cfg 以派生 genesis")
        prev = genesis_of(conn, cfg)
        seq = 1
    ts = ts or datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")
    payload_sha = sha256_hex(canonical_json(payload))
    entry = _chain_hash(prev, seq, actor, action, ts, payload_sha)
    conn.execute(
        "INSERT INTO audit_event(seq, run_id, actor, action, ts, payload_sha256, prev_hash, entry_hash) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (seq, run_id, actor, action, ts, payload_sha, prev, entry),
    )
    return seq, entry


def genesis_of(conn: sqlite3.Connection, cfg: Config) -> str:
    stored = get_meta(conn, "audit_genesis")
    if not stored:
        g = genesis_hash(cfg)
        set_meta(conn, "audit_genesis", g)
        return g
    if stored != genesis_hash(cfg):
        raise RuntimeError("审计链起点与当前 engine/rule_pack 不一致，拒绝写入（防止历史被替换）")
    return stored


def set_genesis(conn: sqlite3.Connection, cfg: Config) -> None:
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


def verify_chain(conn: sqlite3.Connection, cfg: Config) -> ChainVerification:
    rows = conn.execute(
        "SELECT seq, actor, action, ts, payload_sha256, prev_hash, entry_hash FROM audit_event "
        "ORDER BY seq"
    ).fetchall()
    if not rows:
        return ChainVerification(0, True, None, "空链条", genesis_hash(cfg))
    prev = genesis_hash(cfg)
    for r in rows:
        expected = _chain_hash(prev, int(r["seq"]), r["actor"], r["action"], r["ts"], r["payload_sha256"])
        if r["prev_hash"] != prev:
            return ChainVerification(len(rows), False, int(r["seq"]), "prev_hash 与前一条 entry_hash 不衔接",
                                     str(rows[-1]["entry_hash"]))
        if r["entry_hash"] != expected:
            return ChainVerification(len(rows), False, int(r["seq"]), "entry_hash 与内容重算不一致（疑似改写）",
                                     str(rows[-1]["entry_hash"]))
        prev = str(r["entry_hash"])
    return ChainVerification(len(rows), True, None, "", prev)


def tamper_check_report(ver: ChainVerification) -> str:
    return "链完整" if ver.ok else f"链在 seq={ver.broken_at_seq} 处断裂：{ver.reason}"


# ------------------------------------------------------------------ 输入指纹 / 结论摘要
def input_fingerprint(conn: sqlite3.Connection, scope: dict,
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
        f"SELECT rel_path, sha256, row_count, kind FROM raw_file {where} ORDER BY rel_path, sha256",
        params,
    ).fetchall()
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
    "包内 inputs/ 带本次结论真正依赖的原始 CSV（选择规则见 manifest.inputs.selection_rule），"
    "所以复核不必再回头索要数据：verify.py 独立重算审计链与输入文件哈希；"
    "有本项目代码时用 `python -m src.cli replay <包>` 重放引擎并比对三元组。\r\n"
)


# ---------------------------------------------------------------- 责任与未覆盖（US-EX-02 / US-EX-03 / US-RV-01）
NOT_COVERED_PATH = "config/not_covered.json"


def not_covered_block(cfg: Config) -> dict:
    """未覆盖清单：外部接收方最怕的是"缺项＝造假"，所以缺什么必须自己说清楚。

    覆盖城市来自档位表（配置，不写死），其余来自 `config/not_covered.json`。
    """
    from pathlib import Path as _P

    raw = _P(NOT_COVERED_PATH)
    data = json.loads(raw.read_text(encoding="utf-8")) if raw.is_file() else {}
    profile = getattr(cfg, "region_profile", None)
    data["scope"]["cities_covered"] = profile.codes() if profile else [cfg.region_code]
    data["scope"]["cities_covered_labels"] = ([profile.label(c) for c in profile.codes()]
                                              if profile else [cfg.region_label])
    data["generated_from"] = NOT_COVERED_PATH
    return data


def responsibility_block(conn: sqlite3.Connection, cfg: Config, run_id: str) -> dict:
    """谁参与了什么：机器只做解释与检索，数值出自确定性引擎，对外结论必须有人签名。"""
    rows = conn.execute(
        "SELECT f.finding_id, f.rule_id, f.emp_id, f.work_date, f.period_key, f.severity, "
        "       r.status, r.reviewer, r.decided_at, r.note, r.amount_cents_input, "
        "       r.amount_entered_by, r.amount_entered_at "
        "FROM finding f LEFT JOIN review_item r "
        "  ON r.run_id = f.run_id AND r.source_type = 'finding' "
        " AND (f.rule_id || ':' || f.emp_id || ':' || COALESCE(f.work_date, f.period_key, 'None') = r.source_id "
        "      OR f.rule_id || ':' || f.emp_id || ':' || COALESCE(f.work_date, f.period_key, '') = r.source_id) "
        "WHERE f.run_id = ? ORDER BY f.emp_id, f.work_date, f.rule_id", (run_id,)).fetchall()
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

    ai_rows = conn.execute(
        "SELECT qid, asked_at, actor_emp_id, question, intent, gate_decision, citation_ids, "
        "       numeric_tokens, allowed_numbers, provider, model, needs_review "
        "FROM question_log ORDER BY asked_at").fetchall() if _has_table(conn, "question_log") else []
    # 问答留痕不按 run 过滤：它是"这台机器上 AI 参与过什么"的账，
    # 与某一次校验结论没有一一对应关系，硬编成 per-run 反而是假的。
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
        "ai_participation_scope_note": "问答留痕为全仓范围（question_log 不按 run 切分）",
        "ai_participation": ai,
        "ai_participation_count": len(ai),
        "human_confirmations": confirmed,
        "human_confirmed_findings": len(confirmed),
        "unsigned_findings_excluded_from_conclusions": len(pending),
        "pending_findings": [p["rule_id"] + ":" + p["emp_id"] for p in pending][:200],
        "signed_by": [{"seq": int(x["seq"]), "actor": x["actor"], "ts": x["ts"]} for x in signs],
        "signed": bool(signs),
    }


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
                        (name,)).fetchone() is not None


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return conn.execute("SELECT 1 FROM pragma_table_info(?) WHERE name = ?",
                        (table, column)).fetchone() is not None


def sign_package(conn: sqlite3.Connection, cfg: Config, run_id: str, signed_by: str) -> dict:
    """签发：把"谁为这份材料负责"追加进审计链（不改写历史）。CLI 与界面共用这一个入口。"""
    if not signed_by.strip():
        raise ValueError("签发人不能为空")
    seq, entry_hash = append_audit(
        conn, run_id=run_id, actor=f"human:{signed_by}", action="evidence.sign",
        payload={"run_id": run_id, "signed_by": signed_by}, cfg=cfg)
    return {"review_id": None, "audit_seq": seq, "entry_hash": entry_hash, "signed_by": signed_by}


def _write_conclusions_csv(path: Path, rows: list[dict]) -> None:
    """对外结论集：**只收已登记人工结论的条目**（US-RV-01★：无人工结论的异常不得进入）。"""
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rule_id", "emp_id", "work_date", "period_key", "severity",
                    "decision", "confirmed_by", "confirmed_at",
                    "amount_cents_input", "amount_entered_by", "note"])
        for x in rows:
            w.writerow([x["rule_id"], x["emp_id"], x["work_date"], x["period_key"], x["severity"],
                        x["decision"], x["confirmed_by"], x["confirmed_at"],
                        x.get("amount_cents_input"), x.get("amount_entered_by"), x.get("note")])




def _not_covered_markdown(nc: dict) -> str:
    """把未覆盖清单渲染成给人读的 Markdown（数据来自 config/not_covered.json，不写死在代码里）。"""
    NL = chr(10)
    scope = nc["scope"]
    out = [
        "# 未覆盖清单（本期不做 / 未验证）",
        "",
        "- 覆盖工时制：" + str(scope["worktime_regimes_covered"]),
        "- 不覆盖工时制：" + str(scope["worktime_regimes_excluded"]),
        "  - 原因：" + str(scope["excluded_reason"]),
        "- 覆盖城市：" + str(scope.get("cities_covered_labels") or scope.get("cities_covered"))
        + "（清单见 config/region_profile.json）",
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
    return NL.join(out) + NL


# ------------------------------------------------- 输入自含与外部重放（US-EX-01 / A8）
EXPORT_INPUTS_MAX_BYTES = 8 * 1024 * 1024
INPUTS_DIRNAME = "inputs"
INPUTS_MANIFEST_NAME = f"{INPUTS_DIRNAME}/manifest.json"


def _run_input_file_ids(conn: sqlite3.Connection, run_id: str) -> set[int]:
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


def _resolve_input_path(rel_path: str, cfg: Config) -> Path | None:
    """按几个常见落点找原始文件；找不到就返回 None，由调用方如实记成缺项，不猜。"""
    if rel_path.startswith("inline://"):
        return None
    p = Path(rel_path)
    candidates = [p if p.is_absolute() else PROJECT_ROOT / p, Path.cwd() / p,
                  cfg.data_dir / p.name]
    for c in candidates:
        if c.is_file():
            return c
    return None


def collect_package_inputs(conn: sqlite3.Connection, cfg: Config, run_id: str) -> dict:
    """挑出可打包的输入文件，并按字节预算把关（超预算直接报错，不静默截断）。"""
    entries: list[dict] = []
    missing: list[str] = []
    ids = _run_input_file_ids(conn, run_id)
    if not ids:
        return {"entries": [], "missing": [], "total_bytes": 0,
                "reason": "本次运行没有记录引用文件（旧库或空引用），包内不含 inputs/"}
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT file_id, rel_path, sha256, kind, row_count FROM raw_file "
        f"WHERE file_id IN ({placeholders}) ORDER BY file_id", tuple(sorted(ids))).fetchall()
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
                        "arcname": f"{INPUTS_DIRNAME}/{int(r['file_id']):03d}-{src.name}",
                        "source": str(src)})
    total = sum(e["bytes"] for e in entries)
    if total > EXPORT_INPUTS_MAX_BYTES:
        raise ValueError(
            f"待打包输入 {total:,} 字节，超过预算 {EXPORT_INPUTS_MAX_BYTES:,} 字节；"
            f"确认没必要自含时可用 --no-inputs 导出不带原始数据的包")
    note = ""
    if not _has_column(conn, "run", "referenced_file_ids"):
        note = ("旧库没有 run.referenced_file_ids 列（本次运行当时未记录引用集合），"
                "已按主数据 + 结论溯源 + 未归属质量问题文件打包")
    elif not conn.execute("SELECT referenced_file_ids FROM run WHERE run_id = ?",
                          (run_id,)).fetchone()["referenced_file_ids"]:
        note = "该 run 未记录引用文件集合（升级前的旧 run），已按主数据 + 溯源引用打包"
    return {"entries": entries, "missing": missing, "total_bytes": total, "reason": note}


def export_package(conn: sqlite3.Connection, cfg: Config, run_id: str, *,
                   include_inputs: bool = True) -> dict:
    """导出举证包（zip + manifest），返回清单字典。1000 行内应控制在数秒级（设计值）。"""
    run = conn.execute("SELECT * FROM run WHERE run_id = ?", (run_id,)).fetchone()
    if run is None:
        raise ValueError(f"未知 run_id: {run_id}")

    cfg.ensure_dirs()
    work = cfg.packages_dir / run_id
    work.mkdir(parents=True, exist_ok=True)

    findings = conn.execute(
        "SELECT * FROM finding WHERE run_id = ? ORDER BY emp_id, work_date, rule_id", (run_id,)
    ).fetchall()
    files = conn.execute("SELECT * FROM raw_file ORDER BY rel_path").fetchall()
    chain = conn.execute(
        "SELECT seq, run_id, actor, action, ts, payload_sha256, prev_hash, entry_hash "
        "FROM audit_event ORDER BY seq"
    ).fetchall()
    issues = conn.execute(
        "SELECT i.*, f.rel_path FROM ingest_issue i JOIN raw_file f ON f.file_id = i.file_id "
        "ORDER BY i.file_id, i.line_no"
    ).fetchall()

    # 1) 结论明细 CSV（行级来源反查链：finding -> source_refs -> (rel_path, line_no)）
    findings_csv = work / "findings.csv"
    _write_findings_csv(findings_csv, findings, conn)

    # 2) 输入清单
    manifest_files = work / "input_files.csv"
    with manifest_files.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rel_path", "sha256", "row_count", "kind"])
        for f in files:
            w.writerow([f["rel_path"], f["sha256"], int(f["row_count"]), f["kind"]])

    # 3) 审计链快照 + 独立校验器
    chain_json = work / "audit_chain.jsonl"
    with chain_json.open("w", encoding="utf-8", newline="") as fh:
        for c in chain:
            fh.write(canonical_json({
                "seq": int(c["seq"]), "run_id": c["run_id"], "actor": c["actor"], "action": c["action"],
                "ts": c["ts"], "payload_sha256": c["payload_sha256"], "prev_hash": c["prev_hash"],
                "entry_hash": c["entry_hash"],
            }) + "\n")

    # 4) 数据质量报表
    issues_csv = work / "quality_issues.csv"
    with issues_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rel_path", "line_no", "rule_id", "severity", "field", "raw_value", "detail"])
        for i in issues:
            w.writerow([i["rel_path"], int(i["line_no"]), i["rule_id"], i["severity"],
                        i["field_name"], i["raw_value"], i["detail"]])

    # 5) 对外结论集：只收"已登记人工结论"的条目（US-RV-01★）
    resp = responsibility_block(conn, cfg, run_id)
    conclusions_csv = work / "conclusions_final.csv"
    _write_conclusions_csv(conclusions_csv, resp["human_confirmations"])

    # 6) 责任区块（US-EX-02★）：机器做了什么、人确认了什么、谁签的字
    resp_path = work / "responsibility.json"
    resp_doc = dict(resp)
    resp_path.write_text(canonical_json(resp_doc) + chr(10), encoding="utf-8")

    # 7) 未覆盖清单（US-EX-03）：不覆盖什么，自己先说
    nc = not_covered_block(cfg)
    nc_path = work / "not_covered.json"
    nc_path.write_text(canonical_json(nc) + chr(10), encoding="utf-8")
    nc_md = work / "未覆盖清单.md"
    nc_md.write_text(_not_covered_markdown(nc))

    # 8) 输入自含（US-EX-01）：把本次结论真正依赖的原始 CSV 一起打包，让重放不需要另外索要数据
    inputs_dir = work / INPUTS_DIRNAME
    inputs_dir.mkdir(exist_ok=True)
    for stale in inputs_dir.glob("*"):
        if stale.name != "manifest.json":
            stale.unlink()
    if include_inputs:
        collected = collect_package_inputs(conn, cfg, run_id)
    else:
        collected = {"entries": [], "missing": [], "total_bytes": 0,
                     "reason": "调用方指定 --no-inputs：本包不含原始输入，接收方无法离线重放"}
    inputs_manifest = work / INPUTS_MANIFEST_NAME
    inputs_doc = {"schema": "wca-package-inputs-v1", "run_id": run_id,
                  "cap_bytes": EXPORT_INPUTS_MAX_BYTES,
                  "selection_rule": "主数据(org/employee) ∪ 引用集合 ∪ 结论溯源引用 ∪ 未归属质量问题所在文件",
                  "total_bytes": collected["total_bytes"], "missing": collected["missing"],
                  "reason": collected["reason"],
                  "entries": [{k: e[k] for k in ("file_id", "rel_path", "kind", "sha256",
                                                 "bytes", "arcname")} for e in collected["entries"]]}
    inputs_manifest.write_text(canonical_json(inputs_doc) + chr(10), encoding="utf-8")
    for e in collected["entries"]:
        shutil.copyfile(e["source"], work / e["arcname"])

    verification = verify_chain(conn, cfg)
    triple = {
        "rule_pack_version": run["rule_pack_version"],
        "input_fingerprint": run["input_fingerprint"],
        "conclusion_digest": run["conclusion_digest"],
    }
    manifest = {
        "schema": "wca-evidence-package-v1",
        "run_id": run_id,
        "engine_version": run["engine_version"],
        "triple": triple,
        "scope_json": json.loads(run["scope_json"]),
        "counts": {
            "findings": len(findings),
            "input_files": len(files),
            "audit_events": len(chain),
            "quality_issues": len(issues),
            # 对外结论集只含已人工确认的条目；未确认的仍留在 findings.csv 里等处置
            "final_conclusions": len(resp["human_confirmations"]),
            "unsigned_pending": resp["unsigned_findings_excluded_from_conclusions"],
            "ai_answered_questions": resp["ai_participation_count"],
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
                   "total_bytes": collected["total_bytes"],
                   "cap_bytes": EXPORT_INPUTS_MAX_BYTES,
                   "selection_rule": inputs_doc["selection_rule"],
                   "missing": collected["missing"],
                   "reason": collected["reason"],
                   "replay_command": "python -m src.cli replay <本包.zip 或解包目录>"},
        "artifacts": [p.name for p in (findings_csv, manifest_files, chain_json, issues_csv,
                                       conclusions_csv, resp_path, nc_path, nc_md)]
                      + [INPUTS_MANIFEST_NAME] + [e["arcname"] for e in collected["entries"]],
        "disclaimer": "本包不产出应付金额（需求 D-03）；金额是 HR 负责人具名录入的人工结论，不属于引擎输出；"
                      "数据为合成数据，非任何真实个人信息。",
    }
    manifest_path = work / "manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    # manifest 自身的哈希，用于「重跑后比对包是否等价」
    manifest_sha = sha256_hex(manifest_path.read_bytes())

    zip_path = cfg.packages_dir / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", PACKAGE_README)
        for p in (manifest_path, findings_csv, manifest_files, chain_json, issues_csv,
                  conclusions_csv, resp_path, nc_path, nc_md):
            zf.write(p, arcname=p.name)
        zf.write(inputs_manifest, arcname=INPUTS_MANIFEST_NAME)
        for e in collected["entries"]:
            zf.write(work / e["arcname"], arcname=e["arcname"])
        zf.writestr("verify.py", VERIFY_SNIPPET)

    conn.execute(
        "INSERT INTO evidence_package(package_id, run_id, created_at, rule_pack_version, "
        "input_fingerprint, conclusion_digest, manifest_sha256, package_dir, row_count) "
        "VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(package_id) DO UPDATE SET created_at = excluded.created_at, "
        "manifest_sha256 = excluded.manifest_sha256, package_dir = excluded.package_dir",
        (
            f"pkg-{run_id}", run_id,
            datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            triple["rule_pack_version"], triple["input_fingerprint"], triple["conclusion_digest"],
            manifest_sha, str(zip_path), len(findings),
        ),
    )
    append_audit(
        conn, run_id=run_id, actor="system:evidence", action="evidence.export",
        payload={"triple": triple, "manifest_sha256": manifest_sha, "zip": zip_path.name}, cfg=cfg,
    )
    manifest["manifest_sha256"] = manifest_sha
    manifest["package_zip"] = str(zip_path)
    return manifest


def _write_findings_csv(path: Path, findings, conn: sqlite3.Connection) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow([
            "rule_id", "rule_version", "emp_id", "work_date", "period_key", "severity",
            "severity_label", "citations", "metric_json", "source_rel_path", "source_line_no",
            "explanation",
        ])
        for f in findings:
            refs = json.loads(f["source_refs"])
            loc = _source_loc(conn, refs)
            w.writerow([
                f["rule_id"], f["rule_version"], f["emp_id"], f["work_date"], f["period_key"],
                f["severity"], _sev_label(f["severity"]), f["citation_ids"], f["metric_json"],
                loc[0], loc[1], f["explanation"],
            ])


def _source_loc(conn: sqlite3.Connection, refs: list[dict]) -> tuple[str, str]:
    paths: list[str] = []
    lines: list[str] = []
    for r in refs:
        fid = r.get("file_id")
        if fid is None:
            continue
        row = conn.execute("SELECT rel_path FROM raw_file WHERE file_id = ?", (fid,)).fetchone()
        if row:
            paths.append(row["rel_path"])
            lines.append(str(r.get("line_no")))
    return (";".join(dict.fromkeys(paths))), (";".join(lines))


def _sev_label(sev: str) -> str:
    return {"DEFENSIBLE": "可申辩", "REVIEW": "需复核", "VIOLATION": "明显违规"}.get(sev, sev)


VERIFY_SNIPPET = '''"""独立复核脚本：不依赖本项目代码，只用标准库重算 hash 链并校验包内原始输入的哈希。

用法：unzip pkg-<run_id>.zip && python verify.py
期望输出：CHAIN OK + INPUTS OK + 三元组。链与输入哈希一致说明**包没被改写**；
结论是否一致要重跑引擎（`python -m src.cli replay <包>`），本脚本不假装自己能算结论。
"""
import hashlib
import json

GENESES = "wca-audit-chain-v1"


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


manifest = json.load(open("manifest.json", encoding="utf-8"))
engine = manifest["engine_version"]
prev = h(f"{GENESES}|{engine}|" + manifest["triple"]["rule_pack_version"])
ok = True
n = 0
for line in open("audit_chain.jsonl", encoding="utf-8"):
    e = json.loads(line)
    expect = h(f"{prev}|{e['seq']}|{e['actor']}|{e['action']}|{e['ts']}|{e['payload_sha256']}")
    if e["prev_hash"] != prev or e["entry_hash"] != expect:
        ok = False
        print("BROKEN at seq", e["seq"])
        break
    prev = e["entry_hash"]
    n += 1
print("CHAIN", "OK" if ok else "FAIL", "events=", n)
print("TRIPLE", json.dumps(manifest["triple"], sort_keys=True))

# 包内原始输入：逐个按登记 sha256 复算。这一步不需要本项目代码，
# 但它只证明「数据没被换过」；结论要重跑才可比，见 manifest.inputs.replay_command。
import os

inputs_manifest = "inputs/manifest.json"
if os.path.isfile(inputs_manifest):
    im = json.load(open(inputs_manifest, encoding="utf-8"))
    bad, checked = [], 0
    for entry in im["entries"]:
        if not os.path.isfile(entry["arcname"].replace("/", os.sep)):
            bad.append(entry["arcname"] + " (缺失)")
            continue
        with open(entry["arcname"].replace("/", os.sep), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        checked += 1
        if digest != entry["sha256"]:
            bad.append(entry["rel_path"] + " (哈希不一致)")
    print("INPUTS", "OK" if not bad else "FAIL", "checked=", checked,
          "packed=", len(im["entries"]), "missing_at_export=", len(im["missing"]))
    for b in bad:
        print("  BAD", b)
    print("INPUT_BYTES", im["total_bytes"], "SELECTION", im["selection_rule"])
else:
    print("INPUTS NONE（本包未自含原始数据，无法离线重放）")

'''
