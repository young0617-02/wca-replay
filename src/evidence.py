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
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import ENGINE_VERSION
from .config import Config
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
    "包内所有金额均为「参考测算明细」，authorized_final=0，不构成最终应付数额承诺。\r\n"
)


def export_package(conn: sqlite3.Connection, cfg: Config, run_id: str) -> dict:
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
        },
        "chain_verification": verification.as_dict(),
        "artifacts": [p.name for p in (findings_csv, manifest_files, chain_json, issues_csv)],
        "disclaimer": "金额字段为参考测算明细（authorized_final=0），不构成最终应付数额承诺；"
                      "数据为合成数据，非任何真实个人信息。",
    }
    manifest_path = work / "manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    # manifest 自身的哈希，用于「重跑后比对包是否等价」
    manifest_sha = sha256_hex(manifest_path.read_bytes())

    zip_path = cfg.packages_dir / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", PACKAGE_README)
        for p in (manifest_path, findings_csv, manifest_files, chain_json, issues_csv):
            zf.write(p, arcname=p.name)
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


VERIFY_SNIPPET = '''"""独立复核脚本：不依赖本项目代码，只用标准库重算 hash 链。

用法：unzip pkg-<run_id>.zip && python verify.py
期望输出：CHAIN OK + 三元组，与 manifest.json 一致即说明举证包未被改写。
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

'''
