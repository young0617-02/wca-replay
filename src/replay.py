"""外部重放：拿着举证包自己把引擎跑一遍，比对三元组（需求 US-EX-01 / 一票否决项 A8）。

为什么要有这个命令：`verify.py` 只能证明**包没被改写**（链与文件哈希），
证明不了"这些结论是这批数据算出来的"。需求原文写的是「只给包内三元组 + 原始 CSV，重放逐条一致」，
所以包必须自带输入，且必须有一条命令能把输入喂回引擎再比一次摘要。

口径边界要说清（不做无法兑现的承诺）：
  * 重放用的是**当前代码**，规则包版本与包内不一致时直接拒绝，不假装能跨版本复现；
  * 包内 scope 记了哪些参数，重放就强制钉回哪些参数；**没记的**（夜间窗口、月度上限等）
    沿用代码默认值——本机 `.env` 不参与，所以结果只依赖"包 + 仓库默认口径"。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import date
from pathlib import Path

from . import ENGINE_VERSION
from .config import Config
from .db import connect, init_db
from .engine import run_check
from .ingest import import_csv_file
from .util import sha256_hex

GENESES = "wca-audit-chain-v1"
# 导入顺序决定"同一份主数据被谁最后覆盖"，所以重放必须按与 CLI 相同的顺序来
INGEST_ORDER = ("org", "employee", "schedule", "punch", "leave", "trip", "correction")
# scope 里记了哪些口径参数，重放就钉回哪些；其余沿用代码默认值并如实列出
PINNED_SCOPE_PARAMS = {
    "ot_cap_scope": "WCA_OT_CAP_SCOPE",
    "cross_day_cut_hour": "WCA_CROSS_DAY_CUT_HOUR",
    "daily_std_minutes": "WCA_DAILY_STD_MINUTES",
    "weekly_std_minutes": "WCA_WEEKLY_STD_MINUTES",
    "pay_base_source": "WCA_PAY_BASE_SOURCE",
}


def _chain_from_snapshot(lines: list[str], engine_version: str, rule_pack: str) -> dict:
    """不依赖本项目写入逻辑，独立按同一公式重算链（与包内 verify.py 同口径）。"""
    prev = sha256_hex(f"{GENESES}|{engine_version}|{rule_pack}")
    n = 0
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        expect = sha256_hex(f"{prev}|{e['seq']}|{e['actor']}|{e['action']}"
                            f"|{e['ts']}|{e['payload_sha256']}")
        if e["prev_hash"] != prev:
            return {"ok": False, "broken_at_seq": int(e["seq"]),
                    "reason": "prev_hash 与前一条 entry_hash 不衔接", "length": n}
        if e["entry_hash"] != expect:
            return {"ok": False, "broken_at_seq": int(e["seq"]),
                    "reason": "entry_hash 与内容重算不一致（疑似改写）", "length": n}
        prev = str(e["entry_hash"])
        n += 1
    return {"ok": True, "broken_at_seq": None, "reason": "", "length": n, "head_hash": prev}


@contextmanager
def unpacked(package: Path | str):
    """zip 解到临时目录，目录就用原目录；两条路径都支持，因为复核方可能已经解压了。"""
    p = Path(package)
    if p.is_dir():
        if not (p / "manifest.json").is_file():
            raise ValueError(f"目录里没有 manifest.json：{p}")
        yield p
        return
    if not p.is_file():
        raise FileNotFoundError(f"举证包不存在：{p}")
    tmp = Path(tempfile.mkdtemp(prefix="wca-replay-"))
    try:
        with zipfile.ZipFile(p) as zf:
            zf.extractall(tmp)
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _replay_cfg(work: Path, scope: dict, rule_pack: str) -> Config:
    if not scope.get("region_code"):
        raise ValueError("包内 scope 没有 region_code，无法确定重放的城市档")
    overrides = {
        "WCA_DB_PATH": str(work / "replay.sqlite3"),
        "WCA_DATA_DIR": str(work / "data"),
        "WCA_REPORTS_DIR": str(work / "reports"),
        "WCA_PACKAGES_DIR": str(work / "packages"),
        "WCA_UPLOAD_DIR": str(work / "uploads"),
        "WCA_USERS_PATH": str(work / "users.json"),
        "WCA_RULE_PACK": rule_pack,
        "WCA_REGION_CODE": scope["region_code"],
        "WCA_LLM_PROVIDER": "stub",
        "WCA_EMBEDDING_BACKEND": "bm25",
    }
    for scope_key, env_key in PINNED_SCOPE_PARAMS.items():
        if scope.get(scope_key) not in (None, ""):
            overrides[env_key] = str(scope[scope_key])
    # env_path 指向一个不存在的路径：重放只依赖「包 + 仓库默认口径」，不吃本机 .env；
    # 城市标签由档位表解析（代码里没有市名，见 config/region_profile.json）
    return Config.load(env_path=work / "absent.env", **overrides)


def replay(package: Path | str) -> dict:
    """重放一个举证包，返回可比对的字典（不抛异常即代表流程跑通，结论看 ok 字段）。"""
    with unpacked(package) as d:
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
        triple = manifest["triple"]
        scope = manifest.get("scope_json") or {}
        chain = _chain_from_snapshot(
            (d / "audit_chain.jsonl").read_text(encoding="utf-8").splitlines(),
            manifest["engine_version"], triple["rule_pack_version"])
        inputs = json.loads((d / "inputs" / "manifest.json").read_text(encoding="utf-8")) \
            if (d / "inputs" / "manifest.json").is_file() else {"entries": [], "missing": [],
                                                                "reason": "包内没有 inputs/manifest.json"}
        result = {"package": str(package), "run_id": manifest["run_id"],
                  "expected_triple": triple, "chain": chain,
                  "inputs_packed": len(inputs["entries"]), "inputs_missing": inputs["missing"],
                  "engine_expected": manifest["engine_version"], "engine_actual": ENGINE_VERSION,
                  "pinned_params": {k: scope[k] for k in PINNED_SCOPE_PARAMS if k in scope},
                  "inherited_params_note": "包内 scope 未记录的判据参数沿用代码默认值（不读本机 .env）",
                  "ok": False, "reason": ""}
        if not chain["ok"]:
            result["reason"] = f"审计链断裂：seq={chain['broken_at_seq']} {chain['reason']}"
            return result
        if triple["rule_pack_version"] != _current_rule_pack():
            result["reason"] = (f"规则包版本不一致：包内 {triple['rule_pack_version']}，"
                                f"当前代码 {_current_rule_pack()}。重放只能证明同版本代码的行为，"
                                "跨版本差异要走 reports/判据修订.md 的 REV 对账，不能靠重放掩盖")
            return result
        if not inputs["entries"]:
            result["reason"] = f"包内没有可重放的原始输入：{inputs.get('reason') or inputs['missing']}"
            return result

        work = Path(tempfile.mkdtemp(prefix="wca-replay-db-"))
        try:
            cfg = _replay_cfg(work, scope, triple["rule_pack_version"])
            cfg.ensure_dirs()
            conn = connect(cfg.db_path, cfg.sqlite_synchronous)
            init_db(conn)
            by_kind: dict[str, list[dict]] = {}
            for e in inputs["entries"]:
                by_kind.setdefault(e["kind"], []).append(e)
            imported = []
            for kind in INGEST_ORDER:
                for e in sorted(by_kind.pop(kind, []), key=lambda x: x["file_id"]):
                    src = d / e["arcname"]          # arcname 是包内相对路径（inputs/004-punch.csv）
                    if not src.is_file():
                        raise FileNotFoundError(f"包内缺少输入文件：{e['arcname']}")
                    res = import_csv_file(conn, cfg, src, kind=kind, rel_path=e["rel_path"])
                    imported.append({"rel_path": e["rel_path"], "kind": kind,
                                     "sha256": res.sha256[:12], "rows_seen": res.rows_seen,
                                     "accepted": res.rows_accepted, "rejected": res.rows_rejected})
            for kind, rest in by_kind.items():
                raise ValueError(f"包内出现未知数据种类 {kind}（无法确定导入顺序）")
            out = run_check(conn, cfg, start=date.fromisoformat(scope["start"]),
                            end=date.fromisoformat(scope["end"]),
                            emp_ids=scope.get("emp_ids"), notes=f"replay {manifest['run_id']}")
            actual = {"rule_pack_version": cfg.rule_pack_id,
                      "input_fingerprint": out.input_fingerprint,
                      "conclusion_digest": out.conclusion_digest}
            result.update({"actual_triple": actual, "imports": imported,
                           "findings_expected": manifest["counts"]["findings"],
                           "findings_actual": len(out.findings),
                           "counts_actual": out.counts_by_severity()})
            mismatched = [k for k in actual if actual[k] != triple.get(k)]
            result["mismatched_fields"] = mismatched
            if not mismatched and result["findings_expected"] == result["findings_actual"]:
                result["ok"] = True
                result["reason"] = "三元组与结论条数逐项一致"
            else:
                result["reason"] = (f"重放结果与包内三元组不一致：{mismatched or '结论条数不同'}"
                                    f"（期望 {result['findings_expected']} 条 / 实得 "
                                    f"{result['findings_actual']} 条）")
            conn.close()
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return result


def _current_rule_pack() -> str:
    from .rules.rulepack import RULE_PACK_VERSION

    return RULE_PACK_VERSION
