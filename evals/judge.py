"""F-012 判分器：对 evals/golden_set_v1.jsonl 逐条打分并产出评测报告。

指标口径（与方案 §4.7-Q4 对齐，全部为实测；未实现的指标不出现在报告里）：
  intent_top1        提问意图归类首次命中率
  hit@5 / mrr        检索命中：期望条文进入 top-5 的比例 / 期望文档倒数排名均值
  tool_success       确定性数值工具首次成功率（结论存在且数值与手工推导一致）
  citation_faithful  引用忠实率：答案引用条文可解析 且 答案数字全部可溯源
  wrong_commitment   错承诺条数（红线，目标 0）
  acl_zero_recall    越权召回条数（红线，目标 0）
  P95 分段           按 span 表统计（nearest-rank，口径见 src/observability.py）
  token 分布         provider 估算口径，见 est_tokens

用法：
  python -m src.cli all                      # 先造出数据与校验运行
  python evals/judge.py --write-report
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.agent import ComplianceAgent  # noqa: E402
from src.config import Config  # noqa: E402
from src.db import DB_BACKEND_SQLITE, connect  # noqa: E402
from src.guard import numbers_in  # noqa: E402
from src.observability import collect_all_spans, stats_for, token_distribution  # noqa: E402
from src.util import sha256_hex  # noqa: E402

GOLDEN = ROOT / "evals" / "golden_set_v1.jsonl"
# 只有这些答案措辞代表「系统在单方给最终数额承诺」
COMMITMENT_WORDS = ("你应得", "应付金额为", "最终应付", "公司须支付", "必须支付")


@dataclass
class ItemResult:
    item_id: str
    tier: str
    intent_ok: bool
    hit5: bool | None
    mrr: float | None
    tool_ok: bool | None
    faithful: bool
    commitment: bool
    acl_leak: bool
    gate: str
    detail: str = ""
    numbers_bad: list[str] = field(default_factory=list)
    docs_hit: list[str] = field(default_factory=list)
    docs_missed: list[str] = field(default_factory=list)


def load_golden(path: Path = GOLDEN) -> list[dict]:
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            items.append(json.loads(line))
    return items


def _findings_for(conn: sqlite3.Connection, run_id: str, emp: str, rule: str,
                  work_date: str | None, period: str | None) -> list[sqlite3.Row]:
    where = ["run_id = ?", "emp_id = ?", "rule_id = ?"]
    params: list = [run_id, emp, rule]
    if work_date:
        where.append("work_date = ?")
        params.append(work_date)
    if period:
        where.append("(period_key = ? OR substr(work_date,1,7) = ?)")
        params += [period, period]
    return conn.execute(
        f"SELECT severity, metric_json, citation_ids, work_date, period_key FROM finding "
        f"WHERE {' AND '.join(where)}", params
    ).fetchall()


def check_numeric(conn: sqlite3.Connection, run_id: str, gold: dict) -> tuple[bool, str]:
    """把引擎结论与手工推导的标准答案逐字段比对。"""
    emp = gold.get("emp")
    rule = gold.get("expect_rule")
    if not emp or not rule:
        return True, "无数值型标准答案"
    rows = _findings_for(conn, run_id, emp, rule, gold.get("work_date"), gold.get("period"))
    if not rows:
        return False, f"未命中 {rule}@{emp}"
    if "count_holiday_days" in gold:
        got = len(conn.execute(
            "SELECT 1 FROM finding WHERE run_id=? AND emp_id=? AND rule_id='OT-D03'",
            (run_id, emp)).fetchall())
        want = gold["count_holiday_days"]
        return got == want, f"法定当天条数 期望{want} 实得{got}"
    if "count_restdays" in gold:
        got = len(conn.execute(
            "SELECT 1 FROM finding WHERE run_id=? AND emp_id=? AND rule_id='OT-D02'",
            (run_id, emp)).fetchall())
        return got == gold["count_restdays"], f"休息日条数 期望{gold['count_restdays']} 实得{got}"

    metric = json.loads(rows[0]["metric_json"])
    bad = []
    if "severity" in gold and rows[0]["severity"] != gold["severity"]:
        bad.append(f"severity 期望{gold['severity']} 实得{rows[0]['severity']}")
    for key, want in gold.items():
        if key in ("intent", "emp", "expect_rule", "work_date", "period", "severity",
                   "expect_docs", "gate", "must_not_contain_final_amount", "count_holiday_days",
                   "count_restdays", "expect_denied", "expect_own_allowed", "numeric_backed"):
            continue
        if key in ("minutes_extension", "minutes_holiday", "minutes_restdays", "minutes_over",
                   "expected_minutes", "minutes_worked", "counted_minutes", "estimate_cents",
                   "rate_permille", "minutes_night", "days_present", "authorized_final",
                   "ambiguous_day_type"):
            got = metric.get(key)
            if got != want:
                bad.append(f"{key} 期望{want} 实得{got}")
        elif key == "effective_regime" and metric.get("effective_regime") != want:
            bad.append(f"effective_regime 期望{want} 实得{metric.get('effective_regime')}")
        elif key == "counting_scope" and metric.get("counting_scope") != want:
            bad.append(f"counting_scope 期望{want} 实得{metric.get('counting_scope')}")
        elif key == "region_divergence" and metric.get("region_divergence") != want:
            bad.append("region_divergence 不匹配")
    return (not bad), ("数值与手工推导一致" if not bad else "；".join(bad))


def judge(conn: sqlite3.Connection, cfg: Config, items: list[dict],
          *, run_id: str | None = None, verbose: bool = False) -> dict:
    run_id = run_id or conn.execute(
        "SELECT run_id FROM run ORDER BY started_at DESC LIMIT 1").fetchone()["run_id"]
    agent = ComplianceAgent(conn, cfg)
    corpus_ids = {r["doc_id"] for r in conn.execute("SELECT doc_id FROM kb_doc").fetchall()}
    results: list[ItemResult] = []

    for it in items:
        gold = it["gold"]
        ans = agent.ask(it["question"], actor_emp_id=it["actor"])
        intent_ok = ans.intent == gold.get("intent", ans.intent)

        expect_docs = gold.get("expect_docs", [])
        hit5 = mrr = None
        docs_hit, docs_missed = [], []
        if expect_docs:
            top = [c.doc_id for c in ans.citations][: cfg.retrieval_top_k]
            hits = [d for d in expect_docs if d in top]
            docs_hit, docs_missed = hits, [d for d in expect_docs if d not in top]
            hit5 = bool(hits)
            ranks = []
            for d in expect_docs:
                if d in top:
                    ranks.append(1.0 / (top.index(d) + 1))
            mrr = sum(ranks) / len(expect_docs) if expect_docs else 0.0

        tool_ok = None
        if gold.get("expect_rule") or gold.get("count_holiday_days"):
            tool_ok, _ = check_numeric(conn, run_id, gold)

        allowed = set(ans.allowed_numbers)
        bad_numbers = [n for n in numbers_in(ans.answer) if n not in allowed]
        citations_ok = all(c.doc_id in corpus_ids for c in ans.citations)
        faithful = citations_ok and not bad_numbers

        commitment = any(w in ans.answer for w in COMMITMENT_WORDS)
        if gold.get("must_not_contain_final_amount") or gold.get("gate") == "EXPLAIN_ONLY":
            if ans.gate_decision == "ANSWERED" and any(ch.isdigit() for ch in ans.answer):
                # 重大事项却给了带数字的确定答复 -> 计为错承诺
                commitment = True

        leak = False
        for denied in gold.get("expect_denied", []):
            if denied in ans.retrieval["candidates"] or denied in ans.retrieval["hit_doc_ids"]:
                leak = True
        if gold.get("expect_own_allowed"):
            own = f"personnel.payroll.{it['actor']}"
            if own not in ans.retrieval["candidates"]:
                leak = True  # 本人条目被误伤也是权限实现错误

        res = ItemResult(
            item_id=it["id"], tier=it["tier"], intent_ok=intent_ok, hit5=hit5, mrr=mrr,
            tool_ok=tool_ok, faithful=faithful, commitment=commitment, acl_leak=leak,
            gate=ans.gate_decision, numbers_bad=bad_numbers,
            docs_hit=docs_hit, docs_missed=docs_missed,
            detail=f"q={it['question']} intent={ans.intent}/{gold.get('intent')}",
        )
        if gold.get("gate") and ans.gate_decision != gold["gate"]:
            res.detail += f" 门禁 期望{gold['gate']} 实得{ans.gate_decision}"
            if gold["gate"] == "REFUSED_ACL":
                res.acl_leak = True
        results.append(res)
        if verbose:
            print(f"{it['id']:6s} {it['tier']:9s} intent={int(intent_ok)} "
                  f"tool={tool_ok} faithful={int(faithful)} gate={ans.gate_decision} "
                  f"{'| ' + res.detail if not (intent_ok and (tool_ok is not False)) else ''}")

    n = len(results)
    retrieval_items = [r for r in results if r.hit5 is not None]
    numeric_items = [r for r in results if r.tool_ok is not None]
    seg_stats = stats_for(collect_all_spans(conn))
    tok_rows = conn.execute("SELECT tokens_in_est, tokens_out_est FROM question_log").fetchall()

    summary = {
        "run_id": run_id,
        "n_items": n,
        "intent_top1": f"{sum(r.intent_ok for r in results)}/{n}",
        "hit_at_5": (f"{sum(r.hit5 for r in retrieval_items)}/{len(retrieval_items)}"
                     if retrieval_items else "n/a"),
        "mrr": (round(sum(r.mrr or 0.0 for r in retrieval_items) / len(retrieval_items), 3)
                if retrieval_items else None),
        "tool_success": (f"{sum(bool(r.tool_ok) for r in numeric_items)}/{len(numeric_items)}"
                         if numeric_items else "n/a"),
        "citation_faithful": f"{sum(r.faithful for r in results)}/{n}",
        "wrong_commitment": sum(r.commitment for r in results),
        "acl_leak": sum(r.acl_leak for r in results),
        "gate_distribution": _count_by([r.gate for r in results]),
        "tier_distribution": _count_by([r.tier for r in results]),
        "failures": [
            {"id": r.item_id, "why": (f"intent 不匹配 " if not r.intent_ok else "")
                       + (f"hit@5 缺 {r.docs_missed} " if r.hit5 is False else "")
                       + (f"数值不符 " if r.tool_ok is False else "")
                       + (f"数字不可溯 {r.numbers_bad[:4]} " if not r.faithful else "")
                       + (f"门禁 {r.gate} {r.detail}" if r.acl_leak or r.commitment else "")}
            for r in results
            if not (r.intent_ok and r.faithful and r.hit5 is not False and r.tool_ok is not False
                    and not r.acl_leak and not r.commitment)
        ],
        "segments": [{"segment": s.segment, "n": s.n, "p50_ms": _ms(s.p50_us),
                      "p95_ms": _ms(s.p95_us), "p99_ms": _ms(s.p99_us), "max_ms": _ms(s.max_us)}
                     for s in seg_stats],
        "tokens_in": token_distribution([int(r["tokens_in_est"]) for r in tok_rows]),
        "tokens_out": token_distribution([int(r["tokens_out_est"]) for r in tok_rows]),
        "golden_sha256": sha256_hex(GOLDEN.read_bytes()),
    }
    _persist(conn, run_id, results)
    return summary


def _ms(us: int) -> str:
    return f"{us / 1000:.1f}"


def _count_by(seq: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in seq:
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _persist(conn: sqlite3.Connection, run_id: str, results: list[ItemResult]) -> None:
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM eval_result")
        for r in results:
            for metric, passed in (("intent_top1", r.intent_ok), ("hit_at_5", r.hit5),
                                   ("tool_success", r.tool_ok), ("citation_faithful", r.faithful),
                                   ("wrong_commitment", not r.commitment),
                                   ("acl_zero_recall", not r.acl_leak)):
                if passed is None:
                    continue
                conn.execute(
                    "INSERT INTO eval_result(run_label, item_id, tier, metric, passed, observed, "
                    "expected, detail) VALUES(?,?,?,?,?,?,?,?)",
                    (run_id, r.item_id, r.tier, metric, int(bool(passed)), str(passed),
                     "true", r.detail[:500]),
                )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


REPORT_TMPL = """# 评测结果（F-011 / F-012 / F-013）

> 本文件由 `python evals/judge.py --write-report` 生成，**全部为实测值**。
> 实测环境：{env_note}
> 评测集指纹：`golden_set_v1.jsonl` sha256 = `{golden_sha256}`（{n_items} 条，三档：{tier_distribution}）
> 对应校验运行：`{run_id}`

## 一、指标

| 指标 | 实测 | 口径 |
|---|---|---|
| 意图 Top-1 | **{intent_top1}** | 首次归类即等于标准答案 intent |
| Hit@5 | **{hit_at_5}** | 期望条文进入 top-5 即算命中（至少一条） |
| MRR | **{mrr}** | 期望条文排名的倒数均值，未进 top-5 记 0 |
| 数值工具首次成功率 | **{tool_success}** | 结论存在且每个字段等于手工推导值 |
| 引用忠实率 | **{citation_faithful}** | 引用条目可在知识库解析 **且** 答案数字全部落在可溯源白名单 |
| 错承诺条数（红线） | **{wrong_commitment}** | 重大事项由系统单方给出最终数额的条数，目标 0 |
| 越权召回条数（红线） | **{acl_leak}** | 无权主体召回到他人薪酬/考勤条目的条数，目标 0 |

门禁分布：{gate_distribution}

## 二、分段耗时（实测，单位 ms；口径 nearest-rank 百分位，见 `src/observability.py`）

| segment | n | P50 | P95 | P99 | max |
|---|---|---|---|---|---|
{segments_rows}

端到端与检索段的 P95 是否达标属于**设计值对照**，见 `docs/口径声明.md`；
本表只陈述本次实测，不代表生产条件。
**`n` 的口径要说清**：分段耗时取自数据库 `span` 表的**累计**样本（历次评测与界面提问都往这张表写），
所以同一份库上反复跑评测，`n` 会按题目数递增、P95 会随之漂移。
要一个**封闭样本**的数字（fresh 库、单次评测、n=题目数），去干净环境跑一次，
见 `reports/干净环境复跑.md` 第四节。

## 三、每问 token 分布（估算口径）

| 方向 | n | P50 | P95 | max | mean | 合计 |
|---|---|---|---|---|---|---|
| 输入 | {tin_n} | {tin_p50} | {tin_p95} | {tin_max} | {tin_mean} | {tin_sum} |
| 输出 | {tout_n} | {tout_p50} | {tout_p95} | {tout_max} | {tout_mean} | {tout_sum} |

token 口径：CJK 字符记 1、连续 ASCII 词记 1 的**估算**；离线 stub 无 provider 计数，
所以这里不能当账单用。用云 API 后须替换为 provider 返回的真实 usage 再写成本结论。

## 四、未通过条目

{failures_rows}

## 五、复现

```bash
cp .env.example .env
python -m src.cli all
python evals/judge.py --write-report
```
"""


def write_report(summary: dict, path: Path) -> None:
    seg = "\n".join(
        f"| {s['segment']} | {s['n']} | {s['p50_ms']} | {s['p95_ms']} | {s['p99_ms']} | {s['max_ms']} |"
        for s in summary["segments"]
    ) or "| （无 span 记录） | | | | | |"
    fails = summary["failures"]
    fails_rows = "\\n".join(f"- `{f['id']}`：{f['why'] or '（无说明）'}" for f in fails) if fails else "无"
    tin, tout = summary["tokens_in"], summary["tokens_out"]
    path.write_text(REPORT_TMPL.format(
        env_note=summary["env_note"], golden_sha256=summary["golden_sha256"][:16] + "…",
        n_items=summary["n_items"], tier_distribution=summary["tier_distribution"],
        run_id=summary["run_id"], intent_top1=summary["intent_top1"],
        hit_at_5=summary["hit_at_5"], mrr=summary["mrr"], tool_success=summary["tool_success"],
        citation_faithful=summary["citation_faithful"], wrong_commitment=summary["wrong_commitment"],
        acl_leak=summary["acl_leak"], gate_distribution=summary["gate_distribution"],
        segments_rows=seg, failures_rows=fails_rows,
        tin_n=tin["n"], tin_p50=tin["p50"], tin_p95=tin["p95"], tin_max=tin["max"],
        tin_mean=tin["mean"], tin_sum=tin["sum"],
        tout_n=tout["n"], tout_p50=tout["p50"], tout_p95=tout["p95"], tout_max=tout["max"],
        tout_mean=tout["mean"], tout_sum=tout["sum"],
    ), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="判分器：对评测集逐条打分")
    ap.add_argument("--db", default=None, help="SQLite 路径，默认取 .env")
    ap.add_argument("--write-report", action="store_true", help="写 reports/评测结果.md")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--label", default="local")
    args = ap.parse_args(argv)

    cfg = Config.load(args.db and Path(args.db).parent / ".env")
    if args.db:
        # 显式 --db 路径只可能是 SQLite 文件；不要把本机 .env 的 PostgreSQL 后端带进来。
        cfg.db_backend = DB_BACKEND_SQLITE
        cfg.db_path = Path(args.db)
    if cfg.db_backend == DB_BACKEND_SQLITE and not cfg.db_path.is_file():
        print(f"数据库不存在：{cfg.db_path}\n先跑 `python -m src.cli all`", file=sys.stderr)
        return 2
    conn = connect(cfg)
    if conn.execute("SELECT COUNT(*) AS c FROM run").fetchone()["c"] == 0:
        print("库里没有校验运行，先执行 `python -m src.cli all`", file=sys.stderr)
        return 2

    items = load_golden()
    summary = judge(conn, cfg, items, verbose=args.verbose)
    import platform

    summary["env_note"] = (f"{platform.system()} {platform.release()} / Python "
                           f"{platform.python_version()} / provider={cfg.llm_provider} "
                           f"backend={cfg.embedding_backend} / label={args.label}")
    print(json.dumps({k: v for k, v in summary.items()
                      if k not in ("segments", "failures")}, ensure_ascii=False, indent=2))
    print(f"\n分段耗时：{summary['segments']}")
    if summary["failures"]:
        print(f"未通过 {len(summary['failures'])} 条：")
        for f in summary["failures"]:
            print(f"  - {f['id']}: {f['why']}")
    if args.write_report:
        cfg.reports_dir.mkdir(parents=True, exist_ok=True)
        write_report(summary, cfg.reports_dir / "评测结果.md")
        print(f"\n报告已写入 {cfg.reports_dir / '评测结果.md'}")

    if summary["wrong_commitment"] or summary["acl_leak"]:
        print("\n红线未通过：错承诺或越权召回不为 0", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
