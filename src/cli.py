"""命令行入口：一条命令跑通「生成 -> 导入 -> 建库 -> 校验 -> 举证包 -> 问答 -> 评测」。

README 的复跑路径就是这里的 `python -m src.cli all`。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import ENGINE_VERSION
from .agent import ComplianceAgent
from .anomaly import review_backlog, rule_hit_counts, severity_rollup, write_anomaly_report
from .config import Config
from .db import connect, count, get_meta, init_db, set_meta
from .evidence import export_package, input_fingerprint, verify_chain
from .ingest import import_csv_file
from .kb import build_kb, citation_ids_missing
from .rules.citations import ALL_CITATIONS
from .rules.holidays import HolidayCalendar
from .rules.rulepack import RULE_CATALOG

INGEST_ORDER = ("org", "employee", "schedule", "punch", "leave", "trip", "correction")
# 供演示脚本自洽性检查（A12）使用：命令名必须与 build_parser 中的注册保持一致
SUBCOMMAND_NAMES = ("init", "gen", "ingest", "kb", "check", "report", "export", "ask",
                    "verify", "covers", "start", "stop", "status", "all")
KIND_BY_FILE = {
    "org.csv": "org",
    "employee.csv": "employee", "schedule.csv": "schedule", "punch.csv": "punch",
    "leave.csv": "leave", "trip.csv": "trip", "correction.csv": "correction",
}


def _cfg(args: argparse.Namespace) -> Config:
    return Config.load(getattr(args, "env", None))


def cmd_init(args) -> int:
    cfg = _cfg(args)
    cfg.ensure_dirs()
    conn = connect(cfg.db_path)
    init_db(conn)
    print(f"已初始化 SQLite：{cfg.db_path}（schema v{get_meta(conn, 'schema_version')}）")
    return 0


def cmd_gen(args) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "data" / "generator"))
    from make_synthetic import write  # type: ignore

    manifest = write(args.seed)
    total = sum(v["rows"] for v in manifest["files"].values())
    print(f"合成数据生成完成：seed={args.seed}，{len(manifest['files'])} 个文件 / {total} 行 -> data/raw")
    return 0


def cmd_ingest(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    init_db(conn)
    root = Path(args.dir)
    if not root.is_dir():
        print(f"目录不存在：{root}（先跑 python -m src.cli gen）", file=sys.stderr)
        return 2
    files = {f.name: f for f in sorted(root.glob("*.csv"))}
    unknown = set(files) - set(KIND_BY_FILE)
    if unknown:
        print(f"跳过未识别文件：{sorted(unknown)}", file=sys.stderr)
    for kind in INGEST_ORDER:
        for name, path in files.items():
            if KIND_BY_FILE.get(name) != kind:
                continue
            res = import_csv_file(conn, cfg, path, kind=kind, created_at=args.imported_at)
            print(f"[{kind:10s}] {name:16s} 行 {res.rows_seen:5d} 入库 {res.rows_accepted:5d} "
                  f"拒收 {res.rows_rejected:3d} 质量问题 {len(res.issues):3d} "
                  f"sha256={res.sha256[:12]}…")
    print(f"员工 {count(conn, 'employee')} / 打卡 {count(conn, 'punch')} / "
          f"请假 {count(conn, 'leave_record')} / 出差 {count(conn, 'trip_record')} / "
          f"补卡 {count(conn, 'punch_correction')} / 排班 {count(conn, 'shift_plan')} / "
          f"质量记录 {count(conn, 'ingest_issue')}")
    return 0


def cmd_kb(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    init_db(conn)
    res = build_kb(conn)
    missing = citation_ids_missing(conn, ALL_CITATIONS)
    print(f"知识库构建完成：条目 {res.docs}（其中个人数据 {res.personnel_docs}）、"
          f"term 索引 {res.terms}、语料 sha256={res.corpus_sha256[:12]}…")
    if missing:
        print(f"规则引用但库中缺失的条文 id：{missing}", file=sys.stderr)
        return 3
    print("规则引用的全部条文 id 均可在知识库中定位（A2 前置检查通过）")
    return 0


def cmd_check(args) -> int:
    from .engine import run_check

    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    init_db(conn)
    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end)
    emp_ids = args.emp.split(",") if args.emp else None
    out = run_check(conn, cfg, start=start, end=end, emp_ids=emp_ids,
                    notes=args.notes or "cli check")
    print(f"run_id={out.run_id}")
    print(f"  规则版本 {cfg.rule_pack_id} / 引擎 {ENGINE_VERSION}")
    print(f"  员工 {out.employees} 人 / 工作日事实 {out.days} 条 / 结论 {len(out.findings)} 条")
    counts = out.counts_by_severity()
    print(f"  分级：明显违规 {counts['VIOLATION']}，需复核 {counts['REVIEW']}，可申辩 {counts['DEFENSIBLE']}")
    print(f"  输入指纹 {out.input_fingerprint[:20]}…")
    print(f"  结论摘要 {out.conclusion_digest[:20]}…")
    print(f"  耗时 {out.elapsed_us / 1000:.1f} ms")
    return 0


def cmd_report(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    run_id = args.run or get_meta(conn, "last_run_id")
    if not run_id:
        print("尚无校验运行，请先 `python -m src.cli check`", file=sys.stderr)
        return 2
    path = write_anomaly_report(conn, cfg, run_id)
    from .anomaly import build_anomalies

    items = build_anomalies(conn, run_id)
    print(f"异常报表：{path}（{len(items)} 条异常，分级汇总 {severity_rollup(items)}）")
    for row in rule_hit_counts(conn, run_id)[:12]:
        print(f"  {row['rule_id']:10s} {row['severity']:10s} x{row['count']}")
    print(f"待复核队列：{review_backlog(conn)}")
    return 0


def cmd_export(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    run_id = args.run or get_meta(conn, "last_run_id")
    if not run_id:
        print("尚无校验运行，请先 `python -m src.cli check`", file=sys.stderr)
        return 2
    manifest = export_package(conn, cfg, run_id)
    print(f"举证包：{manifest['package_zip']}")
    print(f"  三元组 {json.dumps(manifest['triple'], ensure_ascii=False, sort_keys=True)}")
    print(f"  审计链 {manifest['chain_verification']}")
    print(f"  manifest sha256={manifest['manifest_sha256'][:20]}… 结论 {manifest['counts']['findings']} 条")
    return 0


def cmd_ask(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    init_db(conn)
    agent = ComplianceAgent(conn, cfg)
    ans = agent.ask(args.question, actor_emp_id=args.actor)
    print(f"[{ans.intent}/{ans.tier}] gate={ans.gate_decision} "
          f"置信 {ans.confidence_permille}‰ 证据覆盖 {ans.evidence_coverage_permille}‰ "
          f"耗时 {ans.elapsed_us / 1000:.1f}ms provider={ans.provider}"
          f"{'（离线降级）' if ans.degraded else ''}")
    print(ans.answer)
    print("--- 引用 ---")
    print(ans.citation_markdown)
    if ans.violations:
        print("--- 门禁记录 ---")
        for v in ans.violations:
            print(f"  · {v}")
    print(f"--- 检索候选 {len(ans.retrieval['candidates'])} 条，命中 {ans.retrieval['hit_doc_ids']}")
    return 0


def cmd_verify(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    chain = verify_chain(conn, cfg)
    print(f"审计链：{chain.length} 条，{'完整' if chain.ok else f'在 seq={chain.broken_at_seq} 断裂：{chain.reason}'}")
    return 0 if chain.ok else 4


def cmd_covers(args) -> int:
    """打印判据分支覆盖情况，供 reports/ 直接引用。"""
    cfg = _cfg(args)
    conn = connect(cfg.db_path)
    hit = {r["rule_id"]: int(r["c"]) for r in conn.execute(
        "SELECT rule_id, COUNT(*) AS c FROM finding GROUP BY rule_id").fetchall()}
    cal = HolidayCalendar.load()
    print(f"规则包 {cfg.rule_pack_id}：{len(RULE_CATALOG)} 条规则，覆盖年度 {cal.covered_years}")
    for m in RULE_CATALOG:
        mark = "命中" if hit.get(m.rule_id) else "未命中"
        print(f"  {m.rule_id:10s} [{mark}] {m.name_zh}（{m.tier}/{m.severity_kind}）")
    untouched = [m.rule_id for m in RULE_CATALOG if not hit.get(m.rule_id)]
    print(f"未命中规则 {len(untouched)} 条：{untouched}")
    return 0


def cmd_start(args) -> int:
    from .service_cli import main_start

    return main_start(_service_argv(args, restart_flags=True))


def cmd_stop(args) -> int:
    from .service_cli import main_stop

    return main_stop(_service_argv(args, force_flags=True))


def cmd_status(args) -> int:
    from .service_cli import main_stop

    return main_stop(_service_argv(args) + ["--status"])


def _service_argv(args, *, restart_flags: bool = False, force_flags: bool = False) -> list[str]:
    argv: list[str] = []
    if getattr(args, "config", None):
        argv += ["--config", str(args.config)]
    if getattr(args, "only", ""):
        argv += ["--only", str(args.only)]
    if getattr(args, "json", False):
        argv.append("--json")
    if restart_flags and getattr(args, "no_restart", False):
        argv.append("--no-restart")
    if force_flags and getattr(args, "force", False):
        argv.append("--force")
    return argv


def cmd_all(args) -> int:
    ns = argparse.Namespace(env=args.env, seed=args.seed, dir="data/raw",
                            imported_at="2026-10-06T09:00:00+08:00",
                            start=args.start, end=args.end, emp="", notes="cli all",
                            run="", question="", actor="", db="")
    for fn, name in ((cmd_init, "init"), (cmd_gen, "gen"), (cmd_ingest, "ingest"),
                     (cmd_kb, "kb"), (cmd_check, "check"), (cmd_report, "report"),
                     (cmd_export, "export")):
        print(f"\n=== {name} ===")
        if name == "init":
            if fn(ns) != 0:
                return 1
        else:
            if fn(ns) != 0:
                return 1
    print("\n=== 下一步 ===")
    print("  python -m src.cli ask \"国庆当天上班加班费怎么算\" --as E004")
    print("  python -m pytest tests/ -q")
    print("  python evals/judge.py --write-report")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m src.cli",
                                 description="工时合规校验与制度问答 Agent（合成数据 + 公开法条基准）")
    ap.add_argument("--env", default=None, help=".env 路径，默认项目根 .env")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="建库"); p.set_defaults(fn=cmd_init)
    p = sub.add_parser("gen", help="生成合成数据"); p.add_argument("--seed", type=int, default=20260106)
    p.set_defaults(fn=cmd_gen)
    p = sub.add_parser("ingest", help="导入 CSV（含质量门禁）")
    p.add_argument("--dir", default="data/raw"); p.add_argument("--imported-at", default=None,
                                                                dest="imported_at")
    p.set_defaults(fn=cmd_ingest)
    p = sub.add_parser("kb", help="构建知识库与检索索引"); p.set_defaults(fn=cmd_kb)
    p = sub.add_parser("check", help="运行确定性合规校验")
    p.add_argument("--start", default="2025-09-01"); p.add_argument("--end", default="2026-04-30")
    p.add_argument("--emp", default="", help="逗号分隔员工 id，默认全部")
    p.add_argument("--notes", default=""); p.set_defaults(fn=cmd_check)
    p = sub.add_parser("report", help="导出异常报表 CSV")
    p.add_argument("--run", default=""); p.set_defaults(fn=cmd_report)
    p = sub.add_parser("export", help="导出举证包（三元组 + 审计链）")
    p.add_argument("--run", default=""); p.set_defaults(fn=cmd_export)
    p = sub.add_parser("ask", help="问一答（走同一条 API 链路）")
    p.add_argument("question"); p.add_argument("--as", dest="actor", default="E001")
    p.set_defaults(fn=cmd_ask)
    p = sub.add_parser("verify", help="校验审计 hash 链"); p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("covers", help="规则命中覆盖表"); p.set_defaults(fn=cmd_covers)
    for name, fn, needs in (("start", cmd_start, "restart"), ("stop", cmd_stop, "force"),
                            ("status", cmd_status, "")):
        q = sub.add_parser(name, help={
            "start": "一键启动服务（检测到在跑则先停后起）",
            "stop": "一键优雅停止服务",
            "status": "只看服务状态，不动任何东西",
        }[name])
        q.add_argument("--config", default=None, help="服务清单，默认 config/services.json")
        q.add_argument("--only", default="", help="逗号分隔服务名")
        q.add_argument("--json", action="store_true")
        if needs == "restart":
            q.add_argument("--no-restart", action="store_true")
        if needs == "force":
            q.add_argument("--force", action="store_true")
        q.set_defaults(fn=fn)
    p = sub.add_parser("all", help="一键复跑：init->gen->ingest->kb->check->report->export")
    p.add_argument("--seed", type=int, default=20260106)
    p.add_argument("--start", default="2025-09-01"); p.add_argument("--end", default="2026-04-30")
    p.set_defaults(fn=cmd_all)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
