"""性能探针：把「优化前后」的耗时与 SQL 语句数变成一条可复跑的命令。

为什么要有这个工具：优化方案的验收条件写的是 SQL 语句数与整轮耗时。
这些数字若只存在于一次性手工测量里，就等于把结论建立在不可复跑的证据上。
探针在**数据库副本**上测量：演示库不受影响，也不依赖网络与模型。

两种口径要分清：
  - 批量路径 = 生产代码实际走的（每员工整段区间预取一次，逐日纯计算，落库 executemany）；
  - 参考实现 = 每员工每工作日各预取一次（O-1 改造前的 N+1 形状）。

计时与计数分两趟测：trace_callback 本身有开销，混在一趟里会把耗时测高。
Windows 上单次墙钟抖动可达数倍，所以计时取多次采样中位数并同时给出全部样本。

用法：
  python tools/perf_probe.py                                  # 默认 2025-09-01..2026-04-30
  python tools/perf_probe.py --reference --repeat 5
  python tools/perf_probe.py --json reports/性能探针.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import ENGINE_VERSION  # noqa: E402
from src.config import Config  # noqa: E402
from src.db import connect, init_db, transaction  # noqa: E402
from src.engine import load_employees, run_check  # noqa: E402
from src.evidence import export_package  # noqa: E402
from src.rules.dayfacts import build_day_facts  # noqa: E402
from src.rules.holidays import HolidayCalendar  # noqa: E402

DEFAULT_START = date(2025, 9, 1)
DEFAULT_END = date(2026, 4, 30)


class SqlCounter:
    """用 trace_callback 数 SQL 语句：比读日志或猜代码路径可靠，且不需要改生产代码。"""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, statement: str) -> None:
        if statement.strip():
            self.n += 1


def _copy_db(cfg: Config, tmp_dir: Path) -> tuple[Config, object]:
    """在副本上测量：口径（规则包/地域/阈值/持久化等级）沿用同一个 `.env`。"""
    src = cfg.db_path
    if not Path(src).exists():
        raise SystemExit(f"数据库不存在：{src}（请先 `python -m src.cli all`）")
    dst = tmp_dir / "probe.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        if Path(str(src) + suffix).exists():
            shutil.copy(str(src) + suffix, str(dst) + suffix)
    probe_cfg = Config.load(WCA_DB_PATH=str(dst), WCA_PACKAGES_DIR=str(tmp_dir / "packages"),
                            WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25")
    conn = connect(dst, probe_cfg.sqlite_synchronous)
    init_db(conn)
    probe_cfg.ensure_dirs()
    return probe_cfg, conn


def _timing(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"median_ms": round(statistics.median(s), 1), "min_ms": round(s[0], 1),
            "max_ms": round(s[-1], 1), "samples_ms": [round(x, 1) for x in samples]}


def measure_batch(conn, cfg: Config, start: date, end: date, repeat: int) -> dict:
    samples = []
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        run_check(conn, cfg, start=start, end=end, notes="perf probe")
        samples.append((time.perf_counter() - t0) * 1000)

    counter = SqlCounter()                      # 计数单独一趟，trace 开销不混进耗时
    conn.set_trace_callback(counter)
    counted = run_check(conn, cfg, start=start, end=end, notes="perf probe (counted)")
    conn.set_trace_callback(None)

    spans = {
        r["segment"]: round(int(r["total_us"]) / 1000, 1)
        for r in conn.execute(
            "SELECT segment, SUM(duration_us) AS total_us FROM span WHERE qid = ? "
            "GROUP BY segment ORDER BY segment", (counted.run_id,)).fetchall()
    }
    out = {"sql_statements": counter.n,
           "employees": counted.employees, "days": counted.days,
           "findings": len(counted.findings), "counts": counted.counts,
           "conclusion_digest": counted.conclusion_digest,
           "input_fingerprint": counted.input_fingerprint,
           "rule_pack": cfg.rule_pack_id, "engine": ENGINE_VERSION,
           "spans_ms": spans}
    out.update(_timing(samples))
    return out


def measure_reference(conn, cfg: Config, start: date, end: date, repeat: int) -> dict:
    """参考实现：每员工每工作日各预取一次（N+1 形状），只算事实不落库。"""
    calendar = HolidayCalendar.load()
    employees = load_employees(conn)
    emp_count = len(employees)
    day_count = (end - start).days + 1

    samples = []
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        for emp in employees:
            cur = start
            while cur <= end:
                build_day_facts(conn, cfg, emp["emp_id"], cur, calendar)
                cur += timedelta(days=1)
        samples.append((time.perf_counter() - t0) * 1000)

    counter = SqlCounter()
    conn.set_trace_callback(counter)
    build_day_facts(conn, cfg, employees[0]["emp_id"], start, calendar)   # 单人单日：测形状
    conn.set_trace_callback(None)
    per_call = counter.n
    out = {"sql_per_employee_day": per_call,
           "sql_extrapolated": per_call * emp_count * day_count,
           "employees": emp_count, "days": day_count}
    out.update(_timing(samples))
    return out


AMP_MARKER = "amplify-stress-only"


def measure_export(conn, cfg: Config, repeat: int, amplify: int) -> dict:
    """举证包导出耗时。amplify>0 时把结论**复制**到该行数再测一次（只测导出，不改判据语义）。

    复制行不是真实员工，所以这一列只回答「导出这段代码在 1,000 行下放不放得住」，
    不能当成 1,000 个员工的场景规模。复制行用 rule_version 打标，测完即删。
    """
    run_id = conn.execute(
        "SELECT run_id FROM run ORDER BY started_at DESC LIMIT 1").fetchone()["run_id"]
    base_rows = conn.execute("SELECT COUNT(*) AS c FROM finding WHERE run_id = ?",
                             (run_id,)).fetchone()["c"]

    def timed() -> dict:
        samples = []
        for _ in range(max(1, repeat)):
            t0 = time.perf_counter()
            export_package(conn, cfg, run_id)
            samples.append((time.perf_counter() - t0) * 1000)
        return _timing(samples)

    out = {"run_id": run_id, "rows": base_rows, "native": timed()}
    if amplify > base_rows:
        source_rows = [r["finding_id"] for r in conn.execute(
            "SELECT finding_id FROM finding WHERE run_id = ? ORDER BY finding_id",
            (run_id,)).fetchall()]
        to_add = amplify - base_rows
        with transaction(conn):
            for offset in range(to_add):
                conn.execute(
                    "INSERT INTO finding(run_id, rule_id, rule_version, emp_id, work_date, period_key, "
                    "severity, metric_json, citation_ids, source_refs, explanation) "
                    "SELECT run_id, rule_id, ?, emp_id, work_date, period_key, severity, metric_json, "
                    "citation_ids, source_refs, explanation FROM finding WHERE finding_id = ?",
                    (AMP_MARKER, source_rows[offset % len(source_rows)]))
        out["amplified"] = {"rows_target": amplify, "rows_added": to_add,
                            "note": "复制行仅用于测导出耗时，不代表真实员工规模"}
        out["amplified"].update(timed())
        with transaction(conn):
            conn.execute("DELETE FROM finding WHERE rule_version = ?", (AMP_MARKER,))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="工时校验批量路径性能探针")
    ap.add_argument("--start", default=DEFAULT_START.isoformat())
    ap.add_argument("--end", default=DEFAULT_END.isoformat())
    ap.add_argument("--reference", action="store_true", help="额外测逐日预取参考实现做对照")
    ap.add_argument("--repeat", type=int, default=3, help="计时采样次数（取中位数）")
    ap.add_argument("--export", action="store_true", help="附带举证包导出耗时")
    ap.add_argument("--amplify", type=int, default=0,
                    help="把结论复制到该行数再测一次导出（只在库副本上做）")
    ap.add_argument("--json", default="", help="把结果写成 JSON 文件")
    args = ap.parse_args(argv)

    cfg = Config.load()
    start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
    with tempfile.TemporaryDirectory(prefix="wca-probe-", ignore_cleanup_errors=True) as tmp:
        probe_cfg, conn = _copy_db(cfg, Path(tmp))
        result = {
            "measured_at": date.today().isoformat(),
            "range": {"start": start.isoformat(), "end": end.isoformat()},
            "db_source": str(cfg.db_path),
            "sqlite_synchronous": probe_cfg.sqlite_synchronous,
            "repeat": max(1, args.repeat),
            "batch": measure_batch(conn, probe_cfg, start, end, args.repeat),
        }
        if args.export:
            result["export"] = measure_export(conn, probe_cfg, args.repeat,
                                              max(args.amplify, 0))
        if args.reference:
            ref = measure_reference(conn, probe_cfg, start, end, args.repeat)
            result["reference_per_day_prefetch"] = ref
            result["comparison"] = {
                "sql_ratio_x": round(ref["sql_extrapolated"]
                                     / max(1, result["batch"]["sql_statements"]), 2),
                "median_elapsed_ratio_x": round(ref["median_ms"]
                                                / max(0.1, result["batch"]["median_ms"]), 2),
            }
        conn.close()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                   encoding="utf-8")
        print(f"已写入 {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
