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
import csv
import json
import math
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
from src.db import DB_BACKEND_POSTGRES, connect, init_db, transaction  # noqa: E402
from src.db_guard import (MigrationSafetyError, assert_connection_is_temporary,  # noqa: E402
                          assert_temporary_database, ensure_config_matches_actual)
from src.engine import load_employees, run_check  # noqa: E402
from src.evidence import export_package  # noqa: E402
from src.ingest import import_csv_file  # noqa: E402
from src.replay import replay  # noqa: E402
from src.rules.dayfacts import build_day_facts  # noqa: E402
from src.rules.holidays import HolidayCalendar  # noqa: E402
from src.rules.rulepack import RULE_PACK_VERSION  # noqa: E402

DEFAULT_START = date(2025, 9, 1)
DEFAULT_END = date(2026, 4, 30)


class SqlCounter:
    """用 trace_callback 数 SQL 语句：比读日志或猜代码路径可靠，且不需要改生产代码。"""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, statement: str) -> None:
        if statement.strip():
            self.n += 1


class CountingConnection:
    """PG 没有 sqlite trace_callback 时的等价计数包装：只用于探针，不改生产代码。"""

    def __init__(self, conn) -> None:
        self._conn = conn
        self.counter = SqlCounter()

    def execute(self, *args, **kwargs):
        self.counter.n += 1
        return self._conn.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        self.counter.n += 1
        return self._conn.executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        self.counter.n += 1
        return self._conn.executescript(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _probe_pg_cfg(pg_url: str, tmp_dir: Path) -> Config:
    """PG 探针配置：只连调用方给的临时库；不复制/写入活动库。"""
    return Config.load(
        env_path=tmp_dir / "none-pg.env",
        WCA_DB_BACKEND=DB_BACKEND_POSTGRES, WCA_DATABASE_URL=pg_url,
        WCA_DB_IDENTITY_PATH=str(tmp_dir / "pg_target.json"),
        WCA_DB_PATH=str(tmp_dir / "unused.sqlite3"),
        WCA_DATA_DIR=str(tmp_dir / "data"), WCA_REPORTS_DIR=str(tmp_dir / "reports"),
        WCA_PACKAGES_DIR=str(tmp_dir / "packages"), WCA_USERS_PATH=str(tmp_dir / "users.json"),
        WCA_UPLOAD_DIR=str(tmp_dir / "uploads"), WCA_REGION_CODE="440300",
        WCA_RULE_PACK=RULE_PACK_VERSION, WCA_LLM_PROVIDER="stub",
        WCA_EMBEDDING_BACKEND="bm25",
    )


def _exit_unless_config_temporary(cfg: Config) -> None:
    """连接前的第一道守卫：配置层判定失败时，连连接都不建立。"""
    try:
        assert_temporary_database(cfg)
    except MigrationSafetyError as exc:
        raise SystemExit(f"拒绝执行：{exc}") from exc


def _exit_unless_connection_temporary(conn, cfg: Config) -> None:
    """连接后的第二道守卫：必须在 init_db / _seed_scale 之前调用。"""
    try:
        actual = assert_connection_is_temporary(conn, cfg)
        ensure_config_matches_actual(cfg, actual)
    except MigrationSafetyError as exc:
        conn.close()
        raise SystemExit(f"拒绝执行：{exc}") from exc


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


DENSE_GROUPS = (
    ("comp_no_approval", 0.20),
    ("missing_punch", 0.15),
    ("overtime_cap", 0.10),
    ("multi_shift_no_plan", 0.10),
    ("device_conflict", 0.05),
    ("no_weekly_rest", 0.05),
)


def _dense_groups(employees: int) -> list[dict]:
    """按固定比例切分合成员工；不按城市/岗位随机，保证每次跑出的注入位置可复现。"""
    out: list[dict] = []
    start = 1
    cumulative = 0
    for name, share in DENSE_GROUPS:
        cumulative += int(employees * share)
        out.append({"group": name, "from": start, "to": cumulative,
                    "count": max(0, cumulative - start + 1)})
        start = cumulative + 1
    out.append({"group": "normal_baseline", "from": start, "to": employees,
                "count": max(0, employees - start + 1)})
    return out


def _build_scale_rows(employees: int, month: str, dense: bool) -> tuple[dict, dict]:
    """生成可复现的规模数据。dense=True 时按组注入异常，不改变任何规则阈值。"""
    if employees <= 0:
        raise ValueError("employees 必须为正整数")
    start = date.fromisoformat(month + "-01")
    end = date(start.year + (start.month == 12), (start.month % 12) + 1, 1) - timedelta(days=1)
    workdays = [start + timedelta(days=i) for i in range((end - start).days + 1)
                if (start + timedelta(days=i)).weekday() < 5]
    orgs = [{"org_id": "ORG-ROOT", "org_name": "性能根组织", "parent_id": ""},
            {"org_id": "ORG-PERF", "org_name": "性能组", "parent_id": "ORG-ROOT"}]
    groups = _dense_groups(employees) if dense else [
        {"group": "normal_baseline", "from": 1, "to": employees, "count": employees}]
    group_of: dict[int, str] = {}
    for g in groups:
        for i in range(g["from"], g["to"] + 1):
            group_of[i] = g["group"]

    emps: list[dict] = []
    schedules: list[dict] = []
    punches: list[dict] = []
    anchor = workdays[0]
    for i in range(1, employees + 1):
        emp_id = f"P{i:04d}"
        group = group_of.get(i, "normal_baseline")
        comp = group == "comp_no_approval"
        emps.append({
            "emp_id": emp_id, "pseudonym": f"性能员工{i}",
            "job_code": "warehouse_shift" if comp else "assembly_line",
            "org_id": "ORG-PERF", "region_code": "440300",
            "worktime_regime": "comprehensive_monthly" if comp else "standard",
            "contract_approved_flex": 1 if comp else 0,
            "normal_hourly_cents": 3200,
        })

        def add_punch(ds: str, hhmm: str, punch_type: str, device: str = "DEV-PERF") -> None:
            punches.append({"emp_id": emp_id, "event_ts": f"{ds}T{hhmm}:00+08:00",
                            "punch_type": punch_type, "device_id": device})

        for d in workdays:
            ds = d.isoformat()
            if group == "multi_shift_no_plan" and d == anchor:
                continue   # 该日不排班，改用 4 段打卡制造 SHIFT-01
            schedules.append({"emp_id": emp_id, "work_date": ds,
                              "planned_start": f"{ds}T09:00:00+08:00",
                              "planned_end": f"{ds}T18:00:00+08:00", "rest_minutes": 60})
            add_punch(ds, "09:00", "in")
            if group == "missing_punch" and d == anchor:
                continue   # 缺下班卡 -> QUAL-01
            if group == "overtime_cap" and d == anchor:
                add_punch(ds, "23:00", "out")   # 延长 420 分钟 -> OT-D01 + CAP-D05
            else:
                add_punch(ds, "18:00", "out")
        if group == "multi_shift_no_plan":
            add_punch(anchor.isoformat(), "09:00", "in")
            add_punch(anchor.isoformat(), "12:00", "out")
            add_punch(anchor.isoformat(), "13:00", "in")
            add_punch(anchor.isoformat(), "18:00", "out")
        if group == "device_conflict":
            add_punch(anchor.isoformat(), "18:00", "out", device="DEV-PERF-B")  # OFF-01
        if group == "no_weekly_rest":
            for offset in (5, 6):   # 同一 ISO 周补周六/周日，制造无休 + 周超时 + 休息日加班
                d = anchor + timedelta(days=offset)
                ds = d.isoformat()
                schedules.append({"emp_id": emp_id, "work_date": ds,
                                  "planned_start": f"{ds}T09:00:00+08:00",
                                  "planned_end": f"{ds}T18:00:00+08:00", "rest_minutes": 60})
                add_punch(ds, "09:00", "in")
                add_punch(ds, "18:00", "out")

    files = {"org.csv": ("org", orgs), "employee.csv": ("employee", emps),
             "schedule.csv": ("schedule", schedules), "punch.csv": ("punch", punches)}
    meta = {"mode": "dense" if dense else "baseline", "employees": employees, "month": month,
            "workdays": len(workdays), "groups": groups,
            "rows": {name: len(rows) for name, (_, rows) in files.items()}}
    return files, meta


def _seed_scale(conn, cfg: Config, employees: int, month: str, *, dense: bool = False) -> dict:
    """生成真实规模的可复现合成数据（仅用于性能；不参与质量门禁判分）。"""
    files, meta = _build_scale_rows(employees, month, dense)
    timings = {}
    db_calls = {}
    for name, (kind, rows) in files.items():
        path = cfg.data_dir / name
        _write_csv(path, rows)
        counted = CountingConnection(conn)
        t0 = time.perf_counter()
        import_csv_file(counted, cfg, path, kind=kind, rel_path=name)
        timings[name] = round((time.perf_counter() - t0) * 1000, 1)
        db_calls[name] = counted.counter.n
    meta["seed_import_ms"] = timings
    meta["seed_db_calls"] = db_calls
    meta["seed_db_calls_total"] = sum(db_calls.values())
    return meta


def _copy_db(cfg: Config, tmp_dir: Path) -> Config:
    """在副本上测量：口径（规则包/地域/阈值/持久化等级）沿用同一个 `.env`。

    只负责生成副本配置并复制文件；临时库判定必须在复制前完成，连接/建表由 main 在
    两道守卫都通过之后再做。
    """
    src = cfg.db_path
    if not Path(src).exists():
        raise SystemExit(f"数据库不存在：{src}（请先 `python -m src.cli all`）")
    dst = tmp_dir / "probe.sqlite3"
    probe_cfg = Config.load(WCA_DB_BACKEND="sqlite", WCA_DB_PATH=str(dst),
                            WCA_PACKAGES_DIR=str(tmp_dir / "packages"),
                            WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25")
    _exit_unless_config_temporary(probe_cfg)
    for suffix in ("", "-wal", "-shm"):
        if Path(str(src) + suffix).exists():
            shutil.copy(str(src) + suffix, str(dst) + suffix)
    return probe_cfg


def _percentile(samples: list[float], pct: int) -> float:
    """nearest-rank 百分位（与 `src/observability.py` 同口径），样本已排序。"""
    if not samples:
        raise ValueError("空样本无法计算百分位")
    rank = max(1, math.ceil(pct / 100 * len(samples)))
    return samples[min(rank - 1, len(samples) - 1)]


def _timing(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"median_ms": round(statistics.median(s), 1),
            "p50_ms": round(_percentile(s, 50), 1),
            "p95_ms": round(_percentile(s, 95), 1),
            "p99_ms": round(_percentile(s, 99), 1),
            "min_ms": round(s[0], 1), "max_ms": round(s[-1], 1),
            "n": len(s), "samples_ms": [round(x, 1) for x in samples]}


def measure_batch(conn, cfg: Config, start: date, end: date, repeat: int) -> dict:
    samples = []
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        run_check(conn, cfg, start=start, end=end, notes="perf probe")
        samples.append((time.perf_counter() - t0) * 1000)

    counter = SqlCounter()                      # 计数单独一趟，trace 开销不混进耗时
    if hasattr(conn, "set_trace_callback"):
        conn.set_trace_callback(counter)
        counted = run_check(conn, cfg, start=start, end=end, notes="perf probe (counted)")
        conn.set_trace_callback(None)
        sql_statements = counter.n
    else:
        counted_conn = CountingConnection(conn)
        counted = run_check(counted_conn, cfg, start=start, end=end, notes="perf probe (counted)")
        sql_statements = counted_conn.counter.n

    spans = {
        r["segment"]: round(int(r["total_us"]) / 1000, 1)
        for r in conn.execute(
            "SELECT segment, SUM(duration_us) AS total_us FROM span WHERE qid = ? "
            "GROUP BY segment ORDER BY segment", (counted.run_id,)).fetchall()
    }
    out = {"sql_statements": sql_statements,
           "employees": counted.employees, "days": counted.days,
           "findings": len(counted.findings), "counts": counted.counts,
           "findings_by_rule": {r["rule_id"]: int(r["c"]) for r in conn.execute(
               "SELECT rule_id, COUNT(*) AS c FROM finding WHERE run_id = ? "
               "GROUP BY rule_id ORDER BY rule_id", (counted.run_id,)).fetchall()},
           "conclusion_digest": counted.conclusion_digest,
           "input_fingerprint": counted.input_fingerprint,
           "rule_pack": cfg.rule_pack_id, "engine": ENGINE_VERSION,
           "spans_ms": spans} | _timing(samples)
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
        last_manifest = None
        for _ in range(max(1, repeat)):
            t0 = time.perf_counter()
            last_manifest = export_package(conn, cfg, run_id)
            samples.append((time.perf_counter() - t0) * 1000)
        out_timing = _timing(samples)
        counted = CountingConnection(conn)
        export_package(counted, cfg, run_id)
        out_timing["db_calls"] = counted.counter.n
        if last_manifest:
            out_timing["package_zip"] = last_manifest["package_zip"]
            out_timing["inputs_packed"] = last_manifest["inputs"]["packed"]
            out_timing["inputs_bytes"] = last_manifest["inputs"]["total_bytes"]
            out_timing["approval_rows"] = last_manifest["inputs"].get("approval_rows", 0)
        return out_timing

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


def measure_replay(package_zip: str, repeat: int) -> dict:
    samples = []
    ok = False
    inputs_packed = 0
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        res = replay(Path(package_zip))
        samples.append((time.perf_counter() - t0) * 1000)
        ok = bool(res.get("ok"))
        inputs_packed = int(res.get("inputs_packed", 0))
    out = {"package_zip": package_zip, "ok": ok, "inputs_packed": inputs_packed}
    out.update(_timing(samples))
    return out


def measure_import(conn, cfg: Config, import_file: Path, repeat: int) -> dict:
    if not import_file.is_file():
        return {"skipped": True, "reason": f"找不到导入样本：{import_file}"}
    samples = []
    last = None
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        last = import_csv_file(conn, cfg, import_file, kind="punch",
                               rel_path=f"perf-import-{import_file.name}")
        samples.append((time.perf_counter() - t0) * 1000)
    out = {"file": str(import_file), "rows_seen": last.rows_seen,
           "rows_accepted": last.rows_accepted, "rows_rejected": last.rows_rejected}
    out.update(_timing(samples))
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
    ap.add_argument("--pg-url", default="",
                    help="PG 临时库连接串（必须是不含生产数据的一次性库）；给定时走 PG 模式")
    ap.add_argument("--employees", type=int, default=0,
                    help="PG 模式生成 N 个员工的单月合成数据（只用于性能规模）")
    ap.add_argument("--dense", action="store_true",
                    help="规模数据按组注入异常（缺卡/超时/多段班/设备冲突/审批缺失），制造结论密集")
    ap.add_argument("--month", default="2025-09", help="规模数据所在月份 YYYY-MM")
    ap.add_argument("--export-repeat", type=int, default=0,
                    help="导出计时采样次数；默认沿用 --repeat")
    ap.add_argument("--replay", action="store_true", help="附带 replay 一份刚导出的包")
    ap.add_argument("--import", dest="do_import", action="store_true", help="附带计时一次 CSV 导入")
    ap.add_argument("--import-file", default="", help="导入样本 CSV；默认用当前数据目录 punch.csv")
    ap.add_argument("--json", default="", help="把结果写成 JSON 文件")
    args = ap.parse_args(argv)

    start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
    if args.employees:
        if not args.pg_url:
            raise SystemExit("--employees 目前只支持 PG 模式，请同时给 --pg-url")
        start = date.fromisoformat(args.month + "-01")
        end = date(start.year + (start.month == 12), (start.month % 12) + 1, 1) - timedelta(days=1)

    with tempfile.TemporaryDirectory(prefix="wca-probe-", ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        seed = None
        if args.pg_url:
            probe_cfg = _probe_pg_cfg(args.pg_url, tmp_path)
            # H-02：配置层守卫必须早于任何连接/建目录/建表/播种。
            _exit_unless_config_temporary(probe_cfg)
            probe_cfg.ensure_dirs()
            # provision=False：不让 ensure_database/identity 把目标改写回活动库。
            conn = connect(probe_cfg, provision=False)
            # 连接后按实际库身份复核，同样早于 init_db / _seed_scale。
            _exit_unless_connection_temporary(conn, probe_cfg)
            init_db(conn)
            if args.employees:
                seed = _seed_scale(conn, probe_cfg, args.employees, args.month,
                                   dense=args.dense)
            db_source = probe_cfg.safe_database_target
        else:
            cfg = Config.load()
            probe_cfg = _copy_db(cfg, tmp_path)
            conn = connect(probe_cfg, provision=False)
            _exit_unless_connection_temporary(conn, probe_cfg)
            init_db(conn)
            probe_cfg.ensure_dirs()
            db_source = str(cfg.db_path)
        result = {
            "measured_at": date.today().isoformat(),
            "range": {"start": start.isoformat(), "end": end.isoformat()},
            "db_backend": probe_cfg.db_backend,
            "db_source": db_source,
            "sqlite_synchronous": probe_cfg.sqlite_synchronous,
            "repeat": max(1, args.repeat),
            "batch": measure_batch(conn, probe_cfg, start, end, args.repeat),
        }
        if seed:
            result["scale_seed"] = seed
        package_zip = None
        if args.export or args.replay:
            export_repeat = args.export_repeat or args.repeat
            result["export"] = measure_export(conn, probe_cfg, export_repeat,
                                              max(args.amplify, 0))
            package_zip = result["export"]["native"].get("package_zip")
        if args.replay and package_zip:
            result["replay"] = measure_replay(package_zip, args.repeat)
        if args.do_import:
            import_file = (Path(args.import_file) if args.import_file
                           else probe_cfg.data_dir / "punch.csv")
            result["import"] = measure_import(conn, probe_cfg, import_file, args.repeat)
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
