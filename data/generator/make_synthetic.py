"""合成考勤数据生成器（可复现种子）。

隐私边界（方案 R4）：全部为合成数据，不含任何真实个人信息；姓名用化名 E001/员工A 形式。
复现方式：`python data/generator/make_synthetic.py --seed 20260106` 产出的 CSV 逐字节一致。

刻意设计：每个异常场景都有「精确分钟数」而不是随机数，这样评测集的标准答案可以手工推导并复核，
不会出现「引擎自己生成、引擎自己判分」的循环论证。场景清单同时写出 data/raw/SCENARIOS.md。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

# 官方放假安排是「哪些日子不该上班」的唯一依据：直接读项目内的日历，保证生成器与
# 校验引擎用的是同一份节假日口径，不会出现自己排班又自己判违规的循环。
import sys

sys.path.insert(0, str(ROOT))
from src.rules.holidays import HolidayCalendar  # noqa: E402

CALENDAR = HolidayCalendar.load()

START = date(2025, 9, 1)
END = date(2026, 4, 30)

ORGS = [
    ("ORG-MFG", "制造一组（示例）"),
    ("ORG-OPS", "门店运营组（示例）"),
    ("ORG-SALES", "外勤销售组（示例）"),
]

# emp_id, 化名, 岗位, 组织, 工时制, 是否已审批, 小时工资(分)
EMPLOYEES = [
    ("E001", "员工一", "assembly_line",   "ORG-MFG",  "standard", 0, 3200),
    ("E002", "员工二", "assembly_line",   "ORG-MFG",  "standard", 0, 3200),
    ("E003", "员工三", "store_clerk",     "ORG-OPS",  "standard", 0, 3000),
    ("E004", "员工四", "store_clerk",     "ORG-OPS",  "standard", 0, 3000),
    ("E005", "员工五", "line_leader",     "ORG-MFG",  "standard", 0, 3600),
    ("E006", "员工六", "warehouse_shift", "ORG-MFG",  "comprehensive_monthly", 1, 3100),
    ("E007", "员工七", "tourism_seasonal", "ORG-OPS", "comprehensive_quarterly", 1, 2900),
    ("E008", "员工八", "senior_manager",  "ORG-SALES", "flexible", 1, 9000),
    ("E009", "员工九", "store_clerk",     "ORG-OPS",  "comprehensive_monthly", 0, 3000),
    ("E010", "员工十", "long_haul_driver", "ORG-MFG", "flexible", 1, 4000),
    ("E011", "员工十一", "field_sales",    "ORG-SALES", "standard", 0, 4200),
    ("E012", "员工十二", "assembly_line",  "ORG-MFG",  "standard", 0, 3200),
]

STD_MIN = 480      # 8 小时
REST_MIN = 60      # 午休 60 分钟（排班表里显式给出）

# (emp, work_date, 场景编码, 计划外额外分钟 | None)
SCENARIOS = [
    # 工作日延长工时：正好 1 小时（可申辩档）
    ("E001", "2025-09-08", "OT-WORKDAY-60", None),
    ("E001", "2025-09-15", "OT-WORKDAY-120", None),
    # 单日超 3 小时 -> 上限类明显违规
    ("E002", "2025-09-22", "OT-WORKDAY-240", None),
    # 连续 7 天无休息 -> 劳动法38
    ("E003", "2025-10-01", "STREAK-7", None),
    ("E003", "2025-10-02", "STREAK-7", None),
    ("E003", "2025-10-03", "STREAK-7", None),
    ("E003", "2025-10-04", "STREAK-7", None),
    ("E003", "2025-10-05", "STREAK-7", None),
    ("E003", "2025-10-06", "STREAK-7", None),
    ("E003", "2025-10-07", "STREAK-7", None),
    # 月累计超 36 小时
    ("E005", "2025-11-03", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-04", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-05", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-06", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-07", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-10", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-11", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-12", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-13", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-14", "OT-MONTH-BLOW", 150),
    ("E005", "2025-11-17", "OT-MONTH-BLOW", 150),
    # 法定节假日当天上班（2025 国庆 10/1-10/3 与 2026 元旦 1/1）
    ("E004", "2025-10-01", "HOLIDAY-STATUTORY", 600),
    ("E011", "2026-01-01", "HOLIDAY-STATUTORY", 480),
    # 调休休息日上班（2025-10-04 属于 10/1-10/8 放假块内、非法定当天 -> 200%）
    ("E004", "2025-10-04", "RESTSWAP", 480),
    # 跨天夜班（无排班计划 -> XD-01 需复核；有夜间时段 -> NIGHT-01）
    ("E012", "2025-12-14", "NIGHT-SHIFT", None),
    # 综合计算工时周期超额
    ("E006", "2025-10-10", "COMP-OVER", 180),
    ("E006", "2025-10-11", "COMP-OVER", 180),
    ("E006", "2025-10-12", "COMP-OVER", 180),
    ("E006", "2025-10-13", "COMP-OVER", 180),
    ("E006", "2025-10-14", "COMP-OVER", 180),
    ("E006", "2025-10-15", "COMP-OVER", 180),
    ("E006", "2025-10-16", "COMP-OVER", 180),
    ("E006", "2025-10-17", "COMP-OVER", 180),
    ("E006", "2025-10-18", "COMP-OVER", 180),
    ("E006", "2025-10-19", "COMP-OVER", 180),
    # 周工时 >40 但 ≤44（口径差异档）
    ("E011", "2025-09-29", "WEEK-41", 15),
    ("E011", "2025-09-30", "WEEK-41", 15),
    # 不定时工时员工在法定节假日上班（深圳条例第20条 -> OT-D04）
    ("E008", "2025-10-01", "FLEX-HOLIDAY", 480),
    ("E010", "2026-01-01", "FLEX-HOLIDAY", 300),
    # 数据质量靶子
    ("E001", "2025-09-18", "MISSING-OUT", None),
    ("E002", "2025-09-18", "DUP-PUNCH", None),
    ("E002", "2025-09-19", "BAD-TZ", None),
    ("E004", "2025-11-20", "NO-PUNCH", None),
    ("E007", "2026-04-05", "AMBIG-HOLIDAY", 480),
]

AMBIG_SCENARIOS = {("E007", "2026-04-05")}


def day_type_raw(d: date) -> str:
    return "weekend" if d.weekday() >= 5 else "weekday"


# 这些场景表示「当天确实被安排工作」，其余情况下休息日/法定节假日不产生打卡
WORK_ON_REST_CODES = {"HOLIDAY-STATUTORY", "RESTSWAP", "AMBIG-HOLIDAY", "STREAK-7",
                      "COMP-OVER", "NIGHT-SHIFT", "FLEX-HOLIDAY"}
MONTH_BLOW = {("E005", "2025-11"): 100, ("E012", "2026-01"): 100}


def punches_for(emp_id: str, d: date, rng: random.Random) -> list[tuple[str, str, str, str]]:
    """返回 [(emp_id, event_ts, punch_type, device)]；没有出勤则返回空列表。"""
    iso = d.isoformat()
    sc = next((s for s in SCENARIOS if s[0] == emp_id and s[1] == iso), None)
    code = sc[2] if sc else ""
    month_extra = MONTH_BLOW.get((emp_id, iso[:7]))

    if code == "NO-PUNCH":
        return []

    # 官方放假安排里不是工作日的日子，除显式场景外一律不排班、不打卡
    try:
        info = CALENDAR.classify(d)
    except Exception:
        info = None
    if info is not None and info.day_type != "workday" and code not in WORK_ON_REST_CODES:
        return []

    if code == "NIGHT-SHIFT":
        # 21:00 上班 -> 次日 06:30 下班（跨零点，无排班计划）
        return [
            (emp_id, f"{iso}T21:00:00+08:00", "in", "DEV-N01"),
            (emp_id, f"{(d + timedelta(days=1)).isoformat()}T06:30:00+08:00", "out", "DEV-N01"),
        ]

    extra = sc[3] if sc else 0
    worked_extra = {
        "OT-WORKDAY-60": 60, "OT-WORKDAY-120": 120, "OT-WORKDAY-240": 240,
        "OT-MONTH-BLOW": extra, "COMP-OVER": extra, "WEEK-41": extra,
        "HOLIDAY-STATUTORY": extra, "RESTSWAP": extra, "STREAK-7": 0,
        "AMBIG-HOLIDAY": extra, "MONTH-BLOW": month_extra, "FLEX-HOLIDAY": extra,
    }.get(code, month_extra)

    if not worked_extra:
        # 常规工作日：09:00-18:00，含 60 分钟休息 -> minutes_worked 正好 480（不产生加班）
        base_start, base_end = 9 * 60, 18 * 60
    else:
        if code in ("HOLIDAY-STATUTORY", "RESTSWAP", "AMBIG-HOLIDAY", "FLEX-HOLIDAY"):
            base_start, base_end = 10 * 60, 10 * 60 + worked_extra
        else:
            base_start, base_end = 9 * 60, 9 * 60 + STD_MIN + REST_MIN + worked_extra

    # 抖动只平移整个班次（上下班同一偏移），保证「实际工作分钟数」与注入值精确一致，
    # 这样评测集标准答案可以手工推导，不会变成引擎自产自验。
    jitter = rng.choice([0, 0, -3, 5]) if code == "" and month_extra is None else 0
    t_in = f"{iso}T{_hhmm(base_start + jitter)}:00+08:00"
    t_out = f"{iso}T{_hhmm(base_end + jitter)}:00+08:00"

    if code == "MISSING-OUT":
        return [(emp_id, t_in, "in", "DEV-A1")]
    if code == "BAD-TZ":
        # 无时区标记（naive）与斜杠日期两种脏格式
        return [
            (emp_id, f"{iso} {base_start // 60:02d}:{base_start % 60:02d}:00", "in", "DEV-B2"),
            (emp_id, f"{d.year}/{d.month:02d}/{d.day:02d} {base_end // 60:02d}:{base_end % 60:02d}:00",
             "out", "DEV-B2"),
        ]
    rows = [(emp_id, t_in, "in", "DEV-A1"), (emp_id, t_out, "out", "DEV-A1")]
    if code == "DUP-PUNCH":
        rows.append((emp_id, t_in, "in", "DEV-A1"))  # 完全重复行
    return rows


def _hhmm(minutes: int) -> str:
    minutes = max(0, min(minutes, 23 * 60 + 59))
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def build(seed: int) -> dict[str, list[list]]:
    rng = random.Random(seed)
    punch_rows, sched_rows, leave_rows, trip_rows, corr_rows = [], [], [], [], []
    org_rows = [["org_id", "org_name", "parent_id"]] + [[o[0], o[1], "ORG-ROOT"] for o in ORGS]
    emp_rows = [["emp_id", "pseudonym", "job_code", "org_id", "region_code", "worktime_regime",
                 "contract_approved_flex", "normal_hourly_cents"]]
    for e in EMPLOYEES:
        emp_rows.append([e[0], e[1], e[2], e[3], "440300", e[4], e[5], e[6]])

    for emp in EMPLOYEES:
        emp_id, _, job, _org, regime, _appr, _wage = emp
        cur = START
        while cur <= END:
            rows = punches_for(emp_id, cur, rng)
            for r in rows:
                punch_rows.append(list(r))
            iso = cur.isoformat()
            # 只有明确安排的班次才写排班表：夜班当天故意缺排班，制造 XD-01 靶子
            sc = next((s for s in SCENARIOS if s[0] == emp_id and s[1] == iso), None)
            code = sc[2] if sc else ""
            if rows and code not in ("NIGHT-SHIFT", "MISSING-OUT", "DUP-PUNCH", "BAD-TZ", "NO-PUNCH"):
                start = rows[0][1]
                end = rows[-1][1] if rows[-1][2] == "out" else rows[-1][1]
                no_rest = code in ("HOLIDAY-STATUTORY", "RESTSWAP", "AMBIG-HOLIDAY",
                                   "FLEX-HOLIDAY")
                sched_rows.append([emp_id, iso, start, end, 0 if no_rest else REST_MIN])
            cur += timedelta(days=1)

    # 请假 / 出差 / 补卡
    leave_rows.append(["emp_id", "leave_kind", "start_ts", "end_ts", "approved", "paid"])
    leave_rows.append(["E001", "annual", "2025-09-25T09:00:00+08:00", "2025-09-25T13:00:00+08:00", 1, 1])
    leave_rows.append(["E004", "sick", "2025-12-01T09:00:00+08:00", "2025-12-02T18:00:00+08:00", 1, 1])
    leave_rows.append(["E003", "comp_time", "2025-10-09T09:00:00+08:00", "2025-10-09T18:00:00+08:00", 1, 0])
    trip_rows.append(["emp_id", "destination", "start_ts", "end_ts"])
    trip_rows.append(["E011", "东莞（示例）", "2025-11-19T08:00:00+08:00", "2025-11-19T20:00:00+08:00"])
    trip_rows.append(["E008", "广州（示例）", "2026-01-15T09:00:00+08:00", "2026-01-16T18:00:00+08:00"])
    corr_rows.append(["emp_id", "claimed_ts", "claimed_type", "reason", "approved"])
    corr_rows.append(["E001", "2025-09-18T18:00:00+08:00", "out", "下班卡漏打（示例）", 1])
    corr_rows.append(["E002", "2025-12-03T09:00:00+08:00", "in", "补卡未经主管批准（示例）", 0])
    # 脏行：给质量门禁当靶子
    punch_rows.append(["E001", "2025-13-45T99:99:00+08:00", "in", "DEV-A1"])
    punch_rows.append(["E999", "2025-10-01T09:00:00+08:00", "in", "DEV-X9"])
    punch_rows.append(["E002", "", "out", "DEV-A1"])
    punch_rows.append(["E003", "2025-10-20T09:00:00+08:00", "maybe", "DEV-A1"])

    return {
        "org.csv": org_rows,
        "employee.csv": emp_rows,
        "punch.csv": [["emp_id", "event_ts", "punch_type", "device_id"], *punch_rows],
        "schedule.csv": [["emp_id", "work_date", "planned_start", "planned_end", "rest_minutes"], *sched_rows],
        "leave.csv": leave_rows,
        "trip.csv": trip_rows,
        "correction.csv": corr_rows,
    }


def write(seed: int) -> dict:
    RAW.mkdir(parents=True, exist_ok=True)
    data = build(seed)
    manifest = {"generator": "data/generator/make_synthetic.py", "seed": seed,
                "period": {"start": START.isoformat(), "end": END.isoformat()},
                "files": {}, "privacy": "合成数据，不含任何真实个人信息"}
    for name, rows in data.items():
        path = RAW / name
        with path.open("w", encoding="utf-8", newline="") as fh:
            csv.writer(fh, lineterminator="\n").writerows(rows)
        body = path.read_bytes()
        manifest["files"][name] = {"sha256": hashlib.sha256(body).hexdigest(),
                                   "rows": max(0, len(rows) - 1)}
    (RAW / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                                                  indent=2) + "\n", encoding="utf-8")
    (RAW / "SCENARIOS.md").write_text(_scenarios_md(seed), encoding="utf-8")
    return manifest


def _scenarios_md(seed: int) -> str:
    lines = [
        f"# 合成数据场景清单（seed={seed}，区间 {START}—{END}）",
        "",
        "本文件说明每个异常场景**注入了什么**，评测集标准答案据此手工推导。",
        "凡涉及分钟数的推导一律用整数分钟与整数分（厘）表达，不用浮点。",
        "",
        "| 员工 | 日期 | 场景 | 注入内容 | 预期规则 |",
        "|---|---|---|---|---|",
    ]
    for emp, d, code, extra in SCENARIOS:
        lines.append(f"| {emp} | {d} | {code} | {extra if extra else '按场景默认'} | {EXPECT.get(code, '')} |")
    lines += [
        "",
        "## 常规日口径",
        "",
        "- 工作日：09:00 上班、18:00 下班，含 60 分钟休息 -> `minutes_worked = 480`（正好标准工时，不产生加班）",
        "- 周末：不排班、无打卡 -> 不产生结论（但计入「是否有休息日」判据）",
        "- 员工主数据 `normal_hourly_cents` 即加班基数（合成制度 policy.sz.pay-base 约定不含奖金补贴）",
        "",
        "## 脏数据靶子",
        "",
        "- `2025-13-45T99:99:00+08:00`（非法日期）、空时间戳、未知 punch_type、不存在员工 E999 -> QUAL-*",
        "- 完全重复打卡行 -> QUAL-DUP（只保留首次）",
        "- 无时区 + 斜杠日期 -> QUAL-TZ（按 +08:00 补齐并留痕）",
        "- 2026-04-05：清明法定节假日当天口径待核对 -> 结论强制降级为需复核",
    ]
    return "\n".join(lines) + "\n"


EXPECT = {
    "OT-WORKDAY-60": "OT-D01 可申辩（60 分钟，≤1 小时）",
    "OT-WORKDAY-120": "OT-D01 需复核（120 分钟）",
    "OT-WORKDAY-240": "OT-D01 需复核 + CAP-D05 明显违规（240>180）",
    "STREAK-7": "OT-D02（休息日/节假日上班）+ CAP-W01 连续 7 天无休息",
    "OT-MONTH-BLOW": "OT-D01 + CAP-M01 月累计超 36 小时",
    "MONTH-BLOW": "2025-11 每工作日 +100 分钟 / 2026-01 每工作日 +100 分钟",
    "HOLIDAY-STATUTORY": "OT-D03 法定节假日 300%",
    "RESTSWAP": "OT-D02 调休休息日 200%",
    "NIGHT-SHIFT": "XD-01 跨天无排班 + NIGHT-01 夜间时段",
    "FLEX-HOLIDAY": "OT-D04 不定时工时法定节假日（深圳口径 300%）",
    "COMP-OVER": "COMP-C01 综合工时周期超额",
    "WEEK-41": "WK-W01 周超 40 小时（口径差异，需复核）",
    "MISSING-OUT": "QUAL-01 缺卡（补卡获批后闭合）",
    "DUP-PUNCH": "QUAL-DUP 重复打卡",
    "BAD-TZ": "QUAL-TZ 无时区/斜杠日期",
    "NO-PUNCH": "QUAL-01 当日无任何打卡",
    "AMBIG-HOLIDAY": "OT-D03/OT-D02 之间待核对 -> 只能需复核",
}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="生成合成考勤数据（可复现）")
    ap.add_argument("--seed", type=int, default=20260106)
    args = ap.parse_args()
    m = write(args.seed)
    total = sum(v["rows"] for v in m["files"].values())
    print(f"生成完成：{len(m['files'])} 个文件、合计 {total} 行数据、seed={args.seed}")
    for name, info in sorted(m["files"].items()):
        print(f"  {name:16s} rows={info['rows']:5d} sha256={info['sha256'][:16]}…")
