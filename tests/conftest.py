"""测试夹具：手工构造的小规模数据集（分钟数与金额都能手算复核）。

为什么不用 data/raw 的批量数据跑单测：批量数据用来验证规模与耗时，
但判据分支的覆盖必须在**能人工算出期望值**的小数据集上证明，否则等于让引擎给自己打分。
"""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

import pytest

from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.ingest import import_rows
from src.kb import build_kb

RULE_PACK = "rp-2026.10.gd-pilot-standard.v4"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_PATH=str(tmp_path / "test.sqlite3"),
        WCA_DATA_DIR=str(tmp_path / "data"),
        WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"),
        # 测试用账号写在自己的临时目录里：既不动仓库里的演示账号文件，
        # 也保证"账号绑定的是夹具里的员工"这件事是显式的。
        WCA_USERS_PATH=str(tmp_path / "users.json"),
        WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
        WCA_RULE_PACK=RULE_PACK,
        WCA_REGION_CODE="440300",
        WCA_LLM_PROVIDER="stub",
        WCA_EMBEDDING_BACKEND="bm25",
        # 测试库不需要每条写入都 fsync；生产默认 FULL 以保证审计链落盘
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )


@pytest.fixture
def conn(cfg: Config) -> sqlite3.Connection:
    cfg.ensure_dirs()
    c = connect(cfg.db_path)
    init_db(c)
    return c


ORGS = [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""},
        {"org_id": "ORG-B", "org_name": "B组", "parent_id": ""}]

EMPLOYEES = [
    # emp_id, pseudonym, job_code, org, region, regime, approved, hourly_cents
    {"emp_id": "T-STD", "pseudonym": "标准岗", "job_code": "assembly_line", "org_id": "ORG-A",
     "region_code": "440300", "worktime_regime": "standard", "contract_approved_flex": 0,
     "normal_hourly_cents": 3000},
    {"emp_id": "T-CMP", "pseudonym": "综合岗", "job_code": "warehouse_shift", "org_id": "ORG-A",
     "region_code": "440300", "worktime_regime": "comprehensive_monthly",
     "contract_approved_flex": 1, "normal_hourly_cents": 2000},
    {"emp_id": "T-FLX", "pseudonym": "不定时岗", "job_code": "senior_manager", "org_id": "ORG-A",
     "region_code": "440300", "worktime_regime": "flexible", "contract_approved_flex": 1,
     "normal_hourly_cents": 5000},
    {"emp_id": "T-NAPPR", "pseudonym": "未审批岗", "job_code": "store_clerk", "org_id": "ORG-B",
     "region_code": "440300", "worktime_regime": "comprehensive_monthly",
     "contract_approved_flex": 0, "normal_hourly_cents": 3000},
    {"emp_id": "T-BADJOB", "pseudonym": "错岗申报", "job_code": "office_clerk", "org_id": "ORG-B",
     "region_code": "440300", "worktime_regime": "flexible", "contract_approved_flex": 1,
     "normal_hourly_cents": 3000},
    {"emp_id": "T-OTHER", "pseudonym": "同事", "job_code": "assembly_line", "org_id": "ORG-B",
     "region_code": "440300", "worktime_regime": "standard", "contract_approved_flex": 0,
     "normal_hourly_cents": 7777},
]


def punch(emp: str, ts: str, ptype: str = "in", device: str = "DEV-1") -> dict:
    return {"emp_id": emp, "event_ts": ts, "punch_type": ptype, "device_id": device}


def schedule(emp: str, work_date: str, start: str, end: str, rest: int = 60) -> dict:
    return {"emp_id": emp, "work_date": work_date, "planned_start": start,
            "planned_end": end, "rest_minutes": rest}


def load_base(conn: sqlite3.Connection, cfg: Config) -> None:
    """最小主体数据：组织 + 员工 + 知识库。"""
    import_rows(conn, cfg, "org", ORGS, rel_path="inline://org")
    import_rows(conn, cfg, "employee", EMPLOYEES, rel_path="inline://employee")
    build_kb(conn, include_personnel=False)


def load_full_facts(conn: sqlite3.Connection, cfg: Config) -> None:
    """在最小数据之上加载全部判据场景（2025-09 ~ 2025-11 + 2026-04 歧义日）。"""
    load_base(conn, cfg)

    rows_punch = []
    rows_sched = []

    # --- T-STD 工作日延长工时四档（小时工资 3000 分）---
    # 8 小时整（09:00-18:00 - 60 分休息 = 480 分钟）-> 不产生加班
    rows_sched.append(schedule("T-STD", "2025-09-01", "2025-09-01T09:00:00+08:00",
                               "2025-09-01T18:00:00+08:00"))
    rows_punch += [punch("T-STD", "2025-09-01T09:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-01T18:00:00+08:00", "out")]
    # 延长 60 分钟 -> OT-D01 可申辩，测算 3000*60*1500/60000 = 4500 分（45 元）
    rows_sched.append(schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
                               "2025-09-02T19:00:00+08:00"))
    rows_punch += [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-02T19:00:00+08:00", "out")]
    # 延长 120 分钟 -> OT-D01 需复核，3000*120*1500/60000 = 9000 分
    rows_sched.append(schedule("T-STD", "2025-09-03", "2025-09-03T09:00:00+08:00",
                               "2025-09-03T20:00:00+08:00"))
    rows_punch += [punch("T-STD", "2025-09-03T09:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-03T20:00:00+08:00", "out")]
    # 延长 180 分钟（正好卡在特殊原因上限，不触发 CAP-D05）
    rows_sched.append(schedule("T-STD", "2025-09-04", "2025-09-04T09:00:00+08:00",
                               "2025-09-04T21:00:00+08:00"))
    rows_punch += [punch("T-STD", "2025-09-04T09:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-04T21:00:00+08:00", "out")]
    # 延长 240 分钟 -> CAP-D05 明显违规，3000*240*1500/60000 = 18000 分
    rows_sched.append(schedule("T-STD", "2025-09-05", "2025-09-05T09:00:00+08:00",
                               "2025-09-05T22:00:00+08:00"))
    rows_punch += [punch("T-STD", "2025-09-05T09:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-05T22:00:00+08:00", "out")]

    # 休息日（周六）上班 480 分钟 -> OT-D02 需复核 200%，3000*480*2000/60000 = 48000 分
    rows_sched.append(schedule("T-STD", "2025-09-06", "2025-09-06T10:00:00+08:00",
                               "2025-09-06T18:00:00+08:00", rest=0))
    rows_punch += [punch("T-STD", "2025-09-06T10:00:00+08:00", "in"),
                   punch("T-STD", "2025-09-06T18:00:00+08:00", "out")]
    # 调休休息日（2025-10-04 属 10/1-10/8 放假块内的非法定当天）-> 200%
    rows_sched.append(schedule("T-STD", "2025-10-04", "2025-10-04T10:00:00+08:00",
                               "2025-10-04T18:00:00+08:00", rest=0))
    rows_punch += [punch("T-STD", "2025-10-04T10:00:00+08:00", "in"),
                   punch("T-STD", "2025-10-04T18:00:00+08:00", "out")]
    # 法定节假日当天（2025-10-01）工作 600 分钟 -> OT-D03 300%，3000*600*3000/60000 = 90000 分
    rows_sched.append(schedule("T-STD", "2025-10-01", "2025-10-01T10:00:00+08:00",
                               "2025-10-01T20:00:00+08:00", rest=0))
    rows_punch += [punch("T-STD", "2025-10-01T10:00:00+08:00", "in"),
                   punch("T-STD", "2025-10-01T20:00:00+08:00", "out")]

    # 月累计：2025-11 每工作日延长 150 分钟 x 20 天 = 3000 分钟 > 2160 -> CAP-M01
    for day in _november_workdays():
        rows_sched.append(schedule("T-STD", day, f"{day}T09:00:00+08:00", f"{day}T20:30:00+08:00"))
        rows_punch += [punch("T-STD", f"{day}T09:00:00+08:00", "in"),
                       punch("T-STD", f"{day}T20:30:00+08:00", "out")]

    # --- T-CMP 综合计算工时：2025-11 每工作日 540 分钟 -> 实际 10800，标准 20*480=9600，超额 1200 ---
    for day in _november_workdays():
        rows_sched.append(schedule("T-CMP", day, f"{day}T09:00:00+08:00", f"{day}T19:00:00+08:00"))
        rows_punch += [punch("T-CMP", f"{day}T09:00:00+08:00", "in"),
                       punch("T-CMP", f"{day}T19:00:00+08:00", "out")]

    # --- T-FLX 不定时：法定节假日 2025-10-01 工作 480 分钟 -> OT-D04（深圳 300%），无 OT-D01 ---
    rows_sched.append(schedule("T-FLX", "2025-10-01", "2025-10-01T09:00:00+08:00",
                               "2025-10-01T17:00:00+08:00", rest=0))
    rows_punch += [punch("T-FLX", "2025-10-01T09:00:00+08:00", "in"),
                   punch("T-FLX", "2025-10-01T17:00:00+08:00", "out")]
    # 超长工作日（12 小时）-> 不定时不产生 OT-D01/CAP-D05
    rows_sched.append(schedule("T-FLX", "2025-10-09", "2025-10-09T08:00:00+08:00",
                               "2025-10-09T20:00:00+08:00", rest=0))
    rows_punch += [punch("T-FLX", "2025-10-09T08:00:00+08:00", "in"),
                   punch("T-FLX", "2025-10-09T20:00:00+08:00", "out")]

    # --- T-NAPPR 未审批申报综合工时 -> COMP-C02，并按标准工时校验（延长 60 分钟出 OT-D01）---
    rows_sched.append(schedule("T-NAPPR", "2025-09-02", "2025-09-02T09:00:00+08:00",
                               "2025-09-02T19:00:00+08:00"))
    rows_punch += [punch("T-NAPPR", "2025-09-02T09:00:00+08:00", "in"),
                   punch("T-NAPPR", "2025-09-02T19:00:00+08:00", "out")]

    # --- T-OTHER 供 ACL 测试：他人考勤与薪酬 ---
    rows_sched.append(schedule("T-OTHER", "2025-09-01", "2025-09-01T09:00:00+08:00",
                               "2025-09-01T18:00:00+08:00"))
    rows_punch += [punch("T-OTHER", "2025-09-01T09:00:00+08:00", "in"),
                   punch("T-OTHER", "2025-09-01T18:00:00+08:00", "out")]

    import_rows(conn, cfg, "schedule", rows_sched, rel_path="inline://schedule")
    import_rows(conn, cfg, "punch", rows_punch, rel_path="inline://punch")


def load_night_shift(conn: sqlite3.Connection, cfg: Config) -> None:
    """跨零点夜班且无排班计划 -> XD-01 + NIGHT-01。"""
    load_base(conn, cfg)
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-12-14T21:00:00+08:00", "in", "DEV-N"),
        punch("T-STD", "2025-12-15T06:30:00+08:00", "out", "DEV-N"),
    ], rel_path="inline://night")


def load_ambiguous_holiday(conn: sqlite3.Connection, cfg: Config) -> None:
    """2026-04-05（清明当日待核对）-> 只能需复核。"""
    load_base(conn, cfg)
    # 10:00-22:00、无休息 -> 实际 720 分钟：既是法定节假日（300%），也超日上限 240 分钟。
    # 上限类规则本应下「明显违规」，但该日清明当日口径待核对，必须被降级为需复核。
    import_rows(conn, cfg, "schedule", [
        schedule("T-STD", "2026-04-05", "2026-04-05T10:00:00+08:00",
                 "2026-04-05T22:00:00+08:00", rest=0)])
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2026-04-05T10:00:00+08:00", "in"),
        punch("T-STD", "2026-04-05T22:00:00+08:00", "out"),
    ], rel_path="inline://ambig")


def load_streak(conn: sqlite3.Connection, cfg: Config) -> None:
    """2025-09-29..10-05 连续 7 天出勤（正好是完整的 ISO 周 2025-W40）-> CAP-W01。"""
    load_base(conn, cfg)
    sched, punches = [], []
    for day in ("09-29", "09-30", "10-01", "10-02", "10-03", "10-04", "10-05"):
        d = f"2025-{day}"
        sched.append(schedule("T-OTHER", d, f"{d}T09:00:00+08:00", f"{d}T18:00:00+08:00", rest=0))
        punches += [punch("T-OTHER", f"{d}T09:00:00+08:00", "in"),
                    punch("T-OTHER", f"{d}T18:00:00+08:00", "out")]
    import_rows(conn, cfg, "schedule", sched, rel_path="inline://streak-sched")
    import_rows(conn, cfg, "punch", punches, rel_path="inline://streak-punch")


def _november_workdays() -> list[str]:
    out = []
    for day in range(1, 31):
        d = date(2025, 11, day)
        if d.weekday() < 5:
            out.append(d.isoformat())
    return out


@pytest.fixture
def facts_conn(conn, cfg):
    load_full_facts(conn, cfg)
    return conn


@pytest.fixture
def checked(facts_conn, cfg):
    """跑一次校验，返回 (conn, cfg, CheckOutcome)。"""
    out = run_check(facts_conn, cfg, start=date(2025, 9, 1), end=date(2025, 11, 30),
                    notes="pytest fixture")
    return facts_conn, cfg, out


def find(findings, rule_id: str, emp: str | None = None, work_date: str | None = None,
         period: str | None = None) -> list:
    return [f for f in findings
            if f.rule_id == rule_id
            and (emp is None or f.emp_id == emp)
            and (work_date is None or f.work_date == work_date)
            and (period is None or f.period_key == period)]


def seed_users(cfg, bindings) -> str:
    """给界面/接口测试写一份临时账号文件：bindings = [(用户名, emp_id, [角色], 口令)]。

    口令只以 scrypt 哈希落盘，与真实运行时的 `config/users.json` 同构，
    因此测试覆盖到的是"真的那条校验路径"，不是为测试开的后门。
    """
    import json

    from src.auth import hash_password

    users = [{"username": u, "emp_id": e, "roles": list(r), "pw_hash": hash_password(p)}
             for u, e, r, p in bindings]
    path = Path(cfg.users_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": "wca-users-v1", "users": users}, ensure_ascii=False),
                    encoding="utf-8")
    return str(path)
