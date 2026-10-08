"""校验运行编排：装配 EmpScope → 跑规则 → 落 run/finding/review/audit → 出摘要。

run 记录「规则版本 + 输入指纹 + 结论摘要」三元组；同一三元组重跑必须得到同一结论（A8）。
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from . import ENGINE_VERSION
from .config import Config
from .db import get_meta, insert_many, set_meta, transaction
from .evidence import append_audit, conclusion_digest, genesis_of, input_fingerprint, set_genesis
from .observability import Timer
from .rules.dayfacts import DayFacts, compute_day_facts, load_employee_bundle, stamp
from .rules.findings import (SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION, Finding,
                             UNATTRIBUTED)
from .rules.holidays import DAY_WORKDAY, HolidayCalendar
from .rules.regime import decide


def profile_tiers(cfg: Config, region_code: str) -> list[str]:
    """该城市档的地域层级（国家/省/市），供举证包与报表写明结论是按哪一级条文算的。"""
    city = cfg.region_profile.city(region_code)
    return list(city.tier) if city else []
from .rules.rulepack import DAY_RULES, EmpScope, RULE_PACK_VERSION

RULE_PACK_KEY = "rule_pack_version"
CRITERIA_FROZEN_KEY = "criteria_frozen_on"  # R7：判据冻结日，之后修订须留痕


@dataclass
class CheckOutcome:
    run_id: str
    findings: list[Finding] = field(default_factory=list)
    input_fingerprint: str = ""
    conclusion_digest: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    elapsed_us: int = 0
    employees: int = 0
    days: int = 0

    def counts_by_severity(self) -> dict[str, int]:
        out = {SEV_DEFENSIBLE: 0, SEV_REVIEW: 0, SEV_VIOLATION: 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def new_run_id(started: datetime) -> str:
    return f"run-{started.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"



def load_employees(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT emp_id, pseudonym, job_code, org_id, region_code, worktime_regime, "
        "contract_approved_flex, pay_base_cents, pay_base_hourly_cents, normal_hourly_cents, "
        "is_manager, acl_scope FROM employee ORDER BY emp_id"
    ).fetchall()


def build_scope(conn: sqlite3.Connection, cfg: Config, calendar: HolidayCalendar, emp: sqlite3.Row,
                start: date, end: date) -> EmpScope:
    decision = decide(
        emp_id=emp["emp_id"],
        job_code=emp["job_code"],
        declared_regime=emp["worktime_regime"],
        approved=bool(emp["contract_approved_flex"]),
    )
    profile = getattr(cfg, "region_profile", None)
    scope = EmpScope(
        emp_id=emp["emp_id"],
        job_code=emp["job_code"],
        region_code=emp["region_code"],
        local_citations=(profile.multiplier_citations(emp["region_code"]) if profile else []),
        region_label=(profile.label(emp["region_code"]) if profile else ""),
        region_known=(profile.known(emp["region_code"]) if profile else True),
        org_id=emp["org_id"],
        decision=decision,
        daily_std_minutes=cfg.daily_std_minutes,
        weekly_std_minutes=cfg.weekly_std_minutes,
    )
    # O-1：整段区间只预取一次，逐日改为纯计算（原来每个「员工×日」发 8 条 SQL）
    bundle = load_employee_bundle(conn, cfg, emp["emp_id"], start, end)
    cur = start
    while cur <= end:
        scope.facts.append(compute_day_facts(bundle, cfg, calendar, cur))
        cur += timedelta(days=1)

    # O-2：导入期就尽力归属到人。旧实现靠 JOIN punch 反查，
    # 而「整行被拒收」的数据根本没进 punch，于是永远查不出来。
    issues = conn.execute(
        "SELECT rule_id, severity, field_name, raw_value, detail, file_id, line_no, work_date "
        "FROM ingest_issue WHERE emp_id = ? ORDER BY file_id, line_no",
        (emp["emp_id"],),
    ).fetchall()
    for r in issues:
        scope.quality_issues.append({
            "rule_id": r["rule_id"], "severity": r["severity"], "work_date": r["work_date"],
            "raw_value": r["raw_value"], "file_id": r["file_id"], "line_no": r["line_no"],
        })

    return scope


ATTENDANCE_UPSERT_SQL = (
    "INSERT INTO attendance_day(emp_id, work_date, day_type, minutes_worked, minutes_ot_weekday, "
    "minutes_ot_restday, minutes_ot_holiday, minutes_night, minutes_rest, crossed_midnight, "
    "first_punch, last_punch, punch_count, source_refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT(emp_id, work_date) DO UPDATE SET day_type = excluded.day_type, "
    "minutes_worked = excluded.minutes_worked, minutes_night = excluded.minutes_night, "
    "minutes_rest = excluded.minutes_rest, crossed_midnight = excluded.crossed_midnight, "
    "first_punch = excluded.first_punch, last_punch = excluded.last_punch, "
    "punch_count = excluded.punch_count, source_refs = excluded.source_refs"
)


def persist_attendance_day(conn: sqlite3.Connection, scope: EmpScope) -> None:
    """批量 UPSERT，整批包在一个事务里（O-1 收尾）。

    连接是 autocommit（`isolation_level=None`），不加事务时 executemany 的**每一行**
    各自触发一次 WAL fsync：2,904 行空表写入实测 2,870 ms，包成一个事务后 318 ms，
    落库内容逐字节不变（结论摘要一致，见 reports/优化验证.md）。
    """
    rows = [
        (
            facts.emp_id, facts.work_date.isoformat(), facts.day_type, facts.minutes_worked,
            _weekday_ot(facts, scope), _rest_ot(facts), _holiday_ot(facts), facts.minutes_night,
            facts.minutes_rest, int(facts.crossed_midnight), stamp(facts.in_ts), stamp(facts.out_ts),
            facts.punch_count,
            json.dumps(_dedupe_refs(facts.source_refs), ensure_ascii=False),
        )
        for facts in scope.facts
    ]
    insert_many(conn, ATTENDANCE_UPSERT_SQL, rows)


def _weekday_ot(facts: DayFacts, scope: EmpScope) -> int:
    if facts.day_type != DAY_WORKDAY or facts.regime != "standard":
        return 0
    return max(0, facts.minutes_worked - scope.daily_std_minutes)


def _rest_ot(facts: DayFacts) -> int:
    return facts.minutes_worked if facts.day_type in ("rest_day_swap", "plain_rest_day") else 0


def _holiday_ot(facts: DayFacts) -> int:
    return facts.minutes_worked if facts.day_type == "statutory_holiday" else 0


def _dedupe_refs(refs: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in refs:
        key = (r.get("file_id"), r.get("line_no"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"file_id": key[0], "line_no": key[1]})
    return sorted(out, key=lambda x: (str(x["file_id"]), str(x["line_no"])))


def run_check(conn: sqlite3.Connection, cfg: Config, *, start: date, end: date,
              emp_ids: list[str] | None = None, actor: str = "system:engine",
              notes: str = "", top_k: int | None = None) -> CheckOutcome:
    if start > end:
        raise ValueError(f"区间非法：start={start} > end={end}")
    if cfg.rule_pack_id != RULE_PACK_VERSION:
        # 结论元数据带的是代码里的版本，run 行带的是配置里的版本；两者不一致时
        # 举证包会被贴上错误的可复现声明，必须挡住。
        raise ValueError(
            f"规则包版本不一致：代码 RULE_PACK_VERSION={RULE_PACK_VERSION}，"
            f"配置 WCA_RULE_PACK={cfg.rule_pack_id}。改判据要升版本，配置必须跟着改。")
    timer = Timer()
    set_genesis(conn, cfg)
    started = datetime.now(cfg_tz())
    run_id = new_run_id(started)
    calendar = HolidayCalendar.load()

    scope = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "region_code": cfg.region_code,
        "region_label": getattr(cfg, "region_label", ""),
        "region_tier": (profile_tiers(cfg, cfg.region_code) if getattr(cfg, "region_profile", None) else []),
        "cities_configured": (cfg.region_profile.codes() if getattr(cfg, "region_profile", None) else []),
        "rule_pack_id": cfg.rule_pack_id,
        "ot_cap_scope": cfg.ot_cap_scope,
        "cross_day_cut_hour": cfg.cross_day_cut_hour,
        "daily_std_minutes": cfg.daily_std_minutes,
        "weekly_std_minutes": cfg.weekly_std_minutes,
        "pay_base_source": cfg.pay_base_source,
        "calendar_years": calendar.covered_years,
    }
    if emp_ids:
        scope["emp_ids"] = sorted(emp_ids)

    employees = load_employees(conn)
    if emp_ids:
        wanted = set(emp_ids)
        employees = [e for e in employees if e["emp_id"] in wanted]

    findings: list[Finding] = []
    total_days = 0
    referenced_files: set[int] = set()   # O-11a：指纹只覆盖本次真正引用到的输入文件
    for emp in employees:
        with timer("engine.build_facts"):
            es = build_scope(conn, cfg, calendar, emp, start, end)
            total_days += len(es.facts)
            persist_attendance_day(conn, es)
            for facts in es.facts:
                for ref in facts.source_refs:
                    if ref.get("file_id") is not None:
                        referenced_files.add(int(ref["file_id"]))
            for issue in es.quality_issues:
                if issue.get("file_id") is not None:
                    referenced_files.add(int(issue["file_id"]))
        with timer("engine.rules"):
            for rule_fn in DAY_RULES:
                findings.extend(rule_fn(es, cfg))

    fingerprint = input_fingerprint(conn, scope, file_ids=referenced_files)

    with timer("engine.unattributed"):
        findings.extend(_unattributed_findings(conn, cfg))

    with timer("engine.dedupe"):
        findings = _dedupe_findings(findings)
        findings.sort(key=lambda f: (f.emp_id, f.work_date or "", f.period_key or "", f.rule_id))
        digest = conclusion_digest(findings)

    counts = {SEV_DEFENSIBLE: 0, SEV_REVIEW: 0, SEV_VIOLATION: 0}
    for f in findings:
        counts[f.severity] += 1

    with transaction(conn):
        conn.execute(
            "INSERT INTO run(run_id, started_at, finished_at, engine_version, rule_pack_version, "
            "input_fingerprint, conclusion_digest, scope_json, notes) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, started.isoformat(), datetime.now(cfg_tz()).isoformat(), ENGINE_VERSION,
             cfg.rule_pack_id, fingerprint, digest, json.dumps(scope, sort_keys=True, ensure_ascii=False),
             notes),
        )
        for f in findings:
            conn.execute(
                "INSERT INTO finding(run_id, rule_id, rule_version, emp_id, work_date, period_key, "
                "severity, metric_json, citation_ids, source_refs, explanation) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                f.as_row(run_id),
            )
            if f.severity in (SEV_REVIEW, SEV_VIOLATION):
                conn.execute(
                    "INSERT INTO review_item(run_id, source_type, source_id, status, note) VALUES(?,?,?,?,?)",
                    (run_id, "finding", f"{f.rule_id}:{f.emp_id}:{f.work_date or f.period_key}",
                     "OPEN", "校验引擎自动开单，待人工复核"),
                )
    append_audit(conn, run_id=run_id, actor=actor, action="check.run",
                 payload={"triple": {"rule_pack_version": cfg.rule_pack_id,
                                     "input_fingerprint": fingerprint, "conclusion_digest": digest},
                          "counts": counts, "findings": len(findings), "employees": len(employees)},
                 ts=started.isoformat(), cfg=cfg)

    for seg, vals in timer.samples().items():
        conn.execute(
            "INSERT INTO span(qid, segment, duration_us, extra_json) VALUES(?,?,?,?)",
            (run_id, seg, int(sum(vals)),
             json.dumps({"calls": len(vals), "samples_us": vals}, ensure_ascii=False)),
        )
    set_meta(conn, RULE_PACK_KEY, cfg.rule_pack_id)
    set_meta(conn, "last_run_id", run_id)

    return CheckOutcome(
        run_id=run_id, findings=findings, input_fingerprint=fingerprint, conclusion_digest=digest,
        counts=counts, elapsed_us=timer.total_us(),
        employees=len(employees), days=total_days,
    )


def _unattributed_findings(conn: sqlite3.Connection, cfg: Config) -> list[Finding]:
    """O-2：归属不到员工的质量问题（表头缺列、员工不存在、emp_id 为空）汇成一条未归属结论。

    旧行为是这类行只存在于 ingest_issue 与举证包 quality_issues.csv，
    既不进 finding 也不开复核单 —— 最该补录的数据反而没人看见。
    """
    rows = conn.execute(
        "SELECT rule_id, severity, COUNT(*) AS c, MIN(file_id) AS file_id, MIN(line_no) AS line_no "
        "FROM ingest_issue "
        "WHERE (emp_id = '' OR emp_id NOT IN (SELECT emp_id FROM employee)) "
        "GROUP BY rule_id, severity ORDER BY c DESC"
    ).fetchall()
    if not rows:
        return []

    counts = {r["rule_id"]: int(r["c"]) for r in rows}
    refs = [{"file_id": int(r["file_id"]), "line_no": int(r["line_no"])}
            for r in rows if r["file_id"] is not None]
    return [Finding(
        rule_id="QUAL-02",
        rule_version=cfg.rule_pack_id,
        emp_id=UNATTRIBUTED,
        severity=SEV_REVIEW,
        explanation=(
            f"本次导入有 {sum(counts.values())} 条质量问题无法归属到具体员工（{counts}）。"
            "这些行未进入事实表，因此相关员工/组织的工时结论不完整；"
            "须修正主数据或表头后重跑。原始行与文件指纹保留，可逐行反查。"
        ),
        citations=["policy.sz.attendance", "law.labor-contract.4"],
        metric={"issue_rule_counts": counts, "line_refs": refs[:5],
                "total_rejected_lines": sum(counts.values())},
        source_refs=refs[:5],
    )]


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """同一 (emp, rule, work_date/period) 只保留一条，防止重复登记造成举证噪声。"""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.emp_id, f.rule_id, f.work_date or "", f.period_key or "")
        prev = seen.get(key)
        if prev is None:
            seen[key] = f
            continue
        # 保留更高级别（同规则同范围不可能有两个不同结论，出现即说明规则写重了）
        order = {SEV_DEFENSIBLE: 1, SEV_REVIEW: 2, SEV_VIOLATION: 3}
        if order[f.severity] > order[prev.severity]:
            seen[key] = f
    return list(seen.values())


def cfg_tz():
    from .util import CN_TZ

    return CN_TZ


def criteria_status(conn: sqlite3.Connection) -> dict:
    """R7 判据冻结状态：冻结日之后的修订必须留痕。"""
    return {
        "rule_pack_version": get_meta(conn, RULE_PACK_KEY, ""),
        "frozen_on": get_meta(conn, CRITERIA_FROZEN_KEY, ""),
        "schema_digest": get_meta(conn, "schema_digest", ""),
        "audit_genesis": get_meta(conn, "audit_genesis", "")[:16],
    }
