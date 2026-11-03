"""F-006 异常检测与分级：把逐条 Finding 汇成人能读的异常清单 + 复核闭环。

每条异常必须能回答三件事：触发了哪条规则 ID、算出这个结论用了哪些数、原始数据在哪一行。
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .config import Config
from .db import Connection, transaction_if_needed
from .evidence import append_audit
from .rules.findings import SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION, SEV_LABEL_ZH, SEV_RANK
from .util import CN_TZ, csv_safe_row


@dataclass
class AnomalyItem:
    emp_id: str
    pseudonym: str
    work_date: str | None
    period_key: str | None
    severity: str
    rule_ids: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    source_refs: list[dict] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    review_id: str | None = None

    @property
    def severity_label(self) -> str:
        return SEV_LABEL_ZH[self.severity]

    def as_row(self) -> list[str]:
        return [
            self.emp_id, self.pseudonym, self.work_date or "", self.period_key or "",
            self.severity, self.severity_label, "|".join(self.rule_ids), "|".join(self.citations),
            json.dumps(self.metrics, ensure_ascii=False, sort_keys=True),
            ";".join(f"{r.get('rel_path','')}:{r.get('line_no','')}" for r in self.source_refs),
            " / ".join(self.explanations),
        ]


HEADER = ["emp_id", "pseudonym", "work_date", "period_key", "severity", "分级",
          "触发规则ID", "条文依据", "指标(整数分/分钟)", "行级来源", "解释"]


def build_anomalies(conn: Connection, run_id: str) -> list[AnomalyItem]:
    rows = conn.execute(
        # LEFT JOIN：O-2 之后存在「未归属」结论（表头缺列、员工不存在等），
        # 用 INNER JOIN 会把它们从异常报表里悄悄丢掉。
        "SELECT f.*, COALESCE(e.pseudonym, '(未归属)') AS pseudonym FROM finding f "
        "LEFT JOIN employee e ON e.emp_id = f.emp_id "
        "WHERE f.run_id = ? ORDER BY f.emp_id, f.work_date, f.period_key, f.rule_id",
        (run_id,),
    ).fetchall()
    grouped: dict[tuple, AnomalyItem] = {}
    for r in rows:
        key = (r["emp_id"], r["work_date"], r["period_key"])
        item = grouped.get(key)
        if item is None:
            item = AnomalyItem(
                emp_id=r["emp_id"], pseudonym=r["pseudonym"], work_date=r["work_date"],
                period_key=r["period_key"], severity=r["severity"],
            )
            grouped[key] = item
        item.rule_ids.append(r["rule_id"])
        item.citations.extend(json.loads(r["citation_ids"]))
        item.metrics[r["rule_id"]] = json.loads(r["metric_json"])
        item.explanations.append(r["explanation"])
        for ref in _with_rel_path(conn, json.loads(r["source_refs"])):
            if ref not in item.source_refs:
                item.source_refs.append(ref)
        if SEV_RANK[r["severity"]] > SEV_RANK[item.severity]:
            item.severity = r["severity"]

    out = sorted(grouped.values(), key=lambda i: (-SEV_RANK[i.severity], i.emp_id,
                                                  i.work_date or "", i.period_key or ""))
    review_ids = {r["source_id"]: str(r["review_id"]) for r in conn.execute(
        "SELECT review_id, source_id FROM review_item WHERE run_id = ? AND source_type = 'finding'",
        (run_id,),
    ).fetchall()}
    for item in out:
        for rid in item.rule_ids:
            key = f"{rid}:{item.emp_id}:{item.work_date or item.period_key}"
            if key in review_ids:
                item.review_id = review_ids[key]
    return out


def _with_rel_path(conn: Connection, refs: list[dict]) -> list[dict]:
    out = []
    for ref in refs:
        fid = ref.get("file_id")
        rel = ""
        if fid is not None:
            row = conn.execute("SELECT rel_path FROM raw_file WHERE file_id = ?", (fid,)).fetchone()
            rel = row["rel_path"] if row else ""
        out.append({"file_id": fid, "line_no": ref.get("line_no"), "rel_path": rel})
    return out


def severity_rollup(anomalies: list[AnomalyItem]) -> dict[str, int]:
    counts = {SEV_DEFENSIBLE: 0, SEV_REVIEW: 0, SEV_VIOLATION: 0}
    for a in anomalies:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    counts["异常条目合计"] = len(anomalies)
    return counts


def rule_hit_counts(conn: Connection, run_id: str) -> list[dict]:
    # 同一 run 内同一规则/分级按一组统计；rule_version 用 MAX 聚合，既满足 PG 的
    # GROUP BY 要求，又不改变既有分组行数与“一行一规则/分级”的口径。
    rows = conn.execute(
        "SELECT rule_id, MAX(rule_version) AS rule_version, severity, COUNT(*) AS c "
        "FROM finding WHERE run_id = ? "
        "GROUP BY rule_id, severity ORDER BY c DESC, rule_id, severity",
        (run_id,),
    ).fetchall()
    return [{"rule_id": r["rule_id"], "rule_version": r["rule_version"], "severity": r["severity"],
             "count": int(r["c"])} for r in rows]


def worst_streak(conn: Connection, run_id: str, severity: str = SEV_VIOLATION) -> dict:
    """连续触发同一级别异常的最长天数（严格按日历相邻日计）——
    面试里「你怎么证明不是碰巧一条」的那块证据。"""
    rows = conn.execute(
        "SELECT emp_id, work_date FROM finding WHERE run_id = ? AND severity = ? AND work_date IS NOT NULL",
        (run_id, severity),
    ).fetchall()
    by_emp: dict[str, list[str]] = {}
    for r in rows:
        by_emp.setdefault(r["emp_id"], []).append(r["work_date"])

    best = {"emp_id": "", "days": 0, "from": "", "to": "", "severity": severity}
    for emp, raw_dates in by_emp.items():
        dates = sorted(set(raw_dates))
        cur_start = cur_prev = dates[0]
        cur_len = 1
        emp_best = (1, dates[0], dates[0])
        for d in dates[1:]:
            gap = (datetime.fromisoformat(d).date() - datetime.fromisoformat(cur_prev).date()).days
            if gap == 1:
                cur_len += 1
            else:
                cur_start, cur_len = d, 1
            cur_prev = d
            if cur_len > emp_best[0]:
                emp_best = (cur_len, cur_start, d)
        if emp_best[0] > best["days"]:
            best = {"emp_id": emp, "days": emp_best[0], "from": emp_best[1],
                    "to": emp_best[2], "severity": severity}
    return best


def write_anomaly_report(conn: Connection, cfg: Config, run_id: str,
                         path: Path | None = None) -> Path:
    """写异常报表：先落同目录临时文件，成功后 os.replace 原子替换目标。

    失败时旧文件保持不变，也不会留下半截 CSV；调用方不能只凭 rc 判断有没有产物。
    """
    anomalies = build_anomalies(conn, run_id)
    out = path or (cfg.reports_dir / f"异常报表-{run_id}.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", suffix=".tmp",
                                    dir=str(out.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        with tmp.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(HEADER)
            for a in anomalies:
                w.writerow(csv_safe_row(a.as_row()))
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return out


def decide_review(conn: Connection, cfg: Config, review_id: int, reviewer: str,
                  decision: str, note: str, *, amount_cents: int | None = None) -> dict:
    """人工复核门禁。REVIEW/VIOLATION 结论必须有复核记录才算闭环（audit 追加，不改历史）。

    `amount_cents` 是**人工录入**的应付金额（分）：引擎不产出金额（需求 D-03），
    金额只能由具名的 HR 负责人录进复核单，并且永不进入问答链与送云上下文。
    """
    if decision not in ("APPROVED", "REJECTED", "NEEDS_MORE_DATA"):
        raise ValueError(f"非法复核结论: {decision}")
    if amount_cents is not None:
        if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
            raise ValueError("金额必须是整数分（int），不接受浮点或其它类型")
        if amount_cents < 0:
            raise ValueError("金额不得为负")
    row = conn.execute("SELECT * FROM review_item WHERE review_id = ?", (review_id,)).fetchone()
    if row is None:
        raise ValueError(f"未知 review_id: {review_id}")
    if row["decided_at"]:
        raise ValueError(f"review_id={review_id} 已有复核结论，不得覆盖（只允许追加新单）")
    ts = datetime.now(CN_TZ).isoformat()
    with transaction_if_needed(conn):
        conn.execute(
            "UPDATE review_item SET status = ?, reviewer = ?, decided_at = ?, note = ?, "
            "amount_cents_input = ?, amount_entered_by = ?, amount_entered_at = ? WHERE review_id = ?",
            (decision, reviewer, ts, note, amount_cents,
             f"human:{reviewer}" if amount_cents is not None else None,
             ts if amount_cents is not None else None, review_id),
        )
        seq, entry = append_audit(
            conn, run_id=row["run_id"], actor=f"human:{reviewer}", action="review.decision",
            payload={"review_id": review_id, "source_type": row["source_type"],
                     "source_id": row["source_id"], "decision": decision, "note": note,
                     # 金额进审计链是**人工录入**的记录（谁录的、何时），不是引擎输出
                     "amount_cents_input": amount_cents},
            ts=ts, cfg=cfg,
        )
    return {"review_id": review_id, "decision": decision, "audit_seq": seq, "entry_hash": entry}


def review_queue(conn: Connection, *, run_id: str | None = None,
                 only_open: bool = True, limit: int = 200) -> list[dict]:
    """复核台队列：结论 + 条文 + 行级来源 + 已有复核记录，一条查询取全（视图②的数据源）。"""
    where = ["r.status = 'OPEN'"] if only_open else ["1=1"]
    params: list = []
    if run_id:
        where.append("r.run_id = ?")
        params.append(run_id)
    params.append(int(limit))
    rows = conn.execute(
        f"""SELECT r.review_id, r.run_id, r.source_type, r.source_id, r.status, r.reviewer,
                   r.decided_at, r.note, r.amount_cents_input, r.amount_entered_by,
                   f.rule_id, f.rule_version, f.emp_id, f.work_date, f.period_key,
                   f.severity, f.explanation, f.citation_ids, f.source_refs,
                   f.metric_json,
                   e.pseudonym, e.region_code
            FROM review_item r
            LEFT JOIN finding f
                   ON f.run_id = r.run_id AND r.source_type = 'finding'
                  AND (f.rule_id || ':' || f.emp_id || ':' ||
                       COALESCE(f.work_date, f.period_key, 'None') = r.source_id
                    OR f.rule_id || ':' || f.emp_id || ':' ||
                       COALESCE(f.work_date, f.period_key, '') = r.source_id)
            LEFT JOIN employee e ON e.emp_id = f.emp_id
            WHERE {' AND '.join(where)}
            ORDER BY r.review_id DESC LIMIT ?""",
        params).fetchall()
    return [dict(r) for r in rows]


def review_backlog(conn: Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT run_id, COUNT(*) AS c FROM review_item WHERE status = 'OPEN' GROUP BY run_id ORDER BY c DESC"
    ).fetchall()
    return [{"run_id": r["run_id"], "open_items": int(r["c"])} for r in rows]
