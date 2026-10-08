"""F-008 知识库构建：读语料 JSONL 入库，并派生「个人数据」条目用于 ACL 验证。

分词器是自带的最简中文切分（CJK 二元组 + ASCII 词），零依赖、可离线、可复现。
向量检索的接入点留在 retrieve.py，本层只保证 term 索引可被任意后端复用。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ..rules.findings import SEV_LABEL_ZH
from ..db import transaction
from ..util import sha256_hex
from .acl import ACL_SELF, parse_acl_orgs
from .tokenize import tokenize

CORPUS_PATH = Path(__file__).resolve().parent / "corpus" / "kb_doc.jsonl"

@dataclass
class KbBuildResult:
    docs: int
    terms: int
    personnel_docs: int
    corpus_sha256: str


REQUIRED_FIELDS = ("doc_id", "doc_type", "title", "body", "source_citation", "version", "acl_scope")


def load_corpus_rows(path: Path | None = None) -> list[dict]:
    p = path or CORPUS_PATH
    rows: list[dict] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        doc = json.loads(line)
        missing = [f for f in REQUIRED_FIELDS if not doc.get(f)]
        if missing:
            raise ValueError(f"语料第 {lineno} 行缺字段 {missing}: {doc.get('doc_id')}")
        rows.append(doc)
    return rows


def _insert_corpus(conn: sqlite3.Connection, rows: list[dict]) -> None:
    for doc in rows:
        conn.execute(
            "INSERT INTO kb_doc(doc_id, doc_type, category, title, article_no, body, source_citation, "
            "source_url, issuing_authority, doc_no, effective_from, effective_to, region_code, version, "
            "acl_scope, acl_org_ids, acl_emp_id, confidence_note, body_sha256) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                doc["doc_id"], doc["doc_type"], doc.get("category", ""), doc["title"],
                doc.get("article_no", ""), doc["body"], doc["source_citation"],
                doc.get("source_url", ""), doc.get("issuing_authority", ""), doc.get("doc_no", ""),
                doc.get("effective_from", ""), doc.get("effective_to", ""),
                doc.get("region_code", "CN"), doc["version"], doc["acl_scope"],
                json.dumps(doc.get("acl_org_ids", []), ensure_ascii=False),
                doc.get("acl_emp_id", ""), doc.get("confidence_note", ""),
                sha256_hex(doc["body"].encode("utf-8")),
            ),
        )
        for org in parse_acl_orgs(doc.get("acl_org_ids", [])):
            conn.execute("INSERT OR IGNORE INTO kb_doc_org(doc_id, org_id) VALUES(?,?)",
                         (doc["doc_id"], org))



def build_kb(conn: sqlite3.Connection, *, corpus_path: Path | None = None,
             include_personnel: bool = True) -> KbBuildResult:
    rows = load_corpus_rows(corpus_path)
    corpus_sha = sha256_hex((corpus_path or CORPUS_PATH).read_bytes())

    with transaction(conn):
        conn.execute("DELETE FROM kb_term")
        conn.execute("DELETE FROM kb_doc_org")
        conn.execute("DELETE FROM kb_doc")
        _insert_corpus(conn, rows)
        personnel = build_personnel_docs(conn) if include_personnel else 0
        terms = index_terms(conn)

    from ..db import set_meta

    set_meta(conn, "kb_corpus_sha256", corpus_sha)
    set_meta(conn, "kb_docs", str(len(rows) + personnel))
    return KbBuildResult(docs=len(rows) + personnel, terms=terms,
                         personnel_docs=personnel, corpus_sha256=corpus_sha)


def build_personnel_docs(conn: sqlite3.Connection) -> int:
    """为每个员工派生两条个人数据条目：考勤汇总（主管可见）与薪酬明细（仅本人）。

    这是 A3 的靶子：非授权主体问「某某的考勤/薪酬」时，这两条必须进不了候选集。
    """
    employees = conn.execute(
        "SELECT emp_id, pseudonym, org_id, region_code, normal_hourly_cents, worktime_regime "
        "FROM employee ORDER BY emp_id"
    ).fetchall()
    created = 0
    for e in employees:
        agg = conn.execute(
            "SELECT COUNT(*) AS days, COALESCE(SUM(minutes_worked),0) AS worked, "
            "COALESCE(SUM(minutes_ot_weekday + minutes_ot_restday + minutes_ot_holiday),0) AS ot, "
            "COALESCE(SUM(minutes_night),0) AS night "
            "FROM attendance_day WHERE emp_id = ?",
            (e["emp_id"],),
        ).fetchone()
        sev = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM finding WHERE emp_id = ? GROUP BY severity",
            (e["emp_id"],),
        ).fetchall()
        sev_txt = "、".join(f"{SEV_LABEL_ZH[r['severity']]}{int(r['c'])}条" for r in sev) or "无"
        months = conn.execute(
            "SELECT DISTINCT substr(work_date,1,7) AS m FROM attendance_day WHERE emp_id = ? "
            "ORDER BY m", (e["emp_id"],),
        ).fetchall()
        month_list = ",".join(r["m"] for r in months)

        att_body = (
            f"员工 {e['emp_id']} 考勤汇总：覆盖月份 {month_list or '无'}；"
            f"有出勤记录 {int(agg['days'])} 天，累计工作 {int(agg['worked'])} 分钟，"
            f"其中认定加班 {int(agg['ot'])} 分钟，夜间时段 {int(agg['night'])} 分钟；"
            f"异常分级：{sev_txt}。工时制 {e['worktime_regime']}。"
        )
        # NFR-18：薪酬类条目只索引「存在且受限」这件事，不索引任何金额数值——
        # 一旦把基数/分位数写进正文，它就可能被召回并随上下文发往外部模型后端。
        pay_body = (
            f"员工 {e['emp_id']} 薪酬明细（受限条目）：本条**不含任何金额数值**；"
            f"加班工资基数与个体薪酬的具体取值由 HR 负责人在复核台具名录入与确认，"
            f"不经检索链路外发。可见性：仅本人与授权薪酬岗。"
        )
        conn.execute(
            "INSERT OR REPLACE INTO kb_doc(doc_id, doc_type, category, title, article_no, body, "
            "source_citation, source_url, issuing_authority, doc_no, effective_from, effective_to, "
            "region_code, version, acl_scope, acl_org_ids, acl_emp_id, confidence_note, body_sha256) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"personnel.attendance.{e['emp_id']}", "personnel_data", "attendance_summary",
             f"考勤汇总 · {e['emp_id']}", "", att_body,
             f"系统内合成考勤数据（员工 {e['emp_id']}），生成种子见 data/generator",
             "", "合成数据", "", "", "", e["region_code"], "v1-合成", ACL_SELF,
             json.dumps([e["org_id"]], ensure_ascii=False), e["emp_id"],
             "合成个人数据：用于验证 ACL 谓词下推", sha256_hex(att_body.encode("utf-8"))),
        )
        conn.execute(
            "INSERT OR REPLACE INTO kb_doc(doc_id, doc_type, category, title, article_no, body, "
            "source_citation, source_url, issuing_authority, doc_no, effective_from, effective_to, "
            "region_code, version, acl_scope, acl_org_ids, acl_emp_id, confidence_note, body_sha256) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"personnel.payroll.{e['emp_id']}", "personnel_data", "payroll_detail",
             f"薪酬明细（受限） · {e['emp_id']}", "", pay_body,
             f"系统内合成薪酬基数（员工 {e['emp_id']}）", "", "合成数据", "", "", "",
             e["region_code"], "v1-合成", ACL_SELF,
             json.dumps([e["org_id"]], ensure_ascii=False), e["emp_id"],
             "合成个人数据：薪酬明细仅本人可见，主管也不可召回",
             sha256_hex(pay_body.encode("utf-8"))),
        )
        conn.execute("INSERT OR IGNORE INTO kb_doc_org(doc_id, org_id) VALUES(?,?)",
                     (f"personnel.attendance.{e['emp_id']}", e["org_id"]))
        conn.execute("INSERT OR IGNORE INTO kb_doc_org(doc_id, org_id) VALUES(?,?)",
                     (f"personnel.payroll.{e['emp_id']}", e["org_id"]))
        created += 2
    return created


def index_terms(conn: sqlite3.Connection) -> int:
    docs = conn.execute("SELECT doc_id, title, article_no, body FROM kb_doc").fetchall()
    total = 0
    for d in docs:
        counts: dict[str, int] = {}
        # 标题与条号权重更高：单独多算一次，让「第44条」这类精确查询能压过泛词
        for tok in tokenize(f"{d['title']} {d['article_no']}") * 2 + tokenize(d["body"]):
            counts[tok] = counts.get(tok, 0) + 1
        for term, tf in counts.items():
            conn.execute("INSERT OR REPLACE INTO kb_term(term, doc_id, tf) VALUES(?,?,?)",
                         (term, d["doc_id"], tf))
            total += 1
    return total


def get_doc(conn: sqlite3.Connection, doc_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM kb_doc WHERE doc_id = ?", (doc_id,)).fetchone()
    if row is None:
        return None
    doc = dict(row)
    doc["acl_org_ids"] = parse_acl_orgs(doc.get("acl_org_ids"))
    return doc


def citation_ids_missing(conn: sqlite3.Connection, doc_ids: list[str]) -> list[str]:
    """规则/评测集引用的 doc_id 必须真的在库里——A2 的结构化保障。"""
    if not doc_ids:
        return []
    placeholders = ",".join("?" * len(doc_ids))
    found = {r["doc_id"] for r in conn.execute(
        f"SELECT doc_id FROM kb_doc WHERE doc_id IN ({placeholders})", doc_ids).fetchall()}
    return [d for d in doc_ids if d not in found]
