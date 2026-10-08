"""F-009 ACL-aware 检索：BM25 + 精确匹配，权限谓词下推到 WHERE/JOIN。

证明「下推」而非「先召回再过滤」的两个抓手：
  1. `RetrievalResult.sql` 里能直接看到 ACL 片段在 WHERE 中（不是 filter 函数）；
  2. `RetrievalResult.candidates` 记录进入打分阶段的**全部** doc_id —— 越权文档
     连候选都进不去，所以 top_k 之后没有任何过滤步骤（测试断言 candidates ∩ denied = ∅）。
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field

from .config import Config
from .kb.acl import Principal, acl_predicate
from .kb.tokenize import expand_query, tokenize
from .observability import Timer
from .util import sha256_hex

K1 = 1.2
B = 0.75

BACKEND_BM25 = "bm25"
BACKEND_EXACT = "exact"
BACKEND_VECTOR = "vector"


@dataclass
class Hit:
    doc_id: str
    score_permille: int
    title: str
    doc_type: str
    category: str
    article_no: str
    source_citation: str
    source_url: str
    issuing_authority: str
    doc_no: str
    effective_from: str
    effective_to: str
    region_code: str
    version: str
    acl_scope: str
    snippet: str

    def as_dict(self) -> dict:
        return dict(self.__dict__)

    @property
    def citation_label(self) -> str:
        base = self.source_citation or self.title
        if self.article_no:
            base = f"{base} {self.article_no}"
        return base


@dataclass
class RetrievalResult:
    hits: list[Hit] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    scored: int = 0
    backend: str = BACKEND_BM25
    degraded_from: str = ""
    sql: str = ""
    params: list = field(default_factory=list)
    elapsed_us: int = 0
    query_tokens: list[str] = field(default_factory=list)
    acl_predicate_sha256: str = ""

    @property
    def zero_recall(self) -> bool:
        return not self.hits


def retrieve(conn: sqlite3.Connection, cfg: Config, principal: Principal, query: str,
             *, top_k: int | None = None, backend: str | None = None,
             timer: Timer | None = None, doc_types: list[str] | None = None) -> RetrievalResult:
    top_k = top_k if top_k is not None else cfg.retrieval_top_k
    backend = backend or cfg.embedding_backend
    own = timer or Timer()
    with own("retrieve"):
        result = _retrieve(conn, cfg, principal, query, top_k=top_k, backend=backend,
                           doc_types=doc_types)
    result.elapsed_us = int(sum(own.samples().get("retrieve", [0])))
    return result


def _retrieve(conn: sqlite3.Connection, cfg: Config, principal: Principal, query: str,
              *, top_k: int, backend: str, doc_types: list[str] | None) -> RetrievalResult:
    if backend == BACKEND_VECTOR:
        # 向量后端需要本地 embedding 模型；未启用时如实降级，不假装命中
        res = _bm25(conn, cfg, principal, query, top_k=top_k, doc_types=doc_types)
        res.degraded_from = BACKEND_VECTOR
        res.backend = BACKEND_BM25
        return res
    if backend == BACKEND_EXACT:
        return _exact(conn, cfg, principal, query, top_k=top_k, doc_types=doc_types)
    return _bm25(conn, cfg, principal, query, top_k=top_k, doc_types=doc_types)


def _acl_sql(conn: sqlite3.Connection, cfg: Config, principal: Principal,
             doc_types: list[str] | None) -> tuple[str, str, list]:
    """构造把 ACL 写进 WHERE 的检索 SQL。返回 (SQL, ACL 谓词, 参数)。"""
    pred, pred_params = acl_predicate(principal, alias="d")
    base = (
        "SELECT d.doc_id AS doc_id, d.title AS title, d.doc_type AS doc_type, "
        "d.category AS category, d.article_no AS article_no, d.source_citation AS source_citation, "
        "d.source_url AS source_url, d.issuing_authority AS issuing_authority, d.doc_no AS doc_no, "
        "d.effective_from AS effective_from, d.effective_to AS effective_to, "
        "d.region_code AS region_code, d.version AS version, d.acl_scope AS acl_scope, "
        "d.body AS body, t.term AS term, t.tf AS tf "
        "FROM kb_doc d JOIN kb_term t ON t.doc_id = d.doc_id "
        f"WHERE {pred}"
    )
    params = list(pred_params)
    if doc_types:
        base += f" AND d.doc_type IN ({','.join('?' * len(doc_types))})"
        params += list(doc_types)
    if cfg.region_code and cfg.region_code != "CN":
        # 地域过滤同样下推：地方口径条目只在本地域可见（CN 为全国通用）
        base += " AND (d.region_code IN (?, 'CN') OR d.region_code = '')"
        params.append(cfg.region_code)
    return base, pred, params


def _bm25(conn: sqlite3.Connection, cfg: Config, principal: Principal, query: str,
          *, top_k: int, doc_types: list[str] | None) -> RetrievalResult:
    q_terms = sorted(set(tokenize(expand_query(query))))
    if not q_terms:
        return RetrievalResult(backend=BACKEND_BM25, query_tokens=[])

    sql, pred, params = _acl_sql(conn, cfg, principal, doc_types)
    pred_params = acl_predicate(principal, alias="d")[1]
    in_clause = ",".join("?" * len(q_terms))
    full_sql = f"{sql} AND t.term IN ({in_clause})"
    rows = conn.execute(full_sql, list(params) + q_terms).fetchall()

    lengths: dict[str, int] = {}
    tf: dict[str, dict[str, int]] = {}
    docs: dict[str, sqlite3.Row] = {}
    for r in rows:
        docs.setdefault(r["doc_id"], r)
        tf.setdefault(r["doc_id"], {})[r["term"]] = int(r["tf"])
        lengths[r["doc_id"]] = lengths.get(r["doc_id"], 0) + int(r["tf"])

    # df 只在「本主体可见集合」上统计：连文档频率都不向无权主体泄露
    df_sql = (
        f"SELECT t.term AS term, COUNT(DISTINCT t.doc_id) AS df FROM kb_term t JOIN kb_doc d "
        f"ON d.doc_id = t.doc_id WHERE {pred} AND t.term IN ({in_clause}) GROUP BY t.term"
    )
    df_rows = conn.execute(df_sql, list(pred_params) + q_terms).fetchall()
    df = {r["term"]: int(r["df"]) for r in df_rows}
    N = len(docs) or 1
    avg_len = (sum(lengths.values()) / len(lengths)) if lengths else 1.0

    scored: list[tuple[float, str]] = []
    for doc_id, per_term in tf.items():
        s = 0.0
        dl = lengths.get(doc_id, 1)
        for term in q_terms:
            f = per_term.get(term, 0)
            if f <= 0:
                continue
            n_q = df.get(term, 0)
            idf = math.log(1 + (N - n_q + 0.5) / (n_q + 0.5))
            s += idf * (f * (K1 + 1)) / (f + K1 * (1 - B + B * dl / avg_len))
        scored.append((s, doc_id))

    scored.sort(key=lambda x: (-x[0], x[1]))
    top = scored[:top_k]
    max_score = scored[0][0] if scored and scored[0][0] > 0 else 1.0
    hits = [
        _hit_of(docs[doc_id], int(round(1000 * score / max_score)) if max_score > 0 else 0)
        for score, doc_id in top if score > 0
    ]
    result = RetrievalResult(
        hits=hits,
        candidates=[doc_id for _, doc_id in sorted(scored, key=lambda x: x[1])],
        scored=len(scored), backend=BACKEND_BM25,
        sql=full_sql, params=list(params) + q_terms,
        query_tokens=q_terms, acl_predicate_sha256=sha256_hex(pred.encode("utf-8")),
    )
    return result


def _exact(conn: sqlite3.Connection, cfg: Config, principal: Principal, query: str,
           *, top_k: int, doc_types: list[str] | None) -> RetrievalResult:
    """精确匹配档：条文号/标题/正文子串。用于「向量不可用时的第二档降级」。"""
    pred, pred_params = acl_predicate(principal, alias="d")
    sql = (
        "SELECT * FROM kb_doc d WHERE " + pred +
        (f" AND d.doc_type IN ({','.join('?' * len(doc_types))})" if doc_types else "")
    )
    params = list(pred_params) + (list(doc_types) if doc_types else [])
    rows = conn.execute(sql, params).fetchall()
    text = query.strip()
    scored: list[tuple[int, sqlite3.Row]] = []
    for r in rows:
        pts = 0
        if r["article_no"] and r["article_no"] in text:
            pts += 6
        if r["title"] and any(part and part in text for part in r["title"].split()):
            pts += 2
        for tok in sorted(set(tokenize(text)), key=len, reverse=True)[:12]:
            if len(tok) >= 2 and tok in r["body"]:
                pts += 1
        if text and text in r["body"]:
            pts += 8
        if pts:
            scored.append((pts, r))
    scored.sort(key=lambda x: (-x[0], x[1]["doc_id"]))
    mx = scored[0][0] if scored else 1
    hits = [_hit_of(r, int(round(1000 * p / mx)) if mx else 0) for p, r in scored[:top_k]]
    return RetrievalResult(
        hits=hits, candidates=[r["doc_id"] for _, r in sorted(scored, key=lambda x: x[1]["doc_id"])],
        scored=len(scored), backend=BACKEND_EXACT, sql=sql, params=params,
        query_tokens=sorted(set(tokenize(text))), acl_predicate_sha256=sha256_hex(pred.encode()),
    )


def _hit_of(r: sqlite3.Row, score: int) -> Hit:
    body = r["body"]
    return Hit(
        doc_id=r["doc_id"], score_permille=int(score), title=r["title"], doc_type=r["doc_type"],
        category=r["category"], article_no=r["article_no"], source_citation=r["source_citation"],
        source_url=r["source_url"], issuing_authority=r["issuing_authority"], doc_no=r["doc_no"],
        effective_from=r["effective_from"], effective_to=r["effective_to"],
        region_code=r["region_code"], version=r["version"], acl_scope=r["acl_scope"],
        snippet=(body[:200] + "…") if len(body) > 200 else body,
    )


def hits_json(hits: list[Hit]) -> str:
    return json.dumps([h.as_dict() for h in hits], ensure_ascii=False, sort_keys=True)
