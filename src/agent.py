"""F-010 问答 Agent：NL -> 查询计划 ->（ACL 下推检索 + 确定性数值工具）-> 受守卫成文。

三段式职责边界（面试里最容易被拷打的地方，代码结构本身就是答案）：
  1. LLM 只做「意图归类 + 实体抽取 + 把事实叙述成人话」，不参与任何算术；
  2. 所有数字来自 `rules/`（合规校验引擎）与 SQL 聚合（attendance_day / finding）；
  3. 出口再设守卫：答案里的数字必须落在允许集合内，重大事项只解释不给数，
     无出处则拒答，覆盖率或置信度不足则降级为解释并转人工复核。
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field

from . import ENGINE_VERSION
from .config import Config
from .evidence import append_audit
from .guard import allowed_surface, enforce, offenders
from .kb.acl import Principal
from .llm import (LlmUnavailable, Provider, QueryPlan, StubProvider, build_provider,
                    refine_target, render_template)
from .observability import Timer, est_tokens, record_spans
from .retrieve import Hit, RetrievalResult, retrieve
from .rules.findings import SEV_LABEL_ZH
from .rules.quantities import (
    RATE_HOLIDAY_OT_PERMILLE,
    RATE_RESTDAY_OT_PERMILLE,
    RATE_WEEKDAY_OT_PERMILLE,
)
from .util import CN_TZ, round_half_up
from datetime import datetime

RATE_TEXT = {
    RATE_WEEKDAY_OT_PERMILLE: "150%",
    RATE_RESTDAY_OT_PERMILLE: "200%",
    RATE_HOLIDAY_OT_PERMILLE: "300%",
}

MAJOR_INTENTS = ("others_payroll", "others_attendance")


@dataclass
class Citation:
    doc_id: str
    label: str
    title: str
    source_url: str
    effective_from: str
    region_code: str
    version: str
    score_permille: int

    def as_dict(self) -> dict:
        return dict(self.__dict__)

    @property
    def markdown(self) -> str:
        link = f"（[出处]({self.source_url})）" if self.source_url else "（出处见登记页）"
        return f"[{self.doc_id}] {self.label} — {self.title}{link}"


@dataclass
class Answer:
    qid: str
    question: str
    actor_emp_id: str
    intent: str
    answer: str
    gate_decision: str
    confidence_permille: int
    evidence_coverage_permille: int
    needs_review: bool
    citations: list[Citation] = field(default_factory=list)
    numeric_tokens: list[str] = field(default_factory=list)
    allowed_numbers: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    retrieval: dict = field(default_factory=dict)
    provider: str = "stub"
    model: str = ""
    degraded: bool = False
    tier: str = "unknown"
    elapsed_us: int = 0
    review_id: int | None = None

    def as_dict(self) -> dict:
        out = dict(self.__dict__)
        out["citations"] = [c.as_dict() for c in self.citations]
        return out

    @property
    def citation_markdown(self) -> str:
        return "\n".join(c.markdown for c in self.citations) or "（本次无可引用出处）"


class ComplianceAgent:
    def __init__(self, conn: sqlite3.Connection, cfg: Config,
                 provider: Provider | None = None) -> None:
        self.conn = conn
        self.cfg = cfg
        self.provider = provider or build_provider(cfg)
        self._fallback = StubProvider("stub-offline-v1")
        self._plan_degraded = False

    # ---------------------------------------------------------------- 主入口
    def ask(self, question: str, *, actor_emp_id: str, doc_types: list[str] | None = None,
            top_k: int | None = None) -> Answer:
        timer = Timer()
        asked_at = datetime.now(CN_TZ).isoformat()
        with timer("auth"):
            principal = Principal.from_db(self.conn, actor_emp_id)
        with timer("plan"):
            plan = refine_target(self._plan(question, actor_emp_id), question,
                                 self._known_emp_ids())

        # 1) 越权类问题：候选集由 ACL 决定，命中不到就是命中不到
        retrieval: RetrievalResult = retrieve(
            self.conn, self.cfg, principal, question, top_k=top_k, doc_types=doc_types, timer=timer
        )
        denied = plan.intent in MAJOR_INTENTS or plan.about_other
        tool_calls: list[dict] = []
        facts: list[dict] = []

        # 2) 确定性数值工具（只有本人有权看自己的数据；他人数据一律不查）
        if not denied and plan.intent in ("overtime_calc", "anomaly_lookup", "evidence_export"):
            numeric = with_timer(
                timer,
                lambda: self._numeric_tool(plan, actor_emp_id, period=plan.period),
                "tool_numeric",
            )
            tool_calls.append(numeric["call"])
            facts.extend(numeric["facts"])
        elif not denied:
            tool_calls.append({"tool": "none", "reason": "policy_question 不需要数值工具"})

        for hit in retrieval.hits:
            facts.append({
                "kind": "citation", "doc_id": hit.doc_id, "text": hit.snippet,
                "citation": hit.citation_label, "source_url": hit.source_url,
                "effective_from": hit.effective_from, "region_code": hit.region_code,
                "version": hit.version,
            })

        if denied:
            facts.insert(0, {
                "kind": "acl_denied",
                "text": "该问题指向他人的人事数据。检索层已按主体权限下推过滤，"
                        "未授权条目不进入候选集，因此本次召回 0 条（不是在生成之后删除的）。",
            })

        citations = [
            Citation(doc_id=h.doc_id, label=h.citation_label, title=h.title,
                     source_url=h.source_url, effective_from=h.effective_from,
                     region_code=h.region_code, version=h.version, score_permille=h.score_permille)
            for h in retrieval.hits
        ]

        # 3) 成文 + 守卫
        allowed = allowed_surface(facts)
        with timer("compose"):
            text, provider_name, model, degraded, tok_in, tok_out = self._compose(
                question, plan, facts, allowed)
        degraded = degraded or self._plan_degraded

        numeric_ok = _numeric_backed(plan, facts)
        coverage = _coverage(facts)
        confidence = _confidence(retrieval, coverage, numeric_ok, denied=denied)
        major = _is_major(question, plan)

        guarded = enforce(
            text, facts=facts, major_matter=major, citations_ok=bool(citations) or denied,
            confidence_permille=confidence, threshold_permille=self.cfg.confidence_threshold,
            coverage_permille=coverage, min_coverage_permille=self.cfg.min_evidence_coverage,
        )
        # 拒答优先级：指向他人敏感数据的提问，一律 ACL 拒答，且不带任何数值事实
        if denied:
            guarded.answer = _acl_refusal_text(plan, self.cfg)
            guarded.gate_decision = "REFUSED_ACL"
            guarded.ok = False
            guarded.violations.insert(0, f"越权请求：他人{'薪酬' if plan.intent == 'others_payroll' else '考勤'}"
                                      f"（target={plan.target_emp_id}），检索层对该主体零召回")

        needs_review = guarded.gate_decision in (
            "EXPLAIN_ONLY", "ESCALATED", "REFUSED_NO_EVIDENCE", "REFUSED_ACL")
        with timer("persist"):
            answer = self._persist(
                qid=f"q-{datetime.now(CN_TZ).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}",
                asked_at=asked_at, question=question, plan=plan, actor_emp_id=actor_emp_id,
                text=guarded.answer, gate=guarded.gate_decision, confidence=confidence,
                coverage=coverage, citations=citations, allowed=sorted(allowed),
                found=guarded.numbers_found, violations=guarded.violations, tool_calls=tool_calls,
                retrieval=retrieval, provider=provider_name, model=model, degraded=degraded,
                needs_review=needs_review, timer=timer, tokens_in=tok_in, tokens_out=tok_out,
            )
        return answer

    # ---------------------------------------------------------------- 内部件
    def _known_emp_ids(self) -> list[str]:
        cache = getattr(self, "_emp_ids_cache", None)
        if cache is None:
            cache = [r["emp_id"] for r in self.conn.execute("SELECT emp_id FROM employee").fetchall()]
            self._emp_ids_cache = cache
        return cache

    def _plan(self, question: str, actor_emp_id: str) -> QueryPlan:
        try:
            return self.provider.plan(question, subject_emp_id=actor_emp_id)
        except LlmUnavailable:
            # 意图分类阶段的降级也要留痕：只标成文阶段的降级会让"模型其实没参与路由"这件事被掩盖
            self._plan_degraded = True
            return self._fallback.plan(question, subject_emp_id=actor_emp_id)

    def _compose(self, question: str, plan: QueryPlan, facts: list[dict],
                 allowed: set[str]) -> tuple[str, str, str, bool, int, int]:
        try:
            comp = self.provider.compose(question, plan, facts, allowed)
            text = comp.text or ""
            if comp.provider == self._fallback.name:
                return text, comp.provider, comp.model, comp.degraded, comp.tokens_in, comp.tokens_out
            bad = offenders(text, allowed)
            if bad:
                # provider 擅自造数：立刻退回模板成文，并把违规写进 violations（由 enforce 处理）
                text = render_template(plan, facts)
                text = text + "\n（注：模型输出含未授权数字，已退回确定性模板成文）"
                return text, comp.provider, comp.model, True, comp.tokens_in, comp.tokens_out
            return text, comp.provider, comp.model, False, comp.tokens_in, comp.tokens_out
        except LlmUnavailable:
            comp = self._fallback.compose(question, plan, facts, allowed)
            return (comp.text, self._fallback.name, self._fallback.model, True,
                    comp.tokens_in, comp.tokens_out)

    def _numeric_tool(self, plan: QueryPlan, actor_emp_id: str, *, period: str = "") -> dict:
        """从最近一次校验运行里取该员工本人的确定性结论。SQL 只做聚合，不做算术判断。"""
        run = self.conn.execute(
            "SELECT run_id, rule_pack_version, conclusion_digest FROM run ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        call = {
            "tool": "attendance_summary", "emp_id": actor_emp_id, "period": period,
            "run_id": run["run_id"] if run else None,
        }
        if run is None:
            return {
                "call": {**call, "ok": False, "reason": "尚未执行过校验运行"},
                "facts": [{"kind": "note", "text": "尚未执行校验运行，没有可引用的数值结论。"}],
            }

        where = "run_id = ? AND emp_id = ?"
        params: list = [run["run_id"], actor_emp_id]
        if period:
            if len(period) == 7:
                where += " AND (work_date LIKE ? OR period_key = ?)"
                params += [f"{period}%", period]
            elif len(period) == 4:
                where += " AND (work_date LIKE ? OR period_key LIKE ?)"
                params += [f"{period}%", f"{period}%"]

        rows = self.conn.execute(
            f"SELECT rule_id, work_date, period_key, severity, metric_json, citation_ids, "
            f"explanation FROM finding WHERE {where} ORDER BY work_date, rule_id", params
        ).fetchall()

        agg = self.conn.execute(
            "SELECT COALESCE(SUM(minutes_worked),0) AS worked, "
            "COALESCE(SUM(minutes_ot_weekday),0) AS ot_weekday, "
            "COALESCE(SUM(minutes_ot_restday),0) AS ot_rest, "
            "COALESCE(SUM(minutes_ot_holiday),0) AS ot_holiday, "
            "COALESCE(SUM(minutes_night),0) AS night, COUNT(*) AS days "
            "FROM attendance_day WHERE emp_id = ? "
            + ("AND substr(work_date,1,7) = ?" if period and len(period) == 7 else
               "AND substr(work_date,1,4) = ?" if period and len(period) == 4 else ""),
            [actor_emp_id] + ([period] if period else []),
        ).fetchone()

        facts: list[dict] = []
        if agg and int(agg["days"]) > 0:
            facts.append({
                "kind": "numeric", "label": "本人统计口径",
                "value_text": _hours_text(int(agg["worked"]), int(agg["ot_weekday"]),
                                          int(agg["ot_rest"]), int(agg["ot_holiday"])),
                "minutes_worked": int(agg["worked"]), "minutes_ot_weekday": int(agg["ot_weekday"]),
                "minutes_ot_restdays": int(agg["ot_rest"]), "minutes_ot_holiday": int(agg["ot_holiday"]),
                "days": int(agg["days"]), "period": period or "全部已入库区间",
                "rule_id": "SQL:attendance_day", "rule_version": run["rule_pack_version"],
            })
        for r in rows:
            metric = json.loads(r["metric_json"])
            rate = int(metric.get("rate_permille", 0))
            facts.append({
                "kind": "numeric", "label": f"{r['rule_id']} @ {r['work_date'] or r['period_key']}",
                "value_text": _metric_text(metric),
                "rule_id": r["rule_id"], "rule_version": run["rule_pack_version"],
                "rate_permille": rate, "rate_text": RATE_TEXT.get(rate, ""),
                "severity": r["severity"], "severity_label": SEV_LABEL_ZH[r["severity"]],
                "minutes_extension": int(metric.get("minutes_extension",
                                                    metric.get("minutes_holiday",
                                                               metric.get("minutes_restdays",
                                                                          metric.get("minutes_over", 0))))),
                "citations": json.loads(r["citation_ids"]),
            })
        call = {**call, "ok": True, "findings": len(rows), "days": int(agg["days"]) if agg else 0,
                "conclusion_digest": run["conclusion_digest"][:16]}
        if not facts:
            facts.append({"kind": "note",
                          "text": "该区间没有命中的合规结论，也没有可汇总的出勤记录。"})
        return {"call": call, "facts": facts}

    def _persist(self, **kw) -> Answer:
        timer: Timer = kw["timer"]
        qid = kw["qid"]
        needs_review = kw["needs_review"]
        review_id = None
        self.conn.execute(
            "INSERT INTO question_log(qid, asked_at, actor_emp_id, question, intent, tier, answer, "
            "confidence_permille, evidence_coverage_permille, gate_decision, needs_review, "
            "citation_ids, numeric_tokens, allowed_numbers, provider, model, tokens_in_est, "
            "tokens_out_est, tool_calls_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                qid, kw["asked_at"], kw["actor_emp_id"], kw["question"], kw["plan"].intent,
                _tier_of(kw["plan"].intent, bool(kw["retrieval"].hits)), kw["text"],
                kw["confidence"], kw["coverage"], kw["gate"], int(needs_review),
                json.dumps([c.doc_id for c in kw["citations"]], ensure_ascii=False),
                json.dumps(kw["found"], ensure_ascii=False),
                json.dumps(kw["allowed"][:200], ensure_ascii=False),
                kw["provider"], kw["model"], int(kw["tokens_in"]), int(kw["tokens_out"]),
                json.dumps(kw["tool_calls"], ensure_ascii=False),
            ),
        )
        timer.add("total", int(timer.total_us()))
        record_spans(self.conn, qid, timer)
        if needs_review:
            cur = self.conn.execute(
                "INSERT INTO review_item(source_type, source_id, status, note) VALUES('answer', ?, 'OPEN', ?)",
                (qid, "问答门禁自动开单：需人工复核后回复员工"),
            )
            review_id = int(cur.lastrowid)
        append_audit(
            self.conn, run_id=None, actor=f"employee:{kw['actor_emp_id']}", action="agent.answer",
            payload={"qid": qid, "intent": kw["plan"].intent, "gate": kw["gate"],
                     "confidence_permille": kw["confidence"],
                     "evidence_coverage_permille": kw["coverage"],
                     "citations": [c.doc_id for c in kw["citations"]],
                     "violations": kw["violations"], "provider": kw["provider"],
                     "engine_version": ENGINE_VERSION},
            ts=kw["asked_at"], cfg=self.cfg,
        )
        return Answer(
            qid=qid, question=kw["question"], actor_emp_id=kw["actor_emp_id"],
            intent=kw["plan"].intent, answer=kw["text"], gate_decision=kw["gate"],
            confidence_permille=kw["confidence"], evidence_coverage_permille=kw["coverage"],
            needs_review=needs_review, citations=kw["citations"], numeric_tokens=kw["found"],
            allowed_numbers=kw["allowed"][:200], violations=kw["violations"],
            tool_calls=kw["tool_calls"],
            retrieval={
                "backend": kw["retrieval"].backend,
                "degraded_from": kw["retrieval"].degraded_from,
                "scored": kw["retrieval"].scored,
                "candidates": kw["retrieval"].candidates,
                "hit_doc_ids": [c.doc_id for c in kw["citations"]],
                "acl_predicate_sha256": kw["retrieval"].acl_predicate_sha256,
                "sql_contains_acl": ("acl_scope" in kw["retrieval"].sql),
            },
            provider=kw["provider"], model=kw["model"], degraded=kw["degraded"],
            tier=_tier_of(kw["plan"].intent, bool(kw["retrieval"].hits)),
            elapsed_us=timer.total_us(), review_id=review_id,
        )


def with_timer(timer: Timer, fn, segment: str):
    with timer(segment):
        return fn()


def _hours_text(worked: int, ot_w: int, ot_r: int, ot_h: int) -> str:
    return (f"出勤 {worked} 分钟；其中工作日延长 {ot_w} 分钟、休息日 {ot_r} 分钟、"
            f"法定节假日 {ot_h} 分钟")


def _metric_text(metric: dict) -> str:
    parts = []
    for key in ("minutes_extension", "minutes_restdays", "minutes_holiday", "minutes_over",
                "minutes_worked"):
        if key in metric:
            parts.append(f"{key}={metric[key]}")
    if "counting_scope" in metric:
        parts.append(f"口径={metric['counting_scope']}")
    return "、".join(parts) if parts else "无数值指标"


def _numeric_backed(plan: QueryPlan, facts: list[dict]) -> bool:
    if plan.intent not in ("overtime_calc", "anomaly_lookup"):
        return True
    return any(f.get("kind") == "numeric" for f in facts)


def _coverage(facts: list[dict]) -> int:
    """证据覆盖率：结论性事实条目中，能挂上出处或来自确定性工具的占比（千分位）。"""
    claims = [f for f in facts if f.get("kind") in ("citation", "numeric", "acl_denied")]
    if not claims:
        return 0
    backed = [f for f in claims if f.get("kind") == "citation" or f.get("citations")
              or f.get("kind") == "acl_denied" or f.get("rule_id")]
    return round_half_up(1000 * len(backed), len(claims))


def _confidence(retrieval: RetrievalResult, coverage_permille: int, numeric_ok: bool,
                *, denied: bool) -> int:
    """置信度口径（写死，便于复述）：检索强度 40% + 证据覆盖率 30% + 数值可溯 30%。

    越权问题不套用该公式：召回为 0 是预期行为，直接给满分拒绝置信 1000‰ 走拒答分支。
    """
    if denied:
        return 1000 if retrieval.zero_recall else 400
    top = max((h.score_permille for h in retrieval.hits), default=0)
    return round_half_up(400 * top + 300 * coverage_permille
                         + 300 * (1000 if numeric_ok else 0), 1000)


def _is_major(question: str, plan: QueryPlan) -> bool:
    from .guard import MAJOR_MATTER_RE

    return bool(MAJOR_MATTER_RE.search(question)) or plan.want_amount and plan.intent in (
        "overtime_calc", "anomaly_lookup")


def _acl_refusal_text(plan: QueryPlan, cfg: Config) -> str:
    return (
        f"无法回答：该问题指向 {plan.target_emp_id or '其他员工'} 的"
        f"{'薪酬' if plan.intent == 'others_payroll' else '考勤'}数据。\n"
        "本次检索在 SQL 的 WHERE/JOIN 里就带上了权限谓词（acl_scope 与归属组织、本人标识），"
        "未授权的条目根本没有进入候选集，所以不存在『先生成再删除』的窗口。\n"
        "依据：policy.sz.data-access、policy.sz.compensation-confidential（合成制度）；"
        "《个人信息保护法》第十三条（人力资源管理所必需）与第二十九条（敏感信息单独同意）。\n"
        "如确需查询他人数据，请由该员工的直属主管在其账号下发起，或走人工复核授权。"
    )


def _tier_of(intent: str, has_hits: bool) -> str:
    if intent in ("overtime_calc", "anomaly_lookup"):
        return "numeric" if has_hits else "numeric_no_recall"
    if intent in MAJOR_INTENTS:
        return "acl"
    if intent == "evidence_export":
        return "mixed"
    return "retrieval"


def answer_from_log(conn: sqlite3.Connection, qid: str) -> dict | None:
    row = conn.execute("SELECT * FROM question_log WHERE qid = ?", (qid,)).fetchone()
    return dict(row) if row else None
