"""F-010 问答 Agent + A1（数值不由 LLM 计算）+ A4（错承诺 0 条）。

这里的测试对象是**门禁本身**：故意造一个「模型擅自算钱」的 provider，
断言系统必须拦住它，而不是信任模型自觉。
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from conftest import load_base, punch, schedule
from src.agent import ComplianceAgent
from src.db import connect
from src.engine import run_check
from src.guard import allowed_surface, enforce, numbers_in, offenders
from src.ingest import import_rows
from src.kb import build_kb
from src.llm import Completion, QueryPlan


@pytest.fixture
def agent_db(conn, cfg):
    load_base(conn, cfg)
    import_rows(conn, cfg, "schedule", [
        schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
                 "2025-09-02T19:00:00+08:00")], rel_path="inline://ag-sched")
    import_rows(conn, cfg, "punch", [
        punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
        punch("T-STD", "2025-09-02T19:00:00+08:00", "out")], rel_path="inline://ag-punch")
    build_kb(conn, include_personnel=True)
    run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))
    return conn, cfg


def test_self_overtime_answer_is_numeric_and_backed(agent_db):
    conn, cfg = agent_db
    ans = ComplianceAgent(conn, cfg).ask("我 2025-09 加班多少小时", actor_emp_id="T-STD")
    assert ans.intent == "overtime_calc"
    assert ans.gate_decision == "ANSWERED"
    assert "60" in ans.answer
    assert ans.evidence_coverage_permille >= cfg.min_evidence_coverage
    assert ans.citations, "结论必须带可点开出处"
    assert any("rules" in (t.get("tool", "")) or "attendance" in str(t.get("tool", ""))
               or t.get("tool") == "attendance_summary" for t in ans.tool_calls)


def test_major_matter_never_gets_final_amount(agent_db):
    """A4：重大事项只解释规则，不给最终数额承诺。"""
    conn, cfg = agent_db
    ans = ComplianceAgent(conn, cfg).ask("我上月加班该付多少钱", actor_emp_id="T-STD")
    assert ans.gate_decision in ("EXPLAIN_ONLY", "ESCALATED")
    assert "系统不给出最终数额" in ans.answer or "非最终" in ans.answer
    assert ans.needs_review is True
    # 关键：即便测算明细里存在金额，也不得出现在答案中
    assert "4500 分" not in ans.answer
    assert ans.review_id is not None


def test_llm_cannot_invent_numbers(agent_db):
    """A1：模型输出含未授权数字时，必须被退回模板成文并被门禁记录。"""

    class RogueProvider:
        name = "cloud"

        def plan(self, question, *, subject_emp_id):
            return QueryPlan(intent="overtime_calc", subject_emp_id=subject_emp_id,
                             target_emp_id=subject_emp_id, period="2025-09")

        def compose(self, question, plan, facts, allowed_numbers):
            return Completion(text="你应当获得加班费 99999 元，公司违法了。",
                              provider="cloud", model="rogue", tokens_in=10, tokens_out=20)

    conn, cfg = agent_db
    agent = ComplianceAgent(conn, cfg, provider=RogueProvider())
    ans = agent.ask("我 2025-09 加班费多少钱", actor_emp_id="T-STD")
    assert "99999" not in ans.answer, "未授权数字泄漏到答案 = A1 红线破裂"
    assert ans.gate_decision in ("ESCALATED", "EXPLAIN_ONLY")
    assert ans.needs_review
    assert ans.degraded or any("白名单" in v or "未授权数字" in v
                              for v in ans.violations) or "未授权数字" in ans.answer


def test_no_evidence_means_no_answer(agent_db):
    conn, cfg = agent_db
    cfg.allow_generation_without_retrieval = False
    conn.execute("DELETE FROM kb_doc")
    conn.execute("DELETE FROM kb_term")
    ans = ComplianceAgent(conn, cfg).ask("年终奖发放规则是什么", actor_emp_id="T-STD")
    assert ans.gate_decision in ("REFUSED_NO_EVIDENCE", "EXPLAIN_ONLY")
    assert "证据不足" in ans.answer or "不作结论" in ans.answer


def test_acl_question_is_refused_not_filtered(agent_db):
    conn, cfg = agent_db
    ans = ComplianceAgent(conn, cfg).ask("T-OTHER 的薪酬明细是多少", actor_emp_id="T-STD")
    assert ans.intent == "others_payroll"
    assert ans.gate_decision == "REFUSED_ACL"
    assert "personnel.payroll.T-OTHER" not in ans.retrieval["candidates"]
    assert "personnel.payroll.T-OTHER" not in ans.retrieval["hit_doc_ids"]
    assert "7777" not in ans.answer, "他人薪酬数字绝不出现在答案里"


def test_answer_numbers_are_all_traceable(agent_db):
    """A1 的正向证明：答案中的每个数字都能在允许集合里找到。"""
    conn, cfg = agent_db
    agent = ComplianceAgent(conn, cfg)
    for q in ("我 2025-09 加班多少小时", "法定节假日加班按几倍支付", "补卡要走什么流程"):
        ans = agent.ask(q, actor_emp_id="T-STD")
        allowed = set(ans.allowed_numbers)
        bad = [n for n in numbers_in(ans.answer) if n not in allowed
               and not all(p in allowed for p in n.replace("/", "-").split("-") if p)]
        assert not bad, f"{q} 的答案含不可溯数字 {bad}"


def test_question_and_spans_are_logged(agent_db):
    conn, cfg = agent_db
    ans = ComplianceAgent(conn, cfg).ask("综合计算工时怎么算周期超额", actor_emp_id="T-STD")
    row = conn.execute("SELECT * FROM question_log WHERE qid = ?", (ans.qid,)).fetchone()
    assert row and row["gate_decision"] == ans.gate_decision
    segs = {r["segment"] for r in conn.execute("SELECT segment FROM span WHERE qid = ?",
                                               (ans.qid,)).fetchall()}
    assert {"plan", "retrieve", "compose"} <= segs
    assert conn.execute("SELECT COUNT(*) AS c FROM audit_event WHERE action='agent.answer'"
                        ).fetchone()["c"] >= 1


# ------------------------------------------------------------------ 守卫单元
def test_offenders_detects_unauthorized_amounts():
    facts = [{"kind": "numeric", "estimate_cents": 4500, "minutes_extension": 60}]
    allowed = allowed_surface(facts)
    assert offenders("应付 45 元，延长 60 分钟", allowed) == []
    assert offenders("应付 1200 元", allowed) == ["1200"]


def test_enforce_blocks_when_coverage_too_low():
    facts = [{"kind": "citation", "text": "x", "citation": "y"}]
    # 答案不含数字，确保这里失败的原因只可能是覆盖率/置信度门禁
    res = enforce("只解释规则，不给数字", facts=facts, major_matter=False, citations_ok=True,
                  confidence_permille=100, threshold_permille=700,
                  coverage_permille=200, min_coverage_permille=800)
    assert res.gate_decision == "EXPLAIN_ONLY"
    assert not res.ok


def test_enforce_rejects_when_citations_missing():
    res = enforce("结论", facts=[], major_matter=False, citations_ok=False,
                  confidence_permille=900, threshold_permille=700,
                  coverage_permille=0, min_coverage_permille=800)
    assert res.gate_decision == "REFUSED_NO_EVIDENCE"


def test_enforce_allows_clean_minor_answer():
    facts = [{"kind": "numeric", "minutes_extension": 60, "rule_id": "OT-D01"}]
    res = enforce("延长 60 分钟（规则 OT-D01）", facts=facts, major_matter=False,
                  citations_ok=True, confidence_permille=900, threshold_permille=700,
                  coverage_permille=1000, min_coverage_permille=800)
    assert res.ok and res.gate_decision == "ANSWERED"


def test_enforce_blocks_unauthorized_number():
    """出口白名单本身必须能拦住模型造出来的钱数（不依赖上游 provider 的自检）。"""
    facts = [{"kind": "numeric", "minutes_extension": 60, "estimate_cents": 4500,
              "rule_id": "OT-D01"}]
    res = enforce("你应得加班费 99999 元", facts=facts, major_matter=False, citations_ok=True,
                  confidence_permille=990, threshold_permille=700,
                  coverage_permille=1000, min_coverage_permille=800)
    assert res.gate_decision == "ESCALATED"
    assert not res.ok
    assert any("数字白名单" in v for v in res.violations)
    assert "99999" not in res.answer


def test_enforce_allows_only_traceable_numbers():
    facts = [{"kind": "numeric", "minutes_extension": 60, "estimate_cents": 4500,
              "rule_id": "OT-D01", "rate_permille": 1500}]
    res = enforce("延长 60 分钟，测算明细 4500 分，按 150%", facts=facts, major_matter=False,
                  citations_ok=True, confidence_permille=990, threshold_permille=700,
                  coverage_permille=1000, min_coverage_permille=800)
    assert res.gate_decision == "ANSWERED"
    assert res.numbers_found == ["60", "4500", "150"]


def test_major_matter_regex_covers_the_money_questions():
    from src.guard import MAJOR_MATTER_RE

    for q in ("该付多少加班费", "公司要不要赔", "这算不算违法", "最终金额是多少"):
        assert MAJOR_MATTER_RE.search(q), q
