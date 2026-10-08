"""F-009 ACL-aware 检索 + A3 越权召回为 0。

断言方式针对红线本身：**看进入打分阶段的候选集**，而不是只看最终 top-k。
如果哪天有人把权限过滤改成生成后过滤，这几个断言会立刻失败。
"""

from __future__ import annotations

import pytest

from conftest import EMPLOYEES, load_base
from src.kb.acl import Principal, acl_predicate, can_view
from src.kb.loader import build_kb
from src.retrieve import BACKEND_BM25, BACKEND_EXACT, BACKEND_VECTOR, retrieve


@pytest.fixture
def kb_conn(conn, cfg):
    load_base(conn, cfg)
    build_kb(conn, include_personnel=True)   # 派生 T-STD / T-OTHER 等人的薪酬与考勤条目
    return conn


def _principal(emp_id: str) -> Principal:
    row = next(e for e in EMPLOYEES if e["emp_id"] == emp_id)
    return Principal(emp_id=emp_id, org_id=row["org_id"],
                     is_manager=row["job_code"] == "senior_manager")


def test_other_payroll_doc_never_enters_candidates(kb_conn, cfg):
    """T-STD 问 T-OTHER 的薪酬：那条薪酬文档连候选都不是。"""
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "T-OTHER 的薪酬明细是多少")
    denied = "personnel.payroll.T-OTHER"
    assert denied not in res.candidates, "越权文档进入了打分候选集"
    assert denied not in [h.doc_id for h in res.hits]
    assert "personnel.payroll.T-STD" in res.candidates, "本人条目应当可见"


def test_other_attendance_doc_never_enters_candidates(kb_conn, cfg):
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "T-OTHER 上个月考勤汇总")
    assert "personnel.attendance.T-OTHER" not in res.candidates
    assert res.candidates, "公开条文仍应正常召回，ACL 不是把所有东西关掉"


def test_same_org_manager_sees_subordinate_attendance_summary(kb_conn, cfg):
    """主管可见本组织成员的考勤汇总，但薪酬明细仍然只属于本人。"""
    mgr = Principal(emp_id="T-FLX", org_id="ORG-A", is_manager=True)
    res = retrieve(kb_conn, cfg, mgr, "T-STD 的考勤汇总")
    assert "personnel.attendance.T-STD" in res.candidates
    assert "personnel.payroll.T-STD" not in res.candidates


def test_sql_predicate_is_pushed_down(kb_conn, cfg):
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "加班费倍数怎么算")
    assert "acl_scope" in res.sql, "权限谓词必须在 WHERE 里"
    assert "kb_doc_org" in res.sql or "acl_emp_id" in res.sql
    assert res.acl_predicate_sha256, "谓词要有指纹，便于举证包复核是哪套权限"


def test_python_equivalence_of_predicate(kb_conn, cfg):
    """SQL 下推与 Python 版判定必须等价，否则说明有一条路径漏了过滤。"""
    principal = _principal("T-STD")
    docs = kb_conn.execute("SELECT * FROM kb_doc").fetchall()
    res = retrieve(kb_conn, cfg, principal, "薪酬 明细 保密 受控 不可召回", top_k=50)
    for d in docs:
        doc = dict(d)
        allowed = can_view(principal, doc)
        in_candidates = doc["doc_id"] in res.candidates
        if allowed:
            continue  # 有权看的文档是否进候选取决于词条匹配，不作断言
        assert not in_candidates, f"{doc['doc_id']} 无权却进入候选集"


def test_org_scoped_policy_invisible_to_other_org(kb_conn, cfg):
    """合成制度条目挂在 ORG-OPS/ORG-MFG 等组织上；ORG-B 主体不应召回 ORG-A 专属条目。"""
    kb_conn.execute(
        "INSERT INTO kb_doc(doc_id, doc_type, title, body, source_citation, version, acl_scope, "
        "acl_org_ids, region_code, body_sha256) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("policy.a-only", "internal_policy", "A 组专属排班细则", "A 组专属排班细则 内容 仅 A 组可见",
         "合成制度", "v1", "own_org", '["ORG-A"]', "440300", "0" * 64),
    )
    kb_conn.execute("INSERT INTO kb_doc_org(doc_id, org_id) VALUES('policy.a-only','ORG-A')")
    from src.kb.loader import index_terms

    index_terms(kb_conn)
    outsider = Principal(emp_id="T-NAPPR", org_id="ORG-B", is_manager=False)
    res = retrieve(kb_conn, cfg, outsider, "A 组专属排班细则 内容")
    assert "policy.a-only" not in res.candidates
    insider = Principal(emp_id="T-STD", org_id="ORG-A", is_manager=False)
    res2 = retrieve(kb_conn, cfg, insider, "A 组专属排班细则 内容")
    assert "policy.a-only" in res2.candidates


def test_region_pushdown_excludes_other_city(kb_conn, cfg):
    kb_conn.execute(
        "INSERT INTO kb_doc(doc_id, doc_type, title, body, source_citation, version, acl_scope, "
        "region_code, body_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
        ("local.xx.wage.9", "local_regulation", "某市工资支付条例 第九条",
         "某市加班倍数的地方性规定", "合成地方性法规", "v1", "public", "310100", "0" * 64),
    )
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "某市加班倍数的地方性规定")
    assert "local.xx.wage.9" not in res.candidates, "地域过滤也必须下推，别把外市口径混进深圳结论"


def test_vector_backend_degrades_honestly(kb_conn, cfg):
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "法定节假日加班几倍", backend=BACKEND_VECTOR)
    assert res.degraded_from == BACKEND_VECTOR
    assert res.backend == BACKEND_BM25


def test_exact_backend_still_enforces_acl(kb_conn, cfg):
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "T-OTHER 薪酬明细", backend=BACKEND_EXACT)
    assert "personnel.payroll.T-OTHER" not in res.candidates


def test_empty_query_returns_nothing(kb_conn, cfg):
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "！！！？？？")
    assert res.hits == []


def test_holiday_premium_question_recalls_the_right_article(kb_conn, cfg):
    """检索质量的最低要求：核心条文要能进 top-5（判分器的 Hit@5 靠这个）。"""
    res = retrieve(kb_conn, cfg, _principal("T-STD"), "国庆当天上班加班费按几倍算", top_k=5)
    ids = [h.doc_id for h in res.hits]
    assert "law.labor.44" in ids
    assert ids[0] == "law.labor.44"
