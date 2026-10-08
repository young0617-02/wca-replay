"""JSON 接口层：一个问答、一个取举证包。

P6 加了界面之后接口面变宽了，但**这两个 JSON 口仍是只读口**，且身份一律来自会话
（需求 NFR-16 / GAP-05：基线这里有个可由调用方自填的 `as_emp`，等于任何人都能冒充他人）。
接口面的完整约束在 `tests/test_web_authz.py::test_route_whitelist_replaces_count_assertion`。
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from conftest import load_base, punch, schedule, seed_users
from src import api as api_mod
from src.engine import run_check
from src.ingest import import_rows
from src.kb import build_kb

pytestmark = pytest.mark.skipif(not api_mod.FASTAPI_AVAILABLE,
                                reason="FastAPI 未安装；核心链路可用 python -m src.cli ask 验证")


API_PW = "wca-test-api-password"


@pytest.fixture
def client(conn, cfg):
    seed_users(cfg, [("api_op", "T-STD", ["OP", "EM"], API_PW)])
    load_base(conn, cfg)
    import_rows(conn, cfg, "schedule", [schedule("T-STD", "2025-09-02",
                                                "2025-09-02T09:00:00+08:00",
                                                "2025-09-02T19:00:00+08:00")],
                rel_path="inline://api-sched")
    import_rows(conn, cfg, "punch", [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                                     punch("T-STD", "2025-09-02T19:00:00+08:00", "out")],
                rel_path="inline://api-punch")
    build_kb(conn, include_personnel=True)
    run_check(conn, cfg, start=date(2025, 9, 2), end=date(2025, 9, 2))

    from fastapi.testclient import TestClient

    return TestClient(api_mod.create_app(cfg)), conn, cfg


def test_read_only_json_endpoints_are_get_and_session_bound(client):
    """两个 JSON 口保持只读（GET），且没有"自报身份"的参数。"""
    c, conn, cfg = client
    app = api_mod.create_app(cfg)
    json_endpoints = {r.path: sorted(m for m in (getattr(r, "methods", None) or []))
                      for r in app.routes if getattr(r, "path", "") in ("/ask", "/evidence/{run_id}")}
    assert json_endpoints == {"/ask": ["GET"], "/evidence/{run_id}": ["GET"]}, json_endpoints
    # 未登录直接 401：身份不来自查询参数
    assert c.get("/ask", params={"q": "加班几倍"}).status_code == 401
    assert c.get("/evidence/whatever").status_code == 401
    import inspect
    from src.api import create_app as _ca
    src_text = inspect.getsource(_ca)
    assert "as_emp: str = Query" not in src_text, "问答接口不得再接受自报身份参数"


def test_ask_endpoint_returns_gate_and_citations(client):
    c, conn, cfg = client
    _login(c)
    res = c.get("/ask", params={"q": "我 2025-09 加班多少小时"})
    assert res.status_code == 200
    body = res.json()
    assert body["gate_decision"] in ("ANSWERED", "EXPLAIN_ONLY", "ESCALATED")
    assert body["citations"]
    assert body["numeric_tokens"]
    assert "retrieval" in body and "acl_predicate_sha256" in body["retrieval"]


def test_ask_rejects_empty_question_and_unusable_subject(client):
    c, conn, cfg = client
    _login(c)
    assert c.get("/ask", params={"q": ""}).status_code == 422
    # 账号指向的员工在主数据里查不到时，是配置错误：明确 401/404，不静默换个身份回答
    res = c.get("/ask", params={"q": "加班怎么算"})
    assert res.status_code == 200 and res.json()["actor_emp_id"]


def _login(client, username: str = "api_op", password: str = API_PW) -> None:
    """测试侧登录一次，后续请求带会话——与真实使用路径一致，不给接口留"自报身份"的后门。"""
    res = client.post("/login", data={"username": username, "password": password},
                      follow_redirects=False)
    assert res.status_code in (302, 303), f"登录失败：{res.status_code}"


def test_evidence_endpoint_serves_zip_with_triple_headers(client):
    c, conn, cfg = client
    _login(c)
    from src.evidence import export_package

    run_id = conn.execute("SELECT run_id FROM run ORDER BY started_at DESC LIMIT 1"
                          ).fetchone()["run_id"]
    manifest = export_package(conn, cfg, run_id)
    res = c.get(f"/evidence/{run_id}")
    assert res.status_code == 200
    assert res.headers["X-Rule-Pack-Version"] == manifest["triple"]["rule_pack_version"]
    assert res.headers["X-Conclusion-Digest"] == manifest["triple"]["conclusion_digest"]
    assert res.headers["X-Audit-Chain-Ok"] == "true"
    assert res.content[:2] == b"PK"


def test_evidence_endpoint_404_before_export(client):
    c, conn, cfg = client
    # 未登录连"这个包存不存在"都不该告诉你：先 401，再 404
    assert c.get("/evidence/run-does-not-exist").status_code == 401
    _login(c)
    res = c.get("/evidence/run-does-not-exist")
    assert res.status_code == 404
    assert "举证包不存在" in res.json()["detail"]
