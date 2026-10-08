"""只读 API（方案 §5：FastAPI 只做 2 个只读接口）。"""

from __future__ import annotations

import json
from datetime import date

import pytest

from conftest import load_base, punch, schedule
from src import api as api_mod
from src.engine import run_check
from src.ingest import import_rows
from src.kb import build_kb

pytestmark = pytest.mark.skipif(not api_mod.FASTAPI_AVAILABLE,
                                reason="FastAPI 未安装；核心链路可用 python -m src.cli ask 验证")


@pytest.fixture
def client(conn, cfg):
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


def test_exactly_two_business_endpoints(client):
    c, conn, cfg = client
    app = api_mod.create_app(cfg)
    paths = sorted({r.path for r in app.routes if getattr(r, "methods", None)})
    assert paths == ["/ask", "/evidence/{run_id}"], f"接口数量超出方案约定：{paths}"
    methods = {m for r in app.routes for m in getattr(r, "methods", set())}
    assert methods == {"GET"}, "只读接口必须是 GET"


def test_ask_endpoint_returns_gate_and_citations(client):
    c, conn, cfg = client
    res = c.get("/ask", params={"q": "我 2025-09 加班多少小时", "as_emp": "T-STD"})
    assert res.status_code == 200
    body = res.json()
    assert body["gate_decision"] in ("ANSWERED", "EXPLAIN_ONLY", "ESCALATED")
    assert body["citations"]
    assert body["numeric_tokens"]
    assert "retrieval" in body and "acl_predicate_sha256" in body["retrieval"]


def test_ask_rejects_empty_question_and_unknown_subject(client):
    c, conn, cfg = client
    assert c.get("/ask", params={"q": "", "as_emp": "T-STD"}).status_code == 422
    assert c.get("/ask", params={"q": "加班怎么算", "as_emp": "E-NOPE"}).status_code == 404


def test_evidence_endpoint_serves_zip_with_triple_headers(client):
    c, conn, cfg = client
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
    res = c.get("/evidence/run-does-not-exist")
    assert res.status_code == 404
    assert "举证包不存在" in res.json()["detail"]
