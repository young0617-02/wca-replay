"""审批台账网页入口：只读/写入权限、CSRF、CSV 限制与发布审计。"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from pathlib import Path

import pytest

from conftest import load_base
from src import api as api_mod
from src.auth import User, hash_password
from src.config import Config
from src.db import connect, init_db
from src.rules.approval_docs import create_draft, publish_doc
from src.web.routes import APPROVAL_CSV_MAX_BYTES, APPROVAL_CSV_MAX_ROWS

pytestmark = pytest.mark.skipif(not api_mod.FASTAPI_AVAILABLE,
                                reason="FastAPI 未安装；核心链路可用 python -m src.cli 验证")

ACCOUNTS = {"ad1": "wca-test-ad-web-pw", "au1": "wca-test-au-web-pw"}
CSV_HEADER = ("doc_no,title,issuer,regime,version_no,valid_from,valid_to,job_codes,"
              "region_code,attachment_sha256,scope_type,scope_value,change_note")


@pytest.fixture
def approval_ui(tmp_path):
    db = tmp_path / "approvals.sqlite3"
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({
        "schema": "wca-users-v1",
        "users": [
            {"username": "ad1", "emp_id": "T-STD", "roles": ["AD"],
             "pw_hash": hash_password(ACCOUNTS["ad1"])},
            {"username": "au1", "emp_id": "T-STD", "roles": ["AU"],
             "pw_hash": hash_password(ACCOUNTS["au1"])},
        ],
    }, ensure_ascii=False), encoding="utf-8")
    cfg = Config.load(
        env_path=tmp_path / "none.env", WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(db), WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
        WCA_DATA_DIR=str(tmp_path / "data"), WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"),
        WCA_USERS_PATH=str(users_file), WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF", WCA_REGION_CODE="440300")
    conn = connect(cfg.db_path, cfg.sqlite_synchronous)
    init_db(conn)
    load_base(conn, cfg)
    from fastapi.testclient import TestClient
    client = TestClient(api_mod.create_app(cfg))
    return client, conn, cfg


def login(client, username: str):
    res = client.post("/login", data={"username": username, "password": ACCOUNTS[username]},
                      follow_redirects=False)
    assert res.status_code in (302, 303), res.text[:160]
    return res


def csrf_token(client) -> str:
    page = client.get("/approvals")
    assert page.status_code == 200, page.text[:160]
    match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
    assert match, "审批页面没有 CSRF token"
    return match.group(1)


def post_json(client, path: str, body: dict, token: str | None):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post(path, json=body, headers=headers)


def approval_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_HEADER.split(","), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _setup_published_doc(cfg: Config, conn) -> str:
    user = User("ad-setup", "T-STD", ("AD",), "ORG-A", "440300", "管理员")
    doc_no = "UI-APPROVAL-001"
    create_draft(
        conn, cfg, user, doc_no=doc_no, title="网页演示批文", issuer="人社局",
        regime="comprehensive_monthly", version_no=1,
        valid_from="2025-01-01", valid_to="2025-12-31",
        job_codes='["warehouse_shift"]', region_code="440300",
        attachment_sha256="a" * 64, scopes=[("employee", "T-CMP")])
    publish_doc(conn, cfg, user, doc_no)
    return doc_no


def test_au_reads_list_detail_coverage_and_write_pages_are_403(approval_ui):
    client, conn, cfg = approval_ui
    doc_no = _setup_published_doc(cfg, conn)
    login(client, "au1")
    token = csrf_token(client)

    listing = client.get("/approvals")
    assert listing.status_code == 200 and doc_no in listing.text
    detail = client.get(f"/approvals/{doc_no}")
    assert detail.status_code == 200
    assert "warehouse_shift" in detail.text and "a" * 64 in detail.text
    coverage = client.get("/approvals/coverage", params={"emp_id": "T-CMP"})
    assert coverage.status_code == 200 and doc_no in coverage.text

    assert client.get("/approvals/new").status_code == 403
    assert client.get(f"/approvals/{doc_no}/edit").status_code == 403
    assert client.get("/approvals/import").status_code == 403
    assert post_json(client, "/api/approvals/draft", {
        "doc_no": "AU-SHOULD-NOT-WRITE", "title": "x", "issuer": "x",
        "regime": "comprehensive_monthly", "version_no": 1,
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": "warehouse_shift", "region_code": "440300",
        "attachment_sha256": "b" * 64, "scope_type": "employee",
        "scope_value": "T-CMP"}, token).status_code == 403
    assert post_json(client, f"/api/approvals/{doc_no}/publish",
                     {"version_no": 1}, token).status_code == 403
    assert post_json(client, "/api/approvals/import",
                     {"filename": "x.csv", "content": CSV_HEADER + "\n"}, token).status_code == 403


def test_unauthenticated_approvals_are_rejected(approval_ui):
    client, conn, cfg = approval_ui
    assert client.get("/approvals").status_code == 401
    assert client.post("/api/approvals/draft", json={}).status_code == 401
    assert client.post("/api/approvals/import", json={}).status_code == 401


def test_csrf_token_is_hash_only_in_database(approval_ui):
    client, conn, cfg = approval_ui
    login(client, "ad1")
    token = csrf_token(client)
    row = conn.execute("SELECT csrf_hash FROM app_csrf").fetchone()
    assert row is not None
    assert len(str(row["csrf_hash"])) == 64
    assert token not in str(row["csrf_hash"])
    assert conn.execute("SELECT COUNT(*) c FROM app_csrf WHERE csrf_hash = ?",
                        (token,)).fetchone()["c"] == 0


def test_old_app_csrf_plaintext_table_is_rebuilt_by_init_db(tmp_path: Path):
    db = tmp_path / "old_csrf.sqlite3"
    raw = sqlite3.connect(db)
    raw.execute("CREATE TABLE app_csrf(token_hash TEXT PRIMARY KEY, "
                "csrf_token TEXT NOT NULL, created_at TEXT NOT NULL)")
    raw.execute("INSERT INTO app_csrf(token_hash, csrf_token, created_at) "
                "VALUES('old-hash', 'plaintext-token-must-disappear', '2026-01-01')")
    raw.commit()
    raw.close()
    cfg = Config.load(env_path=tmp_path / "none.env", WCA_DB_BACKEND="sqlite",
                      WCA_DB_PATH=str(db),
                      WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
                      WCA_DATA_DIR=str(tmp_path / "data"),
                      WCA_REPORTS_DIR=str(tmp_path / "reports"),
                      WCA_PACKAGES_DIR=str(tmp_path / "packages"),
                      WCA_USERS_PATH=str(tmp_path / "users.json"),
                      WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
                      WCA_REGION_CODE="440300", WCA_LLM_PROVIDER="stub",
                      WCA_EMBEDDING_BACKEND="bm25", WCA_SQLITE_SYNCHRONOUS="OFF")
    conn = connect(cfg.db_path, cfg.sqlite_synchronous)
    init_db(conn)
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(app_csrf)").fetchall()}
    assert "csrf_hash" in columns and "csrf_token" not in columns
    assert conn.execute("SELECT COUNT(*) c FROM app_csrf").fetchone()["c"] == 0
    conn.close()


def test_ad_create_edit_publish_with_csrf_and_audit(approval_ui):
    client, conn, cfg = approval_ui
    login(client, "ad1")
    token = csrf_token(client)
    body = {
        "doc_no": "UI-APPROVAL-AD", "title": "AD 新建批文", "issuer": "人社局",
        "regime": "comprehensive_monthly", "version_no": 1,
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": "warehouse_shift", "region_code": "440300",
        "attachment_sha256": "c" * 64, "scope_type": "employee",
        "scope_value": "T-CMP", "change_note": "网页草稿",
    }
    created = post_json(client, "/api/approvals/draft", body, token)
    assert created.status_code == 200, created.text[:200]
    assert created.json()["doc_no"] == "UI-APPROVAL-AD"

    listed = client.get("/approvals")
    assert "UI-APPROVAL-AD" in listed.text
    edit_page = client.get("/approvals/UI-APPROVAL-AD/edit")
    assert edit_page.status_code == 200
    edited = post_json(client, "/api/approvals/UI-APPROVAL-AD/edit",
                       {**body, "valid_to": "2025-06-30", "change_note": "编辑后"},
                       token)
    assert edited.status_code == 200, edited.text[:200]
    version = conn.execute(
        "SELECT valid_to, change_note FROM approval_doc_version v "
        "JOIN approval_doc d ON d.doc_id = v.doc_id WHERE d.doc_no = ?",
        ("UI-APPROVAL-AD",)).fetchone()
    assert version["valid_to"] == "2025-06-30" and version["change_note"] == "编辑后"

    published = post_json(client, "/api/approvals/UI-APPROVAL-AD/publish",
                          {"version_no": 1}, token)
    assert published.status_code == 200, published.text[:200]
    doc = conn.execute("SELECT status, current_version FROM approval_doc "
                       "WHERE doc_no = ?", ("UI-APPROVAL-AD",)).fetchone()
    coverage = conn.execute("SELECT COUNT(*) AS c FROM employee_approval_coverage "
                            "WHERE emp_id = ? AND doc_no = ?",
                            ("T-CMP", "UI-APPROVAL-AD")).fetchone()
    assert doc["status"] == "PUBLISHED" and int(doc["current_version"]) == 1
    assert int(coverage["c"]) == 1
    actions = [r["action"] for r in conn.execute(
        "SELECT action FROM audit_event ORDER BY seq").fetchall()]
    assert "approval_doc.draft" in actions
    assert "approval_doc.draft.edit" in actions
    assert "approval_doc.publish" in actions
    publish_events = conn.execute(
        "SELECT actor, payload_sha256 FROM audit_event WHERE action = 'approval_doc.publish'"
    ).fetchall()
    assert publish_events and publish_events[-1]["actor"] == "human:ad1"


def test_ad_post_without_or_with_wrong_csrf_is_rejected(approval_ui):
    client, conn, cfg = approval_ui
    login(client, "ad1")
    token = csrf_token(client)
    body = {
        "doc_no": "UI-CSRF-MISSING", "title": "x", "issuer": "x",
        "regime": "comprehensive_monthly", "version_no": 1,
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": "warehouse_shift", "region_code": "440300",
        "attachment_sha256": "d" * 64, "scope_type": "employee",
        "scope_value": "T-CMP",
    }
    assert post_json(client, "/api/approvals/draft", body, None).status_code == 403
    assert post_json(client, "/api/approvals/draft", body, token + "x").status_code == 403
    assert conn.execute("SELECT COUNT(*) c FROM approval_doc WHERE doc_no = ?",
                        ("UI-CSRF-MISSING",)).fetchone()["c"] == 0


def test_csv_size_and_row_limits_are_rejected(approval_ui):
    client, conn, cfg = approval_ui
    login(client, "ad1")
    token = csrf_token(client)
    oversized = CSV_HEADER + "\n" + "x" * (APPROVAL_CSV_MAX_BYTES + 1)
    too_big = post_json(client, "/api/approvals/import",
                        {"filename": "big.csv", "content": oversized}, token)
    assert too_big.status_code == 413
    assert "上限" in too_big.text

    rows = [{
        "doc_no": f"ROW-{i}", "title": "t", "issuer": "i",
        "regime": "comprehensive_monthly", "version_no": "1",
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": '["warehouse_shift"]', "region_code": "440300",
        "attachment_sha256": "e" * 64, "scope_type": "employee",
        "scope_value": "T-CMP", "change_note": "",
    } for i in range(APPROVAL_CSV_MAX_ROWS + 1)]
    too_many = post_json(client, "/api/approvals/import",
                         {"filename": "rows.csv", "content": approval_csv(rows)}, token)
    assert too_many.status_code == 400
    assert "行数" in too_many.text


def test_csv_import_success_and_audit(approval_ui):
    client, conn, cfg = approval_ui
    login(client, "ad1")
    token = csrf_token(client)
    content = approval_csv([{
        "doc_no": "UI-CSV-001", "title": "CSV 批文", "issuer": "人社局",
        "regime": "comprehensive_monthly", "version_no": "1",
        "valid_from": "2025-01-01", "valid_to": "2025-12-31",
        "job_codes": '["warehouse_shift"]', "region_code": "440300",
        "attachment_sha256": "f" * 64, "scope_type": "employee",
        "scope_value": "T-CMP", "change_note": "CSV 导入",
    }])
    res = post_json(client, "/api/approvals/import",
                    {"filename": "approval.csv", "content": content}, token)
    assert res.status_code == 200, res.text[:200]
    assert res.json()["docs"] == 1
    event = conn.execute(
        "SELECT actor, payload_sha256 FROM audit_event WHERE action = 'approval_doc.import'"
    ).fetchall()
    assert event and event[-1]["actor"] == "human:ad1"
    assert conn.execute("SELECT COUNT(*) c FROM approval_doc WHERE doc_no = ?",
                        ("UI-CSV-001",)).fetchone()["c"] == 1
