"""Web 安全响应头与 Cookie 传输属性（安全审查 L-02 回归）。

覆盖四条面：
  1. 登录页（200）、未登录访问受保护页（401）、审批台账页（200）、
     写接口未登录（401）与已登录无权（403）都必须带同一组安全响应头；
  2. CSP 必须能执行现有页面的内联脚本/样式（模板用一次性 nonce，不用 unsafe-inline）；
  3. 本地 HTTP 默认不写 Secure，登录链路仍然可用；HTTPS 或显式 HTTPS 模式才写 Secure；
  4. HSTS 只在真实 HTTPS 且显式开启时下发，HTTP 与默认 HTTPS 都不下发。
"""

from __future__ import annotations

import json
import re
from dataclasses import replace

import pytest

from conftest import load_base
from src import api as api_mod
from src.auth import hash_password
from src.config import Config
from src.db import connect, init_db

pytestmark = pytest.mark.skipif(not api_mod.FASTAPI_AVAILABLE,
                                reason="FastAPI 未安装；核心链路可用 python -m src.cli 验证")

ACCOUNTS = {"au1": "wca-test-au-security-pw", "ad1": "wca-test-ad-security-pw"}
ROLE_BINDINGS = [("au1", "T-STD", ["AU"]), ("ad1", "T-STD", ["AD"])]


@pytest.fixture
def security_ui(tmp_path):
    """临时 SQLite 库 + 可登录的 AU/AD 账号；不碰活动库。"""
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({
        "schema": "wca-users-v1",
        "users": [{"username": u, "emp_id": e, "roles": r,
                   "pw_hash": hash_password(ACCOUNTS[u])}
                  for u, e, r in ROLE_BINDINGS],
    }, ensure_ascii=False), encoding="utf-8")
    cfg = Config.load(
        env_path=tmp_path / "none.env", WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(tmp_path / "security.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
        WCA_DATA_DIR=str(tmp_path / "data"), WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"),
        WCA_USERS_PATH=str(users_file), WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
        WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF", WCA_REGION_CODE="440300")
    conn = connect(cfg.db_path, cfg.sqlite_synchronous)
    init_db(conn)
    load_base(conn, cfg)
    try:
        yield cfg, conn
    finally:
        conn.close()


def _client(cfg: Config, base_url: str = "http://testserver"):
    from fastapi.testclient import TestClient

    return TestClient(api_mod.create_app(cfg), base_url=base_url)


def _login(client, username: str):
    res = client.post("/login", data={"username": username, "password": ACCOUNTS[username]},
                      follow_redirects=False)
    assert res.status_code == 303, res.text[:160]
    return res


def _cookie_header(res, name: str) -> str:
    for raw in res.headers.get_list("set-cookie"):
        if raw.startswith(name + "="):
            return raw
    raise AssertionError(f"响应没有 {name} Cookie：{res.headers.get_list('set-cookie')}")


def _cookie_attrs(raw: str) -> set[str]:
    return {part.strip().lower() for part in raw.split(";")}


def _assert_common_headers(res) -> str:
    headers = res.headers
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("referrer-policy") == "no-referrer"
    csp = headers.get("content-security-policy")
    assert csp, "缺少 Content-Security-Policy"
    directives = {part.strip().split(" ", 1)[0]: part.strip()
                  for part in csp.split(";") if part.strip()}
    assert directives["default-src"] == "default-src 'self'"
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"
    assert directives["object-src"] == "object-src 'none'"
    assert directives["base-uri"] == "base-uri 'none'"
    assert directives["form-action"] == "form-action 'self'"
    assert "'unsafe-inline'" not in csp, "CSP 不应退回到允许任意内联脚本/样式"
    assert "'unsafe-eval'" not in csp
    return csp


def _nonce_of(csp: str) -> str:
    match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
    assert match, f"CSP 没有 nonce：{csp}"
    return match.group(1)


def _assert_inline_tags_use_nonce(html: str, nonce: str) -> None:
    tags = re.findall(r"<(?:style|script)\b[^>]*>", html, flags=re.I)
    inline = [tag for tag in tags if not re.search(r"\bsrc\s*=", tag, flags=re.I)]
    assert inline, "页面没有内联 style/script，测试前提已变"
    missing = [tag for tag in inline if f'nonce="{nonce}"' not in tag]
    assert not missing, f"内联 style/script 未带本次 CSP nonce：{missing}"
    assert not re.search(r"<[^>]+\sstyle\s*=\s*\"", html, flags=re.I), \
        "仍有内联 style 属性，strict CSP 会静默丢弃它"


def test_security_headers_cover_login_401_approval_and_api(security_ui):
    cfg, _conn = security_ui
    with _client(cfg) as anon:
        login = anon.get("/login")
        assert login.status_code == 200
        _assert_common_headers(login)

        protected = anon.get("/")
        assert protected.status_code == 401
        _assert_common_headers(protected)

        api_401 = anon.post("/api/import", json={})
        assert api_401.status_code == 401
        _assert_common_headers(api_401)

        static = anon.get("/static/app.js")
        assert static.status_code == 200
        _assert_common_headers(static)

        missing = anon.get("/does-not-exist")
        assert missing.status_code == 404
        _assert_common_headers(missing)

    with _client(cfg) as client:
        _login(client, "au1")
        approval_page = client.get("/approvals")
        assert approval_page.status_code == 200
        _assert_common_headers(approval_page)

        # AU 是只读角色：服务端角色判定先于 CSRF，应返回 403 而不是 401
        api_403 = client.post("/api/check", json={})
        assert api_403.status_code == 403
        assert "角色" in api_403.json()["detail"]
        _assert_common_headers(api_403)


def test_csp_nonce_matches_inline_style_and_script(security_ui):
    cfg, _conn = security_ui
    with _client(cfg) as anon:
        page = anon.get("/login")
        assert page.status_code == 200
        nonce = _nonce_of(_assert_common_headers(page))
        _assert_inline_tags_use_nonce(page.text, nonce)
        assert f"script-src 'self' 'nonce-{nonce}'" in page.headers["content-security-policy"]
        assert f"style-src 'self' 'nonce-{nonce}'" in page.headers["content-security-policy"]

    with _client(cfg) as client:
        _login(client, "ad1")
        page = client.get("/approvals/new")
        assert page.status_code == 200
        nonce = _nonce_of(_assert_common_headers(page))
        _assert_inline_tags_use_nonce(page.text, nonce)


def test_local_http_cookie_has_no_secure_and_login_still_works(security_ui):
    cfg, _conn = security_ui
    with _client(cfg) as client:
        res = _login(client, "au1")
        session_attrs = _cookie_attrs(_cookie_header(res, "wca_session"))
        assert "secure" not in session_attrs
        assert "httponly" in session_attrs
        assert "samesite=strict" in session_attrs

        # 登录链路必须真的可用：Secure 缺失不能靠“不发送 Cookie”掩盖
        assert client.get("/api/session").status_code == 200

        page = client.get("/approvals")
        assert page.status_code == 200
        csrf_attrs = _cookie_attrs(_cookie_header(page, "wca_csrf"))
        assert "secure" not in csrf_attrs
        assert "httponly" not in csrf_attrs, "双提交 CSRF Cookie 按现状保持脚本可读"
        assert "samesite=strict" in csrf_attrs


def test_https_sets_secure_on_session_and_csrf_cookies(security_ui):
    cfg, _conn = security_ui
    with _client(cfg, "https://testserver") as client:
        res = _login(client, "au1")
        session_attrs = _cookie_attrs(_cookie_header(res, "wca_session"))
        assert "secure" in session_attrs
        assert "httponly" in session_attrs
        assert "samesite=strict" in session_attrs
        assert client.get("/api/session").status_code == 200

        page = client.get("/approvals")
        assert page.status_code == 200
        csrf_attrs = _cookie_attrs(_cookie_header(page, "wca_csrf"))
        assert "secure" in csrf_attrs
        assert "httponly" not in csrf_attrs
        assert "samesite=strict" in csrf_attrs


def test_explicit_https_mode_sets_secure_even_on_local_http(security_ui):
    cfg, _conn = security_ui
    # 反向代理终止 TLS 时，ASGI 看到的 scheme 可能仍是 http；显式开关用于这种部署。
    cfg = replace(cfg, raw={**cfg.raw, "WCA_HTTPS_MODE": "true"})
    with _client(cfg) as client:
        res = _login(client, "au1")
        session_raw = _cookie_header(res, "wca_session")
        session_attrs = _cookie_attrs(session_raw)
        assert "secure" in session_attrs
        assert "samesite=strict" in session_attrs

        # httpx 按规范不会把 Secure Cookie 回放到 HTTP；这里手工放回同一会话令牌，
        # 仅用于验证服务端在显式 HTTPS 模式下给 CSRF Cookie 也加 Secure。
        token = session_raw.split(";", 1)[0].split("=", 1)[1]
        client.cookies.clear()
        client.cookies.set("wca_session", token, path="/")
        page = client.get("/approvals")
        assert page.status_code == 200
        csrf_attrs = _cookie_attrs(_cookie_header(page, "wca_csrf"))
        assert "secure" in csrf_attrs


def test_hsts_only_on_https_with_explicit_enable(security_ui):
    cfg, _conn = security_ui
    with _client(cfg) as http:
        assert "strict-transport-security" not in http.get("/login").headers

    # 仅 https 不够：没有显式开关就不应让浏览器记住强制 HTTPS
    with _client(cfg, "https://testserver") as https:
        assert "strict-transport-security" not in https.get("/login").headers

    hsts_cfg = replace(cfg, raw={**cfg.raw, "WCA_HSTS": "true"})
    # 即便显式开启 HSTS，纯 HTTP 响应也不下发
    with _client(hsts_cfg) as http:
        assert "strict-transport-security" not in http.get("/login").headers

    with _client(hsts_cfg, "https://testserver") as https:
        value = https.get("/login").headers.get("strict-transport-security")
        assert value == "max-age=31536000"
        assert "includeSubDomains" not in value
