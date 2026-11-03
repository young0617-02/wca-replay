"""M-01：演示口令闸门。

回环绑定（127.0.0.1 / localhost / ::1）允许演示账号；非回环绑定若仍能
用文档公开的 wca-demo-* 口令登录，启动期直接拒绝。演示账号本身不删除。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import load_base
from src.auth import hash_password
from src.config import Config
from src.db import connect, init_db
from src.startup_guard import (DemoCredentialError, assert_demo_credentials_safe,
                               database_demo_credential_accounts, demo_credential_accounts,
                               is_loopback_host)


def _cfg(tmp_path: Path, users: list[dict]) -> Config:
    tmp_path.mkdir(parents=True, exist_ok=True)
    users_path = tmp_path / "users.json"
    users_path.write_text(
        json.dumps({"schema": "wca-users-v1", "users": users}, ensure_ascii=False),
        encoding="utf-8")
    return Config.load(
        env_path=tmp_path / "nonexistent.env",
        WCA_DB_BACKEND="sqlite",
        WCA_DB_PATH=str(tmp_path / "guard.sqlite3"),
        WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
        WCA_DATA_DIR=str(tmp_path / "data"),
        WCA_REPORTS_DIR=str(tmp_path / "reports"),
        WCA_PACKAGES_DIR=str(tmp_path / "packages"),
        WCA_USERS_PATH=str(users_path),
        WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
        WCA_REGION_CODE="440300",
        WCA_LLM_PROVIDER="stub",
        WCA_EMBEDDING_BACKEND="bm25",
        WCA_SQLITE_SYNCHRONOUS="OFF",
    )


def _demo_user() -> dict:
    return {"username": "ad1", "emp_id": "E002", "roles": ["AD"],
            "pw_hash": hash_password("wca-demo-ad1")}


@pytest.mark.parametrize("host", [
    "127.0.0.1", "localhost", "::1", "[::1]",
    # Host 头通常带端口；解析必须能剥掉端口，否则回环演示会被误伤
    "127.0.0.1:9763", "localhost:9763", "[::1]:9763", "127.0.0.1.",
])
def test_loopback_hosts_are_recognised(host: str):
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", [
    "0.0.0.0", "::", "192.168.1.10", "example.com",
    "0.0.0.0:9763", "192.168.1.10:9763", "example.com:443", "evil.example",
])
def test_non_loopback_hosts_are_recognised(host: str):
    assert not is_loopback_host(host)


def test_demo_credential_accounts_detects_documented_password(tmp_path: Path):
    cfg = _cfg(tmp_path, [_demo_user(), {
        "username": "custom1", "emp_id": "E001", "roles": ["OP"],
        "pw_hash": hash_password("wca-custom-pw-1"),
    }])
    assert demo_credential_accounts(cfg) == ["ad1"]


def test_demo_credentials_are_allowed_on_loopback(tmp_path: Path):
    cfg = _cfg(tmp_path, [_demo_user()])
    assert_demo_credentials_safe(cfg, "127.0.0.1")   # 不抛异常


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10"])
def test_demo_credentials_block_non_loopback_startup(tmp_path: Path, host: str):
    cfg = _cfg(tmp_path, [_demo_user()])
    with pytest.raises(DemoCredentialError, match="ad1") as exc:
        assert_demo_credentials_safe(cfg, host)
    message = str(exc.value)
    assert "拒绝启动" in message and host in message
    assert "wca-demo-ad1" not in message          # 错误信息不回显口令


def test_non_demo_accounts_are_unaffected_on_non_loopback(tmp_path: Path):
    cfg = _cfg(tmp_path, [{
        "username": "custom1", "emp_id": "E001", "roles": ["OP"],
        "pw_hash": hash_password("wca-custom-pw-1"),
    }])
    assert_demo_credentials_safe(cfg, "0.0.0.0")   # 不抛异常


def test_create_app_refuses_non_loopback_with_demo_accounts(tmp_path: Path):
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from src import api as api_mod

    cfg = _cfg(tmp_path, [_demo_user()])
    with pytest.raises(DemoCredentialError, match="ad1"):
        api_mod.create_app(cfg, bound_host="0.0.0.0")


def test_create_app_starts_on_loopback_and_with_non_demo_accounts(tmp_path: Path):
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from src import api as api_mod

    loopback_cfg = _cfg(tmp_path / "loopback", [_demo_user()])
    assert api_mod.create_app(loopback_cfg, bound_host="127.0.0.1").title

    custom_cfg = _cfg(tmp_path / "custom", [{
        "username": "custom1", "emp_id": "E001", "roles": ["OP"],
        "pw_hash": hash_password("wca-custom-pw-1"),
    }])
    assert api_mod.create_app(custom_cfg, bound_host="0.0.0.0").title


def test_api_server_main_refuses_non_loopback_with_demo_accounts(monkeypatch, tmp_path: Path,
                                                                capsys):
    """真实走服务进程入口：不启动 uvicorn，闸门在 create_app 阶段就退出。"""
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from src import api_server

    cfg = _cfg(tmp_path, [_demo_user()])
    monkeypatch.setenv("WCA_HOST", "0.0.0.0")
    monkeypatch.setenv("WCA_USERS_PATH", str(cfg.users_path))
    monkeypatch.setenv("WCA_RUN_DIR", str(tmp_path / "run"))
    monkeypatch.delenv("WCA_SERVICE_NAME", raising=False)

    assert api_server.main([]) == 2
    err = capsys.readouterr().err
    assert "启动失败" in err and "ad1" in err and "非回环" in err


# ------------------------------------------------------------------ 数据库残留（M-01 补口）
def _seed_db_demo_account(cfg: Config) -> None:
    """把演示口令账号写进临时库，模拟“配置已删除、app_user 仍有旧行”。"""
    cfg.ensure_dirs()
    conn = connect(cfg.db_path)
    try:
        init_db(conn)
        load_base(conn, cfg)
        conn.execute(
            "INSERT INTO app_user(username, emp_id, roles, pw_hash, algo, created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("ad1", "T-STD", '["AD"]', hash_password("wca-demo-ad1"), "scrypt",
             "2026-11-03T00:00:00+08:00"))
    finally:
        conn.close()


def _delete_db_demo_account(cfg: Config) -> None:
    conn = connect(cfg.db_path)
    try:
        conn.execute("DELETE FROM app_user WHERE username = ?", ("ad1",))
    finally:
        conn.close()


def test_database_check_does_not_create_missing_sqlite(tmp_path: Path):
    """只读检查不得为了“检查”而创建空 SQLite 库。"""
    cfg = _cfg(tmp_path, [])
    assert not Path(cfg.db_path).exists()
    assert database_demo_credential_accounts(cfg) == []
    assert not Path(cfg.db_path).exists()


def test_database_demo_credentials_block_after_config_removal(tmp_path: Path):
    """配置里已没有演示账号，但 app_user 仍有演示口令行：必须拒绝。"""
    cfg = _cfg(tmp_path, [])
    _seed_db_demo_account(cfg)

    assert database_demo_credential_accounts(cfg) == ["ad1"]
    with pytest.raises(DemoCredentialError, match="数据库") as exc:
        assert_demo_credentials_safe(cfg, "0.0.0.0")
    message = str(exc.value)
    assert "拒绝启动" in message and "ad1" in message
    assert "wca-demo-ad1" not in message          # 错误信息不回显口令

    _delete_db_demo_account(cfg)
    assert database_demo_credential_accounts(cfg) == []
    assert_demo_credentials_safe(cfg, "0.0.0.0")   # 清理后放行


# ------------------------------------------------------------------ 请求层闸门（直接 uvicorn CLI）
def _test_client(tmp_path: Path, users: list[dict], base_url: str,
                 headers: dict[str, str] | None = None):
    """TestClient 的 `scope["server"]` 取自 base_url 的 host/port（starlette testclient.py:280）。

    base_url=`http://0.0.0.0:9763` → scope server=`["0.0.0.0", 9763]`；
    `headers={"Host": ...}` 只改 Host 头，不改 scope server，用来验证“Host 不参与放行”。
    """
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from fastapi.testclient import TestClient

    from src import api as api_mod

    cfg = _cfg(tmp_path, users)
    return TestClient(api_mod.create_app(cfg, bound_host="127.0.0.1"), base_url=base_url,
                      headers=headers or {})


class _WithoutServer:
    """删掉 ASGI scope["server"]，模拟无法判定绑定地址的服务器。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            scope = dict(scope)
            scope.pop("server", None)
        await self.app(scope, receive, send)


def test_request_layer_blocks_non_loopback_host_with_demo_accounts(tmp_path: Path):
    client = _test_client(tmp_path / "blocked", [_demo_user()], "http://10.18.0.7:9763")
    res = client.get("/login")
    assert res.status_code == 503
    body = res.json()
    assert body["error"] == "demo_credentials_blocked"
    assert "演示口令" in body["detail"] and "ad1" in body["detail"]
    assert "wca-demo-ad1" not in body["detail"]
    # 安全头中间件仍是最外层：拒绝响应也必须带统一安全头
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"


def test_request_layer_allows_loopback_host_with_demo_accounts(tmp_path: Path):
    client = _test_client(tmp_path / "loopback", [_demo_user()], "http://127.0.0.1:9763")
    res = client.get("/login")
    assert res.status_code == 200
    assert "登录" in res.text


def test_request_layer_allows_non_demo_accounts_on_non_loopback_host(tmp_path: Path):
    client = _test_client(tmp_path / "custom", [{
        "username": "custom1", "emp_id": "E001", "roles": ["OP"],
        "pw_hash": hash_password("wca-custom-pw-1"),
    }], "http://10.18.0.7:9763")
    assert client.get("/login").status_code == 200


def test_request_layer_blocks_database_residual_demo_accounts(tmp_path: Path):
    """请求层也要查库：配置干净但库里残留演示口令时，非回环 Host 仍拒绝。"""
    cfg = _cfg(tmp_path / "db-only", [])
    _seed_db_demo_account(cfg)
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from fastapi.testclient import TestClient

    from src import api as api_mod

    client = TestClient(api_mod.create_app(cfg, bound_host="127.0.0.1"),
                        base_url="http://10.18.0.7:9763")
    res = client.get("/login")
    assert res.status_code == 503
    assert res.json()["error"] == "demo_credentials_blocked"


def test_request_layer_does_not_trust_x_forwarded_host(tmp_path: Path):
    """Host/X-Forwarded-Host 都不参与放行判定；伪造代理头不能洗白非回环绑定。"""
    client = _test_client(tmp_path / "forwarded", [_demo_user()], "http://10.18.0.7:9763")
    res = client.get("/login", headers={"X-Forwarded-Host": "127.0.0.1"})
    assert res.status_code == 503


# ------------------------------------------------------------------ scope["server"] 判定（软肋修复）
def test_request_layer_blocks_wildcard_server_even_with_spoofed_loopback_host(tmp_path: Path):
    """实际绑定 0.0.0.0 + 客户端伪造 Host: 127.0.0.1 → 仍必须拒绝。"""
    client = _test_client(tmp_path / "wildcard", [_demo_user()], "http://0.0.0.0:9763",
                         headers={"Host": "127.0.0.1"})
    res = client.get("/login")
    assert res.status_code == 503
    body = res.json()
    assert body["error"] == "demo_credentials_blocked"
    assert "0.0.0.0" in body["detail"], "拒绝信息应给出实际绑定地址，而不是伪造的 Host"


def test_request_layer_allows_when_server_is_loopback_even_if_host_is_non_loopback(
        tmp_path: Path):
    """实际绑定 127.0.0.1 + Host 伪造为非回环 → 以 scope server 为准，放行。"""
    client = _test_client(tmp_path / "loopback-server", [_demo_user()],
                          "http://127.0.0.1:9763", headers={"Host": "10.18.0.7"})
    assert client.get("/login").status_code == 200


def test_request_layer_missing_server_fails_closed(tmp_path: Path):
    """scope["server"] 缺失/无法判定：即使 Host 是回环，也拒绝服务。"""
    pytest.importorskip("fastapi", reason="FastAPI 未安装；闸门函数本身已单独覆盖")
    from fastapi.testclient import TestClient

    from src import api as api_mod

    cfg = _cfg(tmp_path / "no-server", [_demo_user()])
    app = _WithoutServer(api_mod.create_app(cfg, bound_host="127.0.0.1"))
    client = TestClient(app, base_url="http://127.0.0.1:9763")
    res = client.get("/login", headers={"Host": "127.0.0.1"})
    assert res.status_code == 503
    assert res.json()["error"] == "demo_binding_unknown"


def test_request_layer_wildcard_server_allows_non_demo_accounts(tmp_path: Path):
    """0.0.0.0 绑定下没有演示口令账号 → 不受影响。"""
    client = _test_client(tmp_path / "wildcard-custom", [{
        "username": "custom1", "emp_id": "E001", "roles": ["OP"],
        "pw_hash": hash_password("wca-custom-pw-1"),
    }], "http://0.0.0.0:9763", headers={"Host": "127.0.0.1"})
    assert client.get("/login").status_code == 200
