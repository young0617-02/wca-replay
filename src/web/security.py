"""Web 安全响应头、CSP nonce 与 Cookie 传输属性。

设计边界：
  * 安全头挂在一层纯 ASGI 中间件上，覆盖页面、静态文件、401/403 与 404，不改业务路由；
  * CSP 用**每请求 nonce**放行现有模板里极少量的内联脚本/样式，不引入 ``unsafe-inline``；
    模板已移除内联 style 属性，脚本仍由 ``/static/app.js`` 或带 nonce 的内联块执行；
  * ``Secure`` Cookie：真实 HTTPS 或显式 ``WCA_HTTPS_MODE=true``（反向代理终止 TLS）时设置；
    默认本地 HTTP 不设置，保证开发环境仍能登录；
  * HSTS：只有真实 HTTPS **且** 显式 ``WCA_HSTS=true`` 才下发。HTTP 响应永远不带 HSTS，
    默认也不带 includeSubDomains，避免一次性把尚未纳入 HTTPS 的子域锁死。
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any

from starlette.datastructures import MutableHeaders

from ..startup_guard import (database_demo_credential_accounts, demo_credential_accounts,
                             is_loopback_host, normalise_host)

log = logging.getLogger("wca.web.security")

CSP_NONCE_BYTES = 16
HSTS_MAX_AGE_SECONDS = 31_536_000
TRUE_VALUES = {"1", "true", "yes", "on", "y"}
FALSE_VALUES = {"0", "false", "no", "off", "n", ""}


def _flag(raw: dict[str, str], key: str) -> bool:
    value = str(raw.get(key, "") or "").strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ValueError(f"配置项 {key} 需要布尔值，实际为 {raw.get(key)!r}")


@dataclass(frozen=True)
class SecuritySettings:
    """只从既有 ``Config.raw`` 读取 Web 开关，避免把 Web 关注点写回配置模型。"""

    https_mode: bool = False
    hsts_enabled: bool = False

    @classmethod
    def from_cfg(cls, cfg: Any) -> "SecuritySettings":
        raw = getattr(cfg, "raw", {}) or {}
        return cls(https_mode=_flag(raw, "WCA_HTTPS_MODE"),
                   hsts_enabled=_flag(raw, "WCA_HSTS"))

    def secure_cookie(self, scheme: str) -> bool:
        return scheme == "https" or self.https_mode

    def send_hsts(self, scheme: str) -> bool:
        # 只认实际 HTTPS：HTTP 下发的 HSTS 会被浏览器忽略，也不应出现在被测响应里。
        return scheme == "https" and self.hsts_enabled


def content_security_policy(nonce: str) -> str:
    """最小可用且与现有前端兼容的 CSP。

    ``script-src`` 保留 ``'self'`` 给 /static/app.js，再加当前请求 nonce 放行内联绑定代码；
    ``style-src`` 同理只放行 base.html 里那一段带 nonce 的样式表。
    ``connect-src 'self'`` 覆盖界面所有原生 fetch，未放行任何外部来源。
    """
    return (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )


class SecurityHeadersMiddleware:
    """为每个 HTTP 响应统一追加安全头，并把本次 nonce/ Cookie 策略放进 request.state。"""

    def __init__(self, app: Any, settings: SecuritySettings | None = None) -> None:
        self.app = app
        self.settings = settings or SecuritySettings()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        scheme = str(scope.get("scheme") or "http")
        nonce = secrets.token_urlsafe(CSP_NONCE_BYTES)
        state = scope.setdefault("state", {})
        state["csp_nonce"] = nonce
        state["secure_cookies"] = self.settings.secure_cookie(scheme)

        async def send_with_security_headers(message: dict) -> None:
            if message.get("type") == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Content-Security-Policy"] = content_security_policy(nonce)
                if self.settings.send_hsts(scheme):
                    headers["Strict-Transport-Security"] = f"max-age={HSTS_MAX_AGE_SECONDS}"
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


def _header(scope: dict, name: bytes) -> str:
    for raw_name, raw_value in scope.get("headers") or []:
        if raw_name.lower() == name:
            return raw_value.decode("latin-1")
    return ""


def server_binding_host(scope: dict) -> str | None:
    """读取 ASGI `scope["server"]` 的服务端地址；缺失/格式非法时返回 None。

    ASGI 规范里 `server` 是 `(host, port)`，表示**服务端本地 socket 地址**。
    uvicorn 用 `get_local_addr(transport)` 填这个值，不从请求头推导；因此请求方
    伪造 `Host: 127.0.0.1` 不会改变它。拿不到就由调用方失败关闭，不得默认回环。
    """
    server = scope.get("server")
    if not isinstance(server, (tuple, list)) or len(server) != 2:
        return None
    host = str(server[0] or "").strip()
    return host or None


class DemoCredentialRequestGuardMiddleware:
    """请求层演示口令闸门：补 `uvicorn src.api:app --host 0.0.0.0` 的启动期盲区。

    判定顺序：
      * 以 ASGI `scope["server"]` 的实际服务端地址为准；回环 → 直接放行，演示流程不变；
      * 非回环/通配绑定 → 同时检查配置账号文件与数据库 `app_user`；
        任一仍能用 `wca-demo-*` 口令 → **503**（配置状态不安全，不是调用方没权限，故不用 403）；
      * `scope["server"]` 缺失或格式非法 → 无法判定绑定，**503 失败关闭**；
      * 检查本身失败（配置坏了/数据库不可读）→ 也 503，失败关闭。

    `Host` / `X-Forwarded-Host` **不参与放行判断**，只写入日志便于排障；
    请求方伪造 `Host: 127.0.0.1` 不能绕过。
    """

    def __init__(self, app: Any, cfg: Any) -> None:
        self.app = app
        self.cfg = cfg

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_host = normalise_host(_header(scope, b"host"))
        binding = server_binding_host(scope)
        if binding is None:
            log.error("拒绝请求：ASGI scope['server'] 缺失或非法，Host=%r，失败关闭", request_host)
            await self._reject(
                send, "demo_binding_unknown",
                "拒绝提供服务：无法从 ASGI scope['server'] 判定服务端绑定地址，"
                "按失败关闭拒绝；请检查服务器/代理是否传入合规的 server 地址。")
            return

        binding = normalise_host(binding)
        if is_loopback_host(binding):
            await self.app(scope, receive, send)
            return

        try:
            accounts = sorted(set(demo_credential_accounts(self.cfg))
                              | set(database_demo_credential_accounts(self.cfg)))
        except Exception as exc:  # 失败关闭：检查不了就不能声称“没有演示口令”
            log.error("请求层演示口令检查失败（binding=%s Host=%s，%s）：%s",
                      binding, request_host, type(exc).__name__, exc)
            await self._reject(
                send, "demo_credentials_check_unavailable",
                "拒绝提供服务：无法确认演示口令账号是否已清理，非回环绑定下失败关闭。"
                "请确认 config/users.json 可读、数据库可连接且已执行 init。")
            return

        if accounts:
            log.warning("演示口令闸门拒绝：binding=%s Host=%s accounts=%s",
                        binding, request_host, accounts)
            await self._reject(
                send, "demo_credentials_blocked",
                f"拒绝提供服务：实际绑定地址 {binding!r} 非回环，但账号 "
                f"{', '.join(accounts)} 仍可使用文档公开的演示口令"
                "（来源：账号文件或数据库 app_user）。"
                "请改口令后重启，或仅通过 127.0.0.1/localhost 访问。")
            return

        log.info("非回环绑定 %s，Host=%s，未检出演示口令账号，放行", binding, request_host)
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send: Any, code: str, detail: str) -> None:
        body = json.dumps({"error": code, "detail": detail}, ensure_ascii=False).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        await send({"type": "http.response.start", "status": 503, "headers": headers})
        await send({"type": "http.response.body", "body": body})
