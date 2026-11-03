"""界面路由：3 视图 + 最小登录。权限判定全部在服务端（NFR-16）。

四条写在代码结构里的约束：
  1. **主体身份只来自会话**。HTTP 接口不接受 `as_emp` 这类自报身份（基线的 `/ask?as_emp=` 是缺陷），
     越权测试必须能直连接口打 403，而不是靠前端藏控件。
  2. **动作复用脚本用的同一批函数**（`import_csv_file` / `run_check` / `export_package` /
     `decide_review` / `ComplianceAgent.ask`），界面不另写业务逻辑，
     所以"界面与脚本结果不一致"这条风险被结构性排除（需求 §7.3-5）。
  3. **问答视图不出现金额**：服务层守卫拦一次，渲染前再查一次金额形态，命中就整段换成人工确认提示
     （US-UI-03 ★「页面文本中不出现任何金额数字」）。
  4. 金额只能由 RV 在复核台**录入**并具名（需求 D-03 / DEC-05）；录入值进审计链，
     但不进问答上下文，也不进出发的最小视图。
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import re
from urllib.parse import parse_qs
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..agent import ComplianceAgent
from ..anomaly import (build_anomalies, decide_review, review_queue, rule_hit_counts,
                       severity_rollup)
from ..auth import (COOKIE_NAME, CSRF_COOKIE_NAME, AuthError, User, end_session,
                    issue_csrf_token, resolve_session, start_session, sync_users,
                    validate_csrf_token)
from ..config import Config
from ..api import borrow_connection, return_connection
from ..db import Connection, DatabaseError, get_meta
from ..engine import run_check
from ..evidence import ExportBusyError, export_package, record_delivery_event
from ..ingest import import_csv_file
from ..region_profile import RegionProfileError
from ..rules.approval_docs import (APPROVAL_READ_ROLES, APPROVAL_WRITE_ROLES,
                                   ApprovalConflictError, VALID_REGIMES,
                                   coverage_for, create_draft, import_drafts_csv,
                                   list_docs_summary, publish_doc, update_draft,
                                   version_chain)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATES = Jinja2Templates(directory=str(TEMPLATE_DIR))

AMOUNT_IN_TEXT_RE = re.compile(r"\d[\d,，.]*\s*(元|万元|角|分)\b|[¥￥]\s*\d")
OPERATOR_ROLES = ("OP", "AD")
REVIEWER_ROLES = ("RV", "AD")
EXPORT_ROLES = ("OP", "RV", "AD")
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
# 审批台账 CSV：独立上限；超限明确拒绝，不静默截断。
APPROVAL_CSV_MAX_BYTES = 1 * 1024 * 1024
APPROVAL_CSV_MAX_ROWS = 2_000
APPROVAL_CSV_FIELDS = ("doc_no", "title", "issuer", "regime", "version_no", "valid_from",
                       "valid_to", "job_codes", "region_code", "attachment_sha256",
                       "scope_type", "scope_value", "change_note")
_SAFE_NAME = re.compile(r"^[\w.\-一-龥]{1,80}\.csv$", re.UNICODE)


def _landing_for(user: User) -> str:
    """登录后的落地页按角色选：让 RV 一登录就撞 403 不是"权限严格"，是把人挡在门外。"""
    if user.has("OP", "AD"):
        return "/"
    if user.has("RV"):
        return "/review"
    if user.has("AU"):
        return "/approvals"
    return "/qa"


def _token_of(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


def _secure_cookie(request: Request) -> bool:
    """由安全头中间件按「真实 HTTPS 或 WCA_HTTPS_MODE」写入 request.state。"""
    return bool(getattr(request.state, "secure_cookies", False))


def _user_view(user: User) -> dict:
    return {"username": user.username, "emp_id": user.emp_id, "roles": list(user.roles),
            "org_id": user.org_id, "region_code": user.region_code,
            "pseudonym": user.pseudonym}


def register_web_routes(app: Any, cfg: Config, get_conn) -> None:
    """把界面路由挂到既有 app 上；`get_conn` 复用 api.py 的"每请求一条连接"依赖。"""

    def principal(request: Request, conn: Connection = Depends(get_conn)) -> User:
        user = resolve_session(conn, _token_of(request))
        if user is None:
            raise HTTPException(status_code=401, detail="未登录或会话已过期")
        return user

    def require(user: User, *roles: str) -> None:
        if not user.has(*roles):
            raise HTTPException(status_code=403, detail=(
                f"服务端拒绝：账号 {user.username} 的角色 {list(user.roles)} "
                f"不属于允许范围 {list(roles)}"))

    def page(request: Request, name: str, context: dict,
             conn: Connection | None = None) -> HTMLResponse:
        csrf_token = ""
        set_csrf_cookie = False
        if conn is not None:
            csrf_token, set_csrf_cookie = issue_csrf_token(
                conn, _token_of(request), request.cookies.get(CSRF_COOKIE_NAME, ""))
        ctx = {"request": request, "app_name": "工时合规校验（MVP）",
               "rule_pack": cfg.rule_pack_id, "region_label": cfg.region_label,
               "cities": cfg.region_profile.codes() if cfg.region_profile else [],
               "csrf_token": csrf_token,
               "csp_nonce": getattr(request.state, "csp_nonce", ""),
               **context}
        response = TEMPLATES.TemplateResponse(request, name, ctx)
        if set_csrf_cookie and csrf_token:
            response.set_cookie(CSRF_COOKIE_NAME, csrf_token, httponly=False,
                                samesite="strict", secure=_secure_cookie(request), path="/")
        return response

    def require_csrf(request: Request, conn: Connection, body: dict | None) -> None:
        supplied = (request.headers.get("X-CSRF-Token")
                    or (body or {}).get("csrf_token") or "")
        if not validate_csrf_token(conn, _token_of(request), str(supplied)):
            raise HTTPException(status_code=403,
                                detail="CSRF 校验失败：页面 token 缺失或已过期，请刷新后重试")

    def approval_scopes(value: Any, scope_type: str) -> list[tuple[str, str]]:
        values = [x.strip() for x in re.split(r"[,，]", str(value or "")) if x.strip()]
        if not values:
            raise HTTPException(status_code=400, detail="至少填写一个审批范围值")
        return [(scope_type, v) for v in values]

    # ------------------------------------------------------------------ 登录 / 会话
    @app.get("/login", response_class=HTMLResponse, summary="最小登录页")
    def login_page(request: Request, error: str = "",
                   conn: Connection = Depends(get_conn)):
        return page(request, "login.html", {"error": error, "user_count": _user_count(conn)})

    @app.post("/login", summary="校验口令并签发 HttpOnly 会话 Cookie")
    async def login_post(request: Request):
        """异步端点：连接自己开、自己关（见 api.borrow_connection 的线程亲和说明）。

        表单也是手工解析——本接口只有一个 urlencoded 的 用户名+口令 体，
        为它引入 python-multipart 不划算（依赖越少，评审者一次装起来的把握越大）。
        """
        form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
        username = (form.get("username") or [""])[0].strip()
        password = (form.get("password") or [""])[0]
        conn = borrow_connection(cfg)
        try:
            sync_users(conn, cfg)                   # 账号来源：config/users.json（幂等）
            try:
                token, user = start_session(conn, cfg, username, password)
            except AuthError:
                # 不区分"用户不存在/口令错"，避免账号枚举；但库里一个账号都没有是**配置问题**，
                # 必须说清楚，否则操作人会在口令上反复试错（账号要绑定已导入的员工主数据）。
                n = _user_count(conn)
                hint = ("库里没有可用账号：账号必须绑定已导入的员工主数据。"
                        "请先跑 python -m src.cli all（或 ingest），"
                        "并核对 config/users.json 里的 emp_id 是否存在。") if n == 0 else                     "登录失败：用户名或口令不正确"
                return page(request, "login.html", {"error": hint, "user_count": n})
        finally:
            return_connection(conn)
        resp = RedirectResponse(_landing_for(user), status_code=303)
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict",
                        secure=_secure_cookie(request), max_age=7200, path="/")
        return resp

    @app.post("/logout", summary="撤销会话（带 CSRF）")
    async def logout(request: Request, conn: Connection = Depends(get_conn),
                     user: User = Depends(principal)):
        form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
        require_csrf(request, conn, {k: v[0] for k, v in form.items()})
        end_session(conn, _token_of(request))
        resp = RedirectResponse("/login", status_code=303)
        secure = _secure_cookie(request)
        resp.delete_cookie(COOKIE_NAME, path="/", secure=secure)
        resp.delete_cookie(CSRF_COOKIE_NAME, path="/", secure=secure)
        return resp

    @app.get("/api/session", summary="当前会话身份与角色（界面顶栏用）")
    def api_session(user: User = Depends(principal)):
        return _user_view(user)

    # ------------------------------------------------------------------ 视图①：导入与异常
    @app.get("/", response_class=HTMLResponse, summary="视图① 导入与质量异常")
    def view_index(request: Request, conn: Connection = Depends(get_conn),
                   user: User = Depends(principal)):
        require(user, *OPERATOR_ROLES)
        run_id = get_meta(conn, "last_run_id")
        anomalies = build_anomalies(conn, run_id) if run_id else []
        issues = conn.execute(
            "SELECT rule_id, severity, field_name, line_no, detail, emp_id, file_id "
            "FROM ingest_issue ORDER BY issue_id DESC LIMIT 40").fetchall()
        return page(request, "index.html", {
            "me": _user_view(user), "run_id": run_id,
            "anomalies": anomalies[:120], "rollup": severity_rollup(anomalies),
            "issues": [dict(i) for i in issues],
            "reject_count": int(conn.execute("SELECT COUNT(*) c FROM ingest_issue "
                                             "WHERE severity = 'REJECT'").fetchone()["c"]),
            "hits": rule_hit_counts(conn, run_id) if run_id else [],
            "last_line": conn.execute("SELECT line_no FROM ingest_issue ORDER BY issue_id DESC "
                                      "LIMIT 1").fetchone(),
        }, conn=conn)

    @app.post("/api/import", summary="上传 CSV，走与脚本同一个导入函数（带 CSRF）")
    def api_import(request: Request, body: dict, conn: Connection = Depends(get_conn),
                   user: User = Depends(principal)):
        """界面用 file input + FileReader 以文本提交，服务端落盘后调用**同一个** import_csv_file。

        不引 multipart 解析依赖（NFR-07：requirements 里没有前端相关包），
        行号语义由导入层按落盘文件计算，与脚本通道完全一致。
        """
        require(user, *OPERATOR_ROLES)
        require_csrf(request, conn, body)
        name = Path(str(body.get("filename") or "upload.csv")).name   # 只取文件名，防路径穿越
        if not _SAFE_NAME.match(name):
            raise HTTPException(status_code=400, detail="文件名不合法（只允许 <名称>.csv）")
        text = body.get("content")
        if not isinstance(text, str):
            raise HTTPException(status_code=400, detail="content 必须是 CSV 文本")
        if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="文件超过 4 MB 上限")
        cfg.ensure_dirs()
        target = cfg.upload_dir / name
        target.write_bytes(text.encode("utf-8"))
        kind = str(body.get("kind") or "").strip() or None
        try:
            res = import_csv_file(conn, cfg, target, kind=kind, actor=f"user:{user.username}")
        except ValueError as exc:
            # 文件名推不出类型时不猜：让界面提示操作人选数据类型
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"file_id": res.file_id, "rel_path": res.rel_path, "sha256": res.sha256,
                "kind": res.kind, "rows_seen": res.rows_seen, "rows_accepted": res.rows_accepted,
                "rows_rejected": res.rows_rejected, "issue_count": len(res.issues),
                "reimported": res.reimported, "unattributed": res.unattributed,
                "write_mode": res.write_mode, "requested_write_mode": res.requested_write_mode,
                "degraded_from": res.degraded_from, "chunk_rows": res.chunk_rows,
                "issues": [{"rule_id": i.rule_id, "line_no": i.line_no, "field": i.field_name,
                            "detail": i.detail} for i in res.issues[:60]]}

    @app.post("/api/check", summary="选城市档 + 规则版本发起校验（与 cli check 同一函数，带 CSRF）")
    def api_check(request: Request, body: dict, conn: Connection = Depends(get_conn),
                  user: User = Depends(principal)):
        require(user, *OPERATOR_ROLES)
        require_csrf(request, conn, body)
        try:
            scoped = cfg.with_region(str(body.get("region_code") or cfg.region_code))
        except (ValueError, RegionProfileError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            start = date.fromisoformat(str(body.get("start")))
            end = date.fromisoformat(str(body.get("end")))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="start/end 需要 YYYY-MM-DD") from exc
        out = run_check(conn, scoped, start=start, end=end, actor=f"user:{user.username}",
                        notes="ui check")
        return {"run_id": out.run_id, "employees": out.employees, "days": out.days,
                "findings": len(out.findings), "counts": out.counts_by_severity(),
                "region_code": scoped.region_code, "region_label": scoped.region_label,
                "rule_pack": scoped.rule_pack_id,
                "triple": {"rule_pack_version": scoped.rule_pack_id,
                           "input_fingerprint": out.input_fingerprint,
                           "conclusion_digest": out.conclusion_digest},
                "elapsed_ms": round(out.elapsed_us / 1000, 1)}

    # ------------------------------------------------------------------ 视图②：复核台
    @app.get("/review", response_class=HTMLResponse, summary="视图② 复核台")
    def view_review(request: Request, conn: Connection = Depends(get_conn),
                    user: User = Depends(principal)):
        require(user, *REVIEWER_ROLES)
        run_id = get_meta(conn, "last_run_id")
        return page(request, "review.html", {
            "me": _user_view(user), "run_id": run_id,
            "queue": [_decorate_review_row(r) for r in
                      review_queue(conn, run_id=run_id, only_open=True, limit=150)],
            # 已登记的要能回看（含人工录入的金额与录入人/时间），否则"责任落到人"这句话
            # 在界面上只存在于登记的那一瞬间
            "decided_rows": [_decorate_review_row(r) for r in
                             review_queue(conn, run_id=run_id, only_open=False, limit=40)
                             if r["status"] != "OPEN"],
            "decided": int(conn.execute("SELECT COUNT(*) c FROM review_item "
                                        "WHERE status <> 'OPEN'").fetchone()["c"]),
        }, conn=conn)

    @app.post("/api/review/{review_id}/decision", summary="登记具名人工结论（金额由人录入，带 CSRF）")
    def api_review_decision(review_id: int, request: Request, body: dict,
                            conn: Connection = Depends(get_conn),
                            user: User = Depends(principal)):
        require(user, *REVIEWER_ROLES)
        require_csrf(request, conn, body)
        raw = body.get("amount_cents")
        amount = None
        if raw not in (None, "", "null"):
            try:
                amount = int(raw)
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="金额必须是整数分") from exc
        try:
            return decide_review(conn, cfg, review_id, reviewer=user.username,
                                 decision=str(body.get("decision", "")),
                                 note=str(body.get("note", "")), amount_cents=amount)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/export", summary="登记交付事件并导出举证包（与 cli export 同一函数，带 CSRF）")
    def api_export(request: Request, body: dict, conn: Connection = Depends(get_conn),
                   user: User = Depends(principal)):
        require(user, *EXPORT_ROLES)
        require_csrf(request, conn, body)
        run_id = str(body.get("run_id") or get_meta(conn, "last_run_id"))
        if not run_id:
            raise HTTPException(status_code=409, detail="尚无校验运行，请先发起校验")
        delivery_recorded = False
        if user.has("RV"):
            # 与脚本通道同一个登记函数，避免"界面与脚本写出不同的 evidence.sign"
            # 注意：只写审计事件，不是密码学签名。
            record_delivery_event(conn, cfg, run_id, recorded_by=user.username)
            delivery_recorded = True
        try:
            manifest = export_package(conn, cfg, run_id)
        except ExportBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"package_zip": manifest["package_zip"], "triple": manifest["triple"],
                "manifest_sha256": manifest["manifest_sha256"], "counts": manifest["counts"],
                "chain_ok": manifest["chain_verification"]["ok"],
                "delivery_event_recorded": delivery_recorded}

    # ------------------------------------------------------------------ 视图④：审批台账
    @app.get("/approvals", response_class=HTMLResponse, summary="审批台账：批文列表")
    def view_approvals(request: Request, conn: Connection = Depends(get_conn),
                       user: User = Depends(principal)):
        require(user, *APPROVAL_READ_ROLES)
        return page(request, "approvals.html", {
            "me": _user_view(user),
            "docs": list_docs_summary(conn, user),
        }, conn=conn)

    @app.get("/approvals/coverage", response_class=HTMLResponse,
             summary="审批台账：按员工查覆盖投影")
    def view_approval_coverage(request: Request, emp_id: str = "",
                               conn: Connection = Depends(get_conn),
                               user: User = Depends(principal)):
        require(user, *APPROVAL_READ_ROLES)
        employee = None
        coverage: list[dict] = []
        if emp_id.strip():
            employee = conn.execute(
                "SELECT emp_id, pseudonym, job_code, region_code, worktime_regime "
                "FROM employee WHERE emp_id = ?", (emp_id.strip(),)).fetchone()
            if employee is None:
                raise HTTPException(status_code=404, detail=f"员工不存在：{emp_id}")
            coverage = coverage_for(conn, user, emp_id.strip())
        return page(request, "approval_coverage.html", {
            "me": _user_view(user), "emp_id": emp_id.strip(),
            "employee": dict(employee) if employee else None, "coverage": coverage,
        }, conn=conn)

    @app.get("/approvals/new", response_class=HTMLResponse, summary="审批台账：新建草稿（AD）")
    def view_approval_new(request: Request, conn: Connection = Depends(get_conn),
                          user: User = Depends(principal)):
        require(user, *APPROVAL_WRITE_ROLES)
        return page(request, "approval_form.html", {
            "me": _user_view(user), "mode": "new", "doc": None, "version": None,
            "employees": [dict(r) for r in conn.execute(
                "SELECT emp_id, pseudonym, job_code, region_code FROM employee "
                "ORDER BY emp_id").fetchall()],
            "orgs": [dict(r) for r in conn.execute(
                "SELECT org_id, org_name FROM org_unit ORDER BY org_id").fetchall()],
            "regimes": list(VALID_REGIMES), "default_region": cfg.region_code,
        }, conn=conn)

    @app.get("/approvals/import", response_class=HTMLResponse, summary="审批台账：CSV 批量导入（AD）")
    def view_approval_import(request: Request, user: User = Depends(principal),
                             conn: Connection = Depends(get_conn)):
        require(user, *APPROVAL_WRITE_ROLES)
        return page(request, "approval_import.html", {
            "me": _user_view(user), "fields": list(APPROVAL_CSV_FIELDS),
            "max_bytes": APPROVAL_CSV_MAX_BYTES, "max_rows": APPROVAL_CSV_MAX_ROWS,
        }, conn=conn)

    @app.get("/approvals/{doc_no}/edit", response_class=HTMLResponse,
             summary="审批台账：编辑草稿（AD）")
    def view_approval_edit(doc_no: str, request: Request, version_no: int | None = None,
                           conn: Connection = Depends(get_conn),
                           user: User = Depends(principal)):
        require(user, *APPROVAL_WRITE_ROLES)
        data = version_chain(conn, user, doc_no)
        drafts = [v for v in data["versions"] if v["status"] == "DRAFT"]
        version = next((v for v in drafts if version_no is None or v["version_no"] == version_no),
                       None)
        if version is None:
            raise HTTPException(status_code=409, detail=f"批文 {doc_no} 没有可编辑的 DRAFT 版本")
        return page(request, "approval_form.html", {
            "me": _user_view(user), "mode": "edit", "doc": data["doc"], "version": version,
            "employees": [dict(r) for r in conn.execute(
                "SELECT emp_id, pseudonym, job_code, region_code FROM employee "
                "ORDER BY emp_id").fetchall()],
            "orgs": [dict(r) for r in conn.execute(
                "SELECT org_id, org_name FROM org_unit ORDER BY org_id").fetchall()],
            "regimes": list(VALID_REGIMES), "default_region": cfg.region_code,
        }, conn=conn)

    @app.get("/approvals/{doc_no}", response_class=HTMLResponse,
             summary="审批台账：批文详情（版本链/范围/附件哈希）")
    def view_approval_detail(doc_no: str, request: Request,
                             conn: Connection = Depends(get_conn),
                             user: User = Depends(principal)):
        require(user, *APPROVAL_READ_ROLES)
        data = version_chain(conn, user, doc_no)
        return page(request, "approval_detail.html", {
            "me": _user_view(user), "doc": data["doc"], "versions": data["versions"],
        }, conn=conn)

    def _approval_write_guard(request: Request, body: dict, conn: Connection, user: User) -> None:
        require(user, *APPROVAL_WRITE_ROLES)
        require_csrf(request, conn, body)

    def _approval_error(exc: Exception) -> HTTPException:
        if isinstance(exc, PermissionError):
            return HTTPException(status_code=403, detail=str(exc))
        if isinstance(exc, ApprovalConflictError):
            return HTTPException(status_code=409, detail=str(exc))
        return HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/approvals/draft", summary="新建审批草稿（AD + CSRF）")
    def api_approval_draft(request: Request, body: dict,
                           conn: Connection = Depends(get_conn),
                           user: User = Depends(principal)):
        _approval_write_guard(request, body, conn, user)
        try:
            scope_type = str(body.get("scope_type") or "employee").strip()
            result = create_draft(
                conn, cfg, user,
                doc_no=str(body.get("doc_no") or "").strip(),
                title=str(body.get("title") or "").strip(),
                issuer=str(body.get("issuer") or "").strip(),
                regime=str(body.get("regime") or "").strip(),
                version_no=int(body.get("version_no") or 1),
                valid_from=str(body.get("valid_from") or ""),
                valid_to=str(body.get("valid_to") or ""),
                job_codes=str(body.get("job_codes") or ""),
                region_code=str(body.get("region_code") or "").strip(),
                attachment_sha256=str(body.get("attachment_sha256") or "").strip(),
                scopes=approval_scopes(body.get("scope_value"), scope_type),
                change_note=str(body.get("change_note") or "").strip())
        except (PermissionError, ValueError, TypeError) as exc:
            raise _approval_error(exc) from exc
        return result

    @app.post("/api/approvals/{doc_no}/edit", summary="编辑审批草稿（AD + CSRF）")
    def api_approval_edit(doc_no: str, request: Request, body: dict,
                          conn: Connection = Depends(get_conn),
                          user: User = Depends(principal)):
        _approval_write_guard(request, body, conn, user)
        try:
            result = update_draft(
                conn, cfg, user, doc_no, int(body.get("version_no") or 1),
                valid_from=str(body.get("valid_from") or ""),
                valid_to=str(body.get("valid_to") or ""),
                job_codes=str(body.get("job_codes") or ""),
                region_code=str(body.get("region_code") or "").strip(),
                attachment_sha256=str(body.get("attachment_sha256") or "").strip(),
                scopes=approval_scopes(body.get("scope_value"),
                                       str(body.get("scope_type") or "employee").strip()),
                change_note=str(body.get("change_note") or "").strip())
        except (PermissionError, ValueError, TypeError) as exc:
            raise _approval_error(exc) from exc
        return result

    @app.post("/api/approvals/{doc_no}/publish", summary="发布审批草稿（AD + CSRF）")
    def api_approval_publish(doc_no: str, request: Request, body: dict,
                             conn: Connection = Depends(get_conn),
                             user: User = Depends(principal)):
        _approval_write_guard(request, body, conn, user)
        try:
            version_no = body.get("version_no")
            return publish_doc(conn, cfg, user, doc_no,
                              int(version_no) if version_no not in (None, "") else None)
        except (PermissionError, ValueError, TypeError) as exc:
            raise _approval_error(exc) from exc

    @app.post("/api/approvals/import", summary="审批台账 CSV 批量导入（AD + CSRF）")
    def api_approval_import(request: Request, body: dict,
                            conn: Connection = Depends(get_conn),
                            user: User = Depends(principal)):
        _approval_write_guard(request, body, conn, user)
        name = Path(str(body.get("filename") or "approvals.csv")).name
        if not _SAFE_NAME.match(name):
            raise HTTPException(status_code=400, detail="文件名不合法（只允许 <名称>.csv）")
        text = body.get("content")
        if not isinstance(text, str):
            raise HTTPException(status_code=400, detail="content 必须是 CSV 文本")
        raw = text.encode("utf-8")
        if len(raw) > APPROVAL_CSV_MAX_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"CSV 超过 {APPROVAL_CSV_MAX_BYTES:,} 字节上限；请拆分后再导入，不做截断")
        try:
            records = [r for r in csv.reader(io.StringIO(text)) if any(c.strip() for c in r)]
        except csv.Error as exc:
            raise HTTPException(status_code=400, detail=f"CSV 解析失败：{exc}") from exc
        if not records:
            raise HTTPException(status_code=400, detail="CSV 没有数据行")
        header = records[0]
        missing = [f for f in APPROVAL_CSV_FIELDS if f not in header]
        if missing:
            raise HTTPException(status_code=400, detail=f"审批 CSV 缺列：{missing}")
        if len(records) - 1 > APPROVAL_CSV_MAX_ROWS:
            raise HTTPException(
                status_code=400,
                detail=f"CSV 数据行数 {len(records) - 1} 超过 {APPROVAL_CSV_MAX_ROWS} 行上限；"
                       "请拆分后再导入，不做截断")
        cfg.ensure_dirs()
        target = cfg.upload_dir / name
        target.write_bytes(raw)
        try:
            result = import_drafts_csv(conn, cfg, user, target)
        except (PermissionError, ValueError, TypeError) as exc:
            raise _approval_error(exc) from exc
        return {"filename": name, "bytes": len(raw), "rows": result["rows"],
                "docs": result["docs"], "versions": result["versions"]}

    # ------------------------------------------------------------------ 视图③：制度问答
    @app.get("/qa", response_class=HTMLResponse, summary="视图③ 制度问答")
    def view_qa(request: Request, q: str = "", conn: Connection = Depends(get_conn),
                user: User = Depends(principal)):
        return page(request, "qa.html", {"me": _user_view(user), "q": q,
                                         "result": _ask(conn, cfg, user, q) if q.strip() else None},
                    conn=conn)

    @app.post("/api/ask", summary="问答 JSON 接口（主体只来自会话，无 as_emp 参数，带 CSRF）")
    def api_ask(request: Request, body: dict, conn: Connection = Depends(get_conn),
                user: User = Depends(principal)):
        require_csrf(request, conn, body)
        question = str(body.get("question", "")).strip()
        if not question:
            raise HTTPException(status_code=422, detail="question 不能为空")
        return _ask(conn, cfg, user, question)


def _ask(conn: Connection, cfg: Config, user: User, question: str) -> dict:
    """问答走同一个 agent.ask：权限主体取自会话，请求参数里没有身份可填。"""
    ans = ComplianceAgent(conn, cfg).ask(question, actor_emp_id=user.emp_id)
    payload = dataclasses.asdict(ans) if dataclasses.is_dataclass(ans) else ans.as_dict()
    answer = str(payload.get("answer", ""))
    # 第二道金额闸（US-UI-03 ★）：页面文本里不得出现金额形态
    if AMOUNT_IN_TEXT_RE.search(answer):
        payload["answer"] = ("这里出现了金额形态的文本，界面不予展示。最终数额由 HR 负责人在复核台"
                            "录入并具名确认；本系统只给倍数口径与规则解释。")
        payload["amount_blocked_at_render"] = 1
    payload["ai_generated_note"] = "内容由 AI 生成，需人工确认后方可作为对外依据"
    payload["actor_emp_id"] = user.emp_id
    payload.pop("allowed_numbers", None)
    return payload


def _user_count(conn: Connection) -> int:
    try:
        return int(conn.execute("SELECT COUNT(*) c FROM app_user").fetchone()["c"])
    except (sqlite3.Error, DatabaseError):
        return 0


def _decorate_review_row(row: dict) -> dict:
    """复核台一行需要的东西：条文列表 + 可点开的原始行号（file:line）。

    库里存的是 JSON 文本，渲染前解出来；解不动就原样带上并在界面显示为空，不编造行号。
    """
    out = dict(row)
    for key, target in (("citation_ids", "citations"), ("source_refs", "refs")):
        raw = out.get(key)
        if isinstance(raw, str) and raw:
            try:
                out[target] = json.loads(raw)
            except (ValueError, TypeError):
                out[target] = []
        elif out.get(target) is None:
            out[target] = []
    refs = out.get("refs") or []
    out["line_refs"] = " · ".join(f"{r.get('file_id', '?')}:{r.get('line_no', '?')}"
                                 for r in refs[:3]) or ""
    if not out.get("citations"):
        out["citations"] = []
    return out
