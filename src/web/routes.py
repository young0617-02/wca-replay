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

import dataclasses
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
from ..auth import (COOKIE_NAME, AuthError, User, end_session, resolve_session, start_session,
                    sync_users)
from ..config import Config
from ..api import borrow_connection, return_connection
from ..db import get_meta
from ..engine import run_check
from ..evidence import export_package, sign_package
from ..ingest import import_csv_file
from ..region_profile import RegionProfileError

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATES = Jinja2Templates(directory=str(TEMPLATE_DIR))

AMOUNT_IN_TEXT_RE = re.compile(r"\d[\d,，.]*\s*(元|万元|角|分)\b|[¥￥]\s*\d")
OPERATOR_ROLES = ("OP", "AD")
REVIEWER_ROLES = ("RV", "AD")
EXPORT_ROLES = ("OP", "RV", "AD")
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
_SAFE_NAME = re.compile(r"^[\w.\-一-龥]{1,80}\.csv$", re.UNICODE)


def _landing_for(user: User) -> str:
    """登录后的落地页按角色选：让 RV 一登录就撞 403 不是"权限严格"，是把人挡在门外。"""
    if user.has("OP", "AD"):
        return "/"
    if user.has("RV"):
        return "/review"
    return "/qa"


def _token_of(request: Request) -> str | None:
    return request.cookies.get(COOKIE_NAME)


def _user_view(user: User) -> dict:
    return {"username": user.username, "emp_id": user.emp_id, "roles": list(user.roles),
            "org_id": user.org_id, "region_code": user.region_code,
            "pseudonym": user.pseudonym}


def register_web_routes(app: Any, cfg: Config, get_conn) -> None:
    """把界面路由挂到既有 app 上；`get_conn` 复用 api.py 的"每请求一条连接"依赖。"""

    def principal(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> User:
        user = resolve_session(conn, _token_of(request))
        if user is None:
            raise HTTPException(status_code=401, detail="未登录或会话已过期")
        return user

    def require(user: User, *roles: str) -> None:
        if not user.has(*roles):
            raise HTTPException(status_code=403, detail=(
                f"服务端拒绝：账号 {user.username} 的角色 {list(user.roles)} "
                f"不属于允许范围 {list(roles)}"))

    def page(request: Request, name: str, context: dict) -> HTMLResponse:
        ctx = {"request": request, "app_name": "工时合规校验（MVP）",
               "rule_pack": cfg.rule_pack_id, "region_label": cfg.region_label,
               "cities": cfg.region_profile.codes() if cfg.region_profile else [],
               **context}
        return TEMPLATES.TemplateResponse(request, name, ctx)

    # ------------------------------------------------------------------ 登录 / 会话
    @app.get("/login", response_class=HTMLResponse, summary="最小登录页")
    def login_page(request: Request, error: str = "",
                   conn: sqlite3.Connection = Depends(get_conn)):
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
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict", max_age=7200,
                        path="/")
        return resp

    @app.post("/logout", summary="撤销会话")
    def logout(request: Request, conn: sqlite3.Connection = Depends(get_conn),
               user: User = Depends(principal)):
        end_session(conn, _token_of(request))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    @app.get("/api/session", summary="当前会话身份与角色（界面顶栏用）")
    def api_session(user: User = Depends(principal)):
        return _user_view(user)

    # ------------------------------------------------------------------ 视图①：导入与异常
    @app.get("/", response_class=HTMLResponse, summary="视图① 导入与质量异常")
    def view_index(request: Request, conn: sqlite3.Connection = Depends(get_conn),
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
        })

    @app.post("/api/import", summary="上传 CSV，走与脚本同一个导入函数")
    def api_import(body: dict, conn: sqlite3.Connection = Depends(get_conn),
                   user: User = Depends(principal)):
        """界面用 file input + FileReader 以文本提交，服务端落盘后调用**同一个** import_csv_file。

        不引 multipart 解析依赖（NFR-07：requirements 里没有前端相关包），
        行号语义由导入层按落盘文件计算，与脚本通道完全一致。
        """
        require(user, *OPERATOR_ROLES)
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
                "issues": [{"rule_id": i.rule_id, "line_no": i.line_no, "field": i.field_name,
                            "detail": i.detail} for i in res.issues[:60]]}

    @app.post("/api/check", summary="选城市档 + 规则版本发起校验（与 cli check 同一函数）")
    def api_check(body: dict, conn: sqlite3.Connection = Depends(get_conn),
                  user: User = Depends(principal)):
        require(user, *OPERATOR_ROLES)
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
    def view_review(request: Request, conn: sqlite3.Connection = Depends(get_conn),
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
        })

    @app.post("/api/review/{review_id}/decision", summary="登记具名人工结论（金额由人录入）")
    def api_review_decision(review_id: int, body: dict,
                            conn: sqlite3.Connection = Depends(get_conn),
                            user: User = Depends(principal)):
        require(user, *REVIEWER_ROLES)
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

    @app.post("/api/export", summary="签发并导出举证包（与 cli export 同一函数）")
    def api_export(body: dict, conn: sqlite3.Connection = Depends(get_conn),
                   user: User = Depends(principal)):
        require(user, *EXPORT_ROLES)
        run_id = str(body.get("run_id") or get_meta(conn, "last_run_id"))
        if not run_id:
            raise HTTPException(status_code=409, detail="尚无校验运行，请先发起校验")
        if user.has("RV"):
            # 与脚本通道同一个签发函数，避免"界面签名写的事件和脚本写的不一样"
            sign_package(conn, cfg, run_id, signed_by=user.username)
        manifest = export_package(conn, cfg, run_id)
        return {"package_zip": manifest["package_zip"], "triple": manifest["triple"],
                "manifest_sha256": manifest["manifest_sha256"], "counts": manifest["counts"],
                "chain_ok": manifest["chain_verification"]["ok"]}

    # ------------------------------------------------------------------ 视图③：制度问答
    @app.get("/qa", response_class=HTMLResponse, summary="视图③ 制度问答")
    def view_qa(request: Request, q: str = "", conn: sqlite3.Connection = Depends(get_conn),
                user: User = Depends(principal)):
        return page(request, "qa.html", {"me": _user_view(user), "q": q,
                                         "result": _ask(conn, cfg, user, q) if q.strip() else None})

    @app.post("/api/ask", summary="问答 JSON 接口（主体只来自会话，无 as_emp 参数）")
    def api_ask(body: dict, conn: sqlite3.Connection = Depends(get_conn),
                user: User = Depends(principal)):
        question = str(body.get("question", "")).strip()
        if not question:
            raise HTTPException(status_code=422, detail="question 不能为空")
        return _ask(conn, cfg, user, question)


def _ask(conn: sqlite3.Connection, cfg: Config, user: User, question: str) -> dict:
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


def _user_count(conn: sqlite3.Connection) -> int:
    try:
        return int(conn.execute("SELECT COUNT(*) c FROM app_user").fetchone()["c"])
    except sqlite3.Error:
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
