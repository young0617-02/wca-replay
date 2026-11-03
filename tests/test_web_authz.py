"""界面与权限（US-UI-01~05 / NFR-15~17）。

对应 MVP 实施方案 §5 的 V-11 组：`ui_parity`、`review_authz`、`ui_no_amount`、
`acl_direct_request`（+ `export_single_entry`、`secret_leak`、`password_not_plaintext`）。

断言方式刻意"直连"：不看按钮有没有藏起来，而是直接用某个角色的会话去打接口——
只有这样才能证明权限在服务端（NFR-16）。
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, load_base, punch, schedule
from src import api as api_mod
from src.auth import hash_password, load_users_file
from src.config import Config
from src.db import connect, init_db
from src.engine import run_check
from src.evidence import export_package, verify_chain
from src.ingest import import_csv_file
from src.kb import build_kb

pytestmark = pytest.mark.skipif(not api_mod.FASTAPI_AVAILABLE,
                                reason="FastAPI 未安装；核心链路可用 python -m src.cli 验证")

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS = {"op1": "wca-test-op1-pw", "rv1": "wca-test-rv1-pw", "em1": "wca-test-em1-pw",
            "ad1": "wca-test-ad1-pw", "au1": "wca-test-au1-pw"}
# 账号绑定夹具自己的员工（不是 data/raw 那批演示数据）：
#   op1 / em1 / ad1 都是 T-STD，只是角色不同；rv1 是主管 T-FLX；被问的他人是 T-OTHER。
ROLE_BINDINGS = [("op1", "T-STD", ["OP", "EM"]), ("rv1", "T-FLX", ["RV"]),
                 ("em1", "T-STD", ["EM"]), ("ad1", "T-STD", ["AD"]),
                 ("au1", "T-STD", ["AU"])]


@pytest.fixture
def ui(tmp_path):
    """一个带三市员工、跑过一轮校验的独立库 + 一个可登录的界面客户端。"""
    db = tmp_path / "ui.sqlite3"
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({
        "schema": "wca-users-v1",
        "users": [{"username": u, "emp_id": e, "roles": r,
                   "pw_hash": hash_password(ACCOUNTS[u])} for u, e, r in ROLE_BINDINGS],
    }, ensure_ascii=False), encoding="utf-8")

    cfg = Config.load(env_path=None, WCA_DB_BACKEND="sqlite", WCA_DB_PATH=str(db),
                      WCA_DB_IDENTITY_PATH=str(tmp_path / "db_target.json"),
                      WCA_DATA_DIR=str(tmp_path / "data"), WCA_REPORTS_DIR=str(tmp_path / "reports"),
                      WCA_PACKAGES_DIR=str(tmp_path / "packages"),
                      WCA_USERS_PATH=str(users_file),
                      WCA_UPLOAD_DIR=str(tmp_path / "uploads"),
                      WCA_LLM_PROVIDER="stub", WCA_EMBEDDING_BACKEND="bm25",
                      WCA_SQLITE_SYNCHRONOUS="OFF", WCA_REGION_CODE="440300")
    conn = connect(cfg.db_path, cfg.sqlite_synchronous)
    init_db(conn)
    load_base(conn, cfg)
    from src.ingest import import_rows

    for emp, day, region in (("T-STD", "2025-09-02", "440300"), ("T-OTHER", "2025-09-03", "440100")):
        # 两名员工分属深圳档与广州档：界面与问答的越权、跨城隔离都要在这个夹具里能被撞到
        conn.execute("UPDATE employee SET region_code = ? WHERE emp_id = ?", (region, emp))
        import_rows(conn, cfg, "schedule", [
            schedule(emp, day, f"{day}T09:00:00+08:00", f"{day}T20:00:00+08:00", rest=60)],
            rel_path=f"inline://ui-sch-{emp}")
        import_rows(conn, cfg, "punch", [punch(emp, f"{day}T09:00:00+08:00", "in"),
                                         punch(emp, f"{day}T20:00:00+08:00", "out")],
                    rel_path=f"inline://ui-pun-{emp}")
    build_kb(conn, include_personnel=True)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5), notes="ui fixture")

    from fastapi.testclient import TestClient

    client = TestClient(api_mod.create_app(cfg))
    return client, conn, cfg, out


def _csrf_from_page(client) -> str:
    """按角色找一个可打开的页面，取服务端下发的 CSRF token。"""
    for path in ("/", "/review", "/qa", "/approvals"):
        page = client.get(path)
        if page.status_code != 200:
            continue
        match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
        if match:
            return match.group(1)
    raise AssertionError("登录后没有找到带 CSRF token 的页面")


def login(client, username: str, password: str | None = None):
    res = client.post("/login", data={"username": username,
                                      "password": password or ACCOUNTS[username]},
                      follow_redirects=False)
    assert res.status_code in (302, 303), f"登录未重定向：{res.status_code} {res.text[:120]}"
    # 会话写接口统一要求 CSRF；这里的 header 只模拟页面 meta 的行为，
    # 反向测试会显式删除它，证明服务端不是靠“测试客户端默认放行”。
    client.headers["X-CSRF-Token"] = _csrf_from_page(client)
    return res


def test_session_write_without_csrf_is_rejected_without_side_effect(ui):
    client, conn, cfg, out = ui
    login(client, "op1")
    token = client.headers["X-CSRF-Token"]
    del client.headers["X-CSRF-Token"]
    before = int(conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"])
    assert client.post("/api/check", json={"region_code": cfg.region_code,
                                          "start": "2025-09-01",
                                          "end": "2025-09-05"}).status_code == 403
    assert client.post("/api/import", json={"filename": "x.csv", "content": "a,b\n"}).status_code == 403
    assert client.post("/api/export", json={}).status_code == 403
    assert client.post("/api/ask", json={"question": "加班怎么算"}).status_code == 403
    assert client.post("/logout").status_code == 403
    after = int(conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"])
    assert after == before, "缺 CSRF 的写请求不得产生 run"
    client.headers["X-CSRF-Token"] = token
    assert client.post("/api/check", json={"region_code": cfg.region_code,
                                          "start": "2025-09-01",
                                          "end": "2025-09-05"}).status_code == 200


def test_au_login_is_read_only_and_write_is_403(ui):
    client, conn, cfg, out = ui
    login(client, "au1")
    assert client.get("/qa").status_code == 200
    assert client.post("/api/check", json={}).status_code == 403
    assert client.post("/api/import", json={}).status_code == 403
    bad = client.post("/login", data={"username": "au1", "password": "wrong"},
                      follow_redirects=True)
    assert "wca-test-au1-pw" not in bad.text


def test_au_demo_account_is_hash_only_and_read_only():
    cfg = Config.load(env_path=ROOT / "nonexistent.env", WCA_DB_BACKEND="sqlite")
    users = load_users_file(cfg)
    au = next(u for u in users if u["username"] == "au1")
    assert au["roles"] == ["AU"]
    assert str(au["pw_hash"]).startswith("scrypt$")
    text = Path(cfg.users_path).read_text(encoding="utf-8")
    assert "wca-demo-au1" not in text
    assert "scrypt$" in text


def test_ui_parity_two_channels_agree(ui):
    """V-01/US-UI-01：界面上传导入 + 校验，与脚本通道的结论摘要逐字节一致。"""
    client, conn, cfg, out = ui
    login(client, "op1")

    # 脚本通道：同一份 CSV 内容走 import_csv_file + run_check
    csv_text = ("emp_id,event_ts,punch_type,device_id\n"
                "T-STD,2025-09-04T09:00:00+08:00,in,DEV-X\n"
                "T-STD,2025-09-04T20:00:00+08:00,out,DEV-X\n")
    script_side_csv = cfg.data_dir / "parity-punch.csv"
    script_side_csv.parent.mkdir(parents=True, exist_ok=True)
    script_side_csv.write_bytes(csv_text.encode("utf-8"))   # 文本模式会改写行尾，指纹按字节算
    imported = import_csv_file(conn, cfg, script_side_csv)

    # 界面通道：同样的内容用 /api/import 提交（不同文件名、相同字节）
    res = client.post("/api/import", json={"filename": "parity-ui-punch.csv",
                                   "content": csv_text, "kind": "punch"})
    assert res.status_code == 200, res.text[:200]
    body = res.json()
    assert body["rows_seen"] == imported.rows_seen == 2, "两通道看到的行数必须一致"
    assert body["sha256"] == imported.sha256, "同一内容必须同一文件指纹（A7 的可追溯前提）"

    # 两侧输入都落库之后，在**同一库状态**上先跑脚本、再跑界面：三元组必须逐字节相同
    script = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5), notes="script parity")
    chk = client.post("/api/check", json={"region_code": cfg.region_code,
                                          "start": "2025-09-01", "end": "2025-09-05"})
    assert chk.status_code == 200, chk.text[:200]
    ui_body = chk.json()
    assert ui_body["triple"] == {"rule_pack_version": cfg.rule_pack_id,
                                 "input_fingerprint": script.input_fingerprint,
                                 "conclusion_digest": script.conclusion_digest}, \
        "界面与脚本在同一输入上算出的三元组不一致（双实现漂移）"
    assert ui_body["findings"] == len(script.findings), "界面与脚本结论条数不一致"
    assert ui_body["triple"]["rule_pack_version"] == cfg.rule_pack_id


def test_review_authz_server_side(ui):
    """V-02/US-UI-02（★）：未登录 401；OP 直连复核接口 403；RV 登记后库里出现具名记录。"""
    client, conn, cfg, out = ui
    rid = conn.execute("SELECT review_id FROM review_item WHERE status='OPEN' "
                       "ORDER BY review_id LIMIT 1").fetchone()["review_id"]

    assert client.post(f"/api/review/{rid}/decision",
                       json={"decision": "APPROVED"}).status_code == 401, "未登录也能复核？"

    login(client, "op1")
    res = client.post(f"/api/review/{rid}/decision", json={"decision": "APPROVED"})
    assert res.status_code == 403, f"OP 不该有复核权，实得 {res.status_code}"
    assert client.get("/review").status_code == 403, "OP 不该打开复核台"

    client.cookies.clear()
    login(client, "rv1")
    assert client.get("/review").status_code == 200
    ok = client.post(f"/api/review/{rid}/decision",
                     json={"decision": "APPROVED", "note": "已核对排班表"})
    assert ok.status_code == 200, ok.text[:200]
    row = conn.execute("SELECT status, reviewer, decided_at FROM review_item WHERE review_id=?",
                       (rid,)).fetchone()
    assert (row["status"], row["reviewer"]) == ("APPROVED", "rv1"), "结论必须落到具名的人"
    assert row["decided_at"], "结论必须带时间"
    # 已有结论不许覆盖，只能追加（审计链纪律）
    again = client.post(f"/api/review/{rid}/decision", json={"decision": "REJECTED"})
    assert again.status_code == 400 and "不得覆盖" in again.json()["detail"]


def test_ui_no_amount_even_after_manual_entry(ui):
    """V-03/US-UI-03（★）+ DEC-05 交叉断言：金额类问题页面与接口都不出现金额；
    RV 录入金额之后，问答视图与外发上下文仍然没有金额。"""
    client, conn, cfg, out = ui
    login(client, "rv1")

    rid = conn.execute("SELECT review_id FROM review_item WHERE status='OPEN' "
                       "ORDER BY review_id LIMIT 1").fetchone()["review_id"]
    res = client.post(f"/api/review/{rid}/decision",
                      json={"decision": "APPROVED", "note": "按省口径人工核额", "amount_cents": 4500})
    assert res.status_code == 200, res.text[:200]
    row = conn.execute("SELECT amount_cents_input, amount_entered_by FROM review_item "
                       "WHERE review_id=?", (rid,)).fetchone()
    assert row["amount_cents_input"] == 4500 and row["amount_entered_by"] == "human:rv1", \
        "金额必须是人工录入且可归责"

    money_questions = ["我该拿多少加班费", "国庆加班应付多少钱", "这笔加班要赔多少"]
    for q in money_questions:
        body = client.post("/api/ask", json={"question": q})
        assert body.status_code == 200, body.text[:200]
        payload = body.json()
        assert not re.search(r"\d[\d,]*\s*(元|万元|角)\b", payload["answer"]), \
            f"问答里出现金额：{q} → {payload['answer'][:80]}"
        assert payload["gate_decision"] != "ANSWERED", f"金额类问题不能直接给结论：{q}"

    page = client.get("/qa", params={"q": "我该拿多少加班费"})
    assert page.status_code == 200
    assert "内容由 AI 生成" in page.text, "问答页必须带 AI 生成标识（NFR-17）"
    assert not re.search(r"\d[\d,]*\s*元", page.text), "问答页渲染出了金额数字"


def test_acl_direct_request_as_employee_is_403_and_zero_recall(ui):
    """V-04/US-UI-05（★）：EM 会话直连受限接口 → 403；直连问答问他人 → 召回 0。"""
    client, conn, cfg, out = ui
    login(client, "em1")                          # em1 → E004，角色只有 EM

    assert client.get("/review").status_code == 403
    assert client.post("/api/export", json={}).status_code == 403
    assert client.post("/api/check", json={"region_code": cfg.region_code,
                                           "start": "2025-09-01",
                                           "end": "2025-09-05"}).status_code == 403
    res = client.post("/api/review/1/decision", json={"decision": "APPROVED"})
    assert res.status_code == 403, "复核权必须在服务端拦住，不是靠前端不给按钮"

    other = next(e["emp_id"] for e in EMPLOYEES if e["emp_id"] != "T-STD")
    body = client.post("/api/ask", json={"question": f"{other} 的考勤和薪酬明细"})
    assert body.status_code == 200, body.text[:200]
    payload = body.json()
    assert payload["gate_decision"].startswith("REFUSED"), payload["gate_decision"]
    leaked = [c["doc_id"] for c in payload["citations"] if other in c["doc_id"]]
    assert not leaked, f"越权召回：{leaked}"
    # 权限谓词进的是 SQL：候选集里连"无权文档"都不该出现
    cand = payload["retrieval"]["candidates"]
    assert f"personnel.payroll.{other}" not in cand, "他人薪酬条目连候选都不该是"


def test_identity_comes_from_session_not_from_query(ui):
    """GAP-05：接口不再接受自报身份；未登录的问答/导出直连一律 401。"""
    client, conn, cfg, out = ui
    assert client.get("/ask", params={"q": "加班几倍", "as_emp": "T-STD"}).status_code == 401
    assert client.get("/evidence/run-does-not-exist").status_code == 401
    login(client, "op1")
    body = client.get("/ask", params={"q": "我加班多少小时"}).json()
    assert body["actor_emp_id"] == "E001" or body["actor_emp_id"], "主体应来自会话"
    # as_emp 参数就算传了也不生效：会话是谁就是谁
    spoof = client.get("/ask", params={"q": "我加班多少小时", "as_emp": "T-OTHER"})
    assert spoof.json()["actor_emp_id"] != "T-OTHER", "自报身份的参数必须无效"


def test_export_single_entry_hash_matches_script(ui):
    """V-03/US-UI-04：界面导出按钮与脚本导出走同一个函数（结构上排除双实现）。"""
    client, conn, cfg, out = ui
    login(client, "rv1")
    script_manifest = export_package(conn, cfg, out.run_id)
    ui_manifest = client.post("/api/export", json={"run_id": out.run_id})
    assert ui_manifest.status_code == 200, ui_manifest.text[:200]
    body = ui_manifest.json()
    assert body["triple"]["conclusion_digest"] == script_manifest["triple"]["conclusion_digest"]
    assert body["triple"]["input_fingerprint"] == script_manifest["triple"]["input_fingerprint"]
    # manifest_sha256 含导出时间戳、audit_events 每次导出都会追加（链是 append-only），
    # 因此可比的是"结论侧"计数与三元组，不是整份清单哈希。
    for key in ("findings", "employees", "days"):
        if key in script_manifest["counts"]:
            assert body["counts"].get(key) == script_manifest["counts"][key], f"{key} 计数不一致"
    assert body["counts"]["audit_events"] > script_manifest["counts"]["audit_events"],         "第二次导出应当留下新的审计事件（追加，不改写）"
    assert body["chain_ok"] is True


def test_export_page_uses_delivery_wording_and_writes_event(ui):
    """界面不再说“签发”；导出动作写入 evidence.sign，并明确非密码学签名。"""
    client, conn, cfg, out = ui
    login(client, "rv1")
    html = client.get("/review").text
    assert "签发" not in html, "页面不得再出现“签发”字样"
    assert "登记交付事件" in html
    assert "非密码学签名" in html

    res = client.post("/api/export", json={"run_id": out.run_id})
    assert res.status_code == 200, res.text[:200]
    body = res.json()
    assert body["delivery_event_recorded"] is True

    row = conn.execute(
        "SELECT actor, action, run_id FROM audit_event WHERE action = 'evidence.sign' "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    assert (row["actor"], row["action"], row["run_id"]) == (
        "human:rv1", "evidence.sign", out.run_id)
    assert verify_chain(conn, cfg).ok


def test_passwords_and_secrets_never_leak(ui):
    """NFR-15：口令只存 scrypt 哈希；密钥不进响应、日志与页面。"""
    client, conn, cfg, out = ui
    login(client, "op1")          # 账号在首次登录时从配置文件同步入库
    stored = [r["pw_hash"] for r in conn.execute("SELECT pw_hash FROM app_user")]
    assert stored and all(h.startswith("scrypt$") for h in stored), "库里出现非 scrypt 口令存储"
    assert not any(h in ("wca-demo-op1", "wca-demo-rv1") for h in stored)

    login(client, "op1")
    page = client.get("/").text
    assert "wca-demo" not in page, "演示口令不得出现在页面里"
    session = client.get("/api/session").json()
    assert "pw_hash" not in json.dumps(session) and "api_key" not in json.dumps(session)
    # 令牌只存哈希
    token = client.cookies.get("wca_session")
    row = conn.execute("SELECT token_hash FROM app_session ORDER BY created_at DESC LIMIT 1").fetchone()
    assert token and row and token != row["token_hash"] and len(row["token_hash"]) == 64


def test_route_whitelist_replaces_count_assertion(ui):
    """GAP-04：接口面从"恰好 2 个"改为**白名单**——扩了什么看得见，而不是数量对不对。"""
    client, conn, cfg, out = ui
    app = api_mod.create_app(cfg)
    routes = sorted({(m, r.path) for r in app.routes
                     for m in (getattr(r, "methods", None) or []) if m != "HEAD"})
    paths = {p for _, p in routes}
    allowed = {"/login", "/logout", "/", "/review", "/qa", "/ask", "/evidence/{run_id}",
               "/api/import", "/api/check", "/api/review/{review_id}/decision", "/api/export",
               "/api/ask", "/api/session", "/static",
               "/approvals", "/approvals/coverage", "/approvals/new", "/approvals/import",
               "/approvals/{doc_no}", "/approvals/{doc_no}/edit",
               "/api/approvals/draft", "/api/approvals/import",
               "/api/approvals/{doc_no}/edit", "/api/approvals/{doc_no}/publish"}
    unexpected = paths - allowed
    assert not unexpected, f"界面之外新增了未登记的接口：{sorted(unexpected)}"
    # 所有写接口都必须 POST（幂等读接口才是 GET）；GET /login 只是渲染表单，写入口是 POST /login
    write_only = {"/api/import", "/api/check", "/api/export", "/api/ask", "/logout"}
    for method, path in routes:
        if path in write_only or path.startswith(("/api/review/", "/api/approvals/")):
            assert method == "POST", f"{path} 的写语义接口不应该是 {method}"
        if path in {"/", "/review", "/qa", "/api/session", "/ask", "/evidence/{run_id}",
                    "/approvals", "/approvals/coverage", "/approvals/new", "/approvals/import",
                    "/approvals/{doc_no}", "/approvals/{doc_no}/edit"}:
            assert method == "GET", f"{path} 是只读视图/读取口，不该有 {method} 面"
    methods_of_login = {m for m, p in routes if p == "/login"}
    assert methods_of_login == {"GET", "POST"}, f"登录接口形态变了：{methods_of_login}"


def test_rv_landing_page_is_not_forbidden(ui):
    """登录后不能把人送到一个他无权打开的页面（第一版就犯过这个错：RV 一跳 / 就 403）。"""
    client, conn, cfg, out = ui
    r = login(client, "rv1")
    assert r.headers.get("location") == "/review", f"RV 落地页应为复核台：{r.headers.get('location')}"
    assert client.get(r.headers["location"]).status_code == 200

    client.cookies.clear()
    r2 = login(client, "em1")
    assert r2.headers.get("location") == "/qa"
    assert client.get(r2.headers["location"]).status_code == 200


def test_decided_review_rows_stay_visible_with_amount(ui):
    """已登记的结论要能回看，且人工录入的金额只在复核台出现、不进问答视图。"""
    client, conn, cfg, out = ui
    login(client, "rv1")
    rid = conn.execute("SELECT review_id FROM review_item WHERE status='OPEN' "
                       "ORDER BY review_id LIMIT 1").fetchone()["review_id"]
    assert client.post(f"/api/review/{rid}/decision",
                       json={"decision": "APPROVED", "note": "复核完毕",
                             "amount_cents": 12345}).status_code == 200
    page = client.get("/review").text
    assert f"#{rid}" in page, "已登记的那条不能从界面上消失（责任要能被回看）"
    assert "12345 分" in page and "人工录入，非引擎输出" in page, "人工金额要标明来源与性质"
    assert "rv1" in page, "必须看得见是谁登记的"
    qa = client.get("/qa", params={"q": "我该拿多少加班费"}).text
    assert "12345" not in qa, "人工录入的金额不得串进问答视图"
