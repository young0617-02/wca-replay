"""F-014 交付：FastAPI 只读接口，一共 2 个（问一答 / 取举证包）。

刻意不做前端、不做写接口：
  * 两个接口都是 GET，不修改业务数据；
  * 但会写入 question_log / span / review_item / audit_event 四张观测与留痕表，
    这一点在 README 与口径声明里如实写明，不号称「纯只读无副作用」。
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from . import ENGINE_VERSION
from .agent import ComplianceAgent
from .anomaly import build_anomalies, severity_rollup
from .config import Config
from .db import connect, init_db
from .evidence import verify_chain

log = logging.getLogger("wca.api")

# 连接生命周期账本：stop 工具在关停后核对 opened == closed，
# 「每个请求开的 SQLite 连接都关掉了」因此是可断言的事实，不是靠 code review。
_STATS = {"opened": 0, "closed": 0}
_LIVE: dict[int, sqlite3.Connection] = {}


def open_connections() -> int:
    return len(_LIVE)


def connection_stats() -> dict[str, int]:
    return dict(_STATS)


def close_leaked_connections() -> int:
    """兜底关闭仍悬挂的连接（正常路径走不到这里；走到就说明有请求异常中断）。"""
    n = 0
    for conn in list(_LIVE.values()):
        try:
            conn.close()
        except sqlite3.Error:
            pass
        _LIVE.pop(id(conn), None)
        _STATS["closed"] += 1
        n += 1
    return n


def checkpoint_wal(cfg: Config) -> str:
    """把 WAL 里的数据落回主库文件，返回 ok/skip/failed。"""
    if not Path(cfg.db_path).is_file():
        return "skip"
    conn = None
    try:
        conn = connect(cfg.db_path, cfg.sqlite_synchronous)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return "ok"
    except sqlite3.Error as exc:
        log.warning("wal_checkpoint 失败：%s", exc)
        return "failed"
    finally:
        if conn is not None:
            conn.close()

try:  # FastAPI 只在启动 API 时必需；核心校验与测试不依赖它
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.responses import FileResponse, PlainTextResponse

    FASTAPI_AVAILABLE = True
    IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - 取决于本机装了什么
    FastAPI = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False
    IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


def create_app(cfg: Config | None = None) -> Any:
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            f"FastAPI 不可用（{IMPORT_ERROR}）。核心功能不依赖它：命令行 `python -m src.cli ask ...` "
            "走的是同一条链路。要起 API 请先 `pip install -r requirements.txt`。"
        )
    cfg = cfg or Config.load()

    @asynccontextmanager
    async def lifespan(_app: Any):
        log.info("api 启动：db=%s rule_pack=%s provider=%s backend=%s",
                 cfg.db_path, cfg.rule_pack_id, cfg.llm_provider, cfg.embedding_backend)
        try:
            yield
        finally:
            # 退出前把 WAL 落盘并 close 掉遗留连接，避免进程走了却留下 -wal/-shm 脏状态
            closed = close_leaked_connections()
            checkpointed = checkpoint_wal(cfg)
            log.info("api 关闭：连接开 %d 关 %d（收尾补关 %d），WAL checkpoint=%s",
                     _STATS["opened"], _STATS["closed"], closed, checkpointed)

    # openapi_url=None：连文档路由都不注册，保证「只有 2 个接口」这条约束是可机械检查的
    app = FastAPI(title="worktime-compliance-agent (MVP, read-only)", version=ENGINE_VERSION,
                  docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    def get_conn():
        """每个请求一条连接，请求结束即关——之前是借出去不还给连接池，属于泄漏。"""
        conn = connect(cfg.db_path, cfg.sqlite_synchronous)
        init_db(conn)
        _STATS["opened"] += 1
        _LIVE[id(conn)] = conn
        try:
            yield conn
        finally:
            _LIVE.pop(id(conn), None)
            conn.close()
            _STATS["closed"] += 1

    @app.get("/ask", summary="问一答（带 ACL 下推检索与确定性数值工具）")
    def ask(
        q: str = Query(..., min_length=1, description="自然语言提问"),
        as_emp: str = Query(..., description="提问主体员工 id（决定可见范围）"),
        top_k: int | None = Query(None, ge=1, le=20),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> dict:
        try:
            agent = ComplianceAgent(conn, cfg)
            ans = agent.ask(q, actor_emp_id=as_emp, top_k=top_k)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"主体不存在：{exc}") from exc
        return {
            "qid": ans.qid,
            "question": ans.question,
            "intent": ans.intent,
            "tier": ans.tier,
            "answer": ans.answer,
            "gate_decision": ans.gate_decision,
            "needs_review": ans.needs_review,
            "confidence_permille": ans.confidence_permille,
            "evidence_coverage_permille": ans.evidence_coverage_permille,
            "citations": [c.as_dict() for c in ans.citations],
            "numeric_tokens": ans.numeric_tokens,
            "violations": ans.violations,
            "provider": ans.provider,
            "model": ans.model,
            "degraded_to_offline_stub": ans.degraded,
            "retrieval": ans.retrieval,
            "elapsed_us": ans.elapsed_us,
        }

    @app.get("/evidence/{run_id}", summary="取举证包（zip：三元组 + findings + 审计链 + 质量报表）")
    def evidence(run_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> Any:
        row = conn.execute("SELECT * FROM evidence_package WHERE package_id = ?",
                           (f"pkg-{run_id}",)).fetchone()
        if row is None:
            raise HTTPException(status_code=404,
                                detail=f"举证包不存在：{run_id}（请先 `python -m src.cli export --run {run_id}`）")
        zip_path = Path(row["package_dir"])
        if not zip_path.is_file():
            raise HTTPException(status_code=410,
                                detail=f"举证包记录存在但文件缺失：{zip_path}")
        chain = verify_chain(conn, cfg)
        findings = build_anomalies(conn, run_id)
        headers = {
            "X-Rule-Pack-Version": str(row["rule_pack_version"]),
            "X-Input-Fingerprint": str(row["input_fingerprint"]),
            "X-Conclusion-Digest": str(row["conclusion_digest"]),
            "X-Manifest-Sha256": str(row["manifest_sha256"]),
            "X-Audit-Chain-Ok": "true" if chain.ok else "false",
            # HTTP 头只能是 latin-1，分级里含中文标签，因此这里只回传 ASCII 计数
            "X-Anomaly-Counts": json.dumps(
                {k: v for k, v in severity_rollup(findings).items() if k.isascii()},
                ensure_ascii=True, sort_keys=True),
            "Cache-Control": "no-store",
        }
        return FileResponse(zip_path, media_type="application/zip",
                            filename=zip_path.name, headers=headers)

    return app


def serve(cfg: Config | None = None, *, host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    app_ = create_app(cfg)
    uvicorn.run(app_, host=host, port=port, log_level="info")


# 模块级实例：`uvicorn src.api:app` 与 `tools/start_services.py` 都按这个约定加载。
# 没有它，README 里那条命令会在导入期就报「Attribute "app" not found」。
app = create_app() if FASTAPI_AVAILABLE else None


if not FASTAPI_AVAILABLE:  # pragma: no cover - 便于 CLI 给出可执行的下一步
    def serve(*_a: Any, **_k: Any) -> None:  # type: ignore[misc]
        raise RuntimeError(f"FastAPI/uvicorn 未安装：{IMPORT_ERROR}；请 pip install -r requirements.txt")
