"""被 `tools/start_services.py` 拉起来的服务进程本体（uvicorn 的受控包装）。

为什么不直接 `uvicorn src.api:app`：
  1. Windows 上分离启动（DETACHED_PROCESS）后收不到控制台信号，优雅关闭会退化成强杀；
  2. 强杀 = 在途请求被切断、WAL 没落盘、连接没关 —— 正是「不丢数据、不脏状态」要避免的。

所以这里给进程加一条**与信号无关**的优雅关闭通道：
  停止工具写 `var/run/<name>.stop` → 本进程轮询到就 `should_exit=True`
  → uvicorn 收尾在途请求 → lifespan 的 finally 关闭遗留连接并把 WAL 落盘 → 进程正常退出。
POSIX 上仍同时响应 SIGTERM/SIGINT（uvicorn 原生支持），两条通道都在，谁先到都算优雅。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
from pathlib import Path

import uvicorn

from . import ENGINE_VERSION
from .api import checkpoint_wal, close_leaked_connections, connection_stats, create_app
from .config import Config

STOP_POLL_S = 0.2


def _stop_file(run_dir: Path, name: str) -> Path:
    return run_dir / f"{name}.stop"


async def _watch_stop(server: uvicorn.Server, path: Path, log: logging.Logger) -> None:
    while not server.should_exit:
        await asyncio.sleep(STOP_POLL_S)
        if path.exists():
            log.info("检测到停止请求文件 %s，开始优雅退出", path)
            server.should_exit = True
            break


async def _amain(cfg: Config, name: str, host: str, port: int, run_dir: Path) -> int:
    log = logging.getLogger(f"wca.server.{name}")
    stop_path = _stop_file(run_dir, name)
    # 上一次运行留下的停止文件会让本次启动秒退，必须先清掉
    if stop_path.exists():
        log.warning("清理上次遗留的停止请求文件 %s", stop_path)
        stop_path.unlink(missing_ok=True)

    app = create_app(cfg)
    config = uvicorn.Config(
        app, host=host, port=port, log_level="info", access_log=False,
        lifespan="on", backlog=128, timeout_graceful_shutdown=10,
    )
    server = uvicorn.Server(config)
    log.info("服务 %s 启动：engine=%s rule_pack=%s 监听 %s:%s 停止通道=%s",
             name, ENGINE_VERSION, cfg.rule_pack_id, host, port, stop_path)

    watcher = asyncio.create_task(_watch_stop(server, stop_path, log))
    # 信号通道交给 uvicorn 自己装（它在 Windows 上会捕获 SIGBREAK，POSIX 捕获 SIGTERM/SIGINT）；
    # 停止文件是与信号无关的第二条通道，保证分离启动的进程也能优雅退出。
    try:
        await server.serve()
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await watcher
        stats = connection_stats()
        leaked = close_leaked_connections()
        ckpt = checkpoint_wal(cfg)
        log.info("服务 %s 已退出：连接开 %d / 关 %d / 收尾补关 %d，WAL checkpoint=%s",
                 name, stats["opened"], stats["closed"], leaked, ckpt)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    name = os.environ.get("WCA_SERVICE_NAME") or (args[0] if args else "api")
    host = os.environ.get("WCA_HOST", "127.0.0.1")
    port = int(os.environ.get("WCA_PORT", "8000"))
    run_dir = Path(os.environ.get("WCA_RUN_DIR", "var/run"))
    run_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    cfg = Config.load()
    if name != "api":
        print(f"本包装只认识服务名 api，收到 {name!r}", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_amain(cfg, name, host, port, run_dir))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
