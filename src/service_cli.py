"""启停工具的共同内核：`tools/start_services.py` 与 `tools/stop_services.py` 都只是它的入口。

放在 src 里而不是复制两份，是为了让「启动」和「停止」用的是同一套状态机与同一份服务清单，
避免出现「启动认为是活的、停止认为是死的」这种两边各写一套探测逻辑的经典事故。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .config import Config
from .db import connect
from .service_manager import (
    Report,
    ServiceManager,
    is_required,
    load_services_config,
    now_iso,
    port_open,
    setup_logging,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2


class ConfigError(RuntimeError):
    """配置层错误：工具入口把它翻译成退出码 2，而不是抛栈给用户看。"""


def _app_cfg(env_path: str | None) -> Config:
    return Config.load(env_path)


def _manager(args: argparse.Namespace, op: str) -> tuple[ServiceManager, Path]:
    app_cfg = _app_cfg(getattr(args, "env", None))
    try:
        services = load_services_config(args.config, app_cfg)
    except (FileNotFoundError, ValueError) as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        raise ConfigError(str(exc)) from exc
    logger, log_path = setup_logging(Path(services.defaults.get("log_dir") or "var/logs"),
                                     op, verbose=getattr(args, "verbose", False))
    mgr = ServiceManager(services, logger=logger, env_snapshot=app_cfg.raw)
    return mgr, log_path


def checkpoint_database(app_cfg: Config, logger) -> str:
    """所有被管理的服务都停下之后，把 WAL 落回主库：防止进程走了却留下 -wal/-shm 半成品。"""
    if not Path(app_cfg.db_path).is_file():
        return "skip(无库文件)"
    conn: sqlite3.Connection | None = None
    try:
        conn = connect(app_cfg.db_path, app_cfg.sqlite_synchronous)
        busy, log_size, checkpointed = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return f"busy={busy} log={log_size} checkpointed={checkpointed}"
    except sqlite3.Error as exc:
        logger.warning("WAL checkpoint 失败（不影响已停止的服务）：%s", exc)
        return f"failed({type(exc).__name__})"
    finally:
        if conn is not None:
            conn.close()


def render_report(rep: Report, log_files: list[Path], as_json: bool) -> str:
    if as_json:
        payload = rep.as_dict()
        payload["log_files"] = [str(p) for p in log_files]
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    lines = [rep.as_text()]
    if log_files:
        lines.append("工具日志：" + "、".join(str(p) for p in log_files))
    return "\n".join(lines)


def status_text(args: argparse.Namespace) -> tuple[str, int]:
    """一眼看清：谁在跑、pid 多少、端口通不通、状态文件是不是陈年的。

    `--only` 与 `--json` 过去在这里是**被接收但被忽略**的（`_service_argv` 确实把它们转了进来，
    下游没读）——"转发了但没人用"这类缺陷静态对账看不见，所以两个都补上实现。
    """
    app_cfg = _app_cfg(getattr(args, "env", None))
    try:
        services = load_services_config(args.config, app_cfg)
    except (FileNotFoundError, ValueError) as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        raise ConfigError(str(exc)) from exc
    only = [x.strip() for x in str(getattr(args, "only", "") or "").split(",") if x.strip()]
    names = {s.name for s in services.specs}
    if only:
        missing = sorted(set(only) - names)
        if missing:
            raise ConfigError(f"配置里没有这些服务：{missing}；可选：{sorted(names)}")
    mgr = ServiceManager(services, env_snapshot=app_cfg.raw)
    verdict_map = {
        "ours": "运行中（本工具启动）",
        "foreign": "端口被外部进程占用",
        "stale": "状态残留（进程已不在）",
        "ready": "外部依赖在线",
        "absent": "外部依赖不在线",
        "none": "未运行",
    }
    rows: list[dict] = []
    try:
        by_name = {s.name: s for s in services.specs}
        for st in mgr.status():
            if only and st.name not in only:
                continue
            spec = by_name[st.name]
            rows.append({"name": st.name, "managed": bool(spec.managed), "origin": st.origin,
                         "state": verdict_map[st.origin], "pid": st.pid, "host": spec.host,
                         "port": spec.port, "port_open": bool(st.port_open),
                         "required": bool(spec.managed or is_required(spec, app_cfg.raw)),
                         "started_at": st.started_at})
    finally:
        mgr.close()
    as_of = now_iso()
    code = EXIT_OK
    if getattr(args, "json", False):
        # 一个"按配置根本不需要"的外部依赖不该把整体判成不健康
        judged = [r for r in rows if r["required"]]
        payload = {"as_of": as_of, "services": rows,
                   "filter": only or "all", "judged": [r["name"] for r in judged],
                   "all_ok": all(r["origin"] in ("ours", "ready", "none") for r in judged)}
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), code
    body = "\n".join(
        f"  {r['name']:10s} managed={int(r['managed'])} {r['state']:22s} "
        f"pid={r['pid'] or '-'} addr={r['host']}:{r['port'] or '-'} "
        f"{'端口通' if r['port_open'] else '端口不通'}  started_at={r['started_at'] or '-'}"
        for r in rows)
    scope = "" if not only else f"（只看 {','.join(only)}）"
    return f"服务状态（{as_of}）{scope}：\n{body}", code


def main_start(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="tools/start_services.py",
        description="一键启动：先检测是否在跑，在跑就先全停再按顺序启动")
    ap.add_argument("--config", default=None, help="服务清单 JSON，默认 config/services.json")
    ap.add_argument("--env", default=None, help=".env 路径，默认项目根 .env")
    ap.add_argument("--only", default="", help="逗号分隔服务名，默认全部")
    ap.add_argument("--no-restart", action="store_true",
                    help="已在跑就直接报错退出，不做先停后起")
    ap.add_argument("--timeout", type=float, default=None, help="覆盖就绪等待秒数")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        mgr, log_path = _manager(args, "start")
    except ConfigError:
        return EXIT_CONFIG
    try:
        if args.timeout:
            for spec in mgr.services.specs:
                spec.ready_timeout_s = args.timeout
        rep = mgr.start_all(only=_split(args.only), restart_if_running=not args.no_restart)
    except (KeyError, ValueError, FileNotFoundError, ConfigError) as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        return EXIT_CONFIG
    finally:
        released = mgr.close()
    if log_path:
        rep.log_files = [str(log_path)]
    rep.resources["released"] = released
    print(render_report(rep, [log_path], args.json))
    if not rep.ok:
        print("\n恢复建议：见上面每条 ERR 的 hint；完整日志 var/logs/*.log 与 "
              "config/services.json 的服务定义。", file=sys.stderr)
    return EXIT_OK if rep.ok else EXIT_FAILED


def main_stop(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools/stop_services.py",
                                 description="一键优雅停止：先信号、后强杀，逐项核对端口与资源")
    ap.add_argument("--config", default=None)
    ap.add_argument("--env", default=None)
    ap.add_argument("--only", default="", help="逗号分隔服务名，默认全部被管理的服务")
    ap.add_argument("--grace", type=float, default=None, help="覆盖优雅等待秒数")
    ap.add_argument("--force", action="store_true", help="跳过优雅等待直接强杀")
    ap.add_argument("--no-checkpoint", action="store_true", help="不做停止后的 WAL 落盘")
    ap.add_argument("--status", action="store_true", help="只打印状态，不停任何东西")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.status:
        try:
            text, code = status_text(args)
        except ConfigError as exc:
            # 光返回退出码不说话，用户只会看到"什么都没发生"——配置错误必须把原因打印出来
            print(f"状态查询失败：{exc}", file=sys.stderr)
            return EXIT_CONFIG
        print(text)
        return code

    try:
        mgr, log_path = _manager(args, "stop")
    except ConfigError:
        return EXIT_CONFIG
    try:
        if args.grace:
            for spec in mgr.services.specs:
                spec.grace_period_s = args.grace
        rep = mgr.stop_all(only=_split(args.only), force=args.force)
    except (KeyError, ValueError, ConfigError) as exc:
        print(f"停止失败：{exc}", file=sys.stderr)
        return EXIT_CONFIG
    finally:
        released = mgr.close()
    if not args.no_checkpoint:
        chk = checkpoint_database(_app_cfg(args.env), mgr.log)
        rep.resources["wal_checkpoint"] = chk
    rep.resources["released"] = released
    rep.log_files = [str(log_path)] if log_path else []
    print(render_report(rep, [log_path] if log_path else [], args.json))
    if not rep.ok:
        print("\n还有端口或进程没干净：按上面 hint 处理；不要盲杀不认识的 pid。", file=sys.stderr)
    return EXIT_OK if rep.ok else EXIT_FAILED


def _split(raw: str) -> list[str] | None:
    items = [x.strip() for x in str(raw or "").split(",") if x.strip()]
    return items or None
