"""服务启停引擎：一键启动与一键停止共用同一套状态机。

设计约束（对着需求逐条实现，不是顺手写的）：
  * 启动前自动检测：状态文件里的 pid 是否还活着、端口是否被占；
    是自己起过的服务 -> 先按停止顺序全停再启动；是别人的进程 -> 拒绝抢占并给出排查线索。
  * 优雅停止：先发中断信号（Windows 用 CTRL_BREAK，POSIX 用 SIGTERM），
    等它自己把请求收尾、把 SQLite 的 WAL 落盘；超过宽限期才升级成强杀，并如实标注 forced。
  * 资源清理：本工具自己的线程池、socket、sqlite 句柄、临时文件全部显式关闭；
    停止后再核对「服务连接开=关」与端口已释放。
  * 状态文件用 tmp + os.replace 原子写，中途崩不留半个 JSON。
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config" / "services.json"
STATE_SCHEMA = "wca-service-state-v1"
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    _STOP_SIGNAL = signal.CTRL_BREAK_EVENT      # uvicorn 在 Windows 上会捕获 SIGBREAK
    _KILL_TIMEOUT = 8
else:
    _STOP_SIGNAL = signal.SIGTERM
    _KILL_TIMEOUT = 8


def now_iso() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


# ------------------------------------------------------------------ 配置
@dataclass
class ServiceSpec:
    name: str
    managed: bool = True
    start_order: int = 100
    stop_order: int = 100
    host: str = "127.0.0.1"
    port: int | None = None
    argv: list[str] = field(default_factory=list)
    cwd: str = "."
    env: dict[str, str] = field(default_factory=dict)
    probe: str = "port"                 # port | none
    ready_timeout_s: float = 30.0
    grace_period_s: float = 12.0
    required_when: dict[str, Any] | None = None
    requires_import: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def key(self) -> str:
        return f"{self.name}"


@dataclass
class ServicesConfig:
    defaults: dict[str, Any]
    specs: list[ServiceSpec]
    path: Path
    problems: list[str] = field(default_factory=list)

    def managed(self) -> list[ServiceSpec]:
        return [s for s in self.specs if s.managed]

    def by_start_order(self) -> list[ServiceSpec]:
        return sorted(self.specs, key=lambda s: (s.start_order, s.name))

    def by_stop_order(self) -> list[ServiceSpec]:
        return sorted(self.specs, key=lambda s: (s.stop_order, s.name), reverse=True)


def load_services_config(path: Path | str | None = None, app_cfg: Any | None = None
                         ) -> ServicesConfig:
    p = Path(path) if path else DEFAULT_CONFIG
    problems: list[str] = []
    if not p.is_file():
        raise FileNotFoundError(
            f"服务清单配置不存在：{p}\n恢复建议：从仓库里恢复 config/services.json，"
            "或显式传 --config <路径>")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"服务清单 JSON 解析失败：{p} -> {exc}") from exc
    defaults = raw.get("defaults", {})
    rows = raw.get("services", [])
    if not isinstance(rows, list) or not rows:
        problems.append("services 列表为空")
    env_values = dict(getattr(app_cfg, "raw", {}) or {})
    specs: list[ServiceSpec] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or not row.get("name"):
            problems.append(f"services[{i}] 缺 name")
            continue
        argv = [a.replace("<python>", sys.executable) for a in row.get("argv", [])]
        if row.get("module"):
            argv = argv or [sys.executable, "-m", str(row["module"])]
        spec = ServiceSpec(
            name=str(row["name"]),
            managed=bool(row.get("managed", True)),
            start_order=int(row.get("start_order", defaults.get("start_order", 100))),
            stop_order=int(row.get("stop_order", defaults.get("stop_order", 100))),
            host=str(row.get("host", defaults.get("host", "127.0.0.1"))),
            port=int(row["port"]) if row.get("port") not in (None, "") else None,
            argv=argv,
            cwd=str(row.get("cwd", defaults.get("cwd", str(ROOT)))),
            env={str(k): str(v) for k, v in (row.get("env") or {}).items()},
            probe=str(row.get("probe", "port" if row.get("port") else "none")),
            ready_timeout_s=float(row.get("ready_timeout_s", defaults.get("ready_timeout_s", 30))),
            grace_period_s=float(row.get("grace_period_s", defaults.get("grace_period_s", 12))),
            required_when=row.get("required_when"),
            requires_import=[str(x) for x in (row.get("requires_import") or [])],
            notes=str(row.get("notes", "")),
        )
        if spec.managed and not spec.argv:
            problems.append(f"{spec.name}: managed=true 但没有 argv/module，无法启动")
        specs.append(spec)
    seen: set[str] = set()
    for s in specs:
        if s.name in seen:
            problems.append(f"服务名重复：{s.name}")
        seen.add(s.name)
    cfg = ServicesConfig(defaults=defaults, specs=specs, path=p, problems=problems)
    if problems:
        raise ValueError("服务清单配置不合法：\n  - " + "\n  - ".join(problems)
                         + "\n恢复建议：修正 config/services.json 后重试；"
                         "服务列表支持增删条目，字段含义见 docs/服务启停.md")
    return cfg


def probe_imports(python: str, modules: list[str], cwd: str | None = None) -> str | None:
    """用**将要启动服务的那个解释器**试导入，返回第一个导不进的模块名（全都能导入则 None）。

    为什么不在启动器进程内 `importlib.import_module` 试：本项目的服务是用
    `argv[0]`（= 调用方的 `sys.executable`）拉起的子进程。用 cmd 里的全局 python 直接跑
    `tools/start_services.py` 时，启动器自己可能什么都能导（因为它不 import fastapi），
    而子进程起来就死在 `ImportError: cannot import name 'sentinel' from 'typing_extensions'`，
    30 秒超时后工具只会说"端口若被占"——把解释器问题误诊成端口问题。
    所以要探就得探**那个解释器**。
    """
    if not modules:
        return None
    code = "; ".join(f"import {m}" for m in modules)
    try:
        res = subprocess.run([python, "-c", code], cwd=cwd, capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return modules[0]
    if res.returncode == 0:
        return None
    out = (res.stderr or "") + (res.stdout or "")
    for m in modules:
        if re.search(rf"import name '?{re.escape(m)}'?|No module named '?{re.escape(m)}'?", out):
            return m
    return modules[0]


def interpreter_hint(python: str) -> str:
    """按"解释器是不是项目环境"给出两种不同的下一步，别把两种病因开同一张方子。"""
    venv_dir = (ROOT / ".venv").resolve()
    try:
        resolved = Path(python).resolve()
        inside = resolved.is_relative_to(venv_dir) or venv_dir in resolved.parents
    except (OSError, ValueError):
        inside = False
    if inside:
        return (f"解释器就是项目环境（{python}），但依赖导不进——先 `uv sync` 按 uv.lock 重建环境；"
                "仍失败则看服务自己的日志")
    return (f"当前解释器 {python} **不是**项目环境（{venv_dir}）。本仓库依赖只走 uv，"
            f"请用 `uv run python tools/start_services.py`（或先激活 .venv 再跑）")


def is_required(spec: ServiceSpec, env_snapshot: dict[str, str]) -> bool:
    rw = spec.required_when
    if not rw:
        return True
    key, want = str(rw.get("env", "")), rw.get("equals")
    if not key:
        return True
    return str(env_snapshot.get(key, "")) == str(want)


# ------------------------------------------------------------------ 探测
def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if IS_WINDOWS:
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return ctypes.windll.kernel32.GetLastError() == ERROR_ACCESS_DENIED
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)      # POSIX 上 signal 0 只探活，不会杀
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def port_open(host: str, port: int, timeout_s: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_s):
            return True
    except OSError:
        return False


def listener_pid(host: str, port: int) -> int | None:
    """端口被谁占着。netstat / ss 都不可用时返回 None，并在日志里说清。"""
    if IS_WINDOWS:
        exe = shutil.which("netstat")
        if not exe:
            return None
        out = subprocess.run([exe, "-ano", "-p", "tcp"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
        needle = f":{port}"
        for line in out.stdout.splitlines():
            cols = line.split()
            if len(cols) >= 5 and cols[0].upper() == "TCP" and cols[1].endswith(needle) \
                    and cols[3].upper() == "LISTENING":
                try:
                    return int(cols[4])
                except ValueError:
                    continue
        return None
    for tool in (["ss", "-ltnp"], ["lsof", "-i", f"TCP@{host}:{port}", "-sTCP:LISTEN"]):
        exe = shutil.which(tool[0])
        if not exe:
            continue
        out = subprocess.run(tool, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
        for line in out.stdout.splitlines():
            if f":{port} " in line or f":{port}\t" in line:
                digits = [tok for tok in line.replace(")", " ").split() if tok.isdigit()]
                if digits:
                    return int(digits[-1])
    return None


# ------------------------------------------------------------------ 状态文件
@dataclass
class ServiceState:
    name: str
    pid: int | None = None
    pgid: int | None = None
    port: int | None = None
    host: str = ""
    argv: list[str] = field(default_factory=list)
    started_at: str = ""
    log_path: str = ""
    alive: bool = False
    port_open: bool = False
    foreign_pid: int | None = None
    origin: str = "none"        # none | ours | foreign | stale

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class StateStore:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._temp_files: list[Path] = []

    def path(self, name: str) -> Path:
        return self.run_dir / f"{name}.json"

    def read(self, name: str) -> dict | None:
        p = self.path(name)
        if not p.is_file():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def write(self, payload: dict) -> Path:
        """原子写：先写同目录 tmp，fsync 后 os.replace。"""
        target = self.path(str(payload["name"]))
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(self.run_dir))
        tmp = Path(tmp_name)
        self._temp_files.append(tmp)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
            if tmp in self._temp_files:
                self._temp_files.remove(tmp)
        finally:
            self._discard_leftover(tmp)
        return target

    def _discard_leftover(self, tmp: Path) -> None:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    def remove(self, name: str) -> None:
        p = self.path(name)
        if p.exists():
            p.unlink()

    def cleanup_temp(self) -> list[str]:
        removed = []
        for tmp in list(self._temp_files):
            if tmp.exists():
                try:
                    tmp.unlink()
                    removed.append(tmp.name)
                except OSError:
                    pass
            if tmp in self._temp_files:
                self._temp_files.remove(tmp)
        for stale in self.run_dir.glob(".tmp-*"):
            try:
                stale.unlink()
                removed.append(stale.name)
            except OSError:
                pass
        return removed

    def close(self) -> None:
        self.cleanup_temp()


# ------------------------------------------------------------------ 结果对象
@dataclass
class ServiceOutcome:
    name: str
    action: str            # start | stop | precheck | skip
    ok: bool
    status: str            # started | restarted | already-stopped | graceful | forced | failed | foreign | not-required
    pid: int | None = None
    port: int | None = None
    elapsed_ms: int = 0
    message: str = ""
    hint: str = ""

    def line(self) -> str:
        flag = "OK " if self.ok else "ERR"
        base = f"[{flag}] {self.action:8s} {self.name:10s} {self.status:14s} {self.elapsed_ms:6d} ms"
        return base + (f"  :: {self.message}" if self.message else "")

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Report:
    op: str
    outcomes: list[ServiceOutcome] = field(default_factory=list)
    started_at: str = ""
    elapsed_ms: int = 0
    resources: dict[str, Any] = field(default_factory=dict)
    log_files: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(o.ok for o in self.outcomes)

    def as_text(self) -> str:
        lines = [f"===== {self.op} 结果（{self.started_at}，耗时 {self.elapsed_ms} ms）====="]
        lines += [o.line() for o in self.outcomes]
        bad = [o for o in self.outcomes if not o.ok]
        if bad:
            lines.append("-- 需要处理 --")
            lines += [f"  · {o.name}: {o.hint or o.message}" for o in bad]
        lines.append(f"资源清理：{self.resources}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "op": self.op, "ok": self.ok, "started_at": self.started_at,
            "elapsed_ms": self.elapsed_ms, "resources": self.resources,
            "log_files": self.log_files, "outcomes": [o.as_dict() for o in self.outcomes],
        }


# ------------------------------------------------------------------ 主引擎
class ServiceManager:
    def __init__(self, services: ServicesConfig, *, log_dir: Path | str | None = None,
                 run_dir: Path | str | None = None, logger: logging.Logger | None = None,
                 env_snapshot: dict[str, str] | None = None) -> None:
        self.services = services
        d = services.defaults
        self.log_dir = Path(log_dir or d.get("log_dir", ROOT / "var" / "logs"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.store = StateStore(Path(run_dir or d.get("run_dir", ROOT / "var" / "run")))
        self.log = logger or logging.getLogger("wca.services")
        self.env_snapshot = dict(env_snapshot or {})
        self._executor: ThreadPoolExecutor | None = None
        self._sockets: list[socket.socket] = []
        self._sqlite_handles: list[Any] = []
        self._lock = threading.Lock()
        self._closed = False

    # -------------------------------------------------------------- 资源登记与释放
    def _pool(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._closed:
                raise RuntimeError("ServiceManager 已关闭，请重新创建")
            if self._executor is None:
                workers = max(1, min(8, len(self.services.specs)))
                self._executor = ThreadPoolExecutor(max_workers=workers,
                                                    thread_name_prefix="wca-svc")
            return self._executor

    def register_socket(self, sock: socket.socket) -> None:
        self._sockets.append(sock)

    def register_sqlite(self, conn: Any) -> None:
        self._sqlite_handles.append(conn)

    def status(self) -> list[ServiceState]:
        return [self._probe(s) for s in sorted(self.services.specs,
                                               key=lambda x: (x.start_order, x.name))]

    def stop_file(self, spec: ServiceSpec) -> Path:
        """优雅关闭的主通道：与信号无关，分离进程也收得到。"""
        return self.store.run_dir / f"{spec.name}.stop"

    def _probe(self, spec: ServiceSpec) -> ServiceState:
        data = self.store.read(spec.name) or {}
        pid = int(data.get("pid") or 0) or None
        state = ServiceState(
            name=spec.name, pid=pid, pgid=data.get("pgid"), port=spec.port, host=spec.host,
            argv=list(data.get("argv") or []), started_at=str(data.get("started_at") or ""),
            log_path=str(data.get("log_path") or ""), origin="none",
        )
        state.alive = bool(pid and pid_alive(pid))
        if spec.port:
            state.port_open = port_open(spec.host, spec.port)
        if state.alive:
            state.origin = "ours"
        elif data:
            state.origin = "stale"
        if spec.port and state.port_open and not state.alive:
            if spec.managed:
                state.foreign_pid = listener_pid(spec.host, spec.port)
                state.origin = "foreign"
            else:
                state.origin = "ready"        # 外部依赖在线，不由本工具管生死
        elif not spec.managed and not state.alive:
            state.origin = "absent"
        return state

    # -------------------------------------------------------------- 启动
    def start_all(self, *, only: list[str] | None = None, restart_if_running: bool = True,
                  stop_first: bool = True) -> Report:
        t0 = time.perf_counter()
        rep = Report(op="start", started_at=now_iso())
        targets = self._select(self.services.by_start_order(), only)

        precheck = self._precheck(targets, restart_if_running=restart_if_running)
        rep.outcomes += precheck
        blocking = [o for o in precheck if not o.ok]
        if blocking:
            rep.elapsed_ms = self._ms(t0)
            return rep

        running = [s for s in targets if s.managed and self._probe(s).alive]
        if running and restart_if_running and stop_first:
            self.log.info("检测到 %d 个服务已在运行，先按停止顺序全部停掉：%s",
                          len(running), [s.name for s in running])
            stop_rep = self.stop_all(only=[s.name for s in running], reason="restart")
            rep.outcomes += stop_rep.outcomes
            running = [s for s in targets if s.managed and self._probe(s).alive]
        if running and not restart_if_running:
            for s in running:
                rep.outcomes.append(ServiceOutcome(s.name, "start", False, "already-running",
                                                   pid=self._probe(s).pid, port=s.port,
                                                   message="服务已在运行",
                                                   hint="要先重启就用 tools/start_services.py（默认先停后起），"
                                                        "或先跑 tools/stop_services.py"))
            rep.elapsed_ms = self._ms(t0)
            return rep

        for spec in targets:
            rep.outcomes.append(self._start_one(spec))
        rep.resources = self.release_probe()
        rep.elapsed_ms = self._ms(t0)
        return rep

    def _precheck(self, specs: list[ServiceSpec], *,
                  restart_if_running: bool = True) -> list[ServiceOutcome]:
        probes = list(specs)   # 无端口的服务也要探活，否则 precheck 报不出「已在运行」
        states: dict[str, ServiceState] = {}
        if probes:
            futures = [self._pool().submit(self._probe, s) for s in probes]
            for fut in futures:
                st = fut.result()
                states[st.name] = st
        out: list[ServiceOutcome] = []
        for s in specs:
            if not s.managed:
                if not is_required(s, self.env_snapshot):
                    out.append(ServiceOutcome(s.name, "precheck", True, "not-required",
                                              message="按配置当前不需要该依赖，跳过"))
                    continue
                st = states.get(s.name) or self._probe(s)
                if st.port_open:
                    out.append(ServiceOutcome(s.name, "precheck", True, "ready",
                                              port=s.port, message="外部依赖在线（不由本工具启停）"))
                else:
                    out.append(ServiceOutcome(
                        s.name, "precheck", False, "missing-dependency", port=s.port,
                        message=f"外部依赖 {s.name} 未在 {s.host}:{s.port} 监听",
                        hint=f"先把它起来（例如 `ollama serve`），或把 .env 的 WCA_LLM_PROVIDER 改回 "
                             f"stub 再启动本服务；本工具不会去猜一个没配置好的模型地址"))
                continue
            st = states.get(s.name)
            if s.requires_import and s.managed:
                missing = probe_imports(s.argv[0] if s.argv else sys.executable,
                                        s.requires_import, s.cwd)
                if missing:
                    out.append(ServiceOutcome(
                        s.name, "precheck", False, "missing-interpreter-deps", port=s.port,
                        message=f"将要启动它的解释器导不进 {missing}（依赖只装在项目 .venv 里）",
                        hint=interpreter_hint(s.argv[0] if s.argv else sys.executable)))
                    continue
            if st and st.origin == "foreign":
                out.append(ServiceOutcome(
                    s.name, "precheck", False, "port-occupied", port=s.port,
                    pid=st.foreign_pid,
                    message=f"端口 {s.host}:{s.port} 被外部进程占用"
                            + (f"（pid={st.foreign_pid}）" if st.foreign_pid else "（pid 未取到）"),
                    hint=f"确认那个进程是什么：Windows `tasklist /FI \"PID eq {st.foreign_pid}\"`；"
                         f"确认可以结束它再结束，或改 config/services.json 里的 port"))
            elif st and st.alive:
                out.append(ServiceOutcome(
                    s.name, "precheck", True, "running", pid=st.pid, port=s.port,
                    # 措辞必须与 --no-restart 一致：曾经在这里无条件写「将先停后起」，
                    # 而 --no-restart 随后就拒绝启动，同一屏上前后矛盾
                    message="已在运行，将先停后起" if restart_if_running
                    else "已在运行（按要求不重启，稍后会拒绝对它动手）"))
            else:
                out.append(ServiceOutcome(s.name, "precheck", True, "free", port=s.port,
                                          message="端口空闲" if s.port else "无端口，直接启动"))
        return out

    def _start_one(self, spec: ServiceSpec) -> ServiceOutcome:
        t0 = time.perf_counter()
        if not spec.managed:
            return ServiceOutcome(spec.name, "start", True, "skipped", message="外部依赖不代为启动")
        log_path = self.log_dir / f"{spec.name}.log"
        env = dict(os.environ)
        env.update(spec.env)
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        env.setdefault("WCA_SERVICE_NAME", spec.name)
        if spec.port:
            env.setdefault("WCA_PORT", str(spec.port))
            env.setdefault("WCA_HOST", spec.host)
        env.setdefault("WCA_RUN_DIR", str(self.store.run_dir))
        self.stop_file(spec).unlink(missing_ok=True)      # 清掉上次遗留的停止请求
        try:
            fh = open(log_path, "ab")  # noqa: SIM115 - 句柄交给子进程，父进程不写它
            if IS_WINDOWS:
                # DETACHED：否则启动器所在控制台一关，服务就被连带杀掉（实测踩过）
                flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                proc = subprocess.Popen(  # noqa: S603 - argv 来自本地配置文件
                    spec.argv, cwd=spec.cwd, env=env, stdout=fh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, creationflags=flags)
            else:
                proc = subprocess.Popen(  # noqa: S603
                    spec.argv, cwd=spec.cwd, env=env, stdout=fh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True)
            fh.close()
        except (OSError, ValueError) as exc:
            return ServiceOutcome(
                spec.name, "start", False, "failed", port=spec.port,
                message=f"启动命令执行失败：{type(exc).__name__}: {exc}",
                hint=f"检查 argv 是否可执行：{spec.argv}；cwd 是否存在：{spec.cwd}")

        ready = self._wait_ready(spec, proc.pid)
        if ready is None:
            tail = _tail(log_path, 12)
            self._force_kill(proc.pid, spec)
            self.store.remove(spec.name)
            # 日志里是 ImportError 就别甩锅给端口——这是本工具曾经指错过的一次真事故
            if re.search(r"ImportError|ModuleNotFoundError", tail):
                hint = (f"子进程是**导入失败**，不是端口问题。{interpreter_hint(spec.argv[0] if spec.argv else sys.executable)}"
                        f"；完整日志 {log_path}")
            else:
                hint = (f"看完整日志 {log_path}；端口 {spec.port} 若被占，"
                        f"改 config/services.json 里的 port")
            return ServiceOutcome(
                spec.name, "start", False, "failed", pid=proc.pid, port=spec.port,
                elapsed_ms=self._ms(t0),
                message=f"{spec.ready_timeout_s:.0f}s 内未就绪；日志尾部：{tail}",
                hint=hint)

        self.store.write({
            "schema": STATE_SCHEMA, "name": spec.name, "pid": proc.pid,
            "pgid": proc.pid if IS_WINDOWS else os.getpgid(proc.pid),
            "port": spec.port, "host": spec.host, "argv": spec.argv,
            "started_at": now_iso(), "log_path": str(log_path),
            "stop_file": str(self.stop_file(spec)),
            "readiness_ms": int(self._ms(t0)),
        })
        self.log.info("已启动 %s pid=%s port=%s 日志=%s", spec.name, proc.pid, spec.port, log_path)
        return ServiceOutcome(spec.name, "start", True, "started", pid=proc.pid, port=spec.port,
                              elapsed_ms=self._ms(t0), message=f"日志：{log_path}",
                              hint="")

    def _wait_ready(self, spec: ServiceSpec, pid: int) -> float | None:
        """返回就绪耗时（ms）；None 表示没起来。"""
        t0 = time.perf_counter()
        deadline = t0 + spec.ready_timeout_s
        while time.perf_counter() < deadline:
            if not pid_alive(pid):
                return None
            if spec.probe == "none" or (spec.port and port_open(spec.host, spec.port)):
                return int((time.perf_counter() - t0) * 1000)
            time.sleep(0.1)
        return None

    # -------------------------------------------------------------- 停止
    def stop_all(self, *, only: list[str] | None = None, force: bool = False,
                 reason: str = "stop") -> Report:
        t0 = time.perf_counter()
        rep = Report(op=reason, started_at=now_iso())
        targets = self._select(self.services.by_stop_order(), only)
        for spec in targets:
            rep.outcomes.append(self._stop_one(spec, force=force))
        rep.resources = self.release_probe()
        rep.elapsed_ms = self._ms(t0)
        return rep

    def _stop_one(self, spec: ServiceSpec, *, force: bool) -> ServiceOutcome:
        t0 = time.perf_counter()
        state = self._probe(spec)
        if not spec.managed:
            return ServiceOutcome(spec.name, "stop", True, "skipped", message="外部依赖不由本工具停止")
        if state.origin == "stale":
            self.store.remove(spec.name)
            self.log.warning("%s 状态文件里的进程已不存在（pid=%s），清掉残留状态", spec.name, state.pid)
            state = self._probe(spec)
        if not state.alive:
            if state.origin == "foreign":
                return ServiceOutcome(
                    spec.name, "stop", False, "port-occupied", pid=state.foreign_pid, port=spec.port,
                    elapsed_ms=self._ms(t0),
                    message=f"端口 {spec.host}:{spec.port} 被非本工具启动的进程占用"
                            + (f"（pid={state.foreign_pid}）" if state.foreign_pid else ""),
                    hint="不要盲杀未知进程：先 `tasklist /FI \"PID eq %s\"` 或 "
                         "`Get-Process -Id %s` 确认身份，再决定要不要结束它"
                         % (state.foreign_pid, state.foreign_pid))
            self.store.remove(spec.name)
            return ServiceOutcome(spec.name, "stop", True, "already-stopped", port=spec.port,
                                  elapsed_ms=self._ms(t0), message="本来就没在跑（幂等）")

        pid = int(state.pid)  # type: ignore[arg-type]
        pgid = int(state.pgid or pid)
        graceful = False
        if not force:
            sf = self.stop_file(spec)
            self.log.info("写入停止请求 %s（主通道，与信号无关），宽限 %.0fs",
                          sf.name, spec.grace_period_s)
            sf.write_text(json.dumps({"requested_at": now_iso(), "by": os.getpid()}),
                          encoding="utf-8")
            graceful = _wait_dead(pid, min(3.0, spec.grace_period_s))
            if not graceful:
                self.log.info("停止文件未在 %.0fs 内生效，补发 %s（POSIX/带控制台的场景）",
                              min(3.0, spec.grace_period_s), _STOP_SIGNAL.name)
                try:
                    _send(_STOP_SIGNAL, pgid if IS_WINDOWS else pid)
                    graceful = _wait_dead(pid, spec.grace_period_s - 3.0)
                except OSError as exc:
                    self.log.warning("信号发送失败：%s", exc)
                finally:
                    sf.unlink(missing_ok=True)
            if graceful:
                sf.unlink(missing_ok=True)
        if not graceful:
            how = "宽限期内没退出" if not force else "按要求直接强杀"
            self.log.warning("%s %s，执行强制结束", spec.name, how)
            killed = self._force_kill(pid, spec)
            if not killed:
                return ServiceOutcome(
                    spec.name, "stop", False, "failed", pid=pid, port=spec.port,
                    elapsed_ms=self._ms(t0),
                    message="强制结束失败",
                    hint=f"以管理员身份手动执行：Windows `taskkill /F /T /PID {pid}`，"
                         f"POSIX `kill -9 {pid}`；随后删除 var/run/{spec.name}.json")
            status = "forced"
            message = f"{how}，已强制结束（宽限期 {spec.grace_period_s:.0f}s）"
        else:
            status, message = "graceful", "进程已按信号优雅退出"

        self.store.remove(spec.name)
        released = True
        if spec.port:
            released = _wait_port_free(spec.host, spec.port, 5.0)
        hint = ""
        ok = True
        if not released:
            other = listener_pid(spec.host, spec.port)
            ok = False
            hint = (f"端口 {spec.port} 仍被占用（pid={other}）。若是刚才那个进程的子进程，"
                    f"用 `taskkill /F /T /PID {other}`；否则改 config/services.json 换端口")
            message += f"；但端口未释放（pid={other}）"
        return ServiceOutcome(spec.name, "stop", ok, status, pid=pid, port=spec.port,
                              elapsed_ms=self._ms(t0), message=message, hint=hint)

    def _force_kill(self, pid: int, spec: ServiceSpec) -> bool:
        if IS_WINDOWS:
            exe = shutil.which("taskkill")
            if not exe:
                return not pid_alive(pid)
            # taskkill 在中文 Windows 上输出 GBK：显式指定编码 + 容错，别让解码异常把强杀流程打断
            subprocess.run([exe, "/T", "/F", "/PID", str(pid)], capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
            return _wait_dead(pid, 5.0)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                return False
        return _wait_dead(pid, 5.0)

    # -------------------------------------------------------------- 资源核对与释放
    def release_probe(self) -> dict[str, Any]:
        """工具自己的资源：线程池、socket、sqlite 句柄、临时文件、残留状态与停止文件。"""
        out: dict[str, Any] = {}
        out["executor_threads"] = len(self._executor._threads) if self._executor else 0  # noqa: SLF001
        out["open_sockets"] = len([s for s in self._sockets if not s._closed])  # noqa: SLF001
        out["sqlite_handles"] = len(self._sqlite_handles)
        out["state_files"] = sorted(p.name for p in self.store.run_dir.glob("*.json"))
        stale_stops = sorted(p.name for p in self.store.run_dir.glob("*.stop"))
        if stale_stops:
            for p in self.store.run_dir.glob("*.stop"):
                p.unlink(missing_ok=True)
            out["stale_stop_files_removed"] = stale_stops
        return out

    def close(self) -> list[str]:
        """按需求逐类释放，并返回一份「释放了什么」的清单。"""
        done: list[str] = []
        if self._closed:
            return done
        ex, self._executor = self._executor, None
        if ex is not None:
            ex.shutdown(wait=True)
            done.append("threadpool")
        for sock in self._sockets:
            try:
                sock.close()
                done.append("socket")
            except OSError:
                pass
        self._sockets.clear()
        for conn in self._sqlite_handles:
            try:
                conn.close()
                done.append("sqlite")
            except Exception:
                pass
        self._sqlite_handles.clear()
        removed = self.store.cleanup_temp()
        if removed:
            done.append(f"tempfiles:{len(removed)}")
        self._closed = True
        return done

    __enter__ = lambda self: self  # noqa: E731

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False

    def _select(self, specs: list[ServiceSpec], only: list[str] | None) -> list[ServiceSpec]:
        if not only:
            return specs
        wanted = {o.strip() for o in only if o and o.strip()}
        found = {s.name for s in specs if s.name in wanted}
        missing = wanted - found
        if missing:
            raise KeyError(f"配置里没有这些服务：{sorted(missing)}；"
                           f"可选：{sorted(s.name for s in specs)}")
        return [s for s in specs if s.name in wanted]

    @staticmethod
    def _ms(t0: float) -> int:
        return int((time.perf_counter() - t0) * 1000)


def _send(sig: signal.Signals, target: int) -> None:
    os.kill(int(target), int(sig)) if not IS_WINDOWS else os.kill(int(target), sig)


def _wait_dead(pid: int, timeout_s: float) -> bool:
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return not pid_alive(pid)


def _wait_port_free(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        if not port_open(host, port):
            return True
        time.sleep(0.1)
    return not port_open(host, port)


def _tail(path: Path, n: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(日志读不到)"
    return " | ".join(lines[-n:])


def setup_logging(log_dir: Path, op: str, verbose: bool = False) -> tuple[logging.Logger, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"tool-{op}-{datetime.now().strftime('%Y%m%dT%H%M%S')}.log"
    logger = logging.getLogger(f"wca.services.{op}")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    logger.addHandler(stream)
    fileh = logging.FileHandler(path, encoding="utf-8")
    fileh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fileh)
    return logger, path
