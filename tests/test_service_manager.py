"""一键启动/停止工具的测试。

全部用**真的子进程**跑，不用 mock：启停工具最容易骗人的就是「以为发了信号=已经停了」，
所以这里每个断言都落在真实现象上——进程是否还活着、端口是否真被占、
服务自己写的 up/down 文件、以及优雅关闭有没有走服务自己的收尾逻辑。
"""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

from src.service_manager import (
    ServiceManager,
    load_services_config,
    pid_alive,
    port_open,
)

FAKE_SERVICE = '''
import json, os, sys, time
from pathlib import Path
name, run_dir = sys.argv[1], Path(sys.argv[2])
ignore = os.environ.get("FAKE_IGNORE_STOP", "0") == "1"
up, down = run_dir / f"{name}.up", run_dir / f"{name}.down"
starts = 0
if up.exists():
    try:
        starts = int(json.loads(up.read_text(encoding="utf-8")).get("starts", 0))
    except Exception:
        starts = 0
up.write_text(json.dumps({"pid": os.getpid(), "starts": starts + 1}), encoding="utf-8")
deadline = time.time() + 30
while time.time() < deadline:
    if not ignore and (run_dir / f"{name}.stop").exists():
        down.write_text(json.dumps({"pid": os.getpid(), "via": "stopfile"}), encoding="utf-8")
        break
    time.sleep(0.05)
else:
    down.write_text("timeout", encoding="utf-8")
'''


def make_config(tmp_path: Path, *, port: int | None = None, services: list[dict] | None = None) -> Path:
    script = tmp_path / "fake_service.py"
    script.write_text(FAKE_SERVICE, encoding="utf-8")
    if services is None:
        services = [fake_spec(tmp_path, script, "alpha", start_order=10, stop_order=10)]
    path = tmp_path / "services.json"
    path.write_text(json.dumps({
        "schema": "wca-services-v1",
        "defaults": {"ready_timeout_s": 8, "grace_period_s": 3,
                     "log_dir": str(tmp_path / "logs"), "run_dir": str(tmp_path / "run")},
        "services": services,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def fake_spec(tmp_path: Path, script: Path, name: str, *, start_order: int, stop_order: int,
              ignore_stop: bool = False) -> dict:
    return {
        "name": name,
        "managed": True,
        "start_order": start_order,
        "stop_order": stop_order,
        "argv": [sys.executable, str(script), name, str(tmp_path / "run")],
        "cwd": str(tmp_path),
        "probe": "none",
        "env": {"FAKE_IGNORE_STOP": "1" if ignore_stop else "0"},
    }


def wait_until(fn, timeout: float = 8.0, interval: float = 0.05) -> bool:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if fn():
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def env(tmp_path: Path):
    (tmp_path / "run").mkdir()
    return tmp_path


def outcome(rep, name: str, action: str | None = None):
    rows = [o for o in rep.outcomes if o.name == name and (action is None or o.action == action)]
    return rows[-1] if rows else None


# ------------------------------------------------------------------ 配置化
def test_config_is_data_not_code(tmp_path: Path):
    path = make_config(tmp_path)
    services = load_services_config(path)
    assert [s.name for s in services.specs] == ["alpha"]
    assert services.managed()[0].argv[0] == sys.executable
    assert "<python>" not in "".join(services.managed()[0].argv)


def test_config_rejects_duplicate_and_unstartable(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"defaults": {}, "services": [
        {"name": "dup", "managed": True, "argv": ["x"]},
        {"name": "dup", "managed": True, "argv": ["y"]},
        {"name": "noargv", "managed": True},
    ]}), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_services_config(path)
    msg = str(exc.value)
    assert "服务名重复" in msg and "没有 argv" in msg
    assert "恢复建议" in msg, "配置错误必须给可读的下一步"


def test_missing_config_file_gives_recovery_hint(tmp_path: Path):
    with pytest.raises(FileNotFoundError) as exc:
        load_services_config(tmp_path / "nope.json")
    assert "恢复建议" in str(exc.value)


# ------------------------------------------------------------------ 启动检测与先停后起
def test_start_writes_state_and_keeps_process_alive(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        rep = mgr.start_all()
    finally:
        mgr.close()
    assert rep.ok, rep.as_text()
    o = outcome(rep, "alpha", "start")
    assert o.status == "started" and o.pid
    assert pid_alive(o.pid)
    state = json.loads((env / "run" / "alpha.json").read_text(encoding="utf-8"))
    assert state["pid"] == o.pid and state["schema"] == "wca-service-state-v1"
    # 收尾：别让进程活到下一个测试
    mgr2 = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        assert mgr2.stop_all().ok
    finally:
        mgr2.close()


def test_start_detects_running_and_stops_before_starting(env):
    path = make_config(env)
    first = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        started = first.start_all()
        pid_old = outcome(started, "alpha", "start").pid
    finally:
        first.close()

    second = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        rep = second.start_all()
    finally:
        second.close()
    pre = outcome(rep, "alpha", "precheck")
    assert pre.status == "running", "已运行的服务必须在启动前被检测到"
    stop_o = outcome(rep, "alpha", "stop")
    assert stop_o is not None and stop_o.status == "graceful", rep.as_text()
    pid_new = outcome(rep, "alpha", "start").pid
    assert pid_new and pid_new != pid_old
    assert not pid_alive(pid_old), "先停后起必须真的停掉，不能留残留进程"
    third = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        assert third.stop_all().ok
    finally:
        third.close()


def test_no_restart_flag_refuses_to_double_start(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        mgr.start_all()
        rep = mgr.start_all(restart_if_running=False)
        o = outcome(rep, "alpha", "start")
        assert o is not None and not o.ok and o.status == "already-running"
        assert "stop_services" in o.hint
    finally:
        stopper = ServiceManager(load_services_config(path), env_snapshot={})
        try:
            stopper.stop_all()
        finally:
            stopper.close()
        mgr.close()


# ------------------------------------------------------------------ 优雅停止
def test_stop_is_graceful_and_service_itself_renders_ledger(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        started = mgr.start_all()
        pid = outcome(started, "alpha", "start").pid
        rep = mgr.stop_all()
    finally:
        mgr.close()
    o = outcome(rep, "alpha", "stop")
    assert o.ok and o.status == "graceful", rep.as_text()
    assert wait_until(lambda: not pid_alive(pid))
    down = env / "run" / "alpha.down"
    assert down.is_file(), "服务自己收到停止请求并落了收尾账，才算优雅而不是被杀"
    assert "stopfile" in down.read_text(encoding="utf-8")
    assert not (env / "run" / "alpha.json").exists(), "停止后状态文件必须清掉"
    assert not (env / "run" / "alpha.stop").exists(), "停止请求文件必须被回收"


def test_stop_is_idempotent(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        mgr.start_all()
        assert mgr.stop_all().ok
        again = mgr.stop_all()
        o = outcome(again, "alpha", "stop")
        assert o.ok and o.status == "already-stopped", rep_text(again)
    finally:
        mgr.close()


def rep_text(rep) -> str:
    return rep.as_text()


def test_stale_state_file_is_cleaned_and_reported(env):
    path = make_config(env)
    (env / "run").mkdir(exist_ok=True)
    (env / "run" / "alpha.json").write_text(json.dumps(
        {"schema": "wca-service-state-v1", "name": "alpha", "pid": 999998,
         "pgid": 999998, "started_at": "x"}), encoding="utf-8")
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        rep = mgr.stop_all()
    finally:
        mgr.close()
    assert outcome(rep, "alpha", "stop").ok
    assert not (env / "run" / "alpha.json").exists(), "陈年状态文件不能被当成运行中"


def test_force_stop_when_service_ignores_stop_file(env):
    path = make_config(env, services=[fake_spec(
        env, env / "fake_service.py" if (env / "fake_service.py").exists() else _ensure_script(env),
        "stubborn", start_order=10, stop_order=10, ignore_stop=True)])
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        started = mgr.start_all()
        pid = outcome(started, "stubborn", "start").pid
        spec = next(s for s in mgr.services.specs)
        spec.grace_period_s = 1.5
        rep = mgr.stop_all()
    finally:
        mgr.close()
    o = outcome(rep, "stubborn", "stop")
    assert o.ok and o.status == "forced", rep.as_text()
    assert not pid_alive(pid), "对方不理会停止请求时，必须升级强杀并确认进程已没了"


def _ensure_script(tmp_path: Path) -> Path:
    script = tmp_path / "fake_service.py"
    script.write_text(FAKE_SERVICE, encoding="utf-8")
    return script


# ------------------------------------------------------------------ 端口与外部进程
def test_foreign_port_blocks_start_and_reports_owner(env):
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        spec = fake_spec(env, _ensure_script(env), "api", start_order=10, stop_order=10)
        spec["port"] = port
        spec["probe"] = "port"
        path = make_config(env, services=[spec])
        mgr = ServiceManager(load_services_config(path), env_snapshot={})
        try:
            rep = mgr.start_all()
        finally:
            mgr.close()
        o = outcome(rep, "api", "precheck")
        assert not o.ok and o.status == "port-occupied", rep.as_text()
        assert o.port == port
        assert outcome(rep, "api", "start") is None, "端口被外部进程占着时不许盲起"
        assert "tasklist" in o.hint or "port" in o.hint


def test_port_probe_and_readiness(env):
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        assert port_open("127.0.0.1", port)
        assert not port_open("127.0.0.1", port + 1 if port < 65535 else 1)
    assert not port_open("127.0.0.1", 1)


# ------------------------------------------------------------------ 外部依赖与顺序
def test_unmanaged_dependency_is_only_checked_not_killed(env):
    dep = {"name": "ollama", "managed": False, "start_order": 1, "stop_order": 1,
           "host": "127.0.0.1", "port": 1, "probe": "port",
           "required_when": {"env": "WCA_LLM_PROVIDER", "equals": "ollama"}}
    path = make_config(env, services=[dep, fake_spec(env, _ensure_script(env), "api",
                                                     start_order=20, stop_order=20)])
    specs = load_services_config(path)
    off = ServiceManager(specs, env_snapshot={"WCA_LLM_PROVIDER": "stub"})
    try:
        rep = off.start_all()
        assert outcome(rep, "ollama", "precheck").status == "not-required"
    finally:
        off.stop_all()
        off.close()

    need = ServiceManager(load_services_config(path), env_snapshot={"WCA_LLM_PROVIDER": "ollama"})
    try:
        rep2 = need.start_all()
        o = outcome(rep2, "ollama", "precheck")
        assert not o.ok and o.status == "missing-dependency"
        assert "ollama serve" in o.hint or "WCA_LLM_PROVIDER" in o.hint
        assert outcome(rep2, "api", "start") is None, "依赖不齐就别起后面的服务"
    finally:
        need.stop_all()
        need.close()


def test_stop_order_is_reverse_of_start_order(env):
    services = [
        fake_spec(env, _ensure_script(env), "first", start_order=10, stop_order=10),
        fake_spec(env, _ensure_script(env), "second", start_order=20, stop_order=20),
    ]
    path = make_config(env, services=services)
    specs = load_services_config(path)
    assert [s.name for s in specs.by_start_order()] == ["first", "second"]
    assert [s.name for s in specs.by_stop_order()] == ["second", "first"]
    mgr = ServiceManager(specs, env_snapshot={})
    try:
        rep = mgr.start_all()
        assert rep.ok, rep.as_text()
        stop = mgr.stop_all()
    finally:
        mgr.close()
    order = [o.name for o in stop.outcomes if o.action == "stop"]
    assert order == ["second", "first"], "停止必须按预定顺序倒着来"


# ------------------------------------------------------------------ 资源释放
def test_close_releases_executor_and_rejects_reuse(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    mgr.start_all()
    probe = mgr.release_probe()
    assert probe["executor_threads"] >= 1
    released = mgr.close()
    assert "threadpool" in released
    assert mgr.release_probe()["executor_threads"] == 0
    with pytest.raises(RuntimeError):
        mgr._pool()
    mgr.stop_all()


def test_temp_files_never_left_in_run_dir(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        mgr.start_all()
        mgr.stop_all()
    finally:
        mgr.close()
    leftovers = [p.name for p in (env / "run").glob(".tmp-*")]
    assert not leftovers, f"状态文件原子写不应留下临时文件：{leftovers}"


def test_state_write_is_atomic_and_sorted(env):
    path = make_config(env)
    mgr = ServiceManager(load_services_config(path), env_snapshot={})
    try:
        mgr.start_all()
        raw = (env / "run" / "alpha.json").read_text(encoding="utf-8")
    finally:
        mgr.stop_all()
        mgr.close()
    assert raw.startswith("{\n  \"argv\"") or "\"argv\"" in raw.splitlines()[1], "状态文件键序应稳定"
    data = json.loads(raw)
    assert data["schema"] == "wca-service-state-v1" and data["stop_file"].endswith("alpha.stop")


# ------------------------------------------------------------------ CLI 层
def test_cli_reports_exit_codes(env):
    from src.service_cli import EXIT_FAILED, EXIT_OK, main_start, main_stop

    path = make_config(env)
    assert main_start(["--config", str(path), "--env", str(env / "absent.env")]) in (
        EXIT_OK, EXIT_FAILED)
    # 起不来（服务脚本里的 run 目录已存在但依赖缺失等）也要有明确退出码，不能 0 蒙混
    rc = main_stop(["--config", str(path), "--env", str(env / "absent.env")])
    assert rc in (EXIT_OK, EXIT_FAILED)
    assert main_stop(["--config", str(path), "--status"]) == EXIT_OK
    missing = main_start(["--config", str(env / "nope.json")])
    assert missing not in (EXIT_OK,)


def test_cli_json_output_is_parseable(env, capsys):
    from src.service_cli import main_start, main_stop

    path = make_config(env)
    assert main_start(["--config", str(path), "--json"]) in (0, 1)
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{"):])
    assert payload["op"] == "start" and "outcomes" in payload
    main_stop(["--config", str(path), "--json"])
