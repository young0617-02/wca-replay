"""依赖口径对账：`pyproject.toml` / `uv.lock` / 当前环境，三份必须互相一致。

为什么单独测这个：本项目把「评审者一次装起来」当一票否决项（A6 / US-EV-01 / NFR-07）。
依赖改由 uv 管理之后（2026-10-09 决定，`requirements.txt` 已删除），口径分散在
「声明」「锁」「实装环境」三处。手写锁文件翻过一次车：旧 `requirements.txt` 声明 24 条，
实际环境是 25 条——`fastapi` 的核心传递依赖 `opentelemetry-api` 只写着 `>=1.44.0` 浮动，
「锁版本可复现」这句话当时并不成立。漂移靠自觉挡不住，靠对账挡得住。
"""

from __future__ import annotations

import re
import tomllib
from importlib import metadata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "uv.lock"

BUILD_TOOLING = ("node", "npm", "pnpm", "yarn", "webpack", "vite", "rollup", "esbuild",
                 "postcss", "tailwind", "babel", "typescript", "react", "vue", "svelte")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _pin(item: str) -> tuple[str, str]:
    m = re.match(r"^([A-Za-z0-9._+-]+)==([A-Za-z0-9._+-]+)", item)
    assert m, f"依赖声明里出现没钉版本的一条：{item!r}"
    return _canonical(m.group(1)), m.group(2)


def _declared() -> dict[str, str]:
    """直接依赖 + dev 组 + 传递依赖约束，全部必须钉死。"""
    py = _pyproject()
    items = list(py["project"]["dependencies"])
    for group in py.get("dependency-groups", {}).values():
        items += list(group)
    items += list(py["tool"]["uv"].get("constraint-dependencies", []))
    return dict(_pin(i) for i in items)


def _lock_packages() -> dict[str, str]:
    """解析 uv.lock 的 [[package]] name/version（纯文本，不依赖 uv 是否可用）。"""
    out: dict[str, str] = {}
    for block in LOCK.read_text(encoding="utf-8").split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        if name and version:
            out[_canonical(name.group(1))] = version.group(1)
    return out


def _installed() -> dict[str, str]:
    return {_canonical(d.name): d.version
            for d in metadata.distributions() if d.name}


def test_no_legacy_requirements_file_came_back():
    """依赖只走 uv：`requirements.txt` 回来了就说明有人又开了第二条会漂移的通道。"""
    assert not (ROOT / "requirements.txt").exists(), \
        "requirements.txt 已按 2026-10-09 决定删除；要装依赖请用 `uv sync`（见 README「30 秒跑起来」）"


def test_every_declared_dependency_is_pinned():
    declared = _declared()
    assert declared, "pyproject 里一条依赖都没声明"
    assert declared.get(_canonical("opentelemetry-api")), \
        "fastapi 的核心传递依赖必须显式钉住，否则「锁版本」是假的（本轮就是被它坑过）"


def test_pyproject_matches_lock():
    """声明的版本必须就是锁里的版本——否则 `uv lock` 之后环境会悄悄换包。"""
    declared, lock = _declared(), _lock_packages()
    absent = sorted(n for n in declared if n not in lock)
    drift = [f"{n}: pyproject={declared[n]} lock={lock[n]}"
             for n in sorted(set(declared) & set(lock)) if declared[n] != lock[n]]
    assert not absent, f"声明了但锁里没有：{absent}"
    assert not drift, f"声明与锁不一致：{drift}"


def test_lock_is_hash_pinned_and_closed():
    """锁必须带哈希，且每个非源头包都写明是被谁拉进来的（可读性＝可审计）。"""
    text = LOCK.read_text(encoding="utf-8")
    assert text.count("sha256:") >= 200, f"锁里的哈希少得不正常：{text.count('sha256:')}"
    own = _canonical("worktime-compliance-agent")
    assert own in _lock_packages(), "锁应包含项目自身条目"


def test_installed_environment_matches_the_lock():
    """当前跑测试的解释器必须就是锁描述的那个环境（防止"文档说一套、环境是另一套"）。"""
    lock, installed = _lock_packages(), _installed()
    own = _canonical("worktime-compliance-agent")
    expect = {k: v for k, v in lock.items() if k != own}
    missing = sorted(n for n in expect if n not in installed)
    mismatch = [f"{n}: 锁要求 {expect[n]}，实际 {installed[n]}"
                for n in sorted(expect) if n in installed and installed[n] != expect[n]]
    assert not missing, f"环境里缺这些锁定依赖：{missing}（跑 `uv sync`）"
    assert not mismatch, f"环境版本与锁不符：{mismatch}"


def test_no_frontend_build_dependencies():
    """NFR-07：界面是服务端渲染 + 原生 fetch，依赖闭包里不许出现前端构建工具链。"""
    lock = _lock_packages()
    hits = sorted(n for n in lock if any(b in n for b in BUILD_TOOLING))
    assert not hits, f"依赖闭包里混进前端构建工具：{hits}"
    assert not list(ROOT.glob("package.json")) and not list(ROOT.glob("**/package-lock.json")), \
        "仓库里出现 npm 清单文件，说明引入了前端构建链"


def test_requires_python_is_satisfied_by_this_interpreter():
    spec = _pyproject()["project"]["requires-python"]
    m = re.match(r"^>=(\d+)\.(\d+)", spec)
    assert m, f"requires-python 口径不清楚：{spec}"
    import sys
    assert sys.version_info >= (int(m.group(1)), int(m.group(2))), \
        f"跑测试的解释器 {sys.version.split()[0]} 低于声明的 {spec}"


@pytest.mark.parametrize("doc", ["README.md", "docs/演示脚本-30分钟.md"])
def test_uv_is_the_only_install_channel_and_docs_respect_it(doc):
    """依赖只走 uv，且项目必须能构建出供第三方验算的 wheel。

    历史断言是 `tool.uv.package = false`（“不是可安装包、别构建”）；发行物需求
    要求 `uv build` 产出 wheel，因此改为断言构建后端/入口点存在。开发环境仍只走
    `uv sync`，README 命令块里不允许出现 pip 安装通道。
    """
    py = _pyproject()
    build = py.get("build-system") or {}
    assert build.get("build-backend") == "hatchling.build", \
        "发行物需要可构建 wheel（hatchling 后端）"
    scripts = py.get("project", {}).get("scripts") or {}
    assert scripts.get("wca-verify") == "src.verify_pkg:main", \
        "wheel 必须提供 wca-verify 入口，第三方才不用源码就能跑包内 verify.py"
    readme = (ROOT / doc).read_text(encoding="utf-8")
    assert "uv sync" in readme, f"{doc} 必须以 uv sync 作为依赖入口"
    in_shell, runnable = False, []
    for line in readme.splitlines():
        if line.strip().startswith("```"):
            in_shell = not in_shell
            continue
        if in_shell and "pip install" in line and not line.lstrip().startswith("#"):
            runnable.append(line.strip()[:60])
    assert not runnable, f"{doc} 的命令块里还在推荐 pip 通道：{runnable}"


@pytest.mark.parametrize("module", ["fastapi", "uvicorn", "jinja2", "httpx"])
def test_optional_web_imports_are_the_locked_ones(module):
    """Web 层是可选通道；一旦装着，就必须是锁里的那个版本（漂版本会让界面测试结果不可比）。"""
    pytest.importorskip(module)
    lock, installed = _lock_packages(), _installed()
    name = _canonical(module)
    assert lock[name] == installed[name], f"{module} 版本漂移：{installed[name]} != {lock[name]}"
