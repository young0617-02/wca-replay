"""举证包 producer 版本块：让包能说明“用哪版代码导出”。

`_release_info.py` 由 `scripts/build_release.py` 在构建 wheel 时临时写入并打进 wheel；
源码仓库运行时回退到 `git rev-parse HEAD`。干净环境只装 wheel，因此不会去猜本机源码。
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from . import ENGINE_VERSION

PACKAGE_VERSION = ENGINE_VERSION.removeprefix("wca-")
try:  # pragma: no cover - 仅发布 wheel 内存在
    from ._release_info import BUILD_COMMIT as RELEASE_BUILD_COMMIT
except ImportError:  # 源码工作区
    RELEASE_BUILD_COMMIT = ""

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def current_commit() -> str:
    if RELEASE_BUILD_COMMIT:
        return str(RELEASE_BUILD_COMMIT)
    env = os.environ.get("WCA_BUILD_COMMIT")
    if env:
        return env.strip()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
            capture_output=True, text=True, timeout=15, check=True)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def producer_info(rule_pack_version: str) -> dict:
    return {
        "version": PACKAGE_VERSION,
        "commit": current_commit(),
        "python": platform.python_version(),
        "rule_pack_version": str(rule_pack_version),
    }


def check_manifest_producer(manifest: dict) -> tuple[bool, str]:
    """包里 producer 与当前运行代码逐一核对；旧包无 producer 不判失败。"""
    block = manifest.get("producer")
    if not isinstance(block, dict):
        return True, ""
    current = producer_info(str((manifest.get("triple") or {}).get("rule_pack_version") or ""))
    mismatched = [k for k in ("version", "commit", "rule_pack_version")
                  if block.get(k) != current.get(k)]
    if mismatched:
        return False, ("PRODUCER FAIL 包内 producer 与当前验算版本不一致："
                       + ",".join(mismatched)
                       + f"（包内 {block.get('commit')} / 当前 {current['commit']}）")
    return True, ""
