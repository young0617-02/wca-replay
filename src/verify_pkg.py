"""`wca-verify`：对 zip 或已解压目录运行包内独立 verify.py。

它不替代包内脚本：真正的校验逻辑仍在包内；这里只负责安全解包与转发参数，
让干净环境只装 wheel 也能跑 `verify`。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .replay import unpacked


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("用法：wca-verify <包.zip|已解压目录> [verify.py 参数...]", file=sys.stderr)
        return 2
    package = Path(args[0])
    forwarded = args[1:]
    if package.is_dir():
        if not (package / "verify.py").is_file():
            print(f"目录中没有 verify.py：{package}", file=sys.stderr)
            return 2
        return subprocess.run(
            [sys.executable, str(package / "verify.py"), *forwarded],
            cwd=package).returncode
    if not package.is_file():
        print(f"包不存在：{package}", file=sys.stderr)
        return 2
    with unpacked(package) as root:
        return subprocess.run(
            [sys.executable, str(root / "verify.py"), *forwarded],
            cwd=root).returncode
