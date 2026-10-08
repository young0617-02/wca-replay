#!/usr/bin/env python
"""一键启动全部服务。

    python tools/start_services.py                  # 检测 -> 需要时先全停 -> 按顺序启动
    python tools/start_services.py --only api       # 只启其中一个
    python tools/start_services.py --json           # 机器可读结果
    python tools/start_services.py --no-restart     # 已在跑就报错，不做先停后起

退出码：0 全部就绪；1 有服务没起来；2 配置/参数有问题。
停止请用 tools/stop_services.py（同一套状态机）。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.service_cli import main_start  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main_start())
