#!/usr/bin/env python
"""一键优雅停止全部服务。

    python tools/stop_services.py                   # 先发中断信号，宽限期后升级强杀
    python tools/stop_services.py --status          # 只看状态，不停任何东西
    python tools/stop_services.py --grace 20        # 多等 20 秒让它把在途请求收尾
    python tools/stop_services.py --force           # 跳过优雅等待直接强杀（会在结果里标 forced）
    python tools/stop_services.py --json

停止后还会做两件事：核对端口已释放、把 SQLite 的 WAL 落盘（不留 -wal/-shm 半成品）。
退出码：0 干净；1 有残留（端口/进程/状态文件）；2 配置有问题。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.service_cli import main_stop  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main_stop())
