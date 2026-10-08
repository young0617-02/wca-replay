"""Web 界面（需求决定 4 / US-UI-01~05）：3 视图 + 最小登录。

刻意保持"薄"：
  * 服务端渲染 Jinja2 + 一段原生 fetch，**没有前端框架、没有构建流水线**（NFR-07、预算 2.0 人日）；
  * 每个动作都直接调用 CLI 用的同一个函数（`import_csv_file` / `run_check` / `export_package` /
    `ComplianceAgent.ask`），因此不存在"界面一套逻辑、脚本另一套"的双实现风险；
  * 权限只在服务端判：角色来自会话（`src/auth.py`），主体身份**不接受调用方自报**，
    所以"前端藏起来"不等于有权（NFR-16，配套测试直连接口打 403）。
"""

from __future__ import annotations

from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent
TEMPLATE_DIR = WEB_ROOT / "templates"
STATIC_DIR = WEB_ROOT / "static"

__all__ = ["WEB_ROOT", "TEMPLATE_DIR", "STATIC_DIR", "register_web_routes"]

from .routes import register_web_routes  # noqa: E402
