"""重复批次（QUAL-DUP）的内容派生标识。

`batch_id` 只由来源行的包内相对路径与行号决定，不读取数据库自增 id、运行序号、
时间戳、`run_id`、`file_id` 或 `segment_id`。因此同一批重复在换库重导、反向导入、
不同机器上都应得到完全相同的值。

规范（审计方复算口径）：
  1. 每条来源生成字符串 `"<rel_path>:<line_no>"`；
  2. 去重后按 UTF-8 字节序排序；
  3. 用换行符 `\n` 连接（末尾不加换行）；
  4. 取 SHA-256 十六进制小写摘要。
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def source_text(source: dict) -> str:
    """一条来源的规范化字符串；`line_no` 统一按十进制整数输出。"""
    rel_path = str(source.get("rel_path") or "")
    if not rel_path:
        raise ValueError("批次来源缺少 rel_path，拒绝生成 batch_id")
    return f"{rel_path}:{int(source['line_no'])}"


def batch_id_from_sources(sources: Iterable[dict]) -> str:
    """按模块 docstring 的口径计算批次号。"""
    items = {source_text(source) for source in sources}
    ordered = sorted(items, key=lambda text: text.encode("utf-8"))
    return hashlib.sha256("\n".join(ordered).encode("utf-8")).hexdigest()


def date_from_raw_value(raw_value: object) -> str:
    """从打卡行原值（`emp|ts|ptype|device`）里取日期；取不到返回空串。"""
    match = _DATE_RE.search(str(raw_value or ""))
    return match.group(0) if match else ""
