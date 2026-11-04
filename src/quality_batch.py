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
# 跨文件重复行的 detail 固定写成「…；来源: rel:line, rel:line（按 rel_path 字典序…）」。
_DETAIL_SOURCE_RE = re.compile(r"来源:\s*(.*?)(?:（|$)")


def _detail_sources(detail: str) -> list[tuple[str, int]]:
    """解析跨文件重复 detail 里的物理来源（首次出现行 + 重复行）。"""
    match = _DETAIL_SOURCE_RE.search(str(detail or ""))
    if not match:
        return []
    out: list[tuple[str, int]] = []
    for part in match.group(1).split(","):
        rel_path, _, line_no = part.strip().rpartition(":")
        if rel_path and line_no.isdigit():
            out.append((rel_path, int(line_no)))
    return out


def repeat_sources(rel_path: object, line_no: object, detail: object) -> list[dict]:
    """取该问题行代表的“重复行”物理来源。

    * 文件内重复：库内每行就是一条重复行，直接用自身 rel_path/line_no；
    * 跨文件/重传重复：库里存的是按 rel_path 字典序的首个来源，detail 列出全部物理
      来源；首个来源即首次出现行（不进批次），其余才是重复行（进批次与 batch_id）。
    """
    physical = _detail_sources(str(detail or ""))
    if physical:
        return [{"rel_path": rel, "line_no": num} for rel, num in physical[1:]]
    rel = str(rel_path or "")
    if rel and line_no is not None:
        return [{"rel_path": rel, "line_no": int(line_no)}]
    return []


def detail_physical_sources(detail: object) -> list[tuple[str, int]]:
    """供导出层列出“首次出现行”；没有跨文件明细时返回空。"""
    return _detail_sources(str(detail or ""))


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
