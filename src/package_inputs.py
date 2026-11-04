"""包内输入文件名的稳定推导（0.4.3 起不依赖数据库 `file_id`）。

`inputs/manifest.json` 的 entries 只保留 `rel_path/sha256/bytes/row_count/kind`；
包内实际文件名由 `rel_path` 推导：`inputs/<rel_path>`。若同一规范化路径出现多次，
按 entries 顺序追加 `-2`、`-3` 序号，保证跨库重导时文件名只由输入文件本身决定。
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping

INPUTS_DIRNAME = "inputs"
INLINE_SCHEME = "inline://"

_RELATED_FILE_IDS_RX = re.compile(r"[;；]?\s*related_file_ids\s*=\s*[^;；\n]*")


def redact_issue_detail(value: object) -> str:
    """展示/导出前去掉 DB 主键线索；`来源: rel_path:line_no` 保留。

    DB 的 `ingest_issue.detail` 仍保留 `related_file_ids` 供输入选择；
    这里只处理对外字符串，不修改库内数据。
    """
    text = str(value or "")
    if not text:
        return ""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        cleaned = {k: v for k, v in data.items() if k != "related_file_ids"}
        return json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
    text = _RELATED_FILE_IDS_RX.sub("", text)
    return text.strip(" ;；\t")


def validate_input_rel_path(value: object) -> str:
    """导入入口校验：只接受项目内相对路径；`inline://` 保持既有临时输入契约。"""
    text = str(value).replace("\\", "/").strip()
    if text.startswith(INLINE_SCHEME):
        return text
    if not text:
        raise ValueError("输入文件 rel_path 不能为空")
    if text.startswith("/") or text.startswith("//") or (
            len(text) > 1 and text[1] == ":"):
        raise ValueError(f"输入文件 rel_path 必须是项目内相对路径（拒绝绝对路径）：{value!r}")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts:
        raise ValueError("输入文件 rel_path 不能为空")
    if any(part == ".." for part in parts):
        raise ValueError(f"输入文件 rel_path 不允许包含 ..：{value!r}")
    return "/".join(parts)



def normalize_rel_path(value: object) -> str:
    text = str(value).replace("\\", "/")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts:
        raise ValueError("输入文件 rel_path 为空")
    if any(part == ".." for part in parts):
        raise ValueError(f"输入文件 rel_path 不允许包含 ..：{value!r}")
    return "/".join(parts)


def input_arcnames(entries: Iterable[Mapping[str, object]]) -> list[str]:
    """按 entries 顺序返回稳定包内路径；同一路径重复时追加序号。"""
    used: set[str] = set()
    out: list[str] = []
    for entry in entries:
        rel = normalize_rel_path(entry.get("rel_path"))
        base = f"{INPUTS_DIRNAME}/{rel}"
        candidate = base
        serial = 2
        while candidate in used:
            if "." in rel:
                stem, ext = rel.rsplit(".", 1)
                candidate = f"{INPUTS_DIRNAME}/{stem}-{serial}.{ext}"
            else:
                candidate = f"{base}-{serial}"
            serial += 1
        used.add(candidate)
        out.append(candidate)
    return out
