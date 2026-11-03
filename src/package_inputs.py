"""包内输入文件名的稳定推导（0.4.3 起不依赖数据库 `file_id`）。

`inputs/manifest.json` 的 entries 只保留 `rel_path/sha256/bytes/row_count/kind`；
包内实际文件名由 `rel_path` 推导：`inputs/<rel_path>`。若同一规范化路径出现多次，
按 entries 顺序追加 `-2`、`-3` 序号，保证跨库重导时文件名只由输入文件本身决定。
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

INPUTS_DIRNAME = "inputs"


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
