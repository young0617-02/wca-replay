"""Finding 证据定位元数据的规范化与摘要（独立于结论摘要）。

边界（第四轮整改阻断项）：
  * `metric` 只保留数值与计量口径（天数、分钟数、counting_scope 等）；
  * `evidence` 只保留定位元数据（tables/window/rules/aggregation），不进入
    `Finding.canonical()`，因此不污染 `conclusion_digest`；
  * `evidence_digest` 对全部 finding 的 evidence 块做规范化后计算 SHA-256：
      - 固定字段序 `tables/window/rules/aggregation`；
      - 缺失的标量写成 `null`，缺失的列表写成 `[]`；
      - 表路径统一为 `/`，拒绝空路径与 `..`；
      - 按 `(emp_id, work_date, period_key, rule_id, rule_version)` 排序；
      - canonical JSON（key 排序、UTF-8、无空白）后 SHA-256。
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from .util import digest_of

EVIDENCE_FIELDS = ("tables", "window", "rules", "aggregation")
WINDOW_FIELDS = ("kind", "key", "start", "end")


def _normalize_path(value: object) -> str:
    text = str(value).replace("\\", "/")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts:
        raise ValueError("evidence 表路径为空")
    if any(part == ".." for part in parts):
        raise ValueError(f"evidence 表路径不允许包含 ..：{value!r}")
    return "/".join(parts)


def _string_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"evidence.{label} 必须是数组")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"evidence.{label} 只能是非空字符串")
        out.append(item)
    return out


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def canonical_evidence(block: Mapping[str, object] | None) -> dict:
    """规范化单个 evidence 块；未知字段失败关闭，避免夹带未受摘要覆盖的元数据。"""
    if block is None:
        block = {}
    if not isinstance(block, Mapping):
        raise ValueError("evidence 必须是对象")
    unknown = sorted(set(block) - set(EVIDENCE_FIELDS))
    if unknown:
        raise ValueError("evidence 含未定义字段：" + ",".join(unknown))

    tables = sorted({_normalize_path(item) for item in _string_list(block.get("tables"), "tables")},
                    key=lambda item: item.encode("utf-8"))
    window_raw = block.get("window")
    if window_raw is None:
        window_raw = {}
    if not isinstance(window_raw, Mapping):
        raise ValueError("evidence.window 必须是对象")
    unknown_window = sorted(set(window_raw) - set(WINDOW_FIELDS))
    if unknown_window:
        raise ValueError("evidence.window 含未定义字段：" + ",".join(unknown_window))
    window = {key: _optional_text(window_raw.get(key)) for key in WINDOW_FIELDS}
    rules = sorted(set(_string_list(block.get("rules"), "rules")),
                   key=lambda item: item.encode("utf-8"))
    aggregation = block.get("aggregation")
    if aggregation is not None and not isinstance(aggregation, str):
        raise ValueError("evidence.aggregation 必须是字符串或 null")
    return {
        "tables": tables,
        "window": window,
        "rules": rules,
        "aggregation": aggregation,
    }


def evidence_binding(record: Mapping[str, object]) -> dict:
    """把一条 finding 的定位信息绑定到 finding 身份，防止证据块串位。"""
    return {
        "rule_id": str(record.get("rule_id") or ""),
        "rule_version": str(record.get("rule_version") or ""),
        "emp_id": str(record.get("emp_id") or ""),
        "work_date": _optional_text(record.get("work_date")),
        "period_key": _optional_text(record.get("period_key")),
        "evidence": canonical_evidence(record.get("evidence")),
    }


def _binding_sort_key(item: dict) -> tuple:
    return (item["emp_id"], item["work_date"] or "", item["period_key"] or "",
            item["rule_id"], item["rule_version"])


def evidence_digest(records: Iterable[Mapping[str, object]]) -> str:
    """全部 finding 的 evidence 规范化绑定列表 -> canonical JSON SHA-256。"""
    items = [evidence_binding(record) for record in records]
    items.sort(key=_binding_sort_key)
    return digest_of(items)
