"""Deterministic helpers: canonical JSON, hashing, timezone-normalised timestamps.

Everything that feeds a conclusion digest must be byte-stable across re-runs (A8),
so dict ordering, newline style and float formatting are pinned here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime, timedelta, timezone

CN_TZ = timezone(timedelta(hours=8))
ISO_LIKE = "%Y-%m-%dT%H:%M:%S"

_TS_PATTERNS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y%m%d%H%M",
)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: object) -> str:
    """Sorted keys, no whitespace, ASCII preserved, no floats allowed."""
    _reject_floats(obj, "$")
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def canonical_bytes(obj: object) -> bytes:
    return canonical_json(obj).encode("utf-8")


def _reject_floats(obj: object, path: str) -> None:
    if isinstance(obj, float):
        raise TypeError(
            f"判定链禁止浮点数（避免分钱级舍入争议）：{path} = {obj!r}。"
            "金额请用整数「分」，工时请用整数「分钟」。"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def digest_of(obj: object) -> str:
    return sha256_hex(canonical_bytes(obj))


MANIFEST_CHECKSUM_FIELD = "manifest_checksum"
SIGNATURE_FIELD = "signature"
EVIDENCE_PACKAGE_SCHEMA_V1 = "wca-evidence-package-v1"
EVIDENCE_PACKAGE_SCHEMA_V2 = "wca-evidence-package-v2"
EVIDENCE_PACKAGE_SCHEMA_V3 = "wca-evidence-package-v3"
# 无签名导出仍是 v2；只有显式提供签名私钥时才写 v3 + signature。
EVIDENCE_PACKAGE_SCHEMA = EVIDENCE_PACKAGE_SCHEMA_V2
_EVIDENCE_SCHEMA_RE = re.compile(r"^wca-evidence-package-v(\d+)$")


def evidence_schema_version(value: object) -> int | None:
    """解析 `wca-evidence-package-vN`；未知/缺失返回 None，由调用方失败关闭。"""
    if not isinstance(value, str):
        return None
    match = _EVIDENCE_SCHEMA_RE.match(value)
    return int(match.group(1)) if match else None


_ANCHOR_SCHEMA_RE = re.compile(r"^(?:v|V)?(\d+)$")


def anchor_schema_version(value: object) -> int | None:
    """外部锚点第一段：接受整数、`v2`、`2` 或完整 `wca-evidence-package-v2`。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = _ANCHOR_SCHEMA_RE.match(text)
    if match:
        return int(match.group(1))
    return evidence_schema_version(text)


def manifest_checksum(doc: dict) -> str:
    """manifest 自校验和：覆盖除自身与签名块以外的全部字段。

    `signature` 必须排除，否则“先算校验和再签名”会形成循环；签名 payload
    会覆盖 `manifest_checksum`，因此签名仍间接覆盖除签名外的全部 manifest 字段。
    """
    payload = {k: v for k, v in doc.items()
               if k not in (MANIFEST_CHECKSUM_FIELD, SIGNATURE_FIELD)}
    return sha256_hex(canonical_json(payload))


def parse_timestamp(value: object, *, assume_cn_tz: bool = True) -> datetime:
    """Parse a timestamp into an aware datetime in +08:00.

    Naive input is treated as Beijing time and *flagged upstream* (QUAL-TZ-001), never
    silently converted with the host timezone.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("时间戳为空字符串")
        dt = None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            for pat in _TS_PATTERNS:
                try:
                    dt = datetime.strptime(text, pat)
                    break
                except ValueError:
                    continue
        if dt is None:
            raise ValueError(f"无法识别的时间戳格式: {value!r}")
    else:
        raise TypeError(f"时间戳必须是字符串或 datetime，实际类型 {type(value).__name__}")

    if dt.tzinfo is None:
        if not assume_cn_tz:
            raise ValueError(f"时间戳缺少时区信息: {value!r}")
        dt = dt.replace(tzinfo=CN_TZ)
    return dt.astimezone(CN_TZ)


def parse_date(value: object) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value).strip()
    m = re.match(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})", text)
    if not m:
        raise ValueError(f"无法识别的日期: {value!r}")
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def iso_minute(dt: datetime) -> str:
    return dt.astimezone(CN_TZ).strftime("%Y-%m-%dT%H:%M:00+08:00")


def clamp_minutes(value: int) -> int:
    return max(0, int(value))


def round_half_up(numerator: int, denominator: int) -> int:
    """Integer-only, explicit half-up rounding (财务口径可复述)。"""
    if denominator == 0:
        raise ZeroDivisionError("round_half_up 分母为 0")
    if denominator < 0:
        numerator, denominator = -numerator, -denominator
    q, r = divmod(numerator, denominator)
    if 2 * r >= denominator:
        q += 1
    return q


def permille(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return round_half_up(1000 * numerator, denominator)


def percentile(sorted_values: list[int], pct: int) -> int:
    """Nearest-rank percentile on a pre-sorted integer list (口径写死，便于复述)。

    口径：升序排列后取第 ceil(p/100 * n) 个值；n=0 时返回 0。
    """
    n = len(sorted_values)
    if n == 0:
        return 0
    rank = math.ceil(pct / 100 * n)
    rank = min(max(rank, 1), n)
    return sorted_values[rank - 1]


# ---------------------------------------------------------------- CSV 公式注入防护
# 选 `'` 前缀而不是 OWASP 的制表符前缀：Excel/LibreOffice 都把字段首个 `'` 视为
# “强制文本”标记且不在单元格里显示；制表符前缀会留在单元格内，也容易被后续
# strip/裁剪流程吃掉。只在首字符命中公式起始字符时加前缀，普通中文/数字/日期不变。
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
# 包内 inputs/manifest.json 用这个字段声明“本包的 CSV 已按 `'` 前缀转义”；
# 重放只在看到该声明时才撤销前缀，旧包（无字段）按原始文本导入，避免误改历史值。
CSV_FORMULA_ESCAPE = "apostrophe"


def _looks_like_formula(value: str) -> bool:
    """去掉任意数量的前导 `'` 后，首字符是否仍是公式起始字符。

    这样原始值 `'=cmd` 会编码成 `''=cmd`，重放时只剥一层，仍能精确还原；
    普通以 `'` 开头但后接中文的文本不受影响。
    """
    body = value.lstrip("'")
    return bool(body) and body[0] in _FORMULA_PREFIXES


def csv_safe_cell(value: object) -> object:
    """单个 CSV 单元格的公式注入防护；非字符串（含 None/int）原样返回。"""
    if isinstance(value, str) and _looks_like_formula(value):
        return "'" + value
    return value


def csv_safe_row(row) -> list:
    """逐单元格套用同一个规则，避免各导出函数各写一套。"""
    return [csv_safe_cell(v) for v in row]


def csv_unescape_cell(value: object) -> object:
    """撤销 `csv_safe_cell` 的防护前缀。

    只识别“若干个前导 `'` 后紧跟公式起始字符”的形态，并且只剥一层；普通以
    `'` 开头但后接中文的业务值（例如 `'普通文本`）不会被改动。导入方默认不启用，
    只有重放举证包时按导出约定撤销。
    """
    if isinstance(value, str):
        body = value.lstrip("'")
        if len(value) > len(body) and body and body[0] in _FORMULA_PREFIXES:
            return value[1:]
    return value


NUM_RE = re.compile(r"(?<![0-9A-Za-z.])[-+]?\d[\d,]*(?:\.\d+)?(?![0-9A-Za-z])")


def extract_numeric_tokens(text: str) -> list[str]:
    """Normalised numeric tokens found in an answer, used for the A1/A4 allowlist check."""
    out: list[str] = []
    for m in NUM_RE.finditer(text):
        raw = m.group(0)
        norm = raw.replace(",", "").strip()
        if norm and norm not in out:
            out.append(norm)
    return out
