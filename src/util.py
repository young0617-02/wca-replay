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
