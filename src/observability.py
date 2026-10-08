"""F-013 可观测：分段计时、P95 统计、token 口径。

口径必须与数字写在同一段文字里（§4.7-Q7），所以这里同时产出：
  * 分段耗时（微秒，perf_counter 单调时钟，不受系统时间调整影响）
  * 百分位算法（nearest-rank，已在 util 里钉死）
  * token 计数口径（provider 返回值优先；离线 stub 用「字符数」估算并明确标注为估算）
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from .util import percentile


class Timer:
    """带标签的单调时钟采样器；同名段多次调用会全部保留（用于 P95 统计）。"""

    def __init__(self) -> None:
        self._samples: dict[str, list[int]] = {}
        self._t0 = time.perf_counter()

    @contextmanager
    def __call__(self, segment: str):
        t0 = time.perf_counter_ns()
        try:
            yield self
        finally:
            self.add(segment, int((time.perf_counter_ns() - t0) // 1000))

    def add(self, segment: str, us: int) -> None:
        self._samples.setdefault(segment, []).append(int(us))

    def samples(self) -> dict[str, list[int]]:
        return self._samples

    def snapshot(self) -> dict[str, int]:
        return {k: int(sum(v)) for k, v in self._samples.items()}

    def total_us(self) -> int:
        return int(sum(sum(v) for v in self._samples.values()))

    def wall_us(self) -> int:
        return int((time.perf_counter() - self._t0) * 1_000_000)


@dataclass
class SegmentStats:
    segment: str
    n: int
    p50_us: int
    p95_us: int
    p99_us: int
    max_us: int
    mean_us: int

    def as_row(self) -> list[str]:
        return [
            self.segment, str(self.n), _ms(self.p50_us), _ms(self.p95_us), _ms(self.p99_us),
            _ms(self.max_us), _ms(self.mean_us),
        ]

    @property
    def header(self) -> list[str]:
        return ["segment", "n", "P50(ms)", "P95(ms)", "P99(ms)", "max(ms)", "mean(ms)"]


def _ms(us: int) -> str:
    return f"{us / 1000:.1f}"


def stats_for(samples: dict[str, list[int]]) -> list[SegmentStats]:
    out: list[SegmentStats] = []
    for seg, vals in sorted(samples.items()):
        s = sorted(vals)
        out.append(SegmentStats(
            segment=seg, n=len(s),
            p50_us=percentile(s, 50), p95_us=percentile(s, 95), p99_us=percentile(s, 99),
            max_us=s[-1] if s else 0, mean_us=int(sum(s) / len(s)) if s else 0,
        ))
    return out


def spans_for_qid(conn: sqlite3.Connection, qid: str) -> dict[str, list[int]]:
    rows = conn.execute("SELECT segment, duration_us FROM span WHERE qid = ? ORDER BY span_id",
                        (qid,)).fetchall()
    out: dict[str, list[int]] = {}
    for r in rows:
        out.setdefault(r["segment"], []).append(int(r["duration_us"]))
    return out


def record_spans(conn: sqlite3.Connection, qid: str, timer: Timer) -> None:
    for seg, vals in timer.samples().items():
        for v in vals:
            conn.execute("INSERT INTO span(qid, segment, duration_us) VALUES(?,?,?)", (qid, seg, v))


def collect_all_spans(conn: sqlite3.Connection, segment_prefix: str | None = None) -> dict[str, list[int]]:
    if segment_prefix:
        rows = conn.execute(
            "SELECT segment, duration_us FROM span WHERE segment LIKE ? ORDER BY span_id",
            (f"{segment_prefix}%",),
        ).fetchall()
    else:
        rows = conn.execute("SELECT segment, duration_us FROM span ORDER BY span_id").fetchall()
    out: dict[str, list[int]] = {}
    for r in rows:
        out.setdefault(r["segment"], []).append(int(r["duration_us"]))
    return out


# ------------------------------------------------------------------ token 口径
CJK_RANGES = ((0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF),
              (0xFF00, 0xFFEF), (0x2E80, 0x2EFF), (0x3000, 0x303F))


def est_tokens(text: str) -> int:
    """估算 token 数：CJK 字符按 1 token，连续 ASCII 词按 1 token。

    这是估算口径（离线 stub 无 provider 计数）。报告里必须标注为 est，不当作真实账单数。
    """
    tokens = 0
    in_ascii_word = False
    for ch in text:
        if _is_cjk(ch):
            tokens += 1
            in_ascii_word = False
        elif ch.isalnum():
            if not in_ascii_word:
                tokens += 1
                in_ascii_word = True
        else:
            in_ascii_word = False
    return tokens


def _is_cjk(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in CJK_RANGES)


def token_distribution(counts: list[int]) -> dict[str, int]:
    s = sorted(counts)
    if not s:
        return {"n": 0, "p50": 0, "p95": 0, "max": 0, "mean": 0, "sum": 0}
    return {
        "n": len(s),
        "p50": percentile(s, 50),
        "p95": percentile(s, 95),
        "max": s[-1],
        "mean": int(sum(s) / len(s)),
        "sum": sum(s),
    }
