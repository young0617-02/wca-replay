"""Integer-only quantities: minutes and multiplier in permille.

本模块**不含任何金额计算**（需求 D-03 / A4 红线）：判定链只出分钟数与
法定倍数档位（千分位，1500 = 1.5x），应付金额由 HR 负责人在复核台具名录入。
No float ever enters a decision path.
"""

from __future__ import annotations

from dataclasses import dataclass

# 法定倍数（千分位）。出处见 rules/citations.py 与 docs/字段口径与条文依据.md
RATE_WEEKDAY_OT_PERMILLE = 1500   # 工作日延长工作时间 不低于 150%
RATE_RESTDAY_OT_PERMILLE = 2000   # 休息日加班且不能补休 不低于 200%
RATE_HOLIDAY_OT_PERMILLE = 3000   # 法定节假日加班 不低于 300%
RATE_NORMAL_PERMILLE = 1000



@dataclass(frozen=True)
class Duration:
    minutes: int

    def __post_init__(self) -> None:
        if not isinstance(self.minutes, int):
            raise TypeError(f"Duration.minutes 必须是 int，实际 {type(self.minutes).__name__}")

    @classmethod
    def of(cls, minutes: int) -> "Duration":
        return cls(int(minutes))

    @property
    def hours_text(self) -> str:
        h, m = divmod(abs(self.minutes), 60)
        sign = "-" if self.minutes < 0 else ""
        return f"{sign}{h}小时{m}分钟"

    def __add__(self, other: "Duration") -> "Duration":
        return Duration(self.minutes + other.minutes)

    def __sub__(self, other: "Duration") -> "Duration":
        return Duration(self.minutes - other.minutes)

    def at_least_zero(self) -> "Duration":
        return Duration(max(0, self.minutes))
