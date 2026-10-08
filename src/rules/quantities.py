"""Integer-only quantities: minutes, money in cents, multiplier in permille.

No float ever enters a decision path. Rates are permille (1500 = 1.5x) so that the
150% / 200% / 300% statutory multipliers are exact integers.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..util import round_half_up

# 法定倍数（千分位）。出处见 rules/citations.py 与 docs/字段口径与条文依据.md
RATE_WEEKDAY_OT_PERMILLE = 1500   # 工作日延长工作时间 不低于 150%
RATE_RESTDAY_OT_PERMILLE = 2000   # 休息日加班且不能补休 不低于 200%
RATE_HOLIDAY_OT_PERMILLE = 3000   # 法定节假日加班 不低于 300%
RATE_NORMAL_PERMILLE = 1000

# 分钟 <-> 小时 的分母：hourly_cents * minutes * permille / (60 * 1000)
_MINUTES_PER_HOUR = 60
_PERMILLE = 1000


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


@dataclass(frozen=True)
class Money:
    cents: int

    def __post_init__(self) -> None:
        if not isinstance(self.cents, int):
            raise TypeError(f"Money.cents 必须是整数分，实际 {type(self.cents).__name__}")

    @property
    def yuan_text(self) -> str:
        sign = "-" if self.cents < 0 else ""
        yuan, jiao = divmod(abs(self.cents), 100)
        return f"{sign}{yuan}元{jiao}角" if jiao else f"{sign}{yuan}元"


def overtime_pay_cents(hourly_normal_cents: int, minutes: int, rate_permille: int) -> int:
    """测算加班报酬（分）= 小时工资 x 分钟/60 x 倍数，半进位取整到分。

    这是唯一的算钱入口，`rules/` 之外不得出现金额计算（A1 红线）。
    """
    if hourly_normal_cents < 0 or minutes < 0 or rate_permille < 0:
        raise ValueError("加班测算不接受负值输入")
    return round_half_up(
        hourly_normal_cents * minutes * rate_permille, _MINUTES_PER_HOUR * _PERMILLE
    )


def pay_for_overtime(hourly_normal_cents: int, weekday_min: int, restday_min: int,
                     holiday_min: int) -> dict[str, int]:
    """三段倍数分开测算，便于举证包里逐条复核。"""
    return {
        "weekday_cents": overtime_pay_cents(hourly_normal_cents, weekday_min, RATE_WEEKDAY_OT_PERMILLE),
        "restday_cents": overtime_pay_cents(hourly_normal_cents, restday_min, RATE_RESTDAY_OT_PERMILLE),
        "holiday_cents": overtime_pay_cents(hourly_normal_cents, holiday_min, RATE_HOLIDAY_OT_PERMILLE),
    }


def total_cents(parts: dict[str, int]) -> int:
    return sum(parts.values())
