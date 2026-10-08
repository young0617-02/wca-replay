"""中国大陆法定节假日日历：区分「法定节假日当天」(300%) 与「调休休息日」(200%)。

数据文件 `holidays.json` 每一年都必须能反查到国务院办公厅放假通知，未收录的年份
显式抛 `YearNotCovered`，绝不退化成「按星期几猜」。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

CALENDAR_PATH = Path(__file__).resolve().parent / "holidays.json"

DAY_WORKDAY = "workday"
DAY_STATUTORY_HOLIDAY = "statutory_holiday"
DAY_REST_SWAP = "rest_day_swap"       # 调休形成的休息日 -> 200%
DAY_PLAIN_REST = "plain_rest_day"     # 普通周六日 -> 200%
DAY_UNKNOWN = "unknown"


class YearNotCovered(Exception):
    def __init__(self, year: int) -> None:
        super().__init__(
            f"{year} 年节假日安排未收录，无法判定法定节假日当天与调休休息日；"
            "请补充国务院办公厅该年度放假通知后再纳入校验范围。"
        )
        self.year = year


@dataclass(frozen=True)
class DayInfo:
    day: date
    day_type: str
    holiday_label: str = ""
    notice_doc_id: str = ""
    ambiguous: bool = False           # 法定节假日当天与调休休息日无法区分
    workday_arrangement_unverified: bool = False  # 该年度调休上班日安排未核实

    @property
    def is_rest(self) -> bool:
        return self.day_type in (DAY_REST_SWAP, DAY_PLAIN_REST)

    @property
    def is_statutory(self) -> bool:
        return self.day_type == DAY_STATUTORY_HOLIDAY


class HolidayCalendar:
    def __init__(self, payload: dict) -> None:
        self._years = payload.get("years", {})
        self._schema = payload.get("schema", "unknown")

    @classmethod
    def load(cls, path: Path | None = None) -> "HolidayCalendar":
        p = path or CALENDAR_PATH
        return cls(json.loads(p.read_text(encoding="utf-8")))

    @property
    def covered_years(self) -> list[int]:
        return sorted(int(y) for y in self._years)

    def _year(self, d: date) -> dict:
        entry = self._years.get(str(d.year))
        if entry is None:
            raise YearNotCovered(d.year)
        return entry

    @staticmethod
    def _in_blocks(d: date, blocks: list) -> bool:
        for blk in blocks:
            start = date.fromisoformat(blk[0])
            end = date.fromisoformat(blk[1])
            if start <= d <= end:
                return True
        return False

    def classify(self, d: date) -> DayInfo:
        entry = self._year(d)
        iso = d.isoformat()
        ambiguous = iso in set(entry.get("ambiguous_dates", []))
        blocks_verified = bool(entry.get("work_blocks_verified", True))
        label = entry.get("statutory_days", {}).get(iso, "")
        notice = entry.get("notice_doc_id", "")
        unverified_weekend = (not blocks_verified) and d.weekday() >= 5
        if label:
            return DayInfo(d, DAY_STATUTORY_HOLIDAY, label, notice, ambiguous, unverified_weekend)
        if self._in_blocks(d, entry.get("work_blocks", [])):
            return DayInfo(d, DAY_WORKDAY, "", notice, ambiguous, False)
        if self._in_blocks(d, entry.get("rest_blocks", [])):
            return DayInfo(d, DAY_REST_SWAP, "", notice, ambiguous, unverified_weekend)
        if d.weekday() >= 5:  # 周六=5 周日=6
            return DayInfo(d, DAY_PLAIN_REST, "", notice, ambiguous, unverified_weekend)
        return DayInfo(d, DAY_WORKDAY, "", notice, ambiguous, False)

    def daterange(self, start: date, end: date):
        cur = start
        while cur <= end:
            yield cur
            cur += timedelta(days=1)
