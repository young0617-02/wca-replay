"""城市档位表（region profile）：把「哪个城市适用哪部地方性法规」从代码搬到配置。

- 需求 US-AD-06：城市清单与工时制必须来自配置，`src/` 里不留硬编码市名（有测试逐文件扫）。
- 需求 §7.3-3：口径不一致时**分档实现**，不允许一套规则强盖多城。
- 核实依据与 URL、存疑项见 `docs/字段口径与条文依据.md` 第 2.1 节（核对日期 2026-10-08）。

本表把「条文集合」与「城市」分开建模：广州、佛山经核实都适用《广东省工资支付条例》，
因此共用 `guangdong-province` 集合；深圳有经济特区立法，单独成档。
"""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA = "wca-region-profile-v1"
CITATION_SET_KEYS = ("multiplier",)   # 判定链当前只消费倍数集合


class RegionProfileError(ValueError):
    pass


class CityProfile:
    __slots__ = ("code", "label", "tier", "multiplier_citations", "sets", "not_covered_note")

    def __init__(self, code: str, label: str, tier: list[str], sets: list[str],
                 multiplier_citations: list[str], not_covered_note: str = "") -> None:
        self.code = code
        self.label = label
        self.tier = tier                                    # 地域层级：CN / 440000 / 440300
        self.sets = sets
        self.multiplier_citations = multiplier_citations     # 挂到结论上的本地条文 doc_id
        self.not_covered_note = not_covered_note


class RegionProfile:
    def __init__(self, cities: dict[str, CityProfile], *, default_city: str,
                 unlisted_policy: str, source: str) -> None:
        if not cities:
            raise RegionProfileError("城市档位表为空：至少要有一个城市档")
        if default_city not in cities:
            raise RegionProfileError(f"default_city={default_city} 不在 cities 里（{source}）")
        self.cities = cities
        self.default_city = default_city
        self.unlisted_policy = unlisted_policy
        self.source = source

    # ---------------------------------------------------------------- 构造
    @classmethod
    def load(cls, path: Path) -> "RegionProfile":
        if not path.is_file():
            raise RegionProfileError(
                f"城市档位表不存在：{path}。三市分档依赖它，缺失时**不得**退回硬编码市名。")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != SCHEMA:
            raise RegionProfileError(
                f"城市档位表 schema 不符：期望 {SCHEMA}，实际 {data.get('schema')!r}（{path}）")
        sets = data.get("citation_sets") or {}
        if not sets:
            raise RegionProfileError(f"城市档位表没有 citation_sets（{path}）")
        cities: dict[str, CityProfile] = {}
        for code, entry in (data.get("cities") or {}).items():
            for key in ("label", "tier", "sets"):
                if not entry.get(key):
                    raise RegionProfileError(f"城市 {code} 缺字段 {key}（{path}）")
            refs = entry["sets"]
            missing = [r for r in refs if r not in sets]
            if missing:
                raise RegionProfileError(f"城市 {code} 引用了不存在的条文集合 {missing}（{path}）")
            multiplier: list[str] = []
            for ref in refs:
                for key in CITATION_SET_KEYS:
                    for doc_id in sets[ref].get(key, []):
                        if doc_id not in multiplier:
                            multiplier.append(doc_id)
            if not multiplier:
                raise RegionProfileError(f"城市 {code} 解析出的倍数条文集合为空（{path}）")
            cities[code] = CityProfile(code, entry["label"], list(entry["tier"]), refs,
                                       multiplier, entry.get("not_covered_note", ""))
        return cls(cities, default_city=data.get("default_city", ""),
                   unlisted_policy=data.get("unlisted_policy", "reject-to-scope"),
                   source=str(path))

    # ---------------------------------------------------------------- 查询
    def codes(self) -> list[str]:
        return sorted(self.cities)

    def known(self, region_code: str) -> bool:
        return region_code in self.cities

    def city(self, region_code: str) -> CityProfile | None:
        return self.cities.get(region_code)

    def label(self, region_code: str) -> str:
        c = self.cities.get(region_code)
        return c.label if c else "未建档城市"

    def multiplier_citations(self, region_code: str) -> list[str]:
        """未建档城市返回空列表：只出国家层面结论，由调用方补 SCOPE-04。"""
        c = self.cities.get(region_code)
        return list(c.multiplier_citations) if c else []
