"""规则命中结果（Finding）的规范结构。

severity 三级语义（写死，供 F-006 分级与举证包解释字段使用）：
  DEFENSIBLE 可申辩 —— 事实成立但落在法定/约定区间内，只需补强协商与审批证据；
  REVIEW     需复核 —— 越过阈值或存在地方口径/解释差异，人工确认前不得定论；
  VIOLATION  明显违规 —— 数值超限且不依赖任何外部事实即可判定。
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEV_DEFENSIBLE = "DEFENSIBLE"
SEV_REVIEW = "REVIEW"
SEV_VIOLATION = "VIOLATION"
SEVERITIES = (SEV_DEFENSIBLE, SEV_REVIEW, SEV_VIOLATION)

SEV_LABEL_ZH = {
    SEV_DEFENSIBLE: "可申辩",
    SEV_REVIEW: "需复核",
    SEV_VIOLATION: "明显违规",
}

SEV_RANK = {SEV_DEFENSIBLE: 1, SEV_REVIEW: 2, SEV_VIOLATION: 3}

# O-2：归属不到人的质量问题也要有结论与复核单，用这个保留主体承载（举证包与报表里可见）
UNATTRIBUTED = "(未归属)"


@dataclass
class Finding:
    rule_id: str
    rule_version: str
    emp_id: str
    severity: str
    explanation: str
    citations: list[str] = field(default_factory=list)
    metric: dict = field(default_factory=dict)
    # 证据定位元数据（tables/window/rules/aggregation）：非 canonical 字段，
    # 不进入 conclusion_digest；由 evidence_digest 单独覆盖。
    evidence: dict = field(default_factory=dict)
    source_refs: list[dict] = field(default_factory=list)
    work_date: str | None = None
    period_key: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"非法 severity: {self.severity!r}")
        if not self.citations:
            raise ValueError(f"规则 {self.rule_id} 的结论必须挂条文依据（A2 红线）")

    def as_row(self, run_id: str) -> tuple:
        import json

        return (
            run_id, self.rule_id, self.rule_version, self.emp_id, self.work_date, self.period_key,
            self.severity, json.dumps(self.metric, sort_keys=True, ensure_ascii=False),
            json.dumps(self.evidence, sort_keys=True, ensure_ascii=False),
            json.dumps(sorted(self.citations), ensure_ascii=False),
            json.dumps(self.source_refs, ensure_ascii=False), self.explanation,
        )

    def evidence_record(self) -> dict:
        """evidence_digest 的输入记录；身份字段用于防止证据块串位。"""
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "emp_id": self.emp_id,
            "work_date": self.work_date,
            "period_key": self.period_key,
            "evidence": self.evidence,
        }

    def canonical(self) -> dict:
        """结论摘要用的规范形式：不含时间戳，重跑必须逐字节一致（A8）。"""
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "emp_id": self.emp_id,
            "work_date": self.work_date,
            "period_key": self.period_key,
            "severity": self.severity,
            "metric": self.metric,
            "citations": sorted(self.citations),
            "explanation": self.explanation,
        }

    @property
    def severity_label(self) -> str:
        return SEV_LABEL_ZH[self.severity]
