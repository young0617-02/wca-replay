"""F-002 工时制判定：谁能适用哪种工时制，以及缺审批时的处置。

判定链只用条文，不用推测：
  标准工时 —— 默认形态（劳动法 36/38、国务院工作时间规定 3）
  综合计算工时 —— 适用岗位清单 + 审批（劳部发〔1994〕503 号 5/7 条）
  不定时工时 —— 适用岗位清单 + 审批（503 号 4/7 条）
缺审批时不得按特殊工时豁免加班倍数，而是降级为按标准工时校验 + 出一条 VIOLATION。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import citations as C

REGIME_STANDARD = "standard"
REGIME_COMPREHENSIVE = ("comprehensive_monthly", "comprehensive_quarterly", "comprehensive_yearly")
REGIME_FLEXIBLE = "flexible"

# 503 号文 4/5 条列举的岗位类型（合成岗位编码，口径见 docs）
FLEXIBLE_ELIGIBLE_JOBS = {
    "senior_manager", "field_sales", "external_affairs", "on_duty",
    "long_haul_driver", "taxi_driver", "mobile_maintenance",
}
COMPREHENSIVE_ELIGIBLE_JOBS = {
    "transport_continuous", "railway", "postal_telecom", "waterway", "aviation",
    "fishery", "geology_survey", "construction", "salt_making", "sugar_making",
    "tourism_seasonal", "warehouse_shift",
}

CYCLE_DAYS = {
    "comprehensive_monthly": ("month", 31),
    "comprehensive_quarterly": ("quarter", 92),
    "comprehensive_yearly": ("year", 366),
}


@dataclass
class RegimeDecision:
    emp_id: str
    declared_regime: str
    job_code: str
    approved: bool
    eligible_by_job: bool
    effective_regime: str
    reasons: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)

    @property
    def is_special(self) -> bool:
        return self.effective_regime != REGIME_STANDARD

    def metric(self) -> dict:
        return {
            "declared_regime": self.declared_regime,
            "effective_regime": self.effective_regime,
            "approved": int(self.approved),
            "eligible_by_job": int(self.eligible_by_job),
            "job_code": self.job_code,
        }


def decide(emp_id: str, job_code: str, declared_regime: str, approved: bool) -> RegimeDecision:
    """返回本周期实际生效的工时制；缺审批/岗位不符 → 回落标准工时。"""
    reasons: list[str] = []
    cites = [C.LABOR_LAW_36, C.SC_WORKTIME_3]

    if declared_regime == REGIME_STANDARD:
        return RegimeDecision(emp_id, declared_regime, job_code, True, True, REGIME_STANDARD,
                              ["声明为标准工时，直接适用法定标准"], cites)

    if declared_regime == REGIME_FLEXIBLE:
        cites = cites + [C.MOHRSS_503_4, C.MOHRSS_503_7]
        eligible = job_code in FLEXIBLE_ELIGIBLE_JOBS
        if not eligible:
            reasons.append(f"岗位 {job_code} 不在 503 号文第 4 条列举的不定时工作制适用范围内")
        if not approved:
            reasons.append("未取得劳动行政部门对不定时工作制的批准，不得免除加班工资义务")
        if eligible and approved:
            return RegimeDecision(emp_id, declared_regime, job_code, approved, eligible,
                                  REGIME_FLEXIBLE, ["适用不定时工作制：工作日工时不受延长工时限制"], cites)
        reasons.append("回落为标准工时校验")
        return RegimeDecision(emp_id, declared_regime, job_code, approved, eligible,
                              REGIME_STANDARD, reasons, cites)

    if declared_regime in CYCLE_DAYS:
        cites = cites + [C.MOHRSS_503_5, C.MOHRSS_503_7, C.WAGE_PAYMENT_13]
        eligible = job_code in COMPREHENSIVE_ELIGIBLE_JOBS
        if not eligible:
            reasons.append(f"岗位 {job_code} 不在 503 号文第 5 条列举的综合计算工时适用范围内")
        if not approved:
            reasons.append("未取得综合计算工时工作制批准，不得以周期综合方式计算工时")
        if eligible and approved:
            return RegimeDecision(emp_id, declared_regime, job_code, approved, eligible,
                                  declared_regime, ["适用综合计算工时工作制：以周期平均工时对照法定标准"], cites)
        reasons.append("回落为标准工时校验")
        return RegimeDecision(emp_id, declared_regime, job_code, approved, eligible,
                              REGIME_STANDARD, reasons, cites)

    reasons.append(f"未知工时制声明 {declared_regime!r}，按标准工时处理并标记需复核")
    return RegimeDecision(emp_id, declared_regime, job_code, False, False, REGIME_STANDARD,
                          reasons, cites)
