"""条文引用 ID 常量。唯一真相在 `src/kb/corpus/kb_doc.jsonl`（含原文摘录、出处 URL、确信度）。

规则命中时必须挂这里的 id；举证包与评测集靠它反查到条文原文（A2 红线）。
条号一律来自联网核实结果，核实路径与未核到项见 `docs/字段口径与条文依据.md`。
"""

from __future__ import annotations

# —— 法律：《中华人民共和国劳动法》（2018-12-29 修正）
LABOR_LAW_36 = "law.labor.36"   # 每日≤8小时、平均每周≤44小时
LABOR_LAW_38 = "law.labor.38"   # 每周至少休息一日
LABOR_LAW_40 = "law.labor.40"   # 法定休假日应依法安排休假
LABOR_LAW_41 = "law.labor.41"   # 加班上限：一般每日≤1h；特殊每日≤3h 且每月≤36h
LABOR_LAW_44 = "law.labor.44"   # 150% / 200%(未补休) / 300%
LABOR_LAW_51 = "law.labor.51"   # 法定休假日带薪

LCT_4 = "law.labor-contract.4"       # 直接涉及切身利益的制度须民主程序 + 公示
LCT_31 = "law.labor-contract.31"     # 不得强迫加班；安排加班应支付加班费
LCT_85 = "law.labor-contract.85"     # 逾期不支付：按应付金额 50%–100% 加付赔偿金
PIPL_13 = "law.pipl.13"             # 「人力资源管理所必需」为合法性基础之一
PIPL_29 = "law.pipl.29"             # 敏感个人信息须单独同意

# —— 行政法规
SC_WORKTIME_3 = "reg.state-council.worktime.3"   # 每日 8 小时、每周 40 小时
SC_WORKTIME_7 = "reg.state-council.worktime.7"   # 国家机关事业单位周休息日；企业可灵活安排
HOLIDAY_MEASURE_2 = "reg.state-council.holiday-measure.2"  # 全体公民放假节日合计 13 天及分配

# —— 部门规章
MOHRSS_503_3 = "rule.mohrss.1994-503.3"   # 不能实行标准工时的，经审批可实行特殊工时
MOHRSS_503_4 = "rule.mohrss.1994-503.4"   # 不定时工作制适用岗位
MOHRSS_503_5 = "rule.mohrss.1994-503.5"   # 综合计算工时适用岗位 + 平均日/周工时不得超法定标准
MOHRSS_503_6 = "rule.mohrss.1994-503.6"   # 集中工作、集中休息、轮休调休保障休息权
MOHRSS_503_7 = "rule.mohrss.1994-503.7"   # 审批权限（央企报国务院劳动部门；地方办法由省级制定并备案）
WAGE_PAYMENT_13 = "rule.mohrss.1994-489.13"  # 加班工资三档 + 综合工时超额视为延长工时

# —— 地方性法规 / 地方文件（深圳口径比全国更严：不定时工时法定节假日仍付 300%）
SZ_WAGE_4 = "local.sz.wage-reg.4"     # 约定正常工作时间工资不得低于深圳最低工资标准
SZ_WAGE_18 = "local.sz.wage-reg.18"   # 150%/200%/300%，基数=本人正常工作时间工资
SZ_WAGE_19 = "local.sz.wage-reg.19"   # 综合工时周期内超过正常工作时间部分按 150%
SZ_WAGE_20 = "local.sz.wage-reg.20"   # 不定时工时员工法定节假日工作按 300%
GD_WAGE_20 = "local.gd.wage-reg.20"   # 广东省工资支付条例：150%/200%/300%（广佛适用档）
GD_WAGE_23 = "local.gd.wage-reg.23"   # 广东省：经批准不定时工时不适用第 20 条（本期不判，仅备查）
GD_APPROVAL_2009 = "local.gd.approval-2009"      # 粤劳社发〔2009〕8号 审批管理
SZ_APPROVAL_6 = "local.sz.approval-2009.6"       # 深圳市不定时工作制审批
SZ_APPROVAL_8 = "local.sz.approval-2009.8"       # 深圳市综合计算工时审批

# —— 官方排班
HOLIDAY_NOTICE_2025 = "notice.state-council.holiday-2025"
HOLIDAY_NOTICE_2026 = "notice.state-council.holiday-2026"

# —— 公司内部制度（合成语料，ACL 非 public）
POLICY_ATTENDANCE = "policy.sz.attendance"
POLICY_OT_APPROVAL = "policy.sz.overtime-approval"
POLICY_PAY_BASE = "policy.sz.pay-base"
POLICY_DATA_ACCESS = "policy.sz.data-access"
POLICY_COMP_CONF = "policy.sz.compensation-confidential"

# —— 个人数据类文档（用于证明 ACL 下推：他人薪酬/考勤不可见即不可召回）
PERSONNEL_PAYROLL_PREFIX = "personnel.payroll."
PERSONNEL_ATTEND_PREFIX = "personnel.attendance."

ALL_CITATIONS = [
    LABOR_LAW_36, LABOR_LAW_38, LABOR_LAW_40, LABOR_LAW_41, LABOR_LAW_44, LABOR_LAW_51,
    LCT_4, LCT_31, LCT_85, PIPL_13, PIPL_29,
    SC_WORKTIME_3, SC_WORKTIME_7, HOLIDAY_MEASURE_2,
    MOHRSS_503_3, MOHRSS_503_4, MOHRSS_503_5, MOHRSS_503_6, MOHRSS_503_7,
    WAGE_PAYMENT_13,
    SZ_WAGE_4, SZ_WAGE_18, SZ_WAGE_19, SZ_WAGE_20,
    GD_WAGE_20, GD_WAGE_23,
    GD_APPROVAL_2009, SZ_APPROVAL_6, SZ_APPROVAL_8,
    HOLIDAY_NOTICE_2025, HOLIDAY_NOTICE_2026,
    POLICY_ATTENDANCE, POLICY_OT_APPROVAL, POLICY_PAY_BASE,
    POLICY_DATA_ACCESS, POLICY_COMP_CONF,
]
