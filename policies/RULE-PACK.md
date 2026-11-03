# 规则包定义（对外版）

规则包：`rp-2026.11.gd-pilot-standard.v5`（兼容 v4/v5/v6 历史回放）。
阈值默认值：`daily_std_minutes=480`、`weekly_std_minutes=2400`、
`ot_cap_daily_general_minutes=60`、`ot_cap_daily_special_minutes=180`、
`ot_cap_monthly_minutes=2160`。这些是代码默认值，可由部署配置覆盖；包内 `manifest.scope_json`
会记录实际钉回值，未记录的参数沿用默认值。

`rule_version` 是**单条规则版本**，不等于 rule pack 版本。v5 包内保留未改判据的 v4 规则是预期；
`manifest.counts.rule_versions` 公开分布。

| rule_id | 名称 | 层级 | 规则版本 | 条文引用 | 阈值/公式 | 生效日期 |
|---|---|---|---|---|---|---|
| `OT-D01` | 工作日延长工作时间 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `rule.mohrss.1994-489.13` | 延长分钟 = max(0, 实际工作分钟 - daily_std_minutes)；报酬类最高需复核，不判违法 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `OT-D02` | 休息日工作安排与补休 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44`, `rule.mohrss.1994-503.6` | 休息日工作分钟 > 0；补休/倍数为解释项，最高需复核 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `OT-D03` | 法定节假日当天工作安排 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44`, `law.labor.40`, `law.labor.51` | 法定节假日工作分钟 > 0；报酬类最高需复核 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `CAP-D05` | 单日加班超过 3 小时 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `reg.state-council.worktime.3` | 延长分钟 > ot_cap_daily_special_minutes（默认 180）→ 可判明显违规；≤60 为一般延长 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `CAP-W01` | 连续工作 7 天无休息日 | week | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.38` | 同一 ISO 周 7 个日历日均无“零工作且零打卡”的整天休息 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `WK-W02` | 周实际工时超过 44 小时 | week | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.36` | 周实际分钟 > 2640（44h）；仅近 4 周平均 >2640 才下明显违规，单周只到需复核 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `WK-W01` | 周实际工时超过 40 小时（解释差异） | week | `rp-2026.10.gd-pilot-standard.v4` | `reg.state-council.worktime.3`, `law.labor.36` | 2400 < 周实际分钟 ≤ 2640；解释差异，需复核 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `CAP-M01` | 月延长工时累计超过 36 小时 | month | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41` | 月延长分钟累计 > ot_cap_monthly_minutes（默认 2160 / 36h） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `CAP-M02` | 月延长工时超过内部预警线 | month | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.overtime-approval`, `law.labor.41` | 月延长分钟 > 90% × ot_cap_monthly_minutes（默认 1944），且未超 2160；内部预警 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `XD-01` | 跨天班次切分依据不足 | quality | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `rule.mohrss.1994-503.6` | 跨天班次切分依据不足（quality 提示，不单独下违规） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `NIGHT-01` | 夜间时段工时统计（无全国统一标准） | scope | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.36` | 夜间分钟数 > 0；仅统计，无全国统一标准 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `QUAL-01` | 数据质量异常（缺卡/重复/顺序/畸形入参） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.attendance`, `law.labor-contract.4` | 缺卡/重复/顺序异常/畸形入参等数据质量标记存在 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `QUAL-02` | 被拒收的输入行（事实缺口，须补录后重跑） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.attendance`, `law.labor-contract.4` | 输入行被拒收 > 0（事实缺口，须补录后重跑） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `POL-01` | 加班缺审批记录（内部制度层） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.overtime-approval`, `law.labor-contract.4` | 延长工时缺内部审批记录 > 0（内部制度层，需复核） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `SCOPE-01` | 校验范围外：年度日历或调休安排未核实 | scope | `rp-2026.10.gd-pilot-standard.v4` | `reg.state-council.holiday-measure.2`, `notice.state-council.holiday-2026` | 年度日历或调休安排未核实（scope 提示） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `SCOPE-02` | 工时制不在本期范围（综合计算工时/不定时），未覆盖 | scope | `rp-2026.10.gd-pilot-standard.v4` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.5` | 综合计算工时/不定时工作制不在本期标准工时判定范围（未覆盖） | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `SCOPE-03` | 申报特殊工时但缺审批证据，本期按标准工时校验并提示核实资质 | scope | `rp-2026.10.gd-pilot-standard.v4` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.7` | 申报特殊工时但缺审批证据；本期按标准工时校验并提示核实资质 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `SCOPE-04` | 员工所属城市不在档位表内，只出国家层面结论 | scope | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44` | 员工所属城市不在 region_profile 档位表内；只出国家层面结论 | 2026-10-08（v4 口径冻结；规则包切换日；具体案件适用仍需交付台账确认） |
| `REG-01` | 特殊工时审批覆盖核验（缺失/过期/岗位/城市） | scope | `rp-2026.11.gd-pilot-standard.v5` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.7` | 审批台账缺失/过期/岗位不匹配/城市不匹配（scope 提示） | 2026-11-02（v5 新增；规则包切换日；具体案件适用仍需交付台账确认） |
| `COMP-C01` | 综合工时周期统计（总工时与法定标准差值） | period | `rp-2026.11.gd-pilot-standard.v5` | `rule.mohrss.1994-503.5`, `rule.mohrss.1994-489.13` | 综合工时周期总工时 - 法定标准 > 0 → 需复核；≤0 → 可申辩；只统计不判违规 | 2026-11-02（v5 新增；规则包切换日；具体案件适用仍需交付台账确认） |
| `SHIFT-01` | 多段班次不可拼接（打卡事实不闭合） | quality | `rp-2026.11.gd-pilot-standard.v5` | `policy.sz.attendance`, `rule.mohrss.1994-503.6` | 多段班次打卡事实不闭合，不可直接拼接 | 2026-11-02（v5 新增；规则包切换日；具体案件适用仍需交付台账确认） |
| `OFF-01` | 离线补传冲突（同时点同类型多来源） | quality | `rp-2026.11.gd-pilot-standard.v5` | `policy.sz.attendance`, `law.labor-contract.4` | 离线补传冲突：同一时点/同一类型存在多来源 | 2026-11-02（v5 新增；规则包切换日；具体案件适用仍需交付台账确认） |

说明：

- 本文件是规则包定义对外版，不替代法律意见；条文原文/稳定引用见 `LAW-REFERENCES.md`。
- 金额永不进入规则结论；报酬类规则（OT-*）最高只到“需复核”。
- `COMP-C01` 只作统计，不判违规、不出倍数；周期是否被批准覆盖仍以 `REG-01` 台账核验为准。
- 具体启用/废止日期、特殊工时审批台账有效性需交付方书面确认。
