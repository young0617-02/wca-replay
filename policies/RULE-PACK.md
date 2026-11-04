# 规则包定义（对外版）

默认规则包：`rp-2026.11.gd-pilot-standard.v6`（0.4.8 起，**2026-11-04 生效**）；
`v4`/`v5` 保持不可变，仍可显式 `WCA_RULE_PACK` 选择并回放。
阈值默认值：`daily_std_minutes=480`、`weekly_std_minutes=2400`、
`ot_cap_daily_general_minutes=60`、`ot_cap_daily_special_minutes=180`、
`ot_cap_monthly_minutes=2160`。这些是代码默认值，可由部署配置覆盖；包内 `manifest.scope_json`
会记录实际钉回值，未记录的参数沿用默认值。

`rule_version` 是**单条规则版本**，不等于 rule pack 版本。v5 包内保留未改判据的 v4 规则是预期；
`manifest.counts.rule_versions` 公开分布。v6 是独立冻结列表，`rule_version` 在 v6 run 中统一标为
`rp-2026.11.gd-pilot-standard.v6`，便于回放时一眼区分运行时规则包。

### 规则包版本与切换记录

| 规则包 | 规则包冻结日 | 规则包切换日 | 规则实现 | 旧包回放配套 wheel |
|---|---|---|---|---|
| `rp-2026.10.gd-pilot-standard.v4` | 2026-10-08 | 2026-10-08 | v4 判据集合 | 0.4.4–0.4.6 |
| `rp-2026.11.gd-pilot-standard.v5` | 2026-11-02 | 2026-11-02 | v5 判据集合（含 REG-01/COMP-C01/SHIFT-01/OFF-01） | 0.4.7 |
| `rp-2026.11.gd-pilot-standard.v6` | 2026-11-04 | 2026-11-04 | 独立冻结列表；实现与 v5 相同，run 时统一标 `rule_version=v6` | 0.4.8 |

| 切换动作 | 谁 | 何时 | 从 → 到 | 记录/证据 |
|---|---|---|---|---|
| 默认规则包切换 | 0.4.8 发布维护者（项目负责人批复） | 2026-11-04（发行物构建时刻 22:46:59 +08:00） | `v5` → `v6` | 本文件 + `reports/0.4.8-批次语义实施.md`（0.4.9 校正） |
| 运行库首次 v6 run | `system:audit`（`ensure_audit_epoch`） | 首次 run 的 UTC 时间 | 记录 `prev_rule_pack_version` / `rule_pack_version` / `switched_at` | 审计链 `rule_pack.epoch.start` 事件 |

**新库 genesis 纪元（0.4.9 起）**：库内既无审计事件也无纪元行时，首次使用会直接写入一条
`prev_rule_pack_version='genesis'` 的 `rule_pack_epoch`（版本、生效时刻、`segment_start_seq=1`、
`segment_start_prev_hash` 均为显式值）；随后第一个 run 的审计事件落在该段。因此“新库没有纪元
记录”不再是常态。`meta.audit_genesis` 是**纪元起点记录**（记录该段起点哈希与版本），不是
`audit_event`，不占 `seq`，也不出现在审计链事件列表里；不要把它与 `audit_event` 混为一谈。
`prev_rule_pack_version='legacy'` 只保留给**既有历史库**（已有审计事件但从未记录纪元）迁移时
使用，不是新库语义。

旧包不回改、不重签：v5 包继续用 0.4.7 wheel 回放，v6 包用 0.4.8 wheel；配对关系见
`OLD-WHEELS.md` 与 README。切换按 run 时版本计算，不是立法溯及。

**为什么 v6 实际在 2026-11-04 生效，而不是原计划的 2026-11-05**：0.4.8 发行物在
**2026-11-04T22:46:59+08:00** 构建并默认 `WCA_RULE_PACK=v6`，构建即生效；当时**没有任何生产 run**
使用 v5 或 v6，因此不存在“按 v5 跑过、事后被改标 v6”的历史数据。把文档写成 11-05 会与实际
发行行为不符，故按实际改为 11-04，**不回填历史、不把行为倒回 v5**。v5 仍保持不可变，旧包按
包内 `rule_pack_version` 与 0.4.7 wheel 回放。

### 规则清单

| rule_id | 名称 | 层级 | 规则版本 | 条文引用 | 阈值/公式 | 法律条文生效日 | 规则包冻结/切换日 |
|---|---|---|---|---|---|---|---|
| `OT-D01` | 工作日延长工作时间 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `rule.mohrss.1994-489.13` | 延长分钟 = max(0, 实际工作分钟 - daily_std_minutes)；报酬类最高需复核，不判违法 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `OT-D02` | 休息日工作安排与补休 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44`, `rule.mohrss.1994-503.6` | 休息日工作分钟 > 0；补休/倍数为解释项，最高需复核 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `OT-D03` | 法定节假日当天工作安排 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44`, `law.labor.40`, `law.labor.51` | 法定节假日工作分钟 > 0；报酬类最高需复核 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `CAP-D05` | 单日加班超过 3 小时 | day | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `reg.state-council.worktime.3` | 延长分钟 > ot_cap_daily_special_minutes（默认 180）→ 可判明显违规；≤60 为一般延长 | 1995-01-01 / 1995-05-01 | 2026-10-08（v4 冻结/切换） |
| `CAP-W01` | 连续工作 7 天无休息日 | week | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.38` | 同一 ISO 周 7 个日历日均无“零工作且零打卡”的整天休息 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `WK-W02` | 周实际工时超过 44 小时 | week | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.36` | 周实际分钟 > 2640（44h）；仅近 4 周平均 >2640 才下明显违规，单周只到需复核 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `WK-W01` | 周实际工时超过 40 小时（解释差异） | week | `rp-2026.10.gd-pilot-standard.v4` | `reg.state-council.worktime.3`, `law.labor.36` | 2400 < 周实际分钟 ≤ 2640；解释差异，需复核 | 1995-01-01 / 1995-05-01 | 2026-10-08（v4 冻结/切换） |
| `CAP-M01` | 月延长工时累计超过 36 小时 | month | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41` | 月延长分钟累计 > ot_cap_monthly_minutes（默认 2160 / 36h） | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `CAP-M02` | 月延长工时超过内部预警线 | month | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.overtime-approval`, `law.labor.41` | 月延长分钟 > 90% × ot_cap_monthly_minutes（默认 1944），且未超 2160；内部预警 | 1995-01-01 / 2025-01-01（合成制度） | 2026-10-08（v4 冻结/切换） |
| `XD-01` | 跨天班次切分依据不足 | quality | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.41`, `rule.mohrss.1994-503.6` | 跨天班次切分依据不足（quality 提示，不单独下违规） | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `NIGHT-01` | 夜间时段工时统计（无全国统一标准） | scope | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.36` | 夜间分钟数 > 0；仅统计，无全国统一标准 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `QUAL-01` | 数据质量异常（缺卡/重复/顺序/畸形入参） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.attendance`, `law.labor-contract.4` | 缺卡/重复/顺序异常/畸形入参等数据质量标记存在 | 2008-01-01 / 2025-01-01（合成制度） | 2026-10-08（v4 冻结/切换） |
| `QUAL-02` | 被拒收的输入行（事实缺口，须补录后重跑） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.attendance`, `law.labor-contract.4` | 输入行被拒收 > 0（事实缺口，须补录后重跑） | 2008-01-01 / 2025-01-01（合成制度） | 2026-10-08（v4 冻结/切换） |
| `POL-01` | 加班缺审批记录（内部制度层） | quality | `rp-2026.10.gd-pilot-standard.v4` | `policy.sz.overtime-approval`, `law.labor-contract.4` | 延长工时缺内部审批记录 > 0（内部制度层，需复核） | 2008-01-01 / 2025-01-01（合成制度） | 2026-10-08（v4 冻结/切换） |
| `SCOPE-01` | 校验范围外：年度日历或调休安排未核实 | scope | `rp-2026.10.gd-pilot-standard.v4` | `reg.state-council.holiday-measure.2`, `notice.state-council.holiday-2026` | 年度日历或调休安排未核实（scope 提示） | 2025-01-01 / 2026-01-01 | 2026-10-08（v4 冻结/切换） |
| `SCOPE-02` | 工时制不在本期范围（综合计算工时/不定时），未覆盖 | scope | `rp-2026.10.gd-pilot-standard.v4` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.5` | 综合计算工时/不定时工作制不在本期标准工时判定范围（未覆盖） | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `SCOPE-03` | 申报特殊工时但缺审批证据，本期按标准工时校验并提示核实资质 | scope | `rp-2026.10.gd-pilot-standard.v4` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.7` | 申报特殊工时但缺审批证据；本期按标准工时校验并提示核实资质 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `SCOPE-04` | 员工所属城市不在档位表内，只出国家层面结论 | scope | `rp-2026.10.gd-pilot-standard.v4` | `law.labor.44` | 员工所属城市不在 region_profile 档位表内；只出国家层面结论 | 1995-01-01 | 2026-10-08（v4 冻结/切换） |
| `REG-01` | 特殊工时审批覆盖核验（缺失/过期/岗位/城市） | scope | `rp-2026.11.gd-pilot-standard.v5` | `rule.mohrss.1994-503.3`, `rule.mohrss.1994-503.7` | 审批台账缺失/过期/岗位不匹配/城市不匹配（scope 提示） | 1995-01-01 | 2026-11-02（v5 冻结/切换） |
| `COMP-C01` | 综合工时周期统计（总工时与法定标准差值） | period | `rp-2026.11.gd-pilot-standard.v5` | `rule.mohrss.1994-503.5`, `rule.mohrss.1994-489.13` | 综合工时周期总工时 - 法定标准 > 0 → 需复核；≤0 → 可申辩；只统计不判违规 | 1995-01-01 | 2026-11-02（v5 冻结/切换） |
| `SHIFT-01` | 多段班次不可拼接（打卡事实不闭合） | quality | `rp-2026.11.gd-pilot-standard.v5` | `policy.sz.attendance`, `rule.mohrss.1994-503.6` | 多段班次打卡事实不闭合，不可直接拼接 | 1995-01-01 / 2025-01-01（合成制度） | 2026-11-02（v5 冻结/切换） |
| `OFF-01` | 离线补传冲突（同时点同类型多来源） | quality | `rp-2026.11.gd-pilot-standard.v5` | `policy.sz.attendance`, `law.labor-contract.4` | 离线补传冲突：同一时点/同一类型存在多来源 | 2008-01-01 / 2025-01-01（合成制度） | 2026-11-02（v5 冻结/切换） |

说明：

- 本文件是规则包定义对外版，不替代法律意见；条文原文/稳定引用见 `LAW-REFERENCES.md`。
- 金额永不进入规则结论；报酬类规则（OT-*）最高只到“需复核”。
- `COMP-C01` 只作统计，不判违规、不出倍数；周期是否被批准覆盖仍以 `REG-01` 台账核验为准。
- 具体启用/废止日期、特殊工时审批台账有效性需交付方书面确认。

### `QUAL-01` 重复批次（0.4.8 起）

- 同一员工、同一**实际发生日**的全部重复行合并为 **1 条** `QUAL-01` finding；
  `work_date = period_key =` 该日，不再出现空日期的“期间汇总”条。
- `metric.batch_id` 由来源行集合内容派生：每条来源取 `rel_path:line_no`，按 UTF-8 字节序排序、
  用 `\n` 连接后取 SHA-256；不含 DB 自增、`file_id`、`run_id`、计数器或时间戳。
- `metric.batch_size` 是该批**重复行**条数；`metric.sources` 列出该批全部重复行，不截断为
  前 3/5 条。首次出现行仍是事实表保留的那一条，**不进批次**；`quality_issues.csv` 同一批只输出
  1 行，`detail` 只列“重复行来源”（`rel_path:line_no`），**不列首次出现行**。
  首次出现行的物理位置不在 `detail` 里，而在该批次 finding 的非 canonical
  `evidence.retained_refs`（0.4.9 起，`finding.evidence`，不进 `conclusion_digest`）。
- 被拒收的无日期输入行仍由 `QUAL-02` 单独呈现；这是**有意保留**的事实缺口提示，
  不属于重复批次汇总，也不会被并入 `QUAL-01` 的批次 finding。

### 计数口径（findings_total / findings_batched / issues_total）

- `findings_total`：`findings.csv` 的数据行数（每条 conclusion 一行）。
- `findings_batched`：其中带 `batch_id` 的批次 finding 条数（每 1 条代表多条重复问题）。
- `issues_total`：把批次展开后的实际问题条数，
  `= findings_total - findings_batched + 各批 batch_size 合计`。
- `manifest.counts`、`policies/CONFIDENCE.md`、`未覆盖清单.md` 三处必须一致；
  README 的“如何正确统计重复类问题”给出示例。

### 三类日期的区别

- **法律条文生效日**：条文本身在何时生效/修订；它是法律依据的时间属性，不是本项目规则包的启用日。
- **规则包冻结日**：本项目把该规则及其阈值冻结进规则包、之后不再改动的日期。规则包是
  **不可变快照**；冻结后只允许新建下一版，不回改旧包。
- **规则包切换日**：本项目把**默认**规则包从上一版切到新版的日期（本版为 **2026-11-04**，v5 → v6）。
  切换日只影响“未显式指定规则包”的新 run；已有包按包内 `rule_pack_version` 回放。
  表中的“规则包冻结/切换日”合写两列；v6 的冻结日与切换日均为 2026-11-04。
  每次 run 按当时的规则包版本计算；`findings.csv` 的 `rule_version` 记录的是单条规则版本（v6
  run 统一为 v6）。

**为什么 2025 年事件适用 2026 年规则包**：本工具不是立法机关，也不是在 2025 年做“当时法”的
实时裁判；它是在导出/复核时，用**当时冻结的规则包快照**重算历史区间，并用单条 `rule_version`
标明该条判据的版本。它不是按事件日期回溯适用法律；它只把“用哪套阈值与条文解释”固定下来，
供后续复核/重放。若某条规则的条文生效日或现行性存疑，按 `LAW-REFERENCES.md` 的置信度降级为
“需复核”，不把规则包冻结日当成法律生效日，也不构成立法溯及既往。

### 操作性代理口径：`CAP-M01`（月延长工时上限）

- **法律依据**：`law.labor.41`（《劳动法》第四十一条）每月延长工作时间不得超过三十六小时；
  条文引用与生效日见上表。
- **操作性代理**：配置 `counting_scope=weekday_only` 时，只累加工作日超过 `daily_std_minutes`
  的延长分钟；休息日/法定节假日工作分钟分别记入 `restdays`/`holiday`，不计入 36 小时上限。
- **保守性说明**：这是**偏保守的下界**，不是“所有加班都不计”。休息日与节假日另按 OT-D02/OT-D03
  提示；若换成 `weekday_plus_rest`，月累计会更大。当前默认不把休息日计入，是因为“休息日加班是否
  计入 36 小时上限”存在裁口径差异；该选择会写进 `metric_json.counting_scope`，复核方可按同一口径复算。
- **风险**：若适用地口径要求把休息日加班计入月上限，本代理会低估超限；此时应切换 scope 并重跑，
  不能把当前 `CAP-M01` 结果当成唯一结论。

### 操作性代理口径：`CAP-W01`（连续 7 天无休息）

- **法律依据**：`law.labor.38`（《劳动法》第三十八条）用人单位应保证劳动者每周至少休息一日；
  条文引用与生效日见上表。
- **操作性代理**：在同一 ISO 周内，若 7 个日历日都存在出勤记录（`minutes_worked > 0` 或
  `punch_count > 0`），且没有任何“零工作且零打卡”的整天，则触发；不是对“连续工作 7 天”的
  实时连续时钟推断。
- **保守性说明**：该代理可能把“调休上班日”“跨周连续工作”误读为无休息；遇到调休/日历未核实
  或 `ambiguous_day_type` 时降级为 `REVIEW`，不直接判 `VIOLATION`。触发条件与 `days_present`/
  `rest_days`/`minutes_worked` 一起写入 `metric_json`，复核方按同一 ISO 周和同一出勤事实复算。
- **风险**：年度放假安排或调休未核实时，代理口径可能产生假阳性；因此该条结论必须连同
  `SCOPE-01` 的日历提示一起读，不能单独当违法定性。
