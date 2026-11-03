# data/raw —— 合成考勤数据（不含任何真实个人信息）

| 文件 | 内容 | 行数（seed=20260106） |
|---|---|---|
| `org.csv` | 组织主数据（示例名） | 3 |
| `employee.csv` | 员工主数据：岗位编码、工时制、是否已审批、小时工资（整数分） | 12 |
| `schedule.csv` | 排班：计划上下班时间、休息分钟 | 约 1.9k |
| `punch.csv` | 打卡：`emp_id, event_ts, punch_type, device_id` | 约 3.9k |
| `leave.csv` | 请假/补休 | 3 |
| `trip.csv` | 出差 | 2 |
| `correction.csv` | 补卡（含一条未批准） | 2 |
| `MANIFEST.json` | 每个文件的 sha256 与行数 + 种子 + 隐私声明 | — |
| `SCENARIOS.md` | 注入了哪些异常场景（评测集标准答案据此手工推导） | — |

## 复现

```bash
python -m src.cli gen --seed 20260106
python -m src.cli ingest
```

`make_synthetic.py` 用 `random.Random(seed)`，且**抖动只平移整个班次**（上下班同一偏移），
所以「实际工作分钟数」与注入值精确一致 —— 标准答案能用手算复核，不是引擎自产自验。

## 这些数据的边界（重要）

1. **全部合成**：姓名是「员工一/员工二」式化名，工资与班次是编的；与任何真实个人或企业无关。
2. **字段语义未经 HR 核对**：见 `docs/字段口径与条文依据.md` 第一节，F-001 闸门尚未通过。
   因此这份数据能证明「代码自洽 + 判据可算」，**不能**证明「与真实排班一致」。
3. **工作日安排以官方放假日历为准**：生成器直接读 `src/rules/holidays.json`，
   休息日/法定节假日当天默认不排班，只有显式场景才在那几天打卡 —— 避免「自己排班又自己判违规」。
4. 刻意保留的脏数据（非法日期、空时间戳、未知员工、未知打卡类型、完全重复行、无时区时间戳）
   是质量门禁的靶子，不是错误。

## 导入顺序

`org → employee → schedule → punch → leave → trip → correction`
（员工引用组织、打卡引用员工，顺序错了会整行拒收；`cli ingest` 已按此顺序执行。）

## v5 审批台账（不在本目录）

本目录只有 7 个事实 CSV，**不含** E006 的审批台账。活动库最新 v5 的 **115 条**结论包含一行
人工录入的 E006 台账；全新库如果只跑 `init + ingest`，会得到 **116 条**（多一条 `REG-01 / E006`）。
这不是判据差异，是输入少一行。

要让全新库也得到 115 条，导入员工主数据后执行这条最小录入命令（幂等，可重复执行）：

```powershell
python -m src.cli approval --emp E006 --doc-no "深人社函〔2025〕E006-EPOCH-01号" `
  --regime comprehensive_monthly --valid-from 2025-01-01 --valid-to 2026-12-31 `
  --job-codes warehouse_shift --region 440600 `
  --attachment-sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee `
  --recorded-at 2026-11-02T18:15:51.023185+08:00
```

该行只用于演示数据完整性；它不改变员工申报工时制，也不产出金额或违法定性。
