# 0.4.7 第九轮整改 Spec

## Why

第九轮审计判定 A1/A2/A3/A6/A8/A10/A11/A12 通过，**A4/A5/A13/A7 不通过**。其中 A5 是本方在 0.4.5 修跨文件重复行时新造的泄漏：`related_file_ids` 进入 `quality_issues.csv`，与 README “包内 CSV 不含 DB `file_id`”自相矛盾。A4 的复核台“来源行 `—`”是真实缺陷（有 `metric_json.line_refs` 却未取）。A13 的导入侧静默压平会让残缺包直到导出才暴露。A7 是发行物签名钥在无记录情况下从 `5e797e18…` 变为 `b07741b2…`，属于信任锚点的静默轮换。另有三项附带缺陷（wheel 缺 `make_synthetic`、审批台账规范化未披露、同名 zip 覆盖）必须同轮修复。

## What Changes

- **A5（P0）**：导出与展示统一把 `related_file_ids` 渲染为 `来源: rel_path:line_no, …`；DB `ingest_issue.detail` 与 `related_file_ids` 继续保留供输入选择；新增包级 CSV 扫描测试。
- **A4（P0）**：复核台与首页来源统一 `rel_path:line_no`；`_decorate_review_row` 无 `source_refs` 时回退 `metric_json.line_refs`；`/api/import` 删除 `file_id`。
- **A13（P0）**：导入期拒绝 `..`、绝对路径、盘符、UNC、cwd 外相对路径；中文报错、非零退出；不做静默归一化。
- **A7（P1）**：0.4.7 发行物恢复用持久发行钥 `ed25519:5e797e18…` 签名；`build_release.py` 增加 key_id 守卫；交接目录补 0.4.1–0.4.6 发行物与旧包 SHA-256 清单；`KEY-NOTE.txt`、`docs/签名方案.md` 记录 0.4.6 误用包钥事件。
- **附带 1**：`wca gen` 从 wheel 可运行；新增“干净 wheel → 默认流程全链路”测试与实物包。
- **附带 2**：披露 `approval_ledger.csv` 为数据库确定性重导出（UTF-8 无 BOM、LF），manifest 记录来源说明/原始 sha（可得时）。
- **附带 3**：导出 zip 文件名含 run id + 时间戳 + 短随机串；已存在则拒绝，不覆盖。
- **非授权项**：期间聚合形状只出方案，不改代码、不发新 rule pack。
- **BREAKING（仅对旧包验签流程）**：0.4.7 发行物签名钥回到 `5e797e18…`；0.4.6 发行物仍须用其记录的 `b07741b2…` 验签，不得混用。

## Impact

- 受影响能力：举证包导出、独立验算、Web 复核台/首页、API 导入、CLI 导入与 `gen`、发行物构建、交接 README。
- 受影响代码：`src/evidence.py`、`src/engine.py`、`src/ingest.py`、`src/anomaly.py`、`src/web/routes.py`、模板、`src/cli.py`、`scripts/build_release.py`、`pyproject.toml`、`var/*` 构建脚本、测试。
- 不影响：活动库、默认规则包语义、第六/七/八轮 handoff 目录。

## ADDED Requirements

### Requirement: 包内 CSV 不出现 DB 主键

系统 SHALL 保证举证包内全部 CSV 的数据值不含 `file_id`、`related_file_ids`、`run_id`、`segment_id`；多来源必须渲染为 `rel_path:line_no`。

#### Scenario: 双 punch 包导出
- **WHEN** 同一打卡行来自 `a/punch-a.csv` 与 `b/punch-b.csv`
- **THEN** `quality_issues.csv` 的 `detail` 只含 `来源: a/punch-a.csv:2, b/punch-b.csv:2`，不含 `related_file_ids=`

#### Scenario: 包级扫描
- **WHEN** 扫描包内所有 `.csv` 的每个单元格
- **THEN** 不出现上述四个标识作为数据值；README/政策说明文字不计入

### Requirement: 展示层来源可还原

系统 SHALL 在首页与复核台显示 `rel_path:line_no`，并在 `source_refs` 为空但 `metric_json.line_refs` 存在时回退后者。

#### Scenario: 复核台 QUAL 行
- **WHEN** 结论为 `QUAL-01/QUAL-02` 且 DB `source_refs=[]`
- **THEN** 来源行显示 `punch.csv:3898` 等非空值，不显示 `—`；页面与 JSON 均无裸主键

### Requirement: 导入期确立 rel_path 契约

系统 SHALL 在导入期拒绝任何会丢失目录信息的路径，中文报错并非零退出；SHALL NOT 静默压平成 basename。

#### Scenario: 四种非法路径
- **WHEN** 导入 `../outside/data/*.csv`、`C:\...`、`\\server\share\...` 或含中间 `..` 的路径
- **THEN** 返回非零、错误文案含“必须位于当前工作目录内/不允许 ..”，DB 不新增 `raw_file`

### Requirement: 发行签名钥受控

系统 SHALL 使用持久发行私钥签名发行物；若 key_id 与记录的发行钥不一致且未显式声明轮换理由，构建 SHALL 失败。

#### Scenario: 错误私钥
- **WHEN** 用包签名钥 `b07741b2…` 构建发行物
- **THEN** `build_release.py` 拒绝并提示使用 `var/release-keys/ed25519.key`

### Requirement: wheel 默认流程可复现

系统 SHALL 在干净 wheel 安装后，不指定数据目录跑通 `gen → ingest → check → export → verify → replay`。

#### Scenario: 干净 venv
- **WHEN** 从 `dist/wca-replay-0.4.7` 安装后执行默认流程
- **THEN** 产出包 `inputs/data/raw/*`，`wca-verify` 与 `wca replay` 均 `RESULT OK`

### Requirement: 导出包唯一命名

系统 SHALL 使用 `run_id + 时间戳 + 短随机串` 的 zip 名；同名已存在时 SHALL 拒绝而不是覆盖。

## MODIFIED Requirements

### Requirement: 输入完整性对账

`wca-verify` 的 `INPUTS COMPLETENESS` 继续作为独立门禁；0.4.7 额外覆盖“导入期已拒绝非法 `rel_path`”的回归测试。

## REMOVED Requirements

### Requirement: API 导入返回 file_id
**Reason**: 无消费方，且暴露 DB 主键。
**Migration**: 调用方改用响应中的 `rel_path` 与 `sha256`。

## 非授权项方案（只提案，不改代码）

审计方质疑“1 条期间汇总（48）+ 1 条逐日（1）”的举证形状。三个候选：

| 方案 | 字段变化 | 规则包影响 | 摘要影响 | 需重锚对象 | 测试代价 | 迁移影响 |
|---|---|---|---|---|---|---|
| A 单批 finding + 批次号 | 新增 `batch_id`/`batch_size`；一条 finding 覆盖 49 行 | 必须升 rule pack | `conclusion_digest`、`evidence_digest` 变；`inputs_digest` 不变 | 七包 + 默认流程 + 双 punch + 历史可回放包 | 改计数/摘要常量/新增批次测试 | 旧包需旧 wheel+旧包；DB 若持久化批次号需迁移 |
| B 49 条统一归日 | 逐日 finding ×49，去掉空日期汇总 | 必须升 rule pack | 同上，findings 行数 +47 | 同上 | 同上，回归面更大 | 同上 |
| C 仅展示层补批次 | 导出 CSV 增加派生 `batch_id`（不进 canonical） | 不升 | 四联值不变 | 无 | 小 | 无 |

- A/B 都会破坏“四包不变量”，不能在 0.4.7 内实施，需用户明确豁免并另开 0.4.8。
- C 可先缓解“读者误读为两个独立问题”，且不改 `conclusion_digest`。
- 建议：0.4.7 只做 C 的评估（或不改），A/B 待产品决策。

## 交付与边界

- 版本 `0.4.7`；交接目录 `handoff/20261104-第九轮整改/`；不改第六、七、八轮。
- 包数量：原七个 + 一个“干净 wheel 默认流程”包 = 八个。
- 四包不变量：`b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`。
- 测试先红后绿；不改活动库、不改默认规则包、不 push。
- 报告 `reports/0.4.7-第九轮整改.md`：结论先行，逐条 A4/A5/A13/A7，实测/推断分离。
