# 0.4.7 任务清单

## T0 取证与红灯

- [ ] T0.1 扫描现有 `dup-subdir-*` 包 CSV，记录 `related_file_ids=4,5` 与 README 矛盾行号。
- [ ] T0.2 复现复核台 `—`：确认 `finding.source_refs=[]` 但 `metric_json.line_refs` 非空。
- [ ] T0.3 复现 `../outside/data` exit 0 与 basename 压平。
- [ ] T0.4 记录 0.4.1–0.4.6 发行物 key_id：`5e797e18…`（0.4.1–0.4.5）与 `b07741b2…`（0.4.6）。
- [ ] T0.5 从 0.4.6 wheel 复现 `ModuleNotFoundError: make_synthetic`。
- [ ] T0.6 对比 `approval_ledger.csv` 原始输入与包内重导出字节。
- [ ] T0.7 新增测试并保存红灯输出：CSV 主键扫描、页面/JSON 断言、非法路径矩阵、wheel 默认流程、zip 唯一名。

## T1 A5：包内主键泄漏

- [ ] T1.1 新增统一的 detail 渲染函数：删除 `related_file_ids=…`，保留 `来源: path:line`。
- [ ] T1.2 `quality_issues.csv` 导出走渲染函数；DB `detail` 不改。
- [ ] T1.3 首页质量问题表走渲染函数。
- [ ] T1.4 包级 CSV 扫描测试：`file_id`/`related_file_ids`/`run_id`/`segment_id` 不得作为数据值。
- [ ] T1.5 修正 README 自相矛盾表述，并注明“已由测试扫描验证”。

## T2 A4：展示层去主键

- [ ] T2.1 `_decorate_review_row` 接收 file_id→rel_path 映射，输出 `rel_path:line_no`。
- [ ] T2.2 `source_refs` 为空时回退 `metric_json.line_refs`。
- [ ] T2.3 `/api/import` 删除 `file_id`。
- [ ] T2.4 测试：渲染首页/复核台 HTML 与 JSON，断言无裸主键且来源行非空。
- [ ] T2.5 确认 DB `finding.source_refs` 未改。

## T3 A13：导入期路径契约

- [ ] T3.1 `_rel_path` 对 cwd 外/绝对/UNC/含 `..` 抛中文 ValueError。
- [ ] T3.2 CLI `ingest` 捕获 ValueError，输出中文错误并返回非零。
- [ ] T3.3 测试矩阵：`../outside/data`、`C:\...`、`\\server\share`、中间 `..`。
- [ ] T3.4 回归：合法嵌套 `data/raw/*` 仍可导入。

## T4 A7：发行钥治理

- [ ] T4.1 `build_release.py` 增加 `EXPECTED_RELEASE_KEY_ID` 守卫与 `--allow-key-rotation` 理由参数。
- [ ] T4.2 0.4.7 用 `var/release-keys/ed25519.key`（`5e797e18…`）签名。
- [ ] T4.3 `KEY-NOTE.txt` 与 `docs/签名方案.md` 记录：0.4.6 误用 `b07741b2…`、恢复时间、旧钥处置、新旧 wheel/包配对。
- [ ] T4.4 交接目录附 0.4.1–0.4.6 发行物 SHA-256 清单与旧 wheel。
- [ ] T4.5 README 修正“六个包/七个包”计数与 `docs/安全与证据链现状.md` 引用；该文档补进交接目录。
- [ ] T4.6 确认手写轮换流程：持久钥 + 显式轮换，不再每次构建生成。

## T5 附带 1：wheel 默认流程

- [ ] T5.1 将 `data/generator/make_synthetic.py` 纳入 wheel（移入 `src/generator/` 或 force-include）。
- [ ] T5.2 `wca gen` 输出固定到 `cwd/data/raw`，配置仍按包内路径读取。
- [ ] T5.3 更新 `test_acceptance.py` 与文档中的生成器路径。
- [ ] T5.4 新增干净 wheel 全链路测试：`gen → ingest → check → export → verify → replay`。

## T6 附带 2：审批台账规范化披露

- [ ] T6.1 manifest `inputs` 增加 `approval_export_note`（数据库重导出、UTF-8 无 BOM、LF）。
- [ ] T6.2 包内 README 与交接 README 写明“非原始上传字节”；可得时记录原始 sha。
- [ ] T6.3 测试断言披露字段与文案存在。

## T7 附带 3：zip 唯一命名

- [ ] T7.1 zip 名改为 `run_id + 时间戳 + 短随机串`。
- [ ] T7.2 目标已存在则抛错，不覆盖；临时文件清理。
- [ ] T7.3 测试：同 run 连续导出两次得到两个不同文件，旧包保留。

## T8 回归与不变量

- [ ] T8.1 全量 pytest。
- [ ] T8.2 重建四个平铺包，核对 `b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`。
- [ ] T8.3 若有变化，逐 finding/字段归因并停止交付。

## T9 发行与交接

- [ ] T9.1 版本升到 0.4.7。
- [ ] T9.2 干净树构建 `dist/wca-replay-0.4.7/`，`5e797e18…` 签名，`SHA256SUMS` 校验通过。
- [ ] T9.3 生成八个包：原七个 + 干净 wheel 默认流程包。
- [ ] T9.4 交接目录补 `docs/签名方案.md`、`docs/安全与证据链现状.md`、报告、旧 release/包 SHA 清单、旧 wheel。
- [ ] T9.5 干净 venv 复验八个包，verify/replay `RESULT OK`。
- [ ] T9.6 第六/七/八轮 handoff 未改动。
- [ ] T9.7 代码与文档分开提交；不 push。
- [ ] T9.8 `reports/0.4.7-第九轮整改.md` 结论先行、逐条对应、实测/推断分离、四包值独立一节、聚合方案三选一。

## T10 非授权项

- [ ] T10.1 仅在报告与 spec 写方案 A/B/C；不改代码、不发新 rule pack。

# Task Dependencies

- T1/T2/T3 可并行；T5 依赖 T1/T3 的导入契约；T9 依赖 T0–T8 全部完成。
- T10 与代码任务解耦，只写文档。
