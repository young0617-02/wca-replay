# 0.4.6 任务清单

> 用户已批准 Spec，按顺序执行；每个任务先复现/先写测试，再改实现。

## T0 取证（不改生产代码）

- [x] T0.1 按默认流程复跑 `gen → ingest → check → export`，保存失败 traceback、exit code、残留清单。
- [x] T0.2 复现 F3 绝对路径与 F4 `..`：记录 exit code、缺项数、verify/replay 结果；与审计方描述对齐。
- [x] T0.3 查密钥文件存在性/创建时间/备份/构建时间，形成 P3 证据表。
- [x] T0.4 检查 25 行重复触发的包，记录“聚合 + 逐日”两行的 rule_id/severity/period_key/evidence，形成 P4 判断。
- [x] T0.5 确认 `CONFIDENCE.md` 的 0.4.2 来源（硬编码/模板残留/生成函数）。

## T1 测试先红

- [x] T1.1 新增 `tests/test_nested_export.py`：平铺、单层、两层、空格、中文、同名不同目录、跨子目录重复行。
- [x] T1.2 同文件新增：`..`/绝对路径导入拒绝、缺源文件失败关闭、`inputs/` 子目录自愈。
- [x] T1.3 同文件新增：verify 对账 `INPUTS COMPLETENESS FAIL`（N/M 与 rel_path）。
- [x] T1.4 新增 Web/API 去 `file_id` 展示测试。
- [x] T1.5 记录红灯输出。

## T2 导出修复（P0）

- [x] T2.1 `src/package_inputs.py` 新增 `validate_input_rel_path`（放行 `inline://`）。
- [x] T2.2 `src/ingest.py` 两个导入入口调用校验，中文错误。
- [x] T2.3 `src/evidence.py` `_resolve_input_path` 增加 `data_dir/rel_path`。
- [x] T2.4 `src/evidence.py` 重建暂存目录，删除按文件 unlink 的 stale 循环。
- [x] T2.5 `src/evidence.py` 复制前 `mkdir(parents=True)`。
- [x] T2.6 `src/evidence.py` 缺项失败关闭；`export_package` 异常清理暂存目录。
- [x] T2.7 跑 T1.1–T1.3 至绿。

## T3 验算补洞

- [x] T3.1 `src/package_verify.py` 新增 `check_inputs_completeness`。
- [x] T3.2 接入 `verify_package` 门禁，先于 `inputs` 摘要检查。
- [x] T3.3 `src/verify_pkg.py` 输出新状态行。
- [x] T3.4 用手工删件包实测 `INPUTS COMPLETENESS FAIL`。

## T4 展示层（P1）

- [x] T4.1 `index.html` 异常表与质量问题表改 `rel_path`。
- [x] T4.2 `routes.py` 质量问题查询 JOIN `raw_file`。
- [x] T4.3 `_decorate_review_row` 的 `line_refs` 用 `rel_path`。
- [x] T4.4 API `source_refs` 删除 `file_id` 键（仅展示层，DB 不动）。
- [x] T4.5 跑 T1.4 至绿。

## T5 文档（P2/P3/P4）

- [x] T5.1 交接 README 修正不存在报告引用。
- [x] T5.2 README 补 Web/API `source_refs` 风险与 0.4.6 修复说明。
- [x] T5.3 `policies/CONFIDENCE.md` 版本按当前版本生成；加测试防陈旧。
- [x] T5.4 `docs/签名方案.md` + SOP 写 `conclusion_digest` 边界。
- [x] T5.5 `KEY-NOTE.txt` 与 `docs/签名方案.md` 写轮换记录与旧 wheel 指引。
- [x] T5.6 若 P3 为意外丢失，写 `docs/安全与证据链现状.md`。
- [x] T5.7 P4 判断写入报告；如需改规则语义，先报用户确认。
- [x] T5.8 `scripts/build_release.py` README 补 0.4.6 嵌套导出、`INPUTS COMPLETENESS` 与导入边界说明。

## T6 回归与四包不变量

- [x] T6.1 全量 pytest（566 passed / 9 skipped）。
- [ ] T6.2 重建四个平铺包，逐项核对
      `b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`。
- [ ] T6.3 若有变化，逐 finding/字段归因并停止交付。

## T7 发行与交接

- [x] T7.1 版本号升到 0.4.6（`src/__init__.py`、`pyproject.toml`、`uv.lock`）。
- [ ] T7.2 `scripts/build_release.py` 干净树构建 wheel/sdist。
- [ ] T7.3 生成默认流程包与双 punch 子目录包，放入交接目录。
- [ ] T7.4 交接目录补 `docs/签名方案.md`、报告、旧 wheel 说明。
- [ ] T7.5 `SHA256SUMS` + Ed25519 签名。
- [ ] T7.6 干净 venv 复验四包 + 新增两包（verify/replay）。
- [ ] T7.7 确认第六/七轮 handoff 哈希未变。
- [ ] T7.8 代码提交与文档提交分开；不 push。
- [ ] T7.9 `reports/0.4.6-嵌套路径导出与展示层.md`：结论先行、实测/推断分离、四包值未变独立一节。
