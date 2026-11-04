# 0.4.7 验收检查清单

## A5 包内主键泄漏

- [ ] `quality_issues.csv` 多来源仅显示 `来源: a/punch-a.csv:2, b/punch-b.csv:2`
- [ ] 包内所有 CSV 扫描通过：无 `file_id`/`related_file_ids`/`run_id`/`segment_id` 数据值
- [ ] DB `ingest_issue.detail` 仍含 `related_file_ids`（输入选择可用）
- [ ] README 不再自相矛盾，且声明由实际包扫描验证

## A4 展示层

- [ ] 复核台 `QUAL-01/QUAL-02` 来源行非空（回退 `metric_json.line_refs`）
- [ ] 首页异常表/质量问题表无 `related_file_ids`、无裸 `file_id`
- [ ] `/api/import` 响应不含 `file_id`
- [ ] 页面 HTML 与 JSON 测试断言通过
- [ ] DB `finding.source_refs` 未改

## A13 导入契约

- [ ] `../outside/data` 非零退出 + 中文错误
- [ ] `C:\...` 非零退出 + 中文错误
- [ ] `\\server\share` 非零退出 + 中文错误
- [ ] 中间 `..` 非零退出 + 中文错误
- [ ] 合法 `data/raw/a/punch.csv` 仍成功

## A7 发行钥

- [ ] 0.4.7 `RELEASE.json.release_signature.key_id` = `ed25519:5e797e18…`
- [ ] `build_release.py` 对非预期 key_id 默认拒绝
- [ ] `KEY-NOTE.txt` 记录 0.4.6 误用 `b07741b2…`、恢复、旧钥处置、配对要求
- [ ] 交接目录含 0.4.1–0.4.6 发行物 SHA-256 清单
- [ ] README 包计数为八个，`docs/安全与证据链现状.md` 已交付

## 附带缺陷

- [ ] 干净 wheel 安装后默认流程全链路成功，产出包 verify/replay OK
- [ ] `approval_ledger.csv` 规范化已在 manifest 与 README 披露
- [ ] 同 run 两次导出生成两个不同 zip，旧文件未被覆盖

## 回归与交付

- [ ] 全量 pytest 通过
- [ ] 四包四联值仍为 `b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`
- [ ] 八个包在干净 venv 中 verify/replay 均 `RESULT OK`
- [ ] 第六/七/八轮 handoff 未改动
- [ ] 代码与文档分开提交，未 push
- [ ] 报告结论先行，逐条对应 A4/A5/A13/A7，实测/推断分离
- [ ] 聚合形状仅给 A/B/C 方案，未改代码、未发新 rule pack
