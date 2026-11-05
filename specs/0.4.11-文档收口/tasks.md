# 0.4.11 文档收口 — 任务清单

- [ ] T1 写 `tests/test_round13_docs.py`（文档一致性断言），先跑红
- [ ] T2 修 `scripts/build_release.py` 模板：packages 数组 + 数量口径
- [ ] T3 修模板跨版本段落：门禁先后与两种退出码（P3-2）
- [ ] T4 模板补旧 wheel 声明（P3-3）
- [ ] T5 修 `README.md`：四主包限定、跨版本准确描述、旧 wheel 声明
- [ ] T6 修 `docs/整改回应表.md:72`：作废标注（P3-5）
- [ ] T7 版本升 0.4.11（`src/__init__.py`、`pyproject.toml`、`uv lock --offline`）
- [ ] T8 跑绿测试；离线全量
- [ ] T9 重建 `dist/wca-replay-0.4.11/`；重导八包并核对摘要不变量
- [ ] T10 新干净 venv `wca-clean-0411` 装 0.4.11 wheel，导出 clean-wheel 包
- [ ] T11 八包 `wca-verify` + `wca replay` 全 `RESULT OK`；七类篡改仍 exit 1
- [ ] T12 写 `docs/冻结版本说明.md`；适配 `var/build_handoff_0411.py` 生成第十三轮交接
- [ ] T13 写 `reports/0.4.11-文档收口.md`
- [ ] T14 PG 全量；提交；确认工作树干净、不 push
