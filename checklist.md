# 0.4.13 验收清单

- [x] 阻断缺陷已实测复现：0.4.12 wheel 验算默认 `wca all` 产物得 `INPUTS FAIL`、exit 1
- [x] 验算器按包内 schema 分流：v3 缺 `inputs_digest` → FAIL（exit 1）；v2 缺字段 → NOT CHECKED / PARTIAL（exit 2）
- [x] `tests/test_round15_default_verifiable.py` 先红后绿，覆盖默认产物可判定、版本分流、退出码、三方口径
- [x] 默认流程产物可被自家验算器正确判定：无钥 v2 → `RESULT PARTIAL` exit 2；有钥 v3 + 外部项 → `RESULT OK` exit 0
- [x] `docs/签名方案.md`、`README.md`、验算器输出对“无签名包”的口径一致且与实测退出码相同
- [x] `RELEASE.json` 与 `release/README-验收.md` 写明 `SHA256SUMS` 只覆盖 5 个顶层文件，并写明 `old-wheels/`、`old-packages/` 不在保护范围
- [x] 0.4.13 发行物重出重签；`SHA256SUMS` 5/5 逐文件匹配；`.sig` 验签通过
- [x] `未随交付清单.md` 改为“源码随 wheel 提供”，并说明仓库测试/脚本不随交付
- [x] `README` 给出 wheel diff 复核命令；“0.4.11→0.4.12 仅文档与脚本变更”从“不可独立复现”移出
- [x] `OLD-WHEELS.md` 对 0.4.6 写明签名钥误用、后果、不影响 0.4.7 起，并标注“不可验证 + 原因”
- [x] 八包四联摘要与 0.4.12 逐包相同，仅 `artifacts_digest` 变化
- [x] 同版本七类篡改仍 `FAIL` exit 1，无真篡改降级为 PARTIAL
- [x] 干净 venv（仅 0.4.13 wheel）八包 verify/replay 16/16 `RESULT OK`
- [x] 离线全量与 PG 全量均通过：614 passed / 9 skipped / 1 deselected；638 passed / 2 skipped
- [x] 交付 `dist/wca-replay-0.4.13/`、`handoff/20261104-第十五轮整改/`、`reports/0.4.13-默认流程可验性.md`
- [x] `docs/冻结版本说明.md` 指向 0.4.13，并写明 0.4.12 未对外及原因
- [x] 未改动 0.4.10–0.4.12 发行物与第十二至十四轮交接；未改活动库；未 push
