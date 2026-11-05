# 0.4.13 任务清单

- [x] T1 写红测试：新建 `tests/test_round15_default_verifiable.py`（默认 v2 包应 PARTIAL、v2 缺字段 NOT CHECKED、v3 缺字段仍 FAIL、无签名退出码 2、三方文档口径）
- [x] T2 验算器版本分流：`src/package_verify.py` 按 `schema_ver` 分流；旧包 `inputs` 排除出门禁；新增 `inputs_digest_legacy`
- [x] T3 输出文案：`src/verify_pkg.py::_note` 补 `inputs`/`inputs_completeness` 旧包原因
- [x] T4 CLI 默认流程口径：`src/cli.py::cmd_export` 与 `--signing-key` 帮助文本（无钥 v2 = PARTIAL exit 2；有钥自动 v3）
- [x] T5 三方文档统一：`docs/签名方案.md`、`README.md`（退出码表 + wheel diff 小节）、`scripts/build_release.py` 模板
- [x] T6 签名文件文本修正：README 模板两处 + `RELEASE.json.release_signature.scope` 改为 5 个顶层文件，排除 `old-wheels/`、`old-packages/`
- [x] T7 版本号：`pyproject.toml`、`src/__init__.py:ENGINE_VERSION` → 0.4.13
- [x] T8 构建发行物：`dist/wca-replay-0.4.13/`（`SHA256SUMS` 5 行逐文件匹配；`.sig` key_id `5e797e18…`）
- [x] T9 重导八包并核对不变量：四联摘要与 0.4.12 逐包相同，仅 `artifacts_digest` 变
- [x] T10 篡改回归：七类仍 FAIL exit 1；v3 缺字段 FAIL、v2 缺字段 NOT CHECKED
- [x] T11 干净 venv 16/16：`D:\project\wca-clean-0413` 八包 verify/replay 全 `RESULT OK`
- [x] T12 默认流程实测：无钥 v2 → PARTIAL exit 2；有钥 v3 → PARTIAL exit 2；补外部锚点 → OK exit 0
- [x] T13 交接目录：`handoff/20261104-第十五轮整改/`（8 包、锚点、release、README、OLD-WHEELS 0.4.6 注记、未随交付清单、交付清单全目录哈希）；`check_handoff_links.py`/`check_handoff_refs.py` exit 0
- [x] T14 报告与冻结说明：`reports/0.4.13-默认流程可验性.md`、`reports/round15-techcheck.txt`；`docs/冻结版本说明.md` 指向 0.4.13 并写 0.4.12 未对外原因
- [x] T15 全量测试与提交：离线 614 passed / 9 skipped / 1 deselected；PG 638 passed / 2 skipped；提交不 push

## 不在本轮范围

- 不改 `dist/wca-replay-0.4.10/`、`0.4.11/`、`0.4.12/` 与第十二、十三、十四轮交接。
- 不改活动库；不 push。
- 不自动生成签名密钥（理由见 spec.md §2.2）。
