# 0.4.13 任务清单（待确认后按序执行）

| ID | 任务 | 关键落点 | 验证 |
| --- | --- | --- | --- |
| T1 | 写红测试 | 新建 `tests/test_round15_default_verifiable.py`：默认 v2 包应 PARTIAL、v2 缺字段 NOT CHECKED、v3 缺字段仍 FAIL、无签名退出码 2、三方文档口径、SHA256SUMS 5 文件口径 | `pytest tests/test_round15_default_verifiable.py -q` 预期失败 |
| T2 | 验算器版本分流 | `src/package_verify.py`：`verify_package` 按 `schema_ver` 分流；`internal_checks` 排除旧包 `inputs`；新增 `inputs_digest_legacy` | T1 中 1/2/3/4 转绿 |
| T3 | 输出文案 | `src/verify_pkg.py::_note` 补 `inputs` 旧包原因 | 手工核实输出 |
| T4 | CLI 默认流程口径 | `src/cli.py::cmd_export` 与 `--signing-key` 帮助文本：无钥 v2 = PARTIAL exit 2；有钥自动 v3 | 干净 venv `wca all` 输出 |
| T5 | 三方文档统一 | `docs/签名方案.md`、`README.md`（含退出码表、wheel diff 小节）、`scripts/build_release.py` 模板 | T1 中 5 转绿 |
| T6 | 签名文件文本修正 | `scripts/build_release.py`：README 模板两处 + `RELEASE.json.release_signature.scope` 改为 5 个顶层文件、排除 `old-wheels/` `old-packages/` | 模板断言 + 构建后核对 |
| T7 | 版本号 | `pyproject.toml`、`src/__init__.py:ENGINE_VERSION` → 0.4.13 | `build_release.py` 版本一致性检查 |
| T8 | 构建发行物 | 干净树提交后 `uv run python scripts/build_release.py --signing-key var/release-keys/ed25519.key` | `dist/wca-replay-0.4.13/`：`SHA256SUMS` 5 行且逐文件匹配；`.sig` key_id `5e797e18…` |
| T9 | 重导八包并核对不变量 | `var/handoff_packages.py`（沿用流程，0.4.13 wheel） | 四联摘要与 0.4.12 逐包相同；仅 `artifacts_digest` 变 |
| T10 | 篡改回归 | 既有七类篡改用例 + 新增版本分流断言 | 七类仍 FAIL exit 1；v3 缺字段 FAIL、v2 缺字段 NOT CHECKED |
| T11 | 干净 venv 16/16 | 新建 `D:\project\wca-clean-0413`，仅装 0.4.13 wheel + 锁 | 八包 `wca-verify`/`wca replay` 全 `RESULT OK` |
| T12 | 默认流程实测 | 同 venv：无钥 `wca all` → `wca-verify`；设 `WCA_SIGNING_KEY_FILE` 再跑 | 记录真实结果/退出码（预期均 PARTIAL exit 2；补外部锚点后 v3 可 OK） |
| T13 | 交接目录 | `handoff/20261104-第十五轮整改/`：8 包、锚点、release、README、OLD-WHEELS（0.4.6 注记）、未随交付清单（源码随 wheel 表述）、交付清单 | `check_handoff_links.py` exit 0；`check_handoff_refs` 无错 |
| T14 | 报告与冻结说明 | `reports/0.4.13-默认流程可验性.md`；`docs/冻结版本说明.md` 指向 0.4.13 并写 0.4.12 未对外原因 | 文档断言转绿 |
| T15 | 全量测试与提交 | 离线 `pytest -m "not llm"` + PG 全量 | 全绿；提交不 push；工作树干净 |

## 不在本轮范围

- 不改 `dist/wca-replay-0.4.10/`、`0.4.11/`、`0.4.12/` 与第十二、十三、十四轮交接。
- 不改活动库；不 push。
- 不自动生成签名密钥（理由见 spec §2.2）。
