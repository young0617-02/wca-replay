# 0.4.11 文档收口（对外 PoC 冻结版）— 规格

## 1. 目标与边界

- 目标：只改**文档与生成脚本**，产出对外 PoC 冻结版 0.4.11；引擎、规则语义、摘要算法一律不动。
- 0.4.10 为历史验收基线；`dist/wca-replay-0.4.10/` 与 `handoff/20261104-第十二轮整改/` **只读**。
- 不 push、不改活动库、不改默认规则包；结束工作树干净。

## 2. 已核实事实（本轮实测）

1. 组合式 `anchor.json` 的 `packages` 实际是**数组**（0.4.10 交接为 8 个元素），
   而 `scripts/build_release.py:240` 模板仍写“对象（key → 单包记录）”。
2. 历史发行 README（0.4.1–0.4.10）均含同一句“对象”表述；它们已被 `SHA256SUMS` 与签名覆盖，
   属冻结历史件，**不回改**。修复只作用于模板与 0.4.11 新生成 README。
3. 用 0.4.10 wheel + **v6 完整单包锚点文件**验 v5 `engine-only.zip`：
   先命中 `PACKAGE SHA256 FAIL`，`RESULT FAIL` / exit 1；不会走到可比性判定。
4. 用 0.4.10 wheel + 显式 `--expect-anchor` v6 串 + 正确 v5 `evidence_digest` 验同一包：
   `ANCHOR INCOMPARABLE` → `RESULT INCOMPARABLE` / exit 3。
5. 门禁顺序（`src/package_verify.py::verify_package`）：包 SHA → evidence（外部）→ artifacts（外部）
   → 链/输入/签名 → `evaluate_external_anchor`（可比性）。
6. 旧 wheel 配对表 `handoff/.../OLD-WHEELS.md` 现列 0.4.4–0.4.9；0.4.9 起才有
   `comparability_scope`，0.4.4–0.4.8 的 `RESULT OK` 仅代表旧口径通过。
7. `README.md:125` 的“0.4.8 批次语义后 `conclusion_digest` 统一为…”易读成八包统一，
   实际是四主包（default-flow/dup/clean-wheel 各有其值）。
8. `docs/整改回应表.md:72` 的 D11 行仍写“`packages` 是对象”，属历史记录。

## 3. 变更清单（精确到文件）

| # | 文件 | 变更 | 对应项 |
|---|---|---|---|
| 1 | `scripts/build_release.py` | 模板 `packages` 改为“数组，元素为包对象”，写明数量口径（元素数=该批交付包数，本批 8 项） | P3-1 |
| 2 | `scripts/build_release.py` | 重写跨版本段落：说明外部包 SHA/evidence/artifacts 门禁先于锚点比对，完整 v6 锚点文件验 v5 包 = `PACKAGE SHA256 FAIL` exit 1；仅显式锚点串才 exit 3 | P3-2 |
| 3 | `scripts/build_release.py` | 新增旧 wheel 声明：0.4.4–0.4.8 不做 scope 判定，`RESULT OK` 仅旧口径通过；旧包配旧 wheel 清单 | P3-3 |
| 4 | `README.md` | 第 125 行加“四主包”限定 | P3-4 |
| 5 | `README.md` | 退出码表/跨版本段落补门禁先后的准确描述与旧 wheel 声明 | P3-2/3 |
| 6 | `docs/整改回应表.md:72` | 保留历史行，追加“**已作废**：以 0.4.11 模板与 0.4.11 生成 README 为准”；不删历史 | P3-5 |
| 7 | `docs/冻结版本说明.md` | 新建：0.4.11 相对 0.4.10 仅文档/脚本变更、无规则语义、摘要不变量、对外交付版本、历史保留清单 | 冻结 |
| 8 | `src/__init__.py` / `pyproject.toml` / `uv.lock` | 版本 0.4.10 → 0.4.11（`uv lock --offline`） | 冻结 |
| 9 | `var/build_handoff_0411.py`（由 0410 适配） | 第十三轮交接：修正 §八“跨版本锚点”行、`OLD-WHEELS.md` 补 0.4.10、anchor 必带 scope | P3-2/3 |
| 10 | `reports/0.4.11-文档收口.md` | 新建：结论先行，逐条 5 项，标清实测/推断 | 交付 |

## 4. 硬约束（打破即停）

- 八包 `conclusion_digest` 逐包与 0.4.10 相同：`5dc46558…`（四主包）、`0ae2cfe9…`（default-flow）、
  `924c5e01…`（dup 两包）、`a4e31ef3…`（clean-wheel）。
- `evidence_digest` = `ed3b3f1b…`（四主包）、`inputs_digest` = `aad527d1…`、
  `input_fingerprint` = `8b3b54a0…`（四主包）不变。
- 仅 `artifacts_digest` 可因包内文档版本号变化。
- 七类同版本篡改仍全部 `FAIL` exit 1，不得落 `INCOMPARABLE` 3。

## 5. 验证与交付

- 先写文档一致性测试（先红后绿）：`tests/test_round13_docs.py`。
- 离线全量 + PG 全量。
- 重建 `dist/wca-replay-0.4.11/`（含 wheel、`SHA256SUMS`、`SHA256SUMS.sig`、修正后 README）。
- 新干净 venv `D:\project\wca-clean-0411` 仅装 0.4.11 wheel，重导 clean-wheel 包，八包
  `wca-verify` + `wca replay` 全 `RESULT OK`。
- 交付 `handoff/20261104-第十三轮整改/`、`reports/0.4.11-文档收口.md`。
- 提交后确认工作树干净、不 push。

## 6. 风险与假设

- 历史 dist README 无法回改（签名覆盖）；冻结说明将明确“历史残留、非现行口径”。
- 0.4.11 包必须配 0.4.11 wheel；0.4.10 wheel 保留并在 `OLD-WHEELS.md` 补登。
