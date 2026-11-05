# 0.4.13 规格：默认流程产物可验性修复

## 1. 已实测确认的阻断缺陷（本次不改文档去迁就）

在干净 0.4.12 venv（仅 0.4.12 wheel）中，以 `WCA_DB_BACKEND=sqlite` 执行默认命令：

```powershell
wca all
wca-verify <产物.zip>
```

实测结果（2026-11-05，记录于 `reports/0.4.13-默认流程可验性.md`）：

```text
MANIFEST SCHEMA v2
MANIFEST CHECKSUM OK
ARTIFACTS OK
FINDINGS DIGEST OK
EVIDENCE DIGEST OK
CHAIN OK
INPUTS COMPLETENESS NOT CHECKED 旧包（schema < 3）
INPUTS DIGEST FAIL
SIGNATURE NOT CHECKED（…）
RESULT FAIL —— INPUTS FAIL 缺少 manifest.inputs_digest
exit 1
```

结论：默认 `wca all` 产出 **v2 无签名包**；0.4.12 的 `wca-verify`
（`src/package_verify.py`）对 **schema < 3** 的包也把“缺 `inputs_digest`”判成
`INPUTS FAIL`。这是**用 FAIL 表达“字段因版本缺失”**，与既有
“旧包缺 `evidence_digest` → NOT CHECKED、且不得给 RESULT OK”的分档原则冲突。
同时 `docs/签名方案.md` 第 79 行仍写“v1/v2：…无签名仍通过”，与实测 exit 1 矛盾。

## 2. 修复设计（方案①：密钥可用时默认签 v3；无密钥 v2 明确只能 PARTIAL）

### 2.1 验算器版本分流（核心）

文件：`src/package_verify.py`，函数 `verify_package(...)`，约 837–854 行。

- 保留 `actual_inputs = compute_inputs_digest` 的重算与失败关闭（无法计算仍 FAIL）。
- 缺 `manifest.inputs_digest` 时按 `schema_ver` 分流：
  - `schema_ver >= 3`：`checks["inputs"]="FAIL"`，reason 不变
    `"INPUTS FAIL 缺少 manifest.inputs_digest"`，退出 1。**真篡改/新版本违约不得降级。**
  - `schema_ver < 3`：`checks["inputs"]="NOT CHECKED"`，
    `result["inputs_digest_legacy"]=True`，reason/说明明确
    “v2 契约从未包含 inputs_digest，属版本缺失，不是不一致”。
- `internal_checks` 在 `schema_ver < 3` 时排除 `"inputs"`（与已排除
  `"inputs_completeness"` 同法），否则 NOT CHECKED 会阻断 `content_ok`，仍无法得到 PARTIAL。
- `src/verify_pkg.py::_note` 为 `inputs` 增加 NOT CHECKED 原因：
  旧包 schema<3 时输出“旧包无 inputs_digest 契约；不是缺失”，避免误导为早退。
- 结果字典新增键 `inputs_digest_legacy`（默认 False）。
- 包内便利脚本 `src/evidence.py` 的 `verify.py` 片段（约 2285–2290 行）**已有**
  `schema_ver >= 3` 分流，不改；只补一致文案。

### 2.2 默认流程与退出码口径

文件：`src/cli.py`

- `cmd_export`：当 `manifest["schema"]` 为 v2（无签名钥）时，显式打印：
  `未签名（v2）：wca-verify 最多给 RESULT PARTIAL（exit 2），不能作为完整验收；
   如需完整形态请提供 --signing-key / WCA_SIGNING_KEY_FILE 导出 v3`。
- `--signing-key` 帮助文本：说明不传时读环境变量；有钥出 v3，无钥出 v2 且只能 PARTIAL。
- 方案①的实现边界：**不做自动生成密钥**。`wca all` / `wca export` 在
  `WCA_SIGNING_KEY_FILE` / `WCA_SIGNING_KEY_B64` / `--signing-key` 可用时
  已走 v3（`signing.load_signing_key(None)`）；自动生成一把无人 pin 的钥只会得到
  `package self-check`，不构成来源证明，还会重演 0.4.5 的密钥生命周期缺陷。
  因此“默认完整形态”= 部署方提供钥即自动 v3；无钥则如实降级为 PARTIAL。

### 2.3 三方文档统一（文档改，不改实测）

- `docs/签名方案.md`
  - §3 第 79 行：删除“无签名仍通过”，改为“无签名包 `RESULT OK` 不可达，
    最多 `RESULT PARTIAL`（exit 2）；仅 `--require-signature` 时才 FAIL（exit 1）”。
  - §3 第 80–81 行：写明 v2 无 `inputs_digest` → `INPUTS DIGEST NOT CHECKED`，
    v3 缺字段 → FAIL。
  - §4 “输入摘要”分档：补 v2 NOT CHECKED 一条。
- `README.md`
  - 第 277 行“未配置私钥时仍导出 v2 无签名包，行为不变”改为
    “仍导出 v2 无签名包；`wca-verify` 结果为 `RESULT PARTIAL`（exit 2），
    不能作为完整验收；配钥导出 v3（仍有外部五项门禁）”。
  - 退出码表：在 exit 2 行补“含无签名 v2 包”。
  - 新增“wheel diff 复核”小节（见 2.5）。
- `scripts/build_release.py` 生成的 `release/README-验收.md` 模板
  同步加入“无签名 v2 = PARTIAL exit 2”与“SHA256SUMS 只覆盖 5 个顶层文件”。
- 验算器输出文案与上述一致，以实测退出码为准。

### 2.4 签名文件里的错话（0.4.13 重出并重签）

文件：`scripts/build_release.py`

- `_readme` 第 198 行：改为“`SHA256SUMS` 只覆盖构建时的 **5 个顶层文件**：
  `wheel`、`requirements.lock.txt`、`README-验收.md`、`RELEASE.json`、
  `VERIFY-SIGNATURE.txt`；`old-wheels/`、`old-packages/` 及签发后追加文件
  **不在 `SHA256SUMS.sig` 保护范围内**”。
- `_readme` 第 211 行同步改写，不再写“全部发行文件”。
- `RELEASE.json.release_signature.scope`：改为
  `"SHA256SUMS 覆盖构建时 5 个顶层发行文件；old-wheels/old-packages/ 及签发后追加文件不在保护范围"`。
- `SHA256SUMS` 生成逻辑不变（仍只列顶层普通文件），因此文本与实物 5 行一致。

### 2.5 两处“过度降级”修正

- `handoff/20261104-第十五轮整改/未随交付清单.md`
  - 第 3 节改为“源码随 wheel 提供（`site-packages/src/`，可用于 diff 复核），
    仓库内 `tests/`、`scripts/`、`var/` 构建脚本不随交付”。
  - 不再声称 `src/*.py` 不随交付；仍保留逐条路径以满足引用扫描。
- README 新增“wheel diff 复核”小节：
  `python -c "import zipfile,hashlib; ..."` 对比
  `worktime_compliance_agent-0.4.11-*.whl` 与 `0.4.12-*.whl` 的文件清单与逐文件 SHA-256；
  并写明实测差异：仅版本号/`BUILD_COMMIT` 与 `policies/RULE-PACK.md`（以本轮实测为准），
  从而外部人可自证“无规则语义变更”。
  `docs/冻结版本说明.md` 把该结论从“不可独立复现”移出。

### 2.6 `OLD-WHEELS.md` 的 0.4.6 疑点

- 在 0.4.6 行下加注：
  - 该版发行物签名钥 `ed25519:b07741b2…` **是包签名钥**，属 0.4.6 误用；
  - 后果：发行物外部锚点被静默替换，客户若把该 key_id 当发行锚点会锚错；
  - 为何不影响 0.4.7 起：0.4.7 恢复发行钥 `ed25519:5e797e18…`，
    `build_release.py` 增加 `EXPECTED_RELEASE_KEY_ID` 守卫，不匹配默认拒建；
  - 目录内可核验性：**不可验证**——交付只带 wheel，不带 0.4.6 的
    `SHA256SUMS`/`SHA256SUMS.sig`/`RELEASE.json`，wheel 内也不含发行签名；
    因此不能在本目录内证明该版 `.sig` 的 key_id。清单里的 SHA-256 只证明 wheel 字节。

## 3. 硬约束（验收门禁）

1. 八包 `conclusion_digest` / `evidence_digest` / `inputs_digest` /
   `input_fingerprint` 与 0.4.12 逐包相同：
   `5dc46558…` / `0ae2cfe9…` / `924c5e01…` / `a4e31ef3…`；
   evidence `ed3b3f1b…`、inputs `aad527d1…`、fingerprint `8b3b54a0…`。
   只有 `artifacts_digest` 因包内文档变化而变。
2. 同版本七类篡改仍 `RESULT FAIL` exit 1；**不得把真篡改降级为 PARTIAL**。
   新增断言：**新版本（schema v3）缺 `inputs_digest` 仍 FAIL；旧版本（schema v2）
   缺字段才 NOT CHECKED**。
3. 不改 `dist/wca-replay-0.4.10/`、`0.4.11/`、`0.4.12/` 与第十二至十四轮交接；
   不改活动库；不 push。

## 4. 测试（先红后绿，至少 3 条）

新文件 `tests/test_round15_default_verifiable.py`：

1. `test_default_unsigned_export_is_partial_not_fail`
   - 用 `export_package(... signing_key=None)` 产 v2 包，`verify_package` 断言
     `checks["inputs"]=="NOT CHECKED"`、`partial is True`、`ok is False`、
     reason 含 `PARTIAL`。修复前：`inputs=="FAIL"`（红）。
2. `test_v2_missing_inputs_digest_not_checked`
   - 直接断言 v2 包 `result["inputs_digest_legacy"] is True`、`checks["inputs"]=="NOT CHECKED"`。
3. `test_v3_missing_inputs_digest_still_fail`
   - 构造 schema v3、无 `inputs_digest`、重算 checksum 的包，断言
     `checks["inputs"]=="FAIL"`、`ok is False`（真违约不降级）。
4. `test_unsigned_package_exit_code_is_2`
   - 通过 `src.verify_pkg.main([...])`（或 `verify_package` 的 `partial`）断言
     无签名 v2 包退出码 2，非 1。
5. `test_docs_and_verifier_agree_on_unsigned_package`
   - `docs/签名方案.md` 不含“无签名仍通过”，含“RESULT PARTIAL（exit 2）”；
     `README.md` 同口径；`scripts/build_release.py` 模板含 5 文件覆盖范围并含
     `old-wheels/`、`old-packages/` 不在保护范围。
6. `test_handoff_docs_round15`（交接生成后）：
   - `未随交付清单.md` 写明源码随 wheel 提供；
   - `OLD-WHEELS.md` 0.4.6 行含“误用/不可验证”；
   - `冻结版本说明.md` 指向 0.4.13 且写明 0.4.12 未对外及原因；
   - `check_handoff_refs` 无错、`check_handoff_links` exit 0。

## 5. 验证与交付

1. 离线全量 `pytest -m "not llm"`；PG 全量（端口 5927）。
2. 版本号 `pyproject.toml` 与 `src/__init__.py:ENGINE_VERSION` → `0.4.13`，
   提交干净后跑 `scripts/build_release.py --signing-key var/release-keys/ed25519.key`
   生成 `dist/wca-replay-0.4.13/`（文本/实物一致，5 行 `SHA256SUMS`，重签）。
3. 新干净 venv（仅 0.4.13 wheel）：
   - 八包 `wca-verify` + `wca replay` 共 16/16 `RESULT OK`；
   - 另测默认 `wca all`（无钥 → v2；设 `WCA_SIGNING_KEY_FILE` → v3）两包的
     `wca-verify` 真实输出与退出码，写入报告。
4. 生成 `handoff/20261104-第十五轮整改/`：8 包、锚点、release（含 0.4.10/0.4.11
   旧 wheel 与旧包证据）、README、OLD-WHEELS、未随交付清单、交付清单；
   `scripts/check_handoff_links.py` exit 0。
5. `reports/0.4.13-默认流程可验性.md`：实测命令、输出、退出码、前后对比。
6. 更新 `docs/冻结版本说明.md`：0.4.13 对外；0.4.12 未对外，原因=默认流程产物
   被自家验算器判 FAIL exit 1，属阻断性功能缺陷。
7. 提交，不 push。

## 6. 修复后必须能明确回答

**默认流程现在产出的包，客户用自家验算器会得到什么结果、exit 几？**

- 无签名钥 → v2 包：`RESULT PARTIAL`（exit 2）；`INPUTS DIGEST NOT CHECKED`、
  `SIGNATURE NOT CHECKED`，内容检查通过，但五项外部锚定缺失，**不能当完整验收**。
- 有签名钥 → v3 包：内容与签名自洽通过，但未传外部 pin/锚点/包 SHA/摘要 →
  `RESULT PARTIAL`（exit 2）；传齐外部锚点 → `RESULT OK`（exit 0）。
- 任何情况下都**不会**因“v2 从无 `inputs_digest`”被判 `RESULT FAIL`。
