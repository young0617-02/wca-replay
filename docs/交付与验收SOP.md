# 交付与验收 SOP

> 适用：举证包交付与第三方复核。本文只写“怎么验、看到什么、漏一步会漏什么”，不声称合规已满足。

## 0. 前提与边界

- **信任依据是发行 wheel 的 `wca-verify`**，不是包内 `verify.py`。`wca-verify` 自己实现校验，**不执行**包内代码；包内 `verify.py` 只是便利脚本，运行在已解压目录上，不能当成独立验收。
- `wca-verify` 与 `wca replay` 都来自同版本发行物（`dist/wca-replay-<版本>/`），需要 Python 3.12、带哈希的 `requirements.lock.txt`，以及**包外固定公钥 + 四/五段锚点**。
- 包内 `verify.py` 只用标准库 + PyNaCl（`verify-requirements.txt` 固定 `pynacl==1.6.2`）；未装 PyNaCl 会 `SIGNATURE FAIL`（失败关闭）。
- **不传 `--expect-anchor` 不再给完整通过**：`wca-verify` / `wca replay` 会输出 `ANCHOR NOT CHECKED` 与 `RESULT PARTIAL`（exit 2）。这是“部分通过”，不是验收 OK；理由见 §5.3。
- 默认导出不裁剪；只有显式 `--omit-fields leave:paid` 才有裁剪包，才需要第五段投影锚点。

## 1. 交付方

```powershell
uv run python -m src.cli keygen --out var/keys/ed25519.key --public-out var/keys/ed25519.pub
uv run python -m src.cli export --run <run_id> --signing-key var/keys/ed25519.key
uv run python -m src.cli export --run <run_id> --signing-key var/keys/ed25519.key --omit-fields leave:paid
```

1. 私钥留在交付方受控目录；`key_id` 以输出为准。轮换保留旧 `.pub`，旧包用旧公钥验。
2. 从包内 manifest 取锚点，写到包外邮件/工单/台账：普通包记四段
   `schema_version,rule_pack_version,input_fingerprint,conclusion_digest`；裁剪包记五段（末尾加 `projection_fingerprint`）。
3. 同时记包文件 SHA-256、`manifest.artifacts_digest`（包根工件清单摘要）、`key_id`、交付时间、验收人。
   锚点不要写回包内；`package_sha256` 只对 zip 有效。
4. 交付物：zip 包、公开公钥、四/五段锚点记录、包文件 SHA-256 与 `artifacts_digest`。私钥、原始数据库、内部路径不交付。

## 2. 验收方（0.3.0 起）

```powershell
# 在发行物目录安装 wheel + 锁定依赖后（见 §5）
wca-verify <包>.zip --public-key <固定公钥文件> --expect-anchor "<四/五段>" `
  --expect-package-sha256 <包SHA256> --expect-artifacts-digest <artifacts_digest>
wca replay <包>.zip --public-key <固定公钥文件> --expect-anchor "<四/五段>" `
  --expect-package-sha256 <包SHA256> --expect-artifacts-digest <artifacts_digest>

# 包内 verify.py 仅作便利脚本（解包后运行；不是信任依据）
python verify.py --public-key <固定公钥文件> --expect-anchor "<四/五段>"
```

- `wca-verify` 期望：`MANIFEST CHECKSUM OK`、`ARTIFACTS OK`、`VERIFY SCRIPT OK`、`FINDINGS DIGEST OK`、`COUNTS 发现（未签认）... / 已确认结论 ...`、`CHAIN OK`、`INPUTS DIGEST OK`、`SIGNATURE OK / pinned`、`ANCHOR CHECK OK`、`RESULT OK`。它**不执行包内 `verify.py`**；包内脚本被替换会报 `VERIFY SCRIPT FAIL`。
- `wca replay` 期望：`工件逐文件：OK`、`发现摘要：一致`、三元组逐项 `=`、`发现（未签认）` 条数一致、`RESULT OK`；裁剪包会显示 `≠ input_fingerprint`，这是预期。
- **没有 `--expect-anchor`**：两个工具都输出 `ANCHOR NOT CHECKED` 与 `RESULT PARTIAL`（exit 2），不能当作验收通过；只传 `--expect-triple` 也只是 legacy 外部比对，仍不给 `RESULT OK`。
- `--expect-package-sha256` 只对 zip 有效；目录包传它按失败关闭。`--expect-artifacts-digest` 比对 manifest 的包根工件清单摘要。
- 五段：最后一段是 `projection_fingerprint`，必须与包内相等；四段旧调用不变。未裁剪包没有投影字段，传五段按失败关闭：`ANCHOR FAIL 包内无 projection_fingerprint，第五段无法校验`。
- 两段结果合并：`wca-verify` 覆盖字节层 + 工件绑定 + 发现反算摘要 + 签名 + 外部锚点；`wca replay` 再证明规则字段能复算同一结论。包内 `verify.py` 只作便利脚本，不能替代任何一段。

## 3. 谁保管什么 / 漏一步会漏什么

| 角色 | 必须保管 | 漏做/做错的后果 |
|---|---|---|
| 交付方 | 私钥、旧公钥、锚点记录、原始包 | 私钥丢失无法补签；锚点没留，验收方无法发现整包替换/降级 |
| 验收方 | 包外固定公钥、四/五段锚点、包 SHA-256、`artifacts_digest` | 只用包内公钥 → 仅 `package self-check`，攻击者重签仍 OK；漏 `artifacts_digest` 无法发现工件清单被整组替换 |
| 双方 | 交付时间、`key_id`、验收人 | 轮换后无法说明旧包该用哪把公钥 |

- **只用四段**：裁剪包第五段不在包外记录里，无法用包外锚点独立发现投影被换；只能现场 `replay` 才知道。
- **不 pin 公钥**：攻击者用自己的密钥重签，`wca-verify` 仍可能输出 `package self-check (NOT source trust)`。
- **只跑包内 `verify.py`**：它不是信任依据，也不校验工件绑定/发现反算摘要；必须用 `wca-verify`。
- **只跑 `wca-verify`**：能证明字节层、工件绑定、发现摘要、签名与锚点，但不能证明规则字段能复算结论；必须再跑 `wca replay`。
- **只跑 `wca replay`**：没有独立字节层复核与包外锚点；不能替代 `wca-verify`。

## 4. 本轮可复现演练（临时库，产物不入库）

演练目录：`var/sop/drill-20261103-a/`（`var/` 已 gitignore；未连活动库）。临时库为
`var/sop/drill-20261103-a/wca_sop_20261103.sqlite3`（SQLite，一次性演练库）；密钥/公钥/攻击者演示密钥均在该目录。
run `run-20261103T233625-3fa8b55e`；正常包 `packages/sop-normal.zip`、裁剪包 `packages/sop-trimmed.zip`。

演练五段：`3,rp-2026.11.gd-pilot-standard.v5,500c534631bc1f00de9e1870b4c93517abb021b1feddfc1e63b19657094e0034,5af329689d47b9acb5b14cbdfa39ed2069008bffee6e4a0516b959946086442e,e5aea6ea3eb40603a9d3b91a9daaa5876371c351bcab3b3a6d83404292ad2638`。

真实输出片段（同目录 `.txt`）：

```text
# verify.py 裁剪包（五段 + pin）
ANCHOR CHECK OK
INPUTS DIGEST OK 3a652589cb751328610799ca9a1ef9a7393d45a6a65535cd3e1d93c2bdb90ce4
SIGNATURE OK (pinned key_id=ed25519:123fac8e066ce294c72857d1fcb30fa2270d39f2c0549d7add01f70cda2c6cf0)
RESULT OK

# replay 裁剪包
投影指纹：一致（e5aea6ea3eb40603…）；已裁剪字段 [{'field': 'paid', 'kind': 'leave', ...}]
≠ input_fingerprint: 期望 500c534631bc1f00de9e… 实得 5727ef7b6b09ed9551ed…
= conclusion_digest: 期望 5af329689d47b9acb5b1… 实得 5af329689d47b9acb5b1…
重放结果：一致 —— 投影指纹、结论摘要与结论条数逐项一致

# 篡改 inputs/000-org.csv
INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致
RESULT FAIL

# 攻击者重签、不 pin / 原公钥 pin
SIGNATURE OK (package self-check; NOT source trust, key_id=ed25519:b7666e052c33671d6b9a4b86ec67bd60a53a18bd112bd7649f9560994f6e79a0)
RESULT OK
SIGNATURE FAIL 签名 key_id 不在外部 pin 公钥集合中
RESULT FAIL

# 正常包传五段
ANCHOR FAIL 包内无 projection_fingerprint，第五段无法校验
RESULT FAIL
```

演练中系统 Python 未装 PyNaCl 时 `verify.py` 曾输出 `SIGNATURE FAIL 未安装 PyNaCl`；换项目 `.venv` Python 后通过。安装 `verify-requirements.txt` 是验收前置步骤，不是可选项。

## 5. 验算环境与版本核对（发行物）

本节回答“同版本代码”怎么从口头约定变成可核对的事实。发行物由 `scripts/build_release.py` 生成，
目录为 `dist/wca-replay-<版本>/`，只含：

| 文件 | 作用 |
|---|---|
| `worktime_compliance_agent-<版本>-py3-none-any.whl` | 验算代码；含 `wca` / `wca-replay` / `wca-verify` 入口与 `src/schema.sql`、`config/region_profile.json` |
| `requirements.lock.txt` | `uv export --frozen --all-groups --format requirements.txt --no-emit-project` 的完整锁定清单，**逐包带 `--hash=sha256:`**；含 dev group（pytest），验算不需要它，但保留完整闭包 |
| `SHA256SUMS` | 对目录内除自身外每个文件的 SHA-256 |
| `RELEASE.json` | 版本、构建时间、`git_commit`、Python 要求、支持规则包、证据包 schema 版本 |
| `README-验收.md` | 一页安装/运行/核对说明 |

发行物不入库（`dist/` 已 gitignore）。构建脚本强制工作树干净，并把 commit 写进 wheel 内的
`src/_release_info.py`；因此 `RELEASE.json.git_commit`、wheel 内 `BUILD_COMMIT` 与包内
`manifest.producer.commit` 三者应能逐一对应。**发行物不能替代包**：它不含真实证据包、样例数据、
私钥或数据库。

### 5.1 验收方先核对发行物

```powershell
# 在发行物目录内执行
Get-Content SHA256SUMS -Encoding UTF8 | ForEach-Object {
  $hash, $name = $_ -split '\s+', 2
  $actual = (Get-FileHash $name -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $hash) { throw "SHA256 不匹配：$name" }
  "OK $name"
}
Get-Content RELEASE.json -Encoding UTF8 | ConvertFrom-Json
```

`RELEASE.json` 必查字段：`version`、`build_time`、`git_commit`、`python_requires`、
`supported_rule_pack_versions`、`evidence_schema_versions`。任一文件哈希不符，或
`git_commit` 与你方记录的发行提交不符，**拒收**，不要继续安装。

### 5.2 干净 venv（不能复用项目 `.venv`）

```powershell
py -3.12 -m venv .venv-clean
.venv-clean\Scripts\python -m pip install --require-hashes -r requirements.lock.txt
.venv-clean\Scripts\python -m pip install --no-deps <发行物>.whl
```

- `--require-hashes` 让 pip 校验锁定清单里的每个哈希；失败即依赖与清单不一致，不要加
  `--no-deps` 绕过或改用未锁定版本。
- wheel 必须用 `--no-deps` 安装，避免 pip 重新解析依赖树。
- 装完后用 `.venv-clean\Scripts\wca.exe replay <包>` 与
  `.venv-clean\Scripts\wca-verify.exe <包>`；不要从源码目录运行，避免 Python 导入本地 `src/`。

### 5.3 用包内 `producer` 判断“该用哪个版本复算”

新导出包在 `manifest.producer` 记录：

| 字段 | 含义 | 验收要求 |
|---|---|---|
| `version` | 导出代码版本（`wca-0.3.0` → `0.3.0`） | 必须等于 `RELEASE.json.version` |
| `commit` | 导出代码 git commit（完整 40 位） | 必须等于 `RELEASE.json.git_commit` |
| `python` | 导出时解释器版本 | **仅记录**；跨补丁版本复算不因它失败，但验收记录要写实际复算解释器 |
| `rule_pack_version` | 导出包使用的规则包 | 必须在 `RELEASE.json.supported_rule_pack_versions` 内 |

`replay` 已把 `version` / `commit` / `rule_pack_version` 与当前验算代码逐一核对：

- 一致：正常继续，并在人类可读输出打印“`导出代码：version=... commit=...`”；
- **不一致：`PRODUCER FAIL`，非零退出，失败关闭**。选择失败关闭而不是“警告后继续”，
  因为继续会照样算出一个“三元组一致”的 OK 结果，看起来正好像“同版本可复算”，
  而这正是要防的误读。跨版本复算属于例外流程：需双方书面标注“使用 commit X
  复算 commit Y 的包”，并保留包外锚点，**不得写成同版本可复算**。
- 包内没有 `producer`（修订前旧包）：`replay` 打印“包内未记录 producer（旧包；
  无法核对导出代码版本）”并继续，这是旧包兼容路径；验收方不能把它当成“同版本已核对”。
  v3 签名包若缺 `producer`，按“无法核对版本”处理，**应拒收或转入例外流程**，不得
  直接签发验收结论。

### 5.4 工件绑定、独立验算器与锚点

新版 manifest（v2/v3 新导出）增加三组字段：

| 字段 | 覆盖 | 失败关闭 |
|---|---|---|
| `artifact_sha256` | `findings.csv`、`input_files.csv`、`quality_issues.csv`、`conclusions_final.csv`、`responsibility.json`、`not_covered.json`、`未覆盖清单.md`、`README.txt`、`verify-requirements.txt` 的逐文件 SHA-256 | 文件缺失/哈希不符 → `ARTIFACT FAIL` |
| `artifacts_digest` | 上述映射按 UTF-8 路径字节序排序后的 canonical JSON SHA-256 | 缺失/不一致 → `ARTIFACT BINDING FAIL` |
| `verify_script_sha256` | 包内 `verify.py` 字节哈希 | 缺失/被替换 → `VERIFY SCRIPT FAIL` |

- `artifact_sha256`、`artifacts_digest`、`verify_script_sha256` 都被 `manifest_checksum` 覆盖；v3 新包的签名 payload 还直接包含 `artifacts_digest` 与 `verify_script_sha256`，因此签名覆盖它们。
- `wca-verify` **不执行包内 `verify.py`**：它只读取文件、重算哈希、重算链、重算 `inputs_digest`、验签、从 `findings.csv` 反算 `conclusion_digest`。包内 `verify.py` 被替换时，独立验算器报告 `VERIFY SCRIPT FAIL`，且不会运行替换后的脚本。
- **额外文件失败关闭**：包根与 `inputs/` 出现未在 `artifact_sha256` / `inputs/manifest.json` 声明的文件，直接 `EXTRA FILE FAIL`。没有 `--allow-extra-files` 开关；原因是额外文件可能夹带数据或指令，验收器不应替接收方猜测“哪些额外文件无害”。
- **发现 vs 已确认结论**：`findings.csv` 行数对应 manifest `counts.findings`（未签认）；`conclusions_final.csv` 行数对应 `counts.final_conclusions`（已签认）。`wca-verify` 从 `findings.csv` 按公开规范化算法反算 `conclusion_digest`，并输出 `FINDINGS DIGEST OK`；`wca replay` 也执行同一反算。
- `manifest.counts.rule_versions` 记录单条规则的版本分布（例如 v4 规则 100 条、v5 规则 16 条）。**`rule_version` 是单条规则版本，不等于 rule pack 版本**；v5 包中保留未改判据的 v4 规则是预期，不是包版本漂移。
- **锚点选择：部分通过，而非静默 OK**。`wca-verify` / `wca replay` 未传 `--expect-anchor` 时仍执行字节层检查，但输出 `ANCHOR NOT CHECKED` + `RESULT PARTIAL`（exit 2）；理由是：内部/预检仍需要看字节层结果，但对外验收必须有包外锚点，`PARTIAL` 明确阻断“没有锚点也算通过”。`--expect-triple` 只是 legacy 外部比对，不约束 schema，也不给 `RESULT OK`。
- 锚点记录可另带 `package_sha256`（zip 字节 SHA-256）与 `artifacts_digest`（包根工件清单摘要）；用 `--expect-package-sha256` / `--expect-artifacts-digest` 传入，不匹配失败关闭。目录包不能比较 `package_sha256`。

### 5.5 仍有的前置条件（“独立”不等于“无需任何前置”）

1. **Python 3.12**（构建与实测在 3.12.8；`requires-python >=3.12`）。
2. **依赖来源**：能访问 PyPI，或准备与 `requirements.lock.txt` 同版本的本地 wheel 缓存/镜像；
   发行物不承诺空气隙离线自足。
3. **包外信任根**：你方保管的固定公钥（`--public-key`）、四/五段锚点、包 SHA-256 与 `artifacts_digest`。发行物不附带它们；
   只用包内公钥只能得到 `package self-check (NOT source trust)`。
4. **待验举证包**：真实签名包（zip 或解包目录）。发行物不自带证据包或样例 CSV。

## 6. 上一轮（0.2.0）发行物干净环境实测（历史记录，2026-11-04）

> 以下是 0.2.0 的历史记录，保留作对照；0.3.0 的新实测见 §8。该 0.2.0 包缺工件绑定，不能再用
> `wca-verify` 0.3.0 当成完整验收。

发行物：`dist/wca-replay-0.2.0/`，共 **312,876 字节（305.5 KiB）**；
`RELEASE.json`：版本 `0.2.0`、构建时间 `2026-11-04T00:10:39+08:00`、
commit `f170b272f0dcff51aa88d4489526af6d202c0716`、`python_requires >=3.12`。
wheel `worktime_compliance_agent-0.2.0-py3-none-any.whl`（273,846 字节，
sha256 `57fd43450faca3c2ae88ee0958d60e999ea4821a30b777e9c1e944bcfd932b5a`）。

干净 venv 为 `var/release-clean/venv`（Python 3.12.8，未复用项目 `.venv`），只装上述
wheel 与 `requirements.lock.txt`（安装时显式 `--require-hashes`）。随后在该 venv 内用
`data/raw` 的合成 CSV 建临时 SQLite、跑 check、`keygen`、导出 v3 签名包。关键输出：

```text
# SHA256SUMS
OK README-验收.md 839d5e704083a869a75956a43bf37193cd5d04054ef4795854eafdfcd93f08bf
OK RELEASE.json 63568b8bd5d8ca98781900306839b7bc88ace74d264584d3779e52f0206de458
OK requirements.lock.txt abfe36c7f52d04fb5295beca444d53c5ac8576b64058654d767556ee303e0466
OK worktime_compliance_agent-0.2.0-py3-none-any.whl 57fd43450faca3c2ae88ee0958d60e999ea4821a30b777e9c1e944bcfd932b5a
RELEASE.json version=0.2.0 commit=f170b272f0dcff51aa88d4489526af6d202c0716 python_requires=>=3.12

# manifest.producer 与发行物
manifest.producer version=0.2.0 commit=f170b272f0dcff51aa88d4489526af6d202c0716 python=3.12.8 rule_pack=rp-2026.11.gd-pilot-standard.v5
VERSION CHECK OK：version/commit/rule_pack 与发行物一致

# wca-verify 验真实签名包（四段锚点 + pin）
MANIFEST SCHEMA v3 OK
PRODUCER 0.2.0 f170b272f0dcff51aa88d4489526af6d202c0716 python=3.12.8 rule_pack=rp-2026.11.gd-pilot-standard.v5
MANIFEST CHECKSUM OK
EPOCH OK
CHAIN OK events= 8 segment= legacy
ANCHOR CHECK OK
INPUTS OK checked= 8 packed= 8 missing_at_export= 0
INPUTS DIGEST OK 4979f14f249a6fc24236725988e593d222814c6d12cfb8ca36341c7cd3f689b5
ARTIFACT OK conclusions_final.csv
SIGNATURE OK (pinned key_id=ed25519:f574b0f5edd417721f4d5077439a33f91ba04359e6b01e45192efdaf35e815c5)
INPUTS SIGNED OK (inputs_digest bound by signature)
RESULT OK

# 同一包解包后直接 python verify.py（不经过 wca-verify 包装）也 rc=0；
# 输出与上面一致：PRODUCER ... / ANCHOR CHECK OK / INPUTS DIGEST OK /
# ARTIFACT OK / SIGNATURE OK (pinned ...) / RESULT OK

# wca replay 复算同一包
导出代码：version=0.2.0 commit=f170b272f0dcff51aa88d4489526af6d202c0716 python=3.12.8 rule_pack=rp-2026.11.gd-pilot-standard.v5
签名：有效 / pinned（来源可信） / key_id=ed25519:f574b0f5edd417721f4d5077439a33f91ba04359e6b01e45192efdaf35e815c5
= rule_pack_version: 期望 rp-2026.11.gd-pilot-… 实得 rp-2026.11.gd-pilot-…
= input_fingerprint: 期望 0e225473cf3fd6156326… 实得 0e225473cf3fd6156326…
= conclusion_digest: 期望 01bd44034d61a8ead824… 实得 01bd44034d61a8ead824…
结论条数 期望 116 / 实得 116 分级 {'DEFENSIBLE': 23, 'REVIEW': 86, 'VIOLATION': 7}
重放结果：一致 —— 三元组与结论条数逐项一致

# 伪造 producer.commit（重算 manifest_checksum）后
结论：无法重放 —— PRODUCER FAIL 包内 producer 与当前验算版本不一致：commit（包内 000…000 / 当前 f170b272f0dcff51aa88d4489526af6d202c0716）
EXPECTED FAIL：replay exit=1（PRODUCER FAIL，失败关闭）
```

该真实包：`run-20261104T001053-25ebf744`，54,872 字节，自含输入 8 个 / 301,679 字节，
锚点 `3,rp-2026.11.gd-pilot-standard.v5,0e225473cf3fd6156326063213a7fa332f64347298a170a5391104fff544287b,01bd44034d61a8ead8248a1b7845b794488b46a26424c488bb525ff0d25ac10a`。
完整日志：`var/release-clean/clean-room-output.txt`（`var/` 已 gitignore）。

## 7. 交接目录结构（2026-11-04 验收演练；0.2.0 历史）

> 本节保留上一轮 0.2.0 交接目录的实际结构；0.3.0 发行物目录结构相同，但本轮未重建 handoff。
> 0.3.0 验收请以 §8 的 `dist/wca-replay-0.3.0/` 与干净环境实测为准。

上一轮交接目录：`handoff/20261104-验收演练/`，共 **372,067 字节**（11 个文件，含交付清单）：

```text
handoff/20261104-验收演练/                                     372,067
├── READ-ME-FIRST.txt                                          1,375
├── 交付清单.txt                                                1,680
├── trusted-public-key.pub                                        46
├── anchor.txt                                                  1,051
├── anchor.json                                                   266
├── package/
│   └── run-20261104T001053-25ebf744.zip                       54,872
└── release/                                                   312,777
    ├── README-验收.md                                          4,705
    ├── RELEASE.json                                              858
    ├── requirements.lock.txt                                  33,003
    ├── SHA256SUMS                                                365
    └── worktime_compliance_agent-0.2.0-py3-none-any.whl      273,846
```

`handoff/` 已 gitignore。交付时整体复制该目录即可；**不要**把仓库源码、`docs/`、`reports/`、
测试集、数据库、演练日志、私钥或攻击者密钥带进去。

- `release/` 是 `dist/wca-replay-0.2.0/` 的副本：wheel、`RELEASE.json`、`README-验收.md`
  与 dist 字节一致。交接副本的 `requirements.lock.txt` 头部去掉了本机绝对路径（依赖版本与
  哈希未变），`release/SHA256SUMS` 已按交接副本重算，因此 `release/` 比 dist 少 99 字节。
- `release/SHA256SUMS` 只覆盖 `release/` 内除自身外的文件；`package/`、公钥与锚点不在其中。
  复核命令见 `交付清单.txt` 里的 `Get-FileHash` 片段。
- `anchor.json` 只有四段字段 `schema_version` / `rule_pack_version` / `input_fingerprint` /
  `conclusion_digest`，与 `--expect-anchor` 参数一致；锚点类型、记录时间、记录人、每段含义
  在 `anchor.txt`。
- `trusted-public-key.pub` 是裸 Base64 公钥（不是 PEM），因此用实际扩展名 `.pub`；只含公钥。
- 搬离仓库技术检查：把整个目录复制到 `%TEMP%\wca-handoff-techcheck`，在仓库外新建 venv，
  只装副本的 `release/requirements.lock.txt`（`--require-hashes`）与 wheel（`--no-deps`），
  再跑 `wca-verify`；输出 `RESULT OK`，`import src` 指向该 venv 的 `site-packages`。
  `replay` 故意未跑，留给盲跑会话。

## 8. 0.3.0 发行物与盲跑缺陷修复实测（2026-11-04）

发行物：`dist/wca-replay-0.3.0/`，共 **324,316 字节**（验收 README 按独立验算口径补正后重算）；commit
`c36547bc01ffbd1d2e7d15f17f8a4913760b9436`；构建时间 `2026-11-04T01:41:10+08:00`。
wheel `worktime_compliance_agent-0.3.0-py3-none-any.whl`（284,798 字节，
sha256 `37660716c100dd67ceb0c5c3711a29402b05cf53bc6b222105117f6aa1d8e629`）。

干净 venv 建在仓库外：`%TEMP%\wca-030-clean\venv`（Python 3.12.8），只装
`release/requirements.lock.txt`（`--require-hashes`）与 wheel（`--no-deps`）。
真实包：`run-20261104T014322-1c21ddc7.zip`（55,876 字节），锚点
`3,rp-2026.11.gd-pilot-standard.v5,9d37a312caae194cb8c8da8c36a473ec9eebf0511d2f201be24a01b0c3f0909f,01bd44034d61a8ead8248a1b7845b794488b46a26424c488bb525ff0d25ac10a`；
`artifacts_digest=618dd683ba93cfc2c39517d8f6c697cb2fbfe2d50e1f7e4cedec0e1cd2a57abe`。

```text
# wca-verify 正常包（锚点 + 包 SHA + artifacts_digest）
MANIFEST SCHEMA v3 OK
PRODUCER 0.3.0 c36547bc01ffbd1d2e7d15f17f8a4913760b9436 python=3.12.8 rule_pack=rp-2026.11.gd-pilot-standard.v5
MANIFEST CHECKSUM OK
ARTIFACTS OK checked=9
VERIFY SCRIPT OK sha256=1f3821c20582f13416cb54b264723c1a96cda4f783dad50067093e94999a5752
ARTIFACTS DIGEST OK 618dd683ba93cfc2c39517d8f6c697cb2fbfe2d50e1f7e4cedec0e1cd2a57abe
FINDINGS DIGEST OK 01bd44034d61a8ead8248a1b7845b794488b46a26424c488bb525ff0d25ac10a
COUNTS 发现（未签认） 116 条 / 已确认结论 0 条
RULE VERSIONS {"rp-2026.10.gd-pilot-standard.v4": 100, "rp-2026.11.gd-pilot-standard.v5": 16}
CHAIN OK events=8
INPUTS DIGEST OK e9d901308ad4864d005c09fa12a3041e1a49648a469d4b6bc225d59e87a11368
SIGNATURE OK / pinned（来源可信） / key_id=ed25519:8680c06aff744854a46e8e68082af7f3800fa0fc5f7e36288eafbff480966915
PACKAGE SHA256 OK 15f3c7f6e2236640ea99ccdd7642e73ff5be295a8d97c9552f27eadd4d88888e
ANCHOR CHECK OK
RESULT OK

# 同一包 wca replay
工件逐文件：OK checked=9
发现摘要：一致（findings.csv 116 行，反算 01bd44034d61a8ea…）
= rule_pack_version / = input_fingerprint / = conclusion_digest
发现（未签认） 期望 116 / 实得 116 分级 {'DEFENSIBLE': 23, 'REVIEW': 86, 'VIOLATION': 7}
已确认结论（包内）期望 0 / 实际 0 条（replay 不重建人工确认，只核对包内结论集行数）
RESULT OK
```

七种坏包在**同一个 0.3.0 干净 venv**里逐一失败（不是源码测试的转述）：

| 坏包 | 输出（实测） |
|---|---|
| A 改 findings 一条严重级别 | `ARTIFACT FAIL 工件哈希不一致：findings.csv` |
| B 改 inputs 时间戳 | `INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致` |
| C 往 conclusions_final 塞一条 | `ARTIFACT FAIL 工件哈希不一致：conclusions_final.csv` |
| D 替换包内 verify.py | `VERIFY SCRIPT FAIL verify.py 哈希与 manifest 不一致`；替换脚本未被执行 |
| E 删除 findings.csv | `ARTIFACT FAIL 工件缺失：findings.csv` |
| F 加额外文件 | `EXTRA FILE FAIL 未声明的包内文件：extra.txt` |
| G 改未覆盖清单.md | `ARTIFACT FAIL 工件哈希不一致：未覆盖清单.md` |

另：同一包不传 `--expect-anchor` 时 `wca-verify` 输出 `ANCHOR NOT CHECKED` + `RESULT PARTIAL`
（exit 2），不再给完整通过。

**P1-2 指纹断代**：这次干净环境包的 `input_fingerprint` 从 0.2.0 的 `0e225473…` 变为
`9d37a312…`，原因 `input_files.csv` / `input_fingerprint` 的 `row_count` 从表头列数改为实际数据行数；
`conclusion_digest` 仍为 `01bd4403…`（判据与输入事实未变）。旧包不回改，旧 `row_count` 口径保留在历史包里。

**P2 对账**：`counts.rule_versions` 显示 100 条 v4 规则 + 16 条 v5 规则；`rule_version` 是单条规则版本，
不是 rule pack 版本，v5 包里保留未改判据的 v4 规则是预期。`未覆盖清单.md` 已去掉历史“101 条结论”
口径，改为按本轮实际 `发现（未签认）116 / 已确认结论 0` 生成。

## 9. 复测与整改闭环（AUD-2026-11-04-001）

本轮复测交接包：`handoff/20261104-验收复测/`。它是 0.3.0 的**新批次**，不覆盖上一批
`handoff/20261104-验收演练/`；旧包保留作对照基线。逐条整改状态见 `docs/整改回应表.md`，
**不要在没有证据的情况下把任何一条标成“已闭合”**。

复测方按同一套 A–H 用例执行，`wca-verify` 与 `wca replay` **都要跑**：

| 用例 | 改动 | 期望（0.3.0） |
|---|---|---|
| A | `findings.csv` 改一条 severity | `wca-verify`/`wca replay` 均 FAIL，报 `ARTIFACT FAIL` 或 `FINDINGS DIGEST FAIL` |
| B | `inputs/` 改一个时间戳 | 均 FAIL，报 `INPUTS FAIL` |
| C | `conclusions_final.csv` 追加伪造结论 | 均 FAIL，报 `ARTIFACT FAIL`（结论集哈希/工件哈希） |
| D | 包内 `verify.py` 替换为假桩 | 均 FAIL，报 `VERIFY SCRIPT FAIL`；假桩**不得被执行** |
| E | 删除 `findings.csv` | 均 FAIL，报 `ARTIFACT FAIL 工件缺失` |
| F | 增加未声明文件 | 均 FAIL，报 `EXTRA FILE FAIL` |
| G | 篡改 `未覆盖清单.md` | 均 FAIL，报 `ARTIFACT FAIL` |
| H | 只改 `findings.csv` 的 `source_line_no` | 均 FAIL，报 `ARTIFACT FAIL`（该列不在 `conclusion_digest` 内，由文件级 SHA-256 保护） |

复测命令（从交接包 `release/` 安装 wheel 与锁后）：

```powershell
wca-verify package/<包>.zip --public-key trusted-public-key.pub `
  --expect-anchor "<anchor.json 的四段>" `
  --expect-package-sha256 <anchor.json.package_sha256> `
  --expect-artifacts-digest <anchor.json.artifacts_digest>
wca replay package/<包>.zip --public-key trusted-public-key.pub `
  --expect-anchor "<anchor.json 的四段>" `
  --expect-package-sha256 <anchor.json.package_sha256> `
  --expect-artifacts-digest <anchor.json.artifacts_digest>
```

- 期望正常包：`ARTIFACTS OK checked=9`、`VERIFY SCRIPT OK`、`FINDINGS DIGEST OK`、
  `COUNTS 发现（未签认）116 / 已确认结论 0`、`SIGNATURE OK / pinned`、`PACKAGE SHA256 OK`、
  `ANCHOR CHECK OK`、`RESULT OK`。
- 不传 `--expect-anchor`：`ANCHOR NOT CHECKED` + `RESULT PARTIAL`（exit 2），不是完整验收。
- `KEY-NOTE.txt` 已写明：`trusted-public-key.pub` 与包内 `manifest.signature.public_key_b64`
  是同一把钥匙的两份副本，仅供技术验证，**不构成来源可信**；正式交付应由双方通过独立渠道交换指纹。
- **P0-3 独立信任根属于交付流程，不在软件验收范围内**。软件通过只说明工件绑定/复算/验签链路
  在本发行物上成立，不能说明公钥属于某个已核验的交付主体，也不能替代第三方签名、时间戳或指纹交换。
- 复测方仍需自行构造 A–H 坏包并留存命令/输出/退出码；本交接包按要求不放源码、docs、reports、
  测试、数据库、私钥或旧版发行物。
