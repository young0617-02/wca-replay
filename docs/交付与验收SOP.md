# 交付与验收 SOP

> 适用：举证包交付与第三方复核。本文只写“怎么验、看到什么、漏一步会漏什么”，不声称合规已满足。

## 0. 前提与边界

- 包内 `verify.py` 只用标准库 + PyNaCl（`verify-requirements.txt` 固定 `pynacl==1.6.2`）；未装 PyNaCl 会 `SIGNATURE FAIL`（失败关闭）。
- `replay` 需要**本仓库同版本代码**或**同版本发行 wheel**（`dist/wca-replay-<版本>/`，见 §5）；`verify.py` 不需要代码，只需要 Python 与 PyNaCl。没有同版本代码/发行物时，不能只凭 `verify.py` 说“结论正确”。
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
3. 同时记包文件 SHA-256、`key_id`、交付时间、验收人。锚点不要写回包内。
4. 交付物：zip 包、公开公钥、四/五段锚点记录。私钥、原始数据库、内部路径不交付。

## 2. 验收方

```powershell
Expand-Archive <包>.zip -DestinationPath <解包目录>
Set-Location <解包目录>
python -m pip install -r verify-requirements.txt
python verify.py --public-key <固定公钥文件> --expect-anchor "<四/五段>"

Set-Location <项目根目录>
uv run python -m src.cli replay <包>.zip --public-key <固定公钥文件> --expect-anchor "<四/五段>"
```

- `verify.py` 期望：`ANCHOR CHECK OK`、`INPUTS OK`、`INPUTS DIGEST OK`、`ARTIFACT OK`、`SIGNATURE OK (pinned ...)`、`RESULT OK`。它证明字节/输入摘要/结论集哈希/签名/锚点一致；**不证明结论正确**，也不重算投影。
- `replay` 期望：`投影指纹：一致`、`= conclusion_digest`、`重放结果：一致`；裁剪包会显示 `≠ input_fingerprint`，这是预期。它证明规则字段能复算同一结论，并校验投影/签名/输入摘要。
- 五段：最后一段是 `projection_fingerprint`，必须与包内相等；四段旧调用完全不变。未裁剪包没有投影字段，传五段按失败关闭：`ANCHOR FAIL 包内无 projection_fingerprint，第五段无法校验`。
- 两段结果合并：只跑 `verify.py` 看不到结论是否可复算；只跑 `replay` 没有独立包体复核且依赖本仓库代码；两者都跑才覆盖字节层 + 字段层 + 外部锚点。

## 3. 谁保管什么 / 漏一步会漏什么

| 角色 | 必须保管 | 漏做/做错的后果 |
|---|---|---|
| 交付方 | 私钥、旧公钥、锚点记录、原始包 | 私钥丢失无法补签；锚点没留，验收方无法发现整包替换/降级 |
| 验收方 | 包外固定公钥、四/五段锚点、包 SHA-256 | 只用包内公钥 → 仅 `package self-check`，攻击者重签仍 OK |
| 双方 | 交付时间、`key_id`、验收人 | 轮换后无法说明旧包该用哪把公钥 |

- **只用四段**：裁剪包第五段不在包外记录里，无法用包外锚点独立发现投影被换；只能现场 `replay` 才知道。
- **不 pin 公钥**：攻击者用自己的密钥重签，`verify.py` 仍可能 `RESULT OK`，只打印 `package self-check (NOT source trust)`。
- **只跑 `verify.py`**：无法证明结论可由输入复算；必须再跑 `replay`。
- **只跑 `replay`**：没有独立字节层复核，且依赖项目代码；不能替代包内独立脚本。

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
| `version` | 导出代码版本（`wca-0.2.0` → `0.2.0`） | 必须等于 `RELEASE.json.version` |
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

### 5.4 仍有的前置条件（“独立”不等于“无需任何前置”）

1. **Python 3.12**（构建与实测在 3.12.8；`requires-python >=3.12`）。
2. **依赖来源**：能访问 PyPI，或准备与 `requirements.lock.txt` 同版本的本地 wheel 缓存/镜像；
   发行物不承诺空气隙离线自足。
3. **包外信任根**：你方保管的固定公钥（`--public-key`）与四/五段锚点。发行物不附带它们；
   只用包内公钥只能得到 `package self-check (NOT source trust)`。
4. **待验举证包**：真实签名包（zip 或解包目录）。发行物不自带证据包或样例 CSV。

## 6. 本轮发行物干净环境实测（2026-11-04）

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

## 7. 交接目录结构（2026-11-04 验收演练）

本轮交接目录：`handoff/20261104-验收演练/`，共 **372,067 字节**（11 个文件，含交付清单）：

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
