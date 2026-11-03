# 交付与验收 SOP（两页）

> 适用：举证包交付与第三方复核。本文只写“怎么验、看到什么、漏一步会漏什么”，不声称合规已满足。

## 0. 前提与边界

- 包内 `verify.py` 只用标准库 + PyNaCl（`verify-requirements.txt` 固定 `pynacl==1.6.2`）；未装 PyNaCl 会 `SIGNATURE FAIL`（失败关闭）。
- `replay` 需要**本仓库同版本代码**；`verify.py` 不需要。没有同版本代码时，必须由组织提供同版本 replay 环境，不能只凭 `verify.py` 说“结论正确”。
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
