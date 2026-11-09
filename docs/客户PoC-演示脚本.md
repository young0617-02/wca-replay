# 客户 PoC 演示脚本（0.4.17 · 15–25 分钟）

> 用途：销售/售前照着念、照着敲。全程在一台客户能看见的 Windows 机器上操作，不播放 PPT。
> 依据：`handoff/20261104-第十九轮整改/` 内的 `README-验收.md`、`READ-ME-FIRST.txt`、`KEY-NOTE.txt`、
> `已知残留与未闭合项.md`，以及仓库 `docs/口径声明.md`（演示机若无仓库，需随包外附件提供）、`docs/安全与证据链现状.md`。
> 版本：0.4.17 冻结版，8 个样例包。**本脚本不新增任何流程，只把已交付的能力演出来。**

**先说一句必须随每份材料带走的边界：**

> 本交付是 **验证工具 + 8 个样例包**的 PoC，**不构成合规结论**，**不可作为生产就绪依据**。
> 四项未闭合：**信任根**、**真实具名确认**、**法律文本充分性**、**数据合规**。

---

## 0. 开场前检查清单（需提前准备，不占演示时间）

**以下每一项都标「需提前准备」：不能在客户机器上临时变出来。**

| 要准备什么 | 具体要求 | 没准备好会怎样 |
| --- | --- | --- |
| 交接目录 | 把 `20261104-第十九轮整改/` 整个拷到客户机器，例如 `C:\wca-demo\20261104-第十九轮整改` | 包、锚点、公钥、wheel 都找不到 |
| Python 3.12 | `py -3.12 --version` 能打印 `Python 3.12.x` | 建不了干净环境 |
| 依赖安装条件 | 能访问 PyPI，或提前准备与 `release\requirements.lock.txt` 同版本的本地 wheel 缓存 | 装不上 `pynacl` 等依赖，验签跑不了 |
| 磁盘与临时目录 | `%TEMP%` 可写；预留几百 MB | 解压/回放失败 |
| 演示包 | 至少 `package\engine-only.zip`、`anchor-0.4.17-engine-only.json`、`trusted-public-key.pub` | 第一段就演不下去 |
| 旧包对照 | `release\old-packages\engine-only-0.4.16.zip` 与 `anchor-0.4.16-engine-only.json` | 第五段演不了 |

**上台前 3 分钟自检（也需提前做）：**

```powershell
Set-Location 'C:\wca-demo\20261104-第十九轮整改'

# 1) 包没坏：哈希应与 anchor-0.4.17-engine-only.json 里的 package_sha256 一致
(Get-FileHash package\engine-only.zip -Algorithm SHA256).Hash.ToLower()

# 2) 交接目录齐：下面四个都应存在
'trusted-public-key.pub','anchor-0.4.17-engine-only.json',
'release\worktime_compliance_agent-0.4.17-py3-none-any.whl',
'package\engine-only.zip' | ForEach-Object { "$_ = $(Test-Path $_)" }
```

**三条演示红线（先记在心里）：**

1. **不要**拿现场 `wca all` 默认生成的包演示“删输入被拦截”。默认无签名钥时生成的是 **v2 无签名包**，没有输入契约，删输入只会得到 `RESULT PARTIAL`（exit 2），会给人“删了也没事”的错觉。**要用 `package\` 下的 v3 样例包。**
2. **不要**把 `RESULT PARTIAL` 说成通过。PARTIAL 是“不完整、不能当验收”。
3. **不要**把旧包的 `PRODUCER FAIL` 说成“包被篡改”。那是版本配对问题，不是篡改，也不是验签失败。

---

## 1. 开场：一句话说清是什么、不是什么（2 分钟）

**演什么**：不敲命令，先把交接目录打开给客户看：`package\` 里 8 个 zip、根目录的锚点 JSON、公钥文件、`release\` 里的 wheel。

**说哪句话（可直接念）**：

> 这是一个给工时结论做“可复核举证”的工具。它把规则算出来的结论、用到的原始输入、责任登记和条文出处，封成一个包；**您不需要相信我们，您可以自己重算、自己验签、自己改坏了看它报错**。
>
> 它**不做全栈考勤**：不接打卡机、不做排班、不做薪酬；**不给法律定性**：不说“你违法了”或“你合法”；也**不替代律师**：包里的条文是精简版，法律判断要您的法务来做。

**客户看到什么**：一个普通文件夹，不是云后台；没有登录、没有联网要求；8 个样例包和配套公钥文件。

**这段证明什么**：先把预期钉死——今天演的是“**证据能不能被外人复核**”，不是“我们功能多全”。

---

## 2. 现场验算：客户自己跑出 `RESULT OK`（6 分钟）

**演什么**：当着客户的面建一个干净环境，只装交付的 wheel 和锁定依赖，然后对 `engine-only.zip` 跑 `wca-verify` 和 `wca replay`。**把键盘交给客户，让他自己敲下面两条命令，您只在旁边指路。**

### 2.1 建干净环境（需提前准备：联网或本地 wheel 缓存）

```powershell
Set-Location 'C:\wca-demo\20261104-第十九轮整改'

py -3.12 -m venv .venv-clean
.venv-clean\Scripts\python -m pip install --require-hashes -r release\requirements.lock.txt
.venv-clean\Scripts\python -m pip install --no-deps release\worktime_compliance_agent-0.4.17-py3-none-any.whl
```

**说哪句话**：

> 这个环境里没有我们的源码仓库，没有数据库，也没有私钥；只有客户拿到的 wheel、锁定依赖、包和公钥。验算用的就是您手上这些东西。

### 2.2 验包（字节层）

```powershell
.venv-clean\Scripts\wca-verify.exe package\engine-only.zip `
  --anchor-file anchor-0.4.17-engine-only.json `
  --public-key trusted-public-key.pub
```

**客户看到什么（关键行）**：

```text
MANIFEST SCHEMA v3
PRODUCER 0.4.17 d4e5366b97637b2b4683339ce3ad5404469d8659 ...
MANIFEST CHECKSUM OK
ARTIFACTS OK checked=14
FINDINGS DIGEST OK 5dc46558...
EVIDENCE DIGEST OK ed3b3f1b... / external=OK
CHAIN OK events=8
INPUTS COMPLETENESS OK ... 输入清单 8 个与包内 inputs/ 一致
INPUTS DIGEST OK aad527d1...
SIGNATURE OK / pinned (key matches supplied pin; independent key_id verification not done)
ANCHOR CHECK OK
RESULT OK
```

退出码 `0`。

**说哪句话**：

> `RESULT OK` 说明：包内清单没被改、14 个工件逐个哈希对得上、115 条发现能反算出同一个结论摘要、审计链完整、8 个输入文件与清单一致、签名与您手上这把公钥匹配、包外锚点也对得上。
>
> 注意最后一行括号：**pin 只证明“包与这把公钥匹配”，还没证明这把公钥属于我们**。这一句很重要，后面边界四问会回来讲。

### 2.3 回放（字段层）

```powershell
.venv-clean\Scripts\wca.exe replay package\engine-only.zip `
  --anchor-file anchor-0.4.17-engine-only.json `
  --public-key trusted-public-key.pub
```

**客户看到什么（关键行）**：

```text
输入摘要：与 manifest/签名一致（aad527d1...）
= rule_pack_version: 期望 ... 实得 ...
= input_fingerprint: 期望 8b3b54a0... 实得 8b3b54a0...
= conclusion_digest: 期望 5dc46558... 实得 5dc46558...
发现（未签认） 期望 115 / 实得 115
重放结果：一致 —— 三元组、证据定位摘要与发现（未签认）条数逐项一致
RESULT OK
```

**说哪句话**：

> 刚才验的是“包没被改”；现在这一步是“**拿包里的输入，重新跑一遍引擎，看能不能算出同一个结论**”。三段都对上：规则包版本、输入指纹、结论摘要。
>
> 换句话说：**结论不是我们写进包里的，是这批输入加这个规则版本算出来的**。您换台机器、换个人跑，结果还是这三个值。

**这段证明什么**：

- `wca-verify` 证明**包内自洽 + 签名 + 包外锚点**；
- `wca replay` 证明**结论可复算**，不只是“文件没坏”；
- 两者都跑完，才叫一次完整验收。

---

## 3. 现场篡改：让命令自己变 `RESULT FAIL`（5 分钟）

**演什么**：复制一个包到临时目录，解开，**让客户自己选改一个规则编号（`findings.csv` 里会有 3 行被替换）、或删一个输入文件**，再跑同一条验算命令。

> 操作提示：这一段故意不传外部包 SHA。因为只要 zip 字节变了，包 SHA 会**最先**报错；那样客户只看到“包哈希不对”，看不到里面哪一项被改。用目录形态 + 其余四项门禁，能看清内部检查具体点名的文件。

### 3.1 改一个规则编号（会动 3 行）

```powershell
$demo = "$env:TEMP\wca-demo"
New-Item -ItemType Directory -Force $demo | Out-Null

Copy-Item package\engine-only.zip "$demo\engine-only-conclusion.zip" -Force
Expand-Archive "$demo\engine-only-conclusion.zip" "$demo\engine-only-conclusion" -Force

# 把 findings.csv 里的规则编号 QUAL-02 全部改成 QUAL-03（实测替换 3 处：第 2、3、11 行；包内哈希就对不上了）
$p = "$demo\engine-only-conclusion\findings.csv"
(Get-Content $p -Raw -Encoding UTF8).Replace('QUAL-02','QUAL-03') |
  Set-Content $p -Encoding UTF8 -NoNewline

# 从锚点文件读出包外期望值，避免手抄长哈希
$A = Get-Content anchor-0.4.17-engine-only.json -Raw -Encoding UTF8 | ConvertFrom-Json
$anchor = $A.anchor
$art = $A.artifacts_digest
$ev = $A.evidence_digest

.venv-clean\Scripts\wca-verify.exe "$demo\engine-only-conclusion" `
  --expect-anchor $anchor `
  --expect-artifacts-digest $art `
  --expect-evidence-digest $ev `
  --public-key trusted-public-key.pub
```

**客户看到什么（关键行）**：

```text
ARTIFACTS FAIL checked=3（工件哈希不一致：findings.csv）
...
RESULT FAIL —— ARTIFACT FAIL 工件哈希不一致：findings.csv
```

退出码 `1`。

**说哪句话**：

> 我把 `findings.csv` 里的 `QUAL-02` 规则编号改成了 `QUAL-03`（这条命令会替换全部 3 处，分别在第 2、3、11 行），命令自己就变红了，而且**点名是哪张表**。它没有执行包里的脚本，也没有联网问我们；它比的是包里登记的哈希。

### 3.2 删一个输入文件（更直观，建议现场演这个）

> 若跳过 3.1，请先执行 3.1 里定义 `$demo`、`$A`、`$anchor`、`$art`、`$ev` 的那几行。

```powershell
Copy-Item package\engine-only.zip "$demo\engine-only-deleted.zip" -Force
Expand-Archive "$demo\engine-only-deleted.zip" "$demo\engine-only-deleted" -Force
Remove-Item "$demo\engine-only-deleted\inputs\leave.csv"

.venv-clean\Scripts\wca-verify.exe "$demo\engine-only-deleted" `
  --expect-anchor $anchor `
  --expect-artifacts-digest $art `
  --expect-evidence-digest $ev `
  --public-key trusted-public-key.pub
```

**客户看到什么（关键行）**：

```text
ARTIFACTS OK checked=14
FINDINGS DIGEST OK ...
CHAIN OK events=8
INPUTS COMPLETENESS FAIL 输入清单列了 8 个，包内 inputs 缺少 1 个：leave.csv
...
RESULT FAIL —— INPUTS COMPLETENESS FAIL ... 缺少 inputs/leave.csv
```

退出码 `1`。

**说哪句话**：

> 注意，前面十几项都还是绿的：工件没坏、结论摘要没坏、审计链也完整；**只有“输入完整性”这一项红了，而且直接告诉您缺的是 `leave.csv`**。
>
> 这就是我们要的效果：**不是一句“验不过”，而是能指出哪一项不对、缺了哪个文件**。它在 `INPUTS COMPLETENESS` 这一项就直接停下（早退）；后面的 `INPUTS DIGEST` 显示 `NOT CHECKED`，表示**没有走到**，不是“通过”，也不是“报不一致”。

**这段证明什么**：

- 篡改会得到 `RESULT FAIL`（exit 1），不是 `PARTIAL`；
- 失败信息能定位到具体文件；
- 验算器**不执行包内 `verify.py`**，改包内脚本不会反过来控制验算器。

**如果客户问“那我把包重新打包、重新算哈希呢？”** 照这句答：

> 包内哈希能重算，但包外锚点、包 SHA、签名摘要我们手上也有一份；只改包、不改包外记录，仍然会红。真要连包外记录一起换，靠的就是签名 pin 和独立渠道保存的锚点——这属于“信任根”，后面会讲清楚它还没闭合。

---

## 4. 五个门禁：少给一项就是 `PARTIAL`，不是 `OK`（3 分钟）

**演什么**：把刚才那条完整命令的 `--public-key` 拿掉，其他都不动。

```powershell
.venv-clean\Scripts\wca-verify.exe package\engine-only.zip `
  --anchor-file anchor-0.4.17-engine-only.json
```

**客户看到什么（关键行）**：

```text
SIGNATURE OK / package self-check (NOT source trust)
SIGNATURE PINNED NOT CHECKED（未提供外部公钥或 pin 未命中）
...
RESULT PARTIAL —— RESULT PARTIAL：内容检查通过，但缺少/未通过 外部公钥 pin
```

退出码 `2`。

**说哪句话**：

> 包本身还是好的，内容检查全过；但**少了一项外部参数，结果就从 OK 掉到 PARTIAL**。PARTIAL 的意思是“不完整”，**不能当验收通过**。

**五个门禁一张表（客户问就照这个讲）**：

| 门禁 | 客户要提供什么 | 少给会怎样 |
| --- | --- | --- |
| 1. 签名 pin | `--public-key trusted-public-key.pub` | `package self-check`，不算来源核验，`PARTIAL` |
| 2. 外部锚点 | 四段锚点：`schema,rule_pack,输入指纹,结论摘要` | `ANCHOR NOT CHECKED`，`PARTIAL` |
| 3. 外部包 SHA-256 | zip 文件的 SHA-256 | 包级替换发现不了，`PARTIAL` |
| 4. 外部 `artifacts_digest` | 工件清单摘要 | 工件被改发现不了，`PARTIAL` |
| 5. 外部 `evidence_digest` | 证据定位摘要 | 证据块被改发现不了，`PARTIAL` |

> `--anchor-file` 是把第 2–5 项一次给齐；`--public-key` 是第 1 项。**五项全给，才可能出 `RESULT OK`；缺一项就是 `PARTIAL`（exit 2）；给了但对不上，才是 `RESULT FAIL`（exit 1）。**

**这段证明什么**：门禁不是“跑通就行”，而是“**外部证据齐全才算验收**”。这一条能直接挡住“只拿包、不拿锚点”的走过场验收。

> 正式验收建议再加 `--require-signature`。本段为了跟交接 README 的三步命令保持一致没有加；加与不加不影响这里的 PARTIAL 结论。

---

## 5. 旧包对比：`PRODUCER FAIL` 不是篡改，是版本配对（3 分钟）

**演什么**：用同一套 0.4.17 环境，去验一个 0.4.16 的旧包。

```powershell
.venv-clean\Scripts\wca-verify.exe release\old-packages\engine-only-0.4.16.zip `
  --anchor-file anchor-0.4.16-engine-only.json `
  --public-key trusted-public-key.pub
```

**客户看到什么（关键行）**：

```text
PRODUCER 0.4.16 b51bb48e... python=3.12.8 rule_pack=rp-2026.11.gd-pilot-standard.v5
MANIFEST CHECKSUM OK
ARTIFACTS NOT CHECKED checked=0（早退，尚未走到该检查）
...
SIGNATURE NOT CHECKED（早退，尚未走到验签）
RESULT FAIL —— PRODUCER FAIL 包内 producer 与当前验算版本不一致：version,commit
（包内 b51bb48e... / 当前 d4e5366b...）
```

退出码 `1`。

**说哪句话**：

> 这不是说旧包被篡改，也不是验签失败。它是在第一道“版本核对”就停了：**包内写的导出代码是 0.4.16，您手上这把验算器是 0.4.17**。
>
> 规则是：`producer.version` 必须等于您装的 wheel 版本，`producer.commit` 必须等于那个版本 `RELEASE.json` 里记录的 commit。对不上就先 `PRODUCER FAIL`，后面的签名、工件检查都还没走到，所以显示 `NOT CHECKED`，不是“验不过”。

**版本配对口诀（可直接念）**：

> **什么版本的包，配什么版本的 wheel。** 旧包在 `release\old-packages\`，旧 wheel 在 `release\old-wheels\`，对应关系看 `OLD-WHEELS.md`，不要按“v5 配某一版”去猜。
>
> 这是有意设计的失败关闭：不让新版验算器悄悄用新规则去解释旧包，否则“同版本可复算”这句话就不成立了。

**这段证明什么**：版本配对是硬规则；`PRODUCER FAIL` 与“篡改”是两件事，不能混着说。

---

## 6. 边界四问：四句实话，指向同一页（4 分钟）

**演什么**：不敲命令，主动把这四个问题说出来。**不要等客户问，先讲**。

**客户看到什么**：`README-验收.md` 首页的 PoC 边界段，四项未闭合逐条列着，不是口头承诺。

**说哪句话（每问一句，照念）**：

| 客户会问 | 您照这句答 | 指向 |
| --- | --- | --- |
| **信任根：我凭什么相信这把公钥是你们的？** | 现在只能证明“包与您手上这把公钥匹配”，不能证明这把钥属于我们；要防“公钥和包一起被换”，得靠合同附件、官网指纹或企业 PKI 等独立渠道分发指纹，**这一步本轮还没闭合**。 | `docs/安全与证据链现状.md` 第 3 节第 1 项 |
| **具名确认：`confirmed_by` 是谁？出了事谁负责？** | 样例包里是**演示身份**，审计链只能证明“某个身份确认过哪条结论”，不能证明它对应真实自然人；要接您方的目录服务、实名认证和授权矩阵，**这一步本轮还没闭合**。 | `docs/安全与证据链现状.md` 第 3 节第 1 项、第 4 节 |
| **法律文本：条文是最新、最全的吗？** | 包内 `policies/` 是**对外精简版**条文与口径，不是全文法条库，也**不构成法律意见**；条文范围、版本和解释口径要贵司法务确认，**这一步本轮还没闭合**。 | `docs/安全与证据链现状.md` 第 3 节速查表；包内 `policies/口径声明-对外版.md` |
| **数据合规：真实员工数据怎么脱敏、留存、删除？** | 交付只用**合成数据**，不含真实个人信息；真实接入所需的字段裁剪、假名化、字段级加密、留存删除策略和个保评估都还没做，需要双方一起定并签数据处理协议，**这一步本轮还没闭合**。 | `docs/安全与证据链现状.md` 第 3 节第 2 项 |

**收口一句**：

> 这四项不是代码能补的，是流程和法律要补的。所以我们把边界写在交付首页，而不是等验收时才说。

**这段证明什么**：主动交底，避免“演示很顺、一问就崩”。客户对 PoC 的信任来自**边界说得清**，不是来自“什么都能”。

---

## 7. 收尾：把话留在桌面上（1 分钟）

**演什么**：合上电脑，把四份材料推到客户面前，指着首页的 PoC 边界段。

**客户看到什么**：一张能带走的“边界 + 复现材料”清单，而不是一句“回去等方案”。

**说哪句话**：

> 今天您看到的是一条完整链：**包、公钥、锚点、wheel 都在您手里；您自己验、自己跑、自己改坏了看它报错**。
>
> 但它仍是 PoC：不构成合规结论，不能当生产就绪依据。四项未闭合我们都写在这份材料里，建议随会议纪要一起发。

**这段证明什么**：把“可复核”落到客户手里，同时把边界说在桌面上；演示结束不等于验收结束。

**递给客户的四份材料**：

1. `README-验收.md`（交接目录首页）
2. `已知残留与未闭合项.md`
3. `docs/安全与证据链现状.md` 第 3 节
4. `docs/口径声明.md`（所有数字的口径与“未测”清单；**仓库侧文档，交接目录内没有等价全量文件，需随包外附件提供**。包内 `policies/口径声明-对外版.md` 只是对外精简版，不含全部数字口径与未测清单）

---

## 8. 客户可能问的十个问题与诚实答法

> 每题不超过三句。**不要把未闭合项说成已解决。**

**1. 这套东西能替代我们的考勤或排班系统吗？**
不能。它不做全栈考勤、不接硬件、不排班，只做“给定数据之后的规则计算与举证”。考勤数据仍由你们现有系统提供。

**2. 结论能直接拿去仲裁或法院吗？**
不能直接当法律结论。它是可复核材料，是否采信、能否作为证据，由仲裁/法院和你们法务判断；我们不替代律师。

**3. 你们通过合规审查或等保了吗？**
没有。这是 PoC 验证工具，不是通过合规审查的产品；19 轮是技术验收，不等于合规认证。

**4. 我凭什么相信这把公钥是你们的？**
现在只能证明“包与您手上这把公钥匹配”，不能证明这把钥属于我们。信任根要靠合同附件、官网指纹或企业 PKI 等独立渠道分发；这一步本轮未闭合。

**5. `confirmed_by` 是谁？出了事谁负责？**
样例里是演示身份，审计链只能证明“某个身份确认过哪条结论”，不能证明它对应真实自然人。接你们的实名目录与授权矩阵还没做。

**6. 包里的法条是最新、最全的吗？**
不是全文法条库，是对外精简版条文与口径。条文范围、版本和解释口径要你们法务确认，我们不提供法律意见。

**7. 真实员工数据怎么脱敏、留存、删除？**
交付只用合成数据；真实接入所需的字段裁剪、假名化、字段级加密、留存删除策略和个保评估都还没做。需要和你们一起定，并签数据处理协议。

**8. 为什么少给一项外部参数就只是 `PARTIAL`，不是 `OK`？**
因为 `OK` 的定义是“内容检查 + 五项外部证据全通过”，少一项就说明这次验收不完整。`PARTIAL` 不是失败，但也**不能当通过**；只有给了但对不上，才是 `FAIL`。

**9. 旧包验不过，是不是你们的包有问题？**
不是篡改，是版本配对规则：新版 wheel 验旧包会先 `PRODUCER FAIL`，签名检查还没走到。换对应版本的旧 wheel 才能验，旧物清单在 `OLD-WHEELS.md`。

**10. 能防内部人作恶吗？改一个文件一定会被发现吗？**
防不住持有签名私钥的人，他能签任意包；公钥和包外锚点被一起替换也会失守。工具能发现的是“包内字节、工件、发现、链、输入、签名与外部锚点不一致”；自由文本（比如锚点里的 `note`）不参与验算，不能拿它当证据。

---

## 9. 不要在现场说的话

> 下面这些句子听着顺，但会构成过度承诺。**左边不要说，右边照着换。**

| 不要说 | 换成这句 |
| --- | --- |
| “这套系统**符合法规** / 符合劳动法” | “它按公开条文和自设口径做规则计算，是否符合法规要你们法务判断。” |
| “我们已经**通过合规审查 / 通过审计**了” | “通过了 19 轮技术验收，这是 PoC 验证，不是合规审查。” |
| “举证包**有法律效力** / 等同于仲裁证据” | “它是一份可复核材料，是否采信由仲裁/法院决定。” |
| “**绝对防篡改** / 没人能改” | “能发现包内字节被改；防不住私钥持有人，也防不住公钥与包外锚点被一起替换。” |
| “AI 能**算出加班费 / 自动判定赔偿**” | “引擎只算工时指标，不产出金额；金额由人录入并由人负责。” |
| “我们已经在**几千人生产环境验证**过” | “交付是 8 个合成样例包，规模数据是实验值，不是生产承诺。” |
| “**零漏洞 / 零风险**” | “依赖扫描有明确覆盖范围，也有未覆盖项；详见口径声明和供应链记录。” |
| “公钥能**证明这是我们公司发的**” | “pin 只证明包与这把公钥匹配；主体身份要靠独立渠道核验。” |
| “**改一个字节一定被抓**” | “参与哈希与签名的字节会被抓；自由文本字段不参与验算。” |
| “旧包也能验，说明**版本无所谓**” | “旧包必须配同版本 wheel，否则第一道就是 `PRODUCER FAIL`。” |
| “删输入一定会 `FAIL`” | “带输入契约的 v3 包会 `FAIL`；默认 v2 无签名包只会 `PARTIAL`，不能拿它演示。” |
| “导出只要 3 秒，性能有 SLA” | “那是特定数据量下的实验值，不是 SLA；引用前先看随包外附件提供的 `docs/口径声明.md`。” |

---

## 10. 时间分配（净演示 20–23 分钟，含寒暄控制在 25 分钟内）

| 累计 | 环节 | 应完成什么 |
| --- | --- | --- |
| 0–2 分钟 | 开场一句话 | 客户记住“不做全栈考勤、不给法律定性、不替代律师” |
| 2–8 分钟 | 现场验算 | 客户亲眼看到 `RESULT OK`（exit 0）与三元组逐项一致 |
| 8–13 分钟 | 现场篡改 | 客户亲眼看到 `RESULT FAIL`（exit 1），并听到具体文件名 |
| 13–16 分钟 | 五个门禁 | 客户亲眼看到少一项就 `PARTIAL`（exit 2） |
| 16–19 分钟 | 旧包对比 | 客户听到 `PRODUCER FAIL` 与“版本配对”，不误认成篡改 |
| 19–23 分钟 | 边界四问 | 四句实话讲完，指向 `docs/安全与证据链现状.md` 第 3 节 |
| 23–24 分钟 | 收尾 | 四份材料递到客户手上 |

**时间不够时砍什么**：先砍 3.1「改结论」，保留 3.2「删输入」——删输入的输出最直观；再砍旧包对比的现场命令，只口头讲规则。**不要砍五个门禁和边界四问**，那是本场演示的核心。

---

## 附：本脚本对应的实测输出从哪来

- 八包 `verify` / `replay` 的逐条原始输出与退出码：`reports/round19-techcheck.txt`（交接目录内）。
- 退出码 0/1/2/3 的统一定义：`README-验收.md` 第三节。
- 旧包、旧 wheel、依赖锁的真实位置：`OLD-WHEELS.md` 与 `KEY-NOTE.txt`。
- 本脚本中的篡改、缺公钥、旧包三类输出，已按交接目录的 0.4.17 包与锚点在本机复跑核对；现场请以客户机器上的实际输出为准。
