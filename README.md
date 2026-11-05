# 工时合规校验 + 制度问答 Agent（MVP 原型）

> **一句话**：这不是考勤系统，是**一条不会赔钱的判断链**——加班倍数、月上限、法定节假日
> 认定全部由确定性引擎算出，AI 只负责把提问理解成查询计划、把已算好的事实叙述成人话，
> 出口还有数字白名单与「重大事项只解释不给数」两道闸。
>
> **定位**：求职作品集项目，单人自主。数据 **100% 合成**（seed 可复现），法条基准 **公开可查**，
> **没有任何真实用人主体**，也**没有**生产环境运行记录。
>
> 简历口径（照方案 §4.8 钉死）：`工时合规校验 Agent（合成数据 + 公开法条基准，单人自主，无真实用人主体）`

> **对外演示注意（销售/演示者必读）**：演示“删输入被拦截”**必须用带外部锚点的 v3 包**
> （交接目录 `package/` 下 8 个包 + `anchor-<版本>-<role>.json` + 固定公钥）。默认
> `wca all` 不提供签名钥时导出的是 **v2 无签名包**：它没有输入契约，**v2 包不会因缺少 `inputs_digest` 这一项门禁而被判 FAIL**（该门禁记 `NOT CHECKED`）；删掉输入后结果可能仍是
> `ARTIFACTS OK` / `RESULT PARTIAL`（exit 2）。但**其他任何真实篡改仍判 FAIL**（exit 1），
> `--require-signature` 下无签名即 `SIGNATURE FAIL`（exit 1）。用它演示会给人
> “删了也没事”的错觉。

---

## 30 秒跑起来

```bash
uv sync                                                  # 唯一的依赖通道：按 uv.lock 精确重建 .venv（校验 sha256）
cp .env.example .env                                     # 默认 PostgreSQL 18：先填 WCA_DATABASE_URL
# 无 PostgreSQL 的离线环境：显式设置 WCA_DB_BACKEND=sqlite（SQLite 只是回退）
uv run python -m src.cli status                          # 用 `uv run` 就不用记 .venv 的路径
# 依赖只走 uv（2026-10-09 决定）。`uv sync` 建的 .venv 里没有 pip；
# 需求文档已同步修订到 v2.1：US-EV-01 / NFR-07 的验收命令就是上面这条（裁决 D-07）。
# 下面所有命令都等价于先 `source .venv/bin/activate` 再 `python -m …`。
uv run python -m src.cli all                             # 生成→导入→建库→校验→报表→举证包
uv run pytest -q -m "not llm"                            # 离线全量；计数只写在 reports/round17-techcheck.txt（本文不复制数字）
$env:WCA_TEST_POSTGRES_URL="postgresql://root:<本地口令>@127.0.0.1:5927/postgres"
uv run pytest -q -m "not llm"                            # PG 全量：与离线同一条命令，仅多一个环境变量；计数见同一日志
uv run python evals/judge.py --write-report              # 70 条评测集打分
uv run python tools/mutation_test.py                     # 注入 31 个缺陷，看测试抓不抓得住
uv run python tools/perf_probe.py --pg-url "$WCA_TEST_POSTGRES_URL" --employees 1000 --dense \
  --repeat 5 --export --export-repeat 10 --replay --json reports/性能探针-v5-dense-1000.json  # 结论密集四段实测
uv run python -m src.cli replay var/packages/<run_id>.zip  # 拿包自己重放：重导输入→重跑引擎→比三元组
uv run python -m src.cli keygen --out var/keys/ed25519.key --public-out var/keys/ed25519.pub  # 可选签名密钥
uv run python -m src.cli export --run <run_id> --signing-key var/keys/ed25519.key  # 可选 v3 签名包
uv run python scripts/build_release.py --signing-key var/keys/ed25519.key
# 产出 dist/wca-replay-<版本>/：wheel + 带哈希锁 + SHA256SUMS + SHA256SUMS.sig
# + VERIFY-SIGNATURE.txt + RELEASE.json（发行物签名；不是可复现构建证明）
```

核心校验链路只依赖 **Python 标准库 + pytest**；Ed25519 签名/验签使用 **PyNaCl**（只有显式签名或验签 v3 包时才需要），
Web 界面与只读接口需要 FastAPI（没装时界面测试如实 skip，`python -m src.cli ask` 走的是同一条链路）。

**数据库默认与回退**：PostgreSQL 18 是默认后端，`.env.example` 的 `WCA_DATABASE_URL` 留空时启动期直接报错，
不会静默回退 SQLite；无 PostgreSQL 的离线环境必须显式设置 `WCA_DB_BACKEND=sqlite`。即使工作区有旧
`var/worktime.sqlite3`，没有显式 WCA 配置也不会悄悄采用它。配置 URL 与 `WCA_DB_IDENTITY_PATH` 指向的库不一致时，
`init/ingest/check/export` 一律拒绝，只有显式 `python -m src.cli db-target --reset --confirm <配置库名>`
才允许切换。
向量检索默认**不启用**（未下载 embedding 模型），启用不了时代码会如实降级成 BM25 并在结果里标注。

演示路径与讲解词：`docs/演示脚本-30分钟.md`。

## v5 质量门禁结果（测试计数 2026-11-04；性能数字 2026-11-02；规则包 `rp-2026.11.gd-pilot-standard.v5`）

| 指标 | v5 实测 |
|---|---|
| 测试 | 离线 **549 passed / 8 skipped / 1 deselected**（`-m "not llm"`，2026-11-04 实测；相对第六轮 545 增加 4 项：跨文件重复行单行/聚合 + 同 run 重导与重复确认的 artifacts 稳定性）；带 PG **572 passed / 1 skipped / 1 deselected**（2026-11-04 实测，`WCA_TEST_POSTGRES_URL` 指向维护库 `postgres`） |
| 评测（stub 离线） | 意图 Top-1 **70/70** · Hit@5 **37/37** · MRR **0.664** · 数值工具 **30/30** · 引用忠实 **70/70** · 错承诺 **0** · 越权召回 **0** |
| 门禁分布 | ANSWERED 57 / EXPLAIN_ONLY 9 / REFUSED_ACL 3 / REFUSED_NO_EVIDENCE 1 |
| 评测集 | 70 条（检索 29 / 数值 24 / 混合 17）；`sha256=2b8e91b1f44510c3…`；M-003 已最小改为 v5 REG-01 场景 |
| 变异测试 | **注入 31 个缺陷，捕获 31，还原 MD5 全部一致**；覆盖 REG-01、COMP-C01、SHIFT-01、OFF-01、纪元与审批台账 |
| PG 真实 12 人数据 | 校验 **706.2 ms** 中位（650.9–777.9）· 导出 **206.4 ms** · replay **977.9 ms** · 导入 punch 3,900 行 **4,848 ms** |
| PG 1,000 员工月（合成 baseline） | 校验 **9,964.8 ms**（30,000 员工日）· 导出 **228.7 ms** · replay **8,454.7 ms** · 导入 44,000 行 **53,357.8 ms**；包内 5 输入 / 3,610,263 字节 |
| PG 1,000 员工月（结论密集） | **1,700 条结论**（400/1,000/300）· 校验 P50 **12,804.8 ms** / P95 **14,884.4 ms** · 导出 P50 **677.0 ms** / P95 **1,451.2 ms**（10 次，1,700 行）· replay P50 **12,132.8 ms** / P95 **14,192.6 ms**，`ok=true` · 导入 4 文件 **46,097.5 ms** |
| PG 3,000 员工月（空台账，Phase 6） | **5,100 条结论**（1,200/3,000/900）· 输入 5 个 / 10,881,463 字节 · 包 **731,659 字节** · 导出 P50 **2,234.7 ms** / P95 **2,456.1 ms**（n=10）· replay + verify 一致 |
| PG 3,000 员工月（450 行非空台账） | **4,650 条结论**（1,200/2,550/900；REG-01 150 / COMP-C01 600）· 台账 **450 行 / 450 人**（P0001–P0450 覆盖，P0451–P0600 保留未覆盖）· 输入 **5 个 / 10,966,963 字节**（审批 CSV 85,593 字节）· 余量 **1,615,949 字节**，**距 10.5 MiB 告警线仅 43,085 字节** · 包 **729,492 字节** · 导出首轮 P50 **6,896.1 ms** / P95 **7,830.3 ms**（前 6 次冷、后 4 次约 2 s），热缓存复测 P50 **1,928.4 ms** / P95 **2,140.9 ms**（n=10）· replay + verify 一致 |
| PG 3,000 员工月（600 行全量台账） | **4,500 条结论**（1,200/2,400/900；REG-01 **0** / COMP-C01 600）· 台账 **600 行 / 600 人** · 输入 **5 个 / 10,995,463 字节**（审批 CSV 114,093 字节）· 余量 **1,587,449 字节**，**距 10.5 MiB 告警线 14,585 字节、未触发告警** · 包 **729,729 字节** · 导出 P50 **8,154.6 ms** / P95 **8,664.6 ms**（前 7 次冷、后 3 次约 2 s）· replay + verify 一致 |
| PG 导入 A/B（132,900 行 punch） | single 三轮中位 **229,650.9 ms**、executemany 5,000 **44,842.3 ms**、COPY **24,574.4 ms**；COPY 快 **9.35×**；三组 employee 3,000 / punch 132,900 / shift_plan 66,000 / raw_file 4 与 input_fingerprint、conclusion_digest、5,100 条结论逐项一致。**加固验证（REV-31）发现：同文件并发 raw_file 唯一冲突、中断后 raw_file 不回滚、跨文件重复 issue 膨胀； COPY/executemany 都不具备切默认条件，默认保持 single**（`reports/导入性能AB.md`） |

v5 性能数字来自一次性 PG 库（12 人档为备份恢复数据，1,000/3,000 档为可复现合成数据），不是 SQLite 副本口径；
设计值只对“导出 ≤3 s / 1,000 行”有既有口径：结论密集 1,000 档实测 **1,700 行、P95 1,451.2 ms，达成**；
baseline 1,000 档是 **0 条结论**，228.7 ms 不能单独当作该口径的证据。
Phase 5 在 8 MiB 下曾阻断 3,000 自含导出；Phase 6 用 **12 MiB 受控实验**完成自含导出 + replay + verify。
**12 MiB 是实验默认值，不是 SLA**；实测 3,000 + 450 行非空台账余量约 **1.54 MiB**。
Phase 7 已加 **10.5 MiB（11,010,048 字节）告警线**；Phase 8（REV-25）再加 **11.5 MiB（12,058,624 字节）临界线**。
三档语义：低于 10.5 MiB 为 ok；10.5–11.5 MiB 为 warning（3,000 规模常态提示）；11.5–12 MiB 为 critical
（接近硬上限，manifest/CLI/日志要求人工确认，仍允许导出）；超过 12 MiB 仍拒绝，不静默截断。
manifest/inputs 新增 `critical_bytes/critical/critical_message`；老包缺这些字段仍可 replay/verify。
**600 人全量台账实测**输入 10,995,463 字节，距 10.5 MiB 14,585 字节，未触发。
**3,000 行台账实测**（REV-24/25）：审批 CSV 576,105 字节 / 3,000 行，自含输入 **11,493,475 字节**，
落在 warning 档（超 10.5 MiB 483,427），距 11.5 MiB 余 **565,149**、距 12 MiB 余 **1,089,437**；
包 1,135,356 字节，6,900 条结论，replay 6,900/6,900 一致。**这是实验值，不是 SLA**。
原始 JSON：`reports/性能探针-v5-pg-12.json`、`reports/性能探针-v5-pg-1000.json`、
`reports/性能探针-v5-dense-1000.json`、`reports/性能探针-v5-dense-3000-check.json`、
`reports/性能探针-v5-dense-3000-export-boundary.json`、`reports/性能探针-v5-dense-3000-selfcontained.json`、
`reports/性能探针-v5-dense-3000-approval-selfcontained.json`、
`reports/性能探针-v5-dense-3000-approval-export-warm.json`、
`reports/性能探针-v5-dense-3000-approval600-selfcontained.json`；
评测与变异原始记录：`reports/评测结果.md`、`reports/变异测试.md`。

**演示数据边界（v5）**：`data/raw` 的 7 个事实 CSV **不含**审批台账。活动库最新 v5 的 115 条结论包含
一行人工录入的 E006 台账；全新库只跑 `init + ingest` 得 116 条，多一条 `REG-01 / E006`。要复现 115 条，
按 [`data/raw/README.md`](data/raw/README.md) 的“v5 审批台账”一节执行 `python -m src.cli approval` 最小录入；
这是输入差异，不是判据差异。

**规则版本标签（v4/v5）**：v5 证据包里常见 `99 条 v4 + 16 条 v5`。这里的 `rule_version` 是**单条规则**的
版本标签，不等于 rule pack 版本；v5 规则包保留未改判据的 v4 规则是预期，不是包版本漂移。分布以
`manifest.counts.rule_versions` 为准，逐条规则定义/条文/阈值见表内 `policies/RULE-PACK.md`。
`conclusion_digest` 只覆盖 `rule_id, rule_version, emp_id, work_date, period_key, severity, metric,
citations, explanation` 九个规范字段；`source_rel_path`、`source_line_no`、`severity_label` 由
`artifact_sha256["findings.csv"]` 负责，**单个 `FINDINGS DIGEST OK` 不等于整张表未变**，必须同时看
`ARTIFACTS OK`。

**证据定位与两层输入摘要（0.4.4/0.4.5）**：`metric` 只保留数值与计量口径；证据定位元数据（表/区间/
规则/聚合口径）放在 finding 的非 canonical `evidence` 块，由独立的 `evidence_digest` 覆盖，
**不进入** `conclusion_digest`。v5 包里有 **24 条**带证据定位（`tables/window/rules/aggregation`）
的结论（6 VIOLATION + 17 REVIEW + 1 DEFENSIBLE），逐条列在 `未覆盖清单.md` 的
“证据定位（非单行结论）”一节；0.4.9 起另有 **1 条**重复批次 finding 仅带 `retained_refs`
（被保留行的 `rel_path:line_no`），不计入这 24 条。
`evidence_digest` 是**第五项外部门禁**：`wca-verify`/`wca replay` 必须同时传
`--expect-evidence-digest`（或单包 anchor 文件的 `evidence_digest`，环境变量
`WCA_EXPECT_EVIDENCE_DIGEST` 可兜底）才能 `RESULT OK`；缺失 → `RESULT PARTIAL`，错值 →
`RESULT FAIL`。签名者作恶或私钥失窃时，签名本身不再可信，必须靠包外 evidence 锚定。
`input_fingerprint` 是内容与范围指纹；`inputs_digest` 是包内 `inputs/` 实际文件字节（不含
`run_id` 与 DB `file_id`；文件名由 `rel_path` 推导）。同一批输入跨 run/跨库导包，`inputs_digest`
必须相同；实测见 `tests/test_evidence_digest.py::test_inputs_manifest_cross_database_stable`。
注意：包内 `manifest.json` **顶层确实有 1 个 `run_id`**，它只用于把包回指到库内 run 与审计段；
它不参与 `inputs_digest`、`conclusion_digest`、`evidence_digest`、`artifacts_digest` 或
`input_fingerprint` 的任何计算，四联值本身不含 `run_id`（第十轮复测的表述冲突已按此改写）。
0.4.4 起 `QUAL-01/02` 的 `metric.line_refs` 与 `OFF-01` 的 `conflicts.sources` 只写
`rel_path+line_no`，不再写 DB `file_id`；换新库重导与反向导入顺序（punch/schedule 互换）
`conclusion_digest` 都必须相同，0.4.8 实测四包均为 `5dc46558…`。旧 0.4.3 包的 `01bd4403…`
含 `file_id=4`，移除后不可能复现；不要把旧值当成本轮目标。0.4.5 起同一打卡内容出现在
多个 punch CSV 时，`QUAL-DUP` 行引用按 `rel_path` 字典序确定，全部来源纳入包内输入；
单 `punch.csv` 场景在 0.4.5–0.4.7 曾保持 `b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`；
0.4.8 批次语义后四主包 `conclusion_digest` 统一为 `5dc46558…`、`evidence_digest` 为 `4654a3c7…`；
0.4.9 起批次 finding 增加 `evidence.retained_refs`，四主包 `evidence_digest` 为 `ed3b3f1b…`，
`conclusion_digest` 仍 `5dc46558…`；0.4.10 只改锚点校验与文档，`conclusion_digest` /
`evidence_digest` / `inputs_digest` / `input_fingerprint` 均与 0.4.9 相同。`inputs_digest` 与
`input_fingerprint` 仍为 `aad527d1… / 8b3b54a0…`（旧包值只作历史对照）。

### 跨数据库后端可复算（0.4.8）

同一批输入分别导入 SQLite 与 PostgreSQL，导出包的 `conclusion_digest`、`evidence_digest`、
`inputs_digest`、`input_fingerprint`、`artifacts_digest` 必须逐字节相同（回归用例
`tests/test_postgres_integration.py::test_sqlite_and_postgres_export_five_digests_identical`）。
0.4.8 起，导出侧不再依赖 SQL `ORDER BY` 的 NULL 顺序或文本 collation：`findings.csv`、
`quality_issues.csv`、`input_files.csv`、`responsibility.json`、`anomaly.csv`、投影指纹都把
行序改到 Python 里按“空值在前 / 整数数值 / UTF-8 字节序”显式排序；`QUAL-01` 的空日期
期间汇总路径已删除，49 条空日期行不再存在。

## v4 历史结果（2026-10-08，规则包 `rp-2026.10.gd-pilot-standard.v4`）

> 以下是 v4 时点的历史数字，**不是 v5 实测**；保留用于版本对照。

| 指标 | 实测 |
|---|---|
| 测试 | `197 passed / 1 deselected`（`-m "not llm"`，离线；唯一被筛掉的用例需要真实云凭证） |
| 干净环境复跑 | 三轮，全部在**无 `.env`** 的仓库副本里跑：前两轮走 pip（175 passed），第三轮起**只走 uv**（`uv sync` → 193 → **197 passed / 1 deselected**），`cli all` rc=0、三元组与本机库逐字符一致，`export --sign-as`（旧命令名，现 `--record-delivery-as`，非密码学签名）`→ replay → 独立 verify.py` 整条复核链同样在新环境跑通（`reports/干净环境复跑.md`） |
| 三元组跨环境一致 | 干净环境重跑得同一 `输入指纹 f5021119…` / `结论摘要 95f01ab2…`（与本机演示库逐字符一致） |
| 变异测试 | 注入 20 个缺陷，**捕获 20**，还原 MD5 全部一致（M18 无人工结论混进结论集、M19 签发人不具名、M20 包漏主数据） |
| 意图 Top-1 / Hit@5 / MRR | 70/70 · 37/37 · 0.664（含三市分档题与跨城隔离回归题）|
| 数值工具首次成功率 / 引用忠实率 | 30/30 · 70/70 |
| **错承诺条数（红线）** | **0** |
| **越权召回条数（红线）** | **0** |
| 检索段 P95 / 端到端 P95 | 4.8 ms / 5.6 ms（干净环境 fresh 库、单次 70 题评测、n=70 封闭样本，**离线 stub 轨**；云轨未测） |
| 整轮校验（12 员工 × 2,904 员工日 / 3,215 条 SQL） | **347.4 ms** 中位（样本 338.1 / 347.4 / 439.5）；小档 60 人日 = **59.8 ms**。**同一条命令一小时内曾测得 119.8 ms**，本机跨时段可差 2.9 倍 → 耗时只作相对比较，不当 SLA |
| 举证包导出（含自含输入 7 个文件 / 301,586 字节） | 101 行 **185.2 ms**；1,000 行（复制行，仅测代码形状）**396.0 ms**（预算 ≤3 s 达成）；真实 1,000 员工规模**未测** |
| 重放一份举证包 | `python -m src.cli replay <包>` 全流程 **1.04–1.26 s**（3 次取样）：解包 → 临时库重导输入 → 重跑引擎 → 三元组逐项一致；只用系统 Python 跑包内 `verify.py` 也能验掉链与输入哈希 |
| 界面首屏 TTFB | 复核台 30.8–33.4 ms、问答页 28.7 ms、未登录 401 6.5–7.7 ms（本机 loopback + 真实服务） |
| 发现（未签认）条数与对账 | v2 110 条 → v3/v4 **101 条**，差值逐条可解释（`reports/判据修订.md`）；v5 116 条 → 0.4.8 **115 条**（原期间汇总+逐日 2 条合并为 1 条批次 finding，展开后 `issues_total=115`）/ 0 条已确认结论 |
| 外部重放（US-EX-01） | 包内自带 `inputs/` 原始 CSV；`replay` 把输入喂回引擎重比三元组；改一个打卡时间必须报 `≠`（`tests/test_replay.py` 7 项 + 变异体 M20） |
| 已确认结论集 | 演示库 101 条发现（未签认）里**只有 2 条**有人工结论进了已确认结论集，其余 99 条留在 `findings.csv` 等处置——这是纪律，不是漏数 |
| 服务启停 | 一键开关六条路径实跑通过：启动就绪 1450–1539 ms、优雅停止 764–862 ms、强杀 784 ms、`在跑→先停后起` 总 3051 ms、`--no-restart` 不动进程（rc=1 并给处置建议） |

以上数字的前提条件、以及**哪些是设计值、哪些根本没测**，全部写在
[`docs/口径声明.md`](docs/口径声明.md)。云端延迟、token 账单、向量检索收益、真实字段口径：**未测**。
V1 → V1.1 优化的前后对照（含没达成的目标）在 [`reports/优化验证.md`](reports/优化验证.md)；
判据为什么必须升版本（规则包 v1 → v2 → v3 → v4）记在 [`reports/判据修订.md`](reports/判据修订.md)。

---

## V1.1 这一轮改了什么（一句话一项）

| 项 | 改动 | 有没有改变判据 |
|---|---|---|
| O-1 | 事实装配改为「每员工整段预取 5 条 SQL + 逐日纯计算」，落库批量 UPSERT 且整批包事务 | 否（结论摘要逐字节一致，由回归测试 + 变异体守住） |
| O-2 | 整行被拒收的脏数据现在汇成 `QUAL-02` 结论并自动开复核单；归属不到人的汇成「(未归属)」；异常报表改 LEFT JOIN | **是**（新增规则 + 归属改善 → 规则包升 v2） |
| O-3 | 打卡事实按**内容**唯一（`(emp_id, event_ts, punch_type, device_id)`），改名重传不二次入账 | 否（本数据集无跨文件重复；行为由测试覆盖） |
| O-11a | `input_fingerprint` 只覆盖**本次真正引用到的输入文件** | 否（结论不变，指纹值变；旧口径留作可选参数） |
| — | 新增 `tools/perf_probe.py`：SQL 计数 + 多次采样中位耗时，在库副本上测，不污染演示库 | — |
| — | 验证时顺带修掉两处与语义无关的缺陷：落库没包事务（冷表首轮 2.75 s→0.43 s）、8 个文件行尾 `\r\r\n` | 否 |

---

## 审批台账 P0（服务层，2026-11-02）

- **数据模型**：`approval_doc`（批文主表）+ `approval_doc_version`（版本）+ `approval_doc_scope`（org/employee 范围）+ `employee_approval_coverage`（员工覆盖投影）；`org_unit` 扩展 `org_path/org_level` 用于组织子树展开。
- **发布流程**：先建 DRAFT，再 `publish_doc` 展开范围、检测同员工同工时制的重叠覆盖，成功后生成投影；同批文新版本发布时旧版本转 `SUPERSEDED`，不覆盖历史。
- **原子 CSV 导入**：`import_drafts_csv` 整批校验、单事务写入；任一行非法则全部回滚，不留半份台账。
- **权限**：新增 `AU` 只读角色；AD 可写/发布，AU 只能读批文与覆盖投影；写操作在 service 层拒绝 AU。`config/users.json` 已增加 AU 演示账号 `au1`（只存 scrypt 哈希）。
- **附件**：只登记 64 位 SHA-256，不保存原件、文件路径或 BLOB。
- **审计与冲突**：草稿/导入/编辑/发布写审计事件；同名同版本、批文主数据改写、重叠覆盖均显式拒绝，**不复用旧的静默 `upsert_approval`**。
- **网页入口（2026-11-03）**：`/approvals` 列表（状态/文号/生效期/版本数）、`/approvals/{doc_no}` 详情（版本链/scope/附件哈希）、`/approvals/coverage` 员工覆盖；AD 另有 `/approvals/new`、`/approvals/{doc_no}/edit`、`/approvals/import`。AU 读可、写页面与 POST 均 403；**所有会话写接口（import/check/review/export/ask/logout + 审批四入口）强制 CSRF**；CSV 上限 1 MiB / 2,000 行，超限明确拒绝；发布复用 `publish_doc` 的加锁路径。详见 `docs/审批台账-P0界面与权限方案.md`。
- **CSRF 存储**：`app_csrf` 只存 `sha256(CSRF token)`，页面通过 `wca_csrf` cookie + meta 下发；旧明文表由 `init_db` 整表重建，不留明文。
- **边界**：网页入口只提供审批台账，不提供外部审批 API/附件原件上传（仍只登记 SHA-256）；只读 CLI `approval-doc` 已加；旧台账迁移/对照工具 `approval-migrate` 已加（默认 dry-run、`--apply` 仅临时库，活动库一律拒绝），但未在活动库执行；REG-01 的切换放到独立 v6 规则包（见下节），旧 `worktime_approval` 在 v5 下保持原样。

---

## v6 规则包（REG-01 切换覆盖投影；2026-11-04 起为默认）

- 版本串 `rp-2026.11.gd-pilot-standard.v6`；**0.4.8 起默认 v6**（切换日 2026-11-04，
  与 0.4.8 发行物构建时刻一致；当时无生产 run，属提前生效，详见 `policies/RULE-PACK.md`），
  v5/v4 仍可用显式 `WCA_RULE_PACK` 选择与回放。切换记录（谁/何时/何版本）见
  `policies/RULE-PACK.md`；活动库未在本轮切换，仍由部署配置显式钉住 v5。
- v6 的 REG-01 改读 `employee_approval_coverage`；旧 `worktime_approval` 在 v6 下**不再参与计算**，只保留 legacy 输入与回放。
- v6 首次写入 v5 库时追加 `rule_pack.epoch.start`；v5 genesis 不重置，v5 旧包继续 legacy 回放。
- v6 `input_fingerprint` 纳入覆盖投影摘要（员工、批文号、版本、生效期、工时制、岗位/城市、附件哈希、发布时间）。
- v6 包内 `inputs/000-approval.csv` 来源改为覆盖投影，manifest 记录 `approval_source=v6-coverage`；replay 从该 CSV 重建投影后重算三元组。
- 旧 `worktime_approval` 仍有数据时，v6 check 通过 `CheckOutcome.warnings` 与 CLI stderr 输出显式警告：“旧台账未迁移，v6 只采信覆盖投影”；**该告警不进 `run.scope_json`/输入指纹**，否则包内 replay 在无旧表的临时库里无法复现三元组（REV-21）。
- finding 的 `rule_version` 与产出它的规则包一致：v6 新结论标 v6，v5/v4 旧结论保持原值；**不批量改写历史 finding**（REV-20）。
- 旧台账迁移/对照：`python -m src.cli approval-migrate` 默认 dry-run，输出行数/员工集合/丢弃与合并原因/REG-01 v5↔v6 命中差异；`--apply` 默认只允许 `wca_test_* / wca_perf_* / wca_migrate_* / wca_drill_* / wca_tmp_*` 与 `wca_worktime_v5`，活动库 `wca_worktime` 一律拒绝。临时库实测 600 行 → 600 批文/600 版本/600 覆盖，dry-run 未写库（REV-22）。
- 受控活动库切换（REV-26，**未执行**）：`--allow-active` 必须同时给 `--backup-path`、`--backup-sha256`、`--confirm-active wca_worktime`、`--confirm-apply wca_worktime`；连接后只认 `current_database()`，备份缺失/校验失败/确认串不符/连错库均拒绝。活动库备份副本 `wca_drill_restore_v6_20261103` 已完整演练：迁移 1 行 → 1 批文/1 版本/1 覆盖，v5/v6 REG-01 命中均 4、only_v5/only_v6 均 0；v6 check 115 条，export 8 个输入 / 301,910 字节，包 53,738 字节；replay 115/115，verify 三 OK。
- 临时库全链路（`wca_drill_v6_20261102_3`）：init 329.3 ms → 迁移 1,514.0 ms → v6 check 45,771.1 ms（3,000 员工/90,000 天/4,500 条，REG-01 0）→ export 8,946.6 ms（包 724,071 字节，自含输入 10,996,675 字节）→ replay 38,449.3 ms（4,500/4,500，三元组一致）→ verify.py 155.7 ms（`EPOCH OK` / `CHAIN OK` / `INPUTS OK`）。
- PG v6 自含包专项测试已加入 `tests/test_postgres_integration.py`（条件定义，离线不新增 skip）：实测 `inputs_bytes=843`、`package_bytes=13102`、`check_ms=143.1`、`export_ms=133.1`、`findings=7`。
- 等价性：临时库上 450 行旧台账构造等价投影后，v5 与 v6 的 REG-01 命中员工集合 **100% 相同**（均为 P0451–P0600 这 150 人）。
- 告警线已落定方案 C（REV-25）：10.5 MiB warning + 11.5 MiB critical + 12 MiB 硬上限；三档语义与实测见上节和 `reports/告警线方案分析.md`。
- v6 质量门禁重跑（REV-27）：评测 **70/70 逐题与 v5 一致**、错承诺 0、越权 0；变异 **31/31**、13 个文件还原 MD5 一致。详见 `reports/评测-v6.md`、`reports/变异测试.md`。

---

## 如何正确统计重复类问题（0.4.8 批次语义）

`findings.csv` 里一条 `QUAL-01` 可能代表一整批重复行。直接数 CSV 行数会把 49 条重复
算成 1 条。按下面三个口径分别读 `manifest.counts`：

| 字段 | 含义 | 示例（49 条重复、无其他结论） |
|---|---|---|
| `findings_total` | `findings.csv` 数据行数（每条结论一行） | 1 |
| `findings_batched` | 其中带 `batch_id` 的批次 finding 条数 | 1 |
| `issues_total` | 把批次展开后的实际问题条数 | 49 |

关系：`issues_total = findings_total - findings_batched + 各批 batch_size 合计`。
同一批的 `batch_id` 由来源行内容派生，换库重导、反向导入、不同机器都相同。
审计方复算 `batch_id`：把该批 `metric.sources` 每项写成 `rel_path:line_no`，去重后按
UTF-8 字节序排序，用换行符连接，取 SHA-256 十六进制小写摘要；与 `metric.batch_id` 比对。
`policies/CONFIDENCE.md`、`未覆盖清单.md`、`manifest.counts` 三处计数必须一致。
0.4.8 离线实测 **585 passed / 10 skipped**（`-m "not llm"`，2026-11-04）。

---

## 它能做什么

1. **举证级工时合规校验**（价值核心，默认规则包 `rp-2026.11.gd-pilot-standard.v6`；v5/v4 仍可显式选择）
   22 条确定性规则（v4 的 18 条 + v5 新增 4 条）：工作日延长工时、休息日与补休、法定节假日当天 300%、
   每日/每月加班上限、每周至少休息一日、周 40/44 小时、跨零点切分、夜间时段、数据质量、
   内部制度预警、年度日历未核标记、**工时制未覆盖标记（SCOPE-02/03）**；
   v5 另加 **审批台账覆盖（REG-01）**、**综合工时完整周期统计（COMP-C01）**、
   **多段班次不可拼接（SHIFT-01）**、**离线补传冲突（OFF-01）**。
   每条异常给三级分级（**可申辩 / 需复核 / 明显违规**）+ 触发规则 ID + 条文依据 + 原始行号。
   城市分三档（`config/region_profile.json`）：广州、佛山适用《广东省工资支付条例》第 20 条，深圳适用特区条例第 18 条，未建档城市只出国家层面结论并记 `SCOPE-04`。
   **引擎不产出任何应付金额**（需求 D-03）：只出小时数与法定倍数档位，金额由 HR 负责人具名录入。
   综合计算工时与不定时工时的周期超额/豁免判定仍不套用标准工时硬判：v5 的 COMP-C01 只做周期统计，
   REG-01 只核审批覆盖，均不改变 `effective_regime`、不下违规、不出倍数。
2. **可复核、可验签的举证包（hash 链 + 工件绑定 + 外部锚点 + Ed25519）**
   审计 hash 链 + 一次导出生成「规则版本 + 输入指纹 + 结论摘要」三元组；包内另有
   `artifact_sha256` 逐文件哈希、`artifacts_digest` 清单摘要与 `verify_script_sha256`。
   复核方不需要相信我——**发行 wheel 的 `wca-verify`** 自己重算链、输入摘要、工件哈希、
   findings 反算摘要与签名；它**不执行包内 `verify.py`**。包内脚本只是便利脚本，不是信任依据。
   包内另附**已确认结论集**（只收已登记具名人工结论的条目）、**责任区块**、**未覆盖清单**，
   以及**本次结论真正依赖的原始 CSV**（`inputs/`）。
   复核方拿着包就能自己走完两步：`wca-verify` 做字节层/工件绑定/发现摘要/验签，
   `wca replay` 把包内输入喂回引擎、比对三元组——**不必回头向我索要数据**。
   `manifest_checksum` 只能发现“字段被改但校验和没同步重算”；它**不是签名**。需要证明来源时，
   用 Ed25519 私钥导出 **schema v3** 包：
   ```powershell
   uv run python -m src.cli keygen --out var/keys/ed25519.key --public-out var/keys/ed25519.pub
   uv run python -m src.cli export --run <run_id> --signing-key var/keys/ed25519.key
   ```
   v3 的 `manifest.signature` 覆盖 schema、三元组、`inputs_digest`、`artifact_sha256`/
   `artifacts_digest`/`verify_script_sha256`、`manifest_checksum` 与重算链头；0.4.3 起还覆盖
   `evidence_digest`（0.4.5 延续），且 evidence 必须由包外参数/单包 anchor 文件额外锚定。`inputs_digest`
   覆盖 `inputs/` 下全部文件（含 `inputs/manifest.json`），所以换输入 CSV、只改登记表、增删文件
   都会被 `INPUTS FAIL` 发现。改 `findings.csv` 一条严重级别会被 `ARTIFACT FAIL` 发现；
   即使同步重算工件哈希/checksum 并重签，`FINDINGS DIGEST FAIL` 仍会因 findings 反算摘要不一致而拦下。
   **包内自带公钥只能打印 `package self-check` (NOT source trust)**；只有包外固定公钥 pin 才打印
   `SIGNATURE OK (pinned ...)`。签名不证明结论正确，也不能防私钥持有人作恶；结论正确性仍要靠
   `wca replay` 证明。未配置私钥时仍导出 v2 无签名包；`wca-verify` 对它的结果最多是
   `RESULT PARTIAL`（exit 2），**不能作为完整验收**；配钥（`--signing-key` /
   `WCA_SIGNING_KEY_FILE`）则自动导出 v3。
   交付时请把**四元组**另行记录在包外：`schema_version,rule_pack_version,input_fingerprint,
   conclusion_digest`，并记录签名 `key_id`、包 SHA-256、`artifacts_digest` 与
   `evidence_digest`（0.4.3 起为第五项外部门禁，0.4.5 延续）；事后用
   `wca-verify ... --expect-anchor ... --expect-evidence-digest ... --public-key fixed.pub` 或
   `wca replay ...` 做外部锚点、证据摘要与验签；
   环境变量 `WCA_EXPECT_ANCHOR` / `WCA_EXPECT_EVIDENCE_DIGEST` 等价。**不传 `--expect-anchor` 只给 `RESULT PARTIAL`（exit 2）**，
   不再静默放行；`--expect-triple` / `WCA_EXPECT_TRIPLE` 仍保留，但它**不约束 schema**，
   交付验收请用四元组，否则“伪装成 v1 旧包”的降级不会被发现。
   **跨版本可比性（0.4.9）**：摘要只在**同 `rule_pack_version` + 同 evidence schema** 下可比。
   锚点文件应带 `comparability_scope`（写明 `rule_pack_version` 与 `schema`）；跨版本或跨 schema
   比对输出 `RESULT INCOMPARABLE`（**exit 3**），不是 `FAIL`。同版本同 schema 摘要不符仍是
   `FAIL`（exit 1）；缺字段/缺签名仍按原规则失败关闭，**不因 INCOMPARABLE 放宽任何真失败**。
   旧锚点按版本命名（`anchor-<version>-<role>.json`），新版本不覆盖旧文件。
   **退出码（完整表）**：

| 退出码 | 标签 | 含义 | 脚本处置 |
| --- | --- | --- | --- |
| 0 | `RESULT OK` | 包体、工件、审计链、输入、签名、外部锚点与摘要全部一致 | 可通过 |
| 1 | `RESULT FAIL` | 同版本同 schema 下内容/摘要/签名/工件真实不符，或锚点文件自相矛盾 | **阻断**，按篡改/损坏调查 |
| 2 | `RESULT PARTIAL` | 外部门禁缺失（如未传 artifacts_digest / evidence_digest），或包为 v2 无签名；旧包缺 `inputs_digest` 也归此档 | **不得当通过**；补齐门禁/改用 v3 后重跑 |
| 3 | `RESULT INCOMPARABLE` | 可比性判定发现跨 `rule_pack_version`/schema（仅显式锚点串，或外部包 SHA/evidence/artifacts 已通过时），或锚点文件缺 `comparability_scope` | **不得当通过，也不得当篡改**；转人工核对版本，改用对应版本锚点与 wheel |

   **跨版本锚点的门禁先后（0.4.11 更正）**：用**完整单包锚点文件**（含 `package_sha256`/
   `evidence_digest`/`artifacts_digest`）验跨版本包时，外部包 SHA/摘要门禁**先于**可比性判定，
   任一不匹配即 `RESULT FAIL`（exit 1）；例如用 v6 包的完整锚点文件验 v5 包会先报
   `PACKAGE SHA256 FAIL`，不是 exit 3。只有仅传显式 `--expect-anchor` 串（无外部 SHA/摘要）时，
   才会因版本/schema 不同输出 `RESULT INCOMPARABLE`（exit 3）。两种路径都失败关闭，不把真失败降级。
   **旧 wheel 的 scope 边界（0.4.11）**：0.4.4–0.4.8 旧 wheel 不做 `comparability_scope` 判定，
   其 `RESULT OK` 仅表示旧口径通过，**不表示可比性已核验**；0.4.9 起才有该判定。旧包必须配
   对应版本旧 wheel（清单见交接包 `OLD-WHEELS.md`）。
   **wheel diff 复核（0.4.13，外部人可自证“无规则语义变更”）**：不解包也能逐文件比对两版 wheel：
   ```powershell
   python -c "import zipfile,hashlib,sys; a,b=sys.argv[1:]; ha={n:hashlib.sha256(zipfile.ZipFile(a).read(n)).hexdigest() for n in zipfile.ZipFile(a).namelist()}; hb={n:hashlib.sha256(zipfile.ZipFile(b).read(n)).hexdigest() for n in zipfile.ZipFile(b).namelist()}; print('changed:', sorted(n for n in set(ha)&set(hb) if ha[n]!=hb[n])); print('added:', sorted(set(hb)-set(ha))); print('removed:', sorted(set(ha)-set(hb)))" old.whl new.whl
   ```
   实测 0.4.11→0.4.12：`changed` 只有 `policies/RULE-PACK.md`、`src/__init__.py`（版本号）、
   `src/_release_info.py`（版本号/BUILD_COMMIT）；`added`/`removed` 只是 `dist-info` 目录名随版本变化。
   `src/` 其余模块逐字节相同，可据此独立确认“仅文档与版本号变更，无规则语义变更”，
   不需要信任本 README 的结论。

   **锚点文件缺 `comparability_scope`（0.4.10）**：只要传了带 `anchor` 串的锚点文件却缺
   `comparability_scope`，输出 `RESULT INCOMPARABLE`（exit 3），**不静默按可比处理**；
   仅用 `--expect-anchor` 命令行串时，串本身已声明的 schema/rule_pack 就是可比范围，行为不变。
   新版本锚点文件必须带该字段；旧文件缺字段时请按 3 处理并换新版本锚点。
   **锚点冗余字段校验（0.4.10）**：锚点文件除 `anchor` 串外若还写了 `schema` /
   `rule_pack_version` / `input_fingerprint` / `conclusion_digest`，必须与串解出值逐项一致；
   不一致报 `ANCHOR SELF-CONFLICT` 并 `FAIL`（exit 1）。校验逻辑在
   `load_anchor_record`，`wca-verify` 与 `wca replay` 共用。
   **多包组合式 `anchor.json`** 不能直接传给 `--anchor-file`；单包验算请用
   `anchor-<version>-<role>.json`。
   **`PRODUCER FAIL` ≠ 篡改**：用新版 wheel 验旧包会先报 `PRODUCER FAIL`，签名检查早退为
   `SIGNATURE NOT CHECKED`；这是 wheel/包版本配对问题，应改用对应版本旧 wheel，不能据此认定包被改。
   **交付验收必须两条一起跑**：`wca-verify` 校验包体完整性、工件绑定、审计链、输入逐文件哈希、
   输入摘要、findings 反算摘要与签名，并与外部四元组/包 SHA/工件摘要比对；`wca replay` 独立重算
   得到实算三元组与**发现（未签认）**条数。只跑一条都不足以证明。按 `manifest.schema` 分档：
   新 schema（v2 及以后）缺少 `manifest_checksum` 或工件绑定字段直接失败；v1 旧包只保留历史回放；
   schema 声称 v3 却缺签名直接失败；schema 缺失/未知按失败关闭处理。
   **术语**：引擎输出的是**发现（findings，未签认）**；只有具名人工确认过的才叫**已确认结论**。
   包内 `conclusions_final.csv` 行数对应 `counts.final_conclusions`；两者不能混成“结论条数”。
   数据最小化：包内 `responsibility.json` / `conclusions_final.csv` 不导出人工金额与录入人（库/复核台保留）；
   `question_log` 只带本 run 关联的问答，不再混入其他 run。输入 CSV 默认不裁剪。
   两层指纹：`inputs_digest + 签名` 管原始字节/来源；`projection_fingerprint + conclusion_digest`
   管规则字段复算结论。受控开关 `export --omit-fields leave:paid`（默认关）才裁剪并写
   `omitted_fields`；`replay` 用投影指纹判定，缺投影或字段不一致输出 `PROJECTION FAIL`。
   裁剪包交付时包外锚点用五段（末尾 `projection_fingerprint`），详见 `docs/数据最小化方案.md`
   与 `docs/交付与验收SOP.md`。
3. **带 ACL 的制度问答**
   权限谓词在检索层下推（SQL 的 WHERE/JOIN），未授权条目**进不了候选集**；
   答案必须带可点开出处、证据覆盖率与置信度门禁；「该付多少加班费」这类重大事项**只解释规则、
   不给最终数额承诺**，并自动开人工复核单。发往模型后端的上下文走**最小视图**：
   不含姓名、薪酬基数、原始打卡行与证件号形态（NFR-18）。
4. **可审计的评测**
   70 条三档评测集（纯检索 29 / 数值校验 24 / 混合 16，另含 1 条跨城隔离回归），每条标准答案都有**手工推导式**与条文号，
   判分器逐条比对，红线不为 0 时退出码非 0。

## 它明确不做什么

不做 SaaS、多租户、审批流引擎、排班优化、社保与薪酬核算、私有化交付、考勤硬件对接；界面只有 3 视图 + 最小登录（无前端框架、无构建链，见「界面」一节）；
不追求任何真实用人主体。**下判决也不做，算钱也不做**：系统只出「分级 + 小时数 + 倍数档位」，
金额是 HR 负责人在复核台具名录入的人工结论——因为 AI 结论在劳动争议里不构成安全证据。
> 关于「薪酬」的边界要说清楚：本项目**没有**加班费金额计算、工资表、个税、社保、实发，
> 连"参考测算明细"都不做（v3 起），所以这不叫薪酬模块，也叫不上"算错总比不算好"。

---

## 目录结构

```
worktime-compliance-agent/
├── README.md
├── pytest.ini                    # 标记注册：llm / slow（`-m "not llm"` 真能筛掉东西）
├── pyproject.toml                # 唯一的依赖声明：直接依赖 + 传递依赖约束（测试配置只在 pytest.ini）
├── uv.lock                       # 唯一的锁：25 包版本闭包 + 248 条 sha256（`uv sync` 按它装）
├── .env.example                  # 全部待填项集中在这里，带 TODO
├── docs/
│   ├── 需求文档-用户故事.md        # 唯一目标依据（F-001~F-014 / A1~A12 / 边界与异常）
│   ├── 项目定义-一页.md            # 一页版范围与非目标
│   ├── 技术方案-架构选型与实现路径.md   # 分层选型 TECH-01~05 + 落差清单 GAP-01~11
│   ├── MVP实施方案-范围里程碑与验收.md  # 33 项 Must 对照、S1~S7 排期、V-01~15 验收对账
│   ├── 字段口径与条文依据.md      # F-001 F-002（本项目合法性的根，含 P0 闸门状态）
│   ├── 口径声明.md                # 实测 / 设计值 / 未测 三态
│   ├── 待确认清单.md              # 需要人回答的问题，我不猜
│   ├── 服务启停.md                # 一键启动/停止的字段含义、行为边界与恢复建议
│   ├── 演示脚本-30分钟.md
│   └── 交付总结-本轮.md            # 本轮做了什么、验到哪一步、哪些没做
├── config/
│   ├── services.json              # 服务清单（启停工具读它，加服务不改代码）
│   ├── region_profile.json         # 城市档位表：市名、地域层级、适用条文只写在这里
│   └── users.json                  # 界面账号（只存 scrypt 口令哈希，不存明文）
├── data/
│   ├── generator/make_synthetic.py  # seed 固定，逐字节可复现
│   └── raw/                      # 合成 CSV + SCENARIOS.md + MANIFEST.json(sha256)
├── src/
│   ├── ingest.py                 # F-003 F-004
│   ├── rules/                    # F-005（quantities/holidays/regime/dayfacts/rulepack/citations）
│   ├── engine.py                 # 校验编排 + run 三元组
│   ├── anomaly.py                # F-006 分级 + 复核闭环
│   ├── evidence.py               # F-007 hash 链 + 举证包
│   ├── signing.py                # Ed25519 签名/验签、密钥文件与 pin
│   ├── projection.py             # 两层指纹：规则字段 projection_fingerprint
│   ├── kb/                       # F-008 语料 + F-009 ACL 谓词 + 分词
│   ├── retrieve.py               # F-009 ACL 下推检索（BM25/exact/vector 降级）
│   ├── llm.py                    # provider 抽象：stub / Ollama / 云 API
│   ├── guard.py                  # A1/A4 的执行机制：数字白名单 + 重大事项拒诺
│   ├── agent.py                  # F-010 问答编排
│   ├── observability.py          # F-013 分段计时 + P95 + token 口径
│   ├── api.py                    # 2 个只读 GET
│   ├── api_server.py             # 服务进程本体（停止文件驱动的优雅关闭 + WAL 落盘）
│   ├── service_manager.py        # 启停状态机：检测 / 先停后起 / 优雅停止 / 强杀升级
│   ├── service_cli.py            # 启停工具的共同内核
│   └── cli.py                    # 一键复跑入口（含 start/stop/status）
├── evals/
│   ├── golden_set_v1.jsonl       # F-011 70 条，三档，含手工推导
│   └── judge.py                  # F-012 判分器
├── tools/
│   ├── start_services.py         # 一键启动
│   ├── stop_services.py          # 一键优雅停止（含 --status）
│   ├── mutation_test.py          # F-012 变异测试（MD5 基线校验 + 字节码缓存清理）
│   └── perf_probe.py             # 性能探针：SQL/DB 调用计数 + 多次采样中位耗时（SQLite 副本或 PG 临时库）
├── tests/                        # 收集 533 项；离线 524 passed / 8 skipped / 1 deselected：判据/质量门禁/ACL/守卫/接口/界面权限/城市档/启停/CLI 表面/重放/v5 规则/纪元/探针/三档输入预算/审批 P0/审批网页/全站 CSRF/CSRF 哈希/旧台账迁移/连接后库守卫/allow-active/v6/导入事务与并发/QUAL-DUP 汇总/首次切包事务/分块与降级/COPY 中断/并发 check 审计/流式读取与哈希/审计事务边界/同 run 导出锁/临时表清理/维护策略/依赖口径/数据库身份硬失败/report 原子写/配置路径/签名与验签/两层指纹/五段锚点/producer 版本指纹/工件绑定/独立验算器/七种坏包/验收
└── reports/                      # 评测结果.md、变异测试.md、优化验证.md、判据修订.md、
                                  # 性能探针.json、P0-闸门.md、异常报表 CSV
```

## 输入 / 输出

| 环节 | 输入 | 输出 |
|---|---|---|
| 导入 | `data/raw/*.csv` 或程序化 `list[dict]` | 事实表（每行带 `file_id+line_no`+文件 sha256）+ 质量问题表 + 审计事件 |
| 校验 | 事实 + 员工主数据 + 节假日日历 + 规则包版本 | `run` 三元组、`finding`（分级/整数指标/条文/行级来源）、复核单、异常报表 CSV |
| 举证 | 一个 `run` | zip：`manifest.json`（v3 含 `signature` / `artifact_sha256` / `artifacts_digest` / `verify_script_sha256` / `conclusions_sha256`）+ `findings.csv` + **`conclusions_final.csv`（只收已人工确认的条目）** + `input_files.csv` + `audit_chain.jsonl` + `quality_issues.csv` + **`responsibility.json`（责任区块）** + **`not_covered.json` / `未覆盖清单.md`** + **`inputs/`（本次结论真正依赖的原始 CSV + `inputs/manifest.json`）** + 便利脚本 `verify.py` + `verify-requirements.txt`；独立验算用发行 wheel 的 `wca-verify`，重放用 `wca replay` |
| 问答 | 一句自然语言 + 提问主体 `emp_id` | 答案 + 门禁决策（ANSWERED/EXPLAIN_ONLY/ESCALATED/REFUSED_ACL/REFUSED_NO_EVIDENCE）+ 可点开出处 + 置信/覆盖率 + 分段耗时 |
| HTTP | 会话 Cookie（**没有** `as_emp` 这类可自报身份的参数）：`GET /ask?q=…`、`GET /evidence/{run_id}`；界面 `POST /api/import` `/api/check` `/api/review/{id}/decision` `/api/export` `/api/ask` | JSON；zip 下载（响应头带三元组与链校验结果）；权限一律在服务端判 |

命令行都走同一条链路，接口只是它的一张皮：

```bash
python -m src.cli check --start 2025-09-01 --end 2026-04-30
python -m src.cli report && python -m src.cli export
python -m src.cli keygen --out var/keys/ed25519.key --public-out var/keys/ed25519.pub
python -m src.cli export --signing-key var/keys/ed25519.key   # v3 Ed25519 签名包
python -m src.cli ask "国庆当天上班加班费按几倍算" --as E004
python -m src.cli verify                        # 审计链自检
```

## 一键启动 / 一键停止（`tools/`，配置化服务清单）

```bash
uv run python tools/start_services.py            # 检测在跑？→ 先全停 → 再按顺序起
uv run python tools/stop_services.py             # 优雅停止 + 端口核对 + WAL 落盘
uv run python tools/stop_services.py --status    # 只看状态，不动任何东西
uv run python tools/start_services.py --json     # 机器可读结果（退出码 0/1/2）
```

服务清单在 `config/services.json`（加/减服务只改这个文件，不改代码）。要点：

- **启动前检测**：自己起过的（状态文件里 pid 还活着）就先按停止顺序全停再启动；
  端口被**陌生进程**占用则拒绝抢占，并打印 `tasklist /FI "PID eq <pid>"` 让你先认身份——不盲杀。
- **优雅停止主通道是停止文件而不是信号**：Windows 上服务以分离进程启动（否则会跟着启动器
  的控制台一起被杀，这点实测踩过），收不到控制台信号；服务自己轮询 `var/run/<name>.stop`
  后走正常退出，3s 无效补发信号，再无效升级强杀并在报告里如实标 `forced`。
- **停止后必做的两件事**：确认端口已释放（没释放就报错，不谎报成功）；
  `PRAGMA wal_checkpoint(TRUNCATE)` 把 WAL 落回主库，不留 `-wal/-shm` 半成品。
- **资源账本可核对**：服务侧每个请求开的 SQLite 连接都在依赖的 `finally` 里关掉，
  异常中断的由关停兜底关闭，退出时打印 `连接开 N / 关 N / 收尾补关 0`；
  工具自己的线程池、socket、临时文件在 `close()` 里逐项释放并回显。
- **日志**：`var/logs/<name>.log`（服务）+ `var/logs/tool-start|stop-<时间戳>.log`（工具全过程）。
- 非 `managed` 的条目（如 Ollama 11434）只做依赖预检，且由 `required_when` 决定要不要检——
  用离线 stub 时不检查，工具也永远不启动、不杀别人的模型服务。

细节、字段表与异常恢复建议见 [`docs/服务启停.md`](docs/服务启停.md)。
边界说明：这是本机单用户进程管理，不是 systemd/服务管理器替代品（无开机自启、无崩溃自动重启）。

## 关键约束（写在代码结构里，不是写在文档里）

1. **数值不由 LLM 计算，引擎也不碰钱**：`src/rules/` 与 `agent.py`、`evidence.py` 里不存在任何金额
   字段与算钱函数（`tests/test_rules_engine.py::test_rules_layer_contains_no_money_math` 逐文件扫
   `overtime_pay_cents/estimate_cents/authorized_final/value_cents`，命中即失败）；
   工时全部整数分钟，判定链**禁止浮点**（`util.canonical_json` 遇 float 直接抛）。
2. **报酬类规则不下违规结论**：规则元数据 `severity_kind="pay"` 的，结构上无法产出 VIOLATION
   ——是否足额支付需要工资台账，而本项目按范围声明不做薪酬核算。上限/资质类规则才可以判违规。
3. **口径有歧义就降级**：年度日历未核实、地方裁口径不一致时，严重级自动降为「需复核」，
   并把差异写进解释文本。
4. **权限只在检索层**：ACL 编译进 SQL 的 WHERE/JOIN；`RetrievalResult.candidates` 暴露进入打分的
   全部 doc_id，测试断言「无权文档连候选都不是」。
5. **结论必挂条文**：`Finding` 没有 citations 就构造失败；评测集每条 `basis` 都要能在语料里解析。
6. **审计链只追加**：genesis 绑定 engine+rule_pack；已有复核结论不许覆盖，只能追加新单。
7. **接口面是白名单不是数量**：`tests/test_web_authz.py` 逐条列举允许的路径与写语义（GET 只读、POST 才写），`openapi_url` 关闭，扩接口必须在测试里显式登记；身份一律来自会话，接口不接受自报 `as_emp`。
8. **事实按内容唯一，不按文件唯一**（V1.1）：`punch` 上 `(emp_id, event_ts, punch_type, device_id)`
   唯一索引——换文件名重传不二次入账，重复行记 `QUAL-DUP` 留痕。
9. **质量缺口必须可见**（V1.1）：整行被拒收=该日事实不完整，必须汇成 `QUAL-02` 结论并自动开复核单；
   归属不到人的汇成一条「(未归属)」，异常报表用 LEFT JOIN（INNER JOIN 会把它们丢掉）。
10. **指纹只覆盖真正引用到的输入**（V1.1）：范围外文件的新增不改变本次 `input_fingerprint`；
    旧的「全库登记文件」口径保留为可选参数，取证时可对照。

## 异常处理要点

- 导入层：任何一行异常（含 `None/bool/NaN/bytes/dict/list` 等非字符串入参）都被隔离成质量记录，
  **不允许打断整个导入**；必填字段畸形=整行拒收，可选字段畸形=置空+降级留痕。
- 判定层：未收录年份抛 `YearNotCovered` 并落 SCOPE-01；周期被校验区间截断时不出周期超额结论。
- 检索层：向量后端不可用 → 如实降级 BM25 并标记 `degraded_from`。
- 生成层：provider 不可达 → 回退离线 stub 并在答案元数据里标注降级，不静默成功。
- 出口层：答案出现不在白名单的数字 → 整条改写为「只解释规则、不给数」+ 转人工复核；
  无出处 → 拒答；覆盖率/置信度低于阈值 → 只解释。

## 验收标准对照（方案 §8 的 A1–A12）

| 编号 | 现在状态 | 怎么验 |
|---|---|---|
| A1 ★ 数值不由 LLM 算 | **已达成** | `tests/test_agent_guard.py`（含「模型擅自造数被拦下」用例）+ `guard.py` 白名单；变异测试 M10 验证该断言有效 |
| A2 ★ 标准答案有可复核条文 | **已达成** | `tests/test_acceptance.py::test_golden_set_citations_resolve_to_corpus`；条文号在 `docs/字段口径与条文依据.md` 第三节 |
| A3 ★ ACL 越权召回 0 | **已达成（离线实测）** | `tests/test_acl_retrieval.py` 断言打在候选集；评测 `acl_leak=0`；变异测试 M5（改成先召回再过滤）被捕获 |
| A4 ★ 错承诺 0 | **已达成（离线实测）** | `tests/test_agent_guard.py`；评测 `wrong_commitment=0`；变异测试 M11 被捕获 |
| A5 ★ 测试有鉴别力 | **已达成** | `python tools/mutation_test.py`：v4 时注入 20 捕获 20；v5 扩到 **31 注入 / 31 捕获**，还原 MD5 一致（工装自身曾报出一条**不存在的漏网**，修法与记录见 `reports/优化验证.md` 第四节的 `tools/mutation_test.py` 出处） |
| A6 测试可跑且可复现 | **已达成** | v4 时点仓库副本 + **无 `.env`**，依赖走 `uv sync`：`uv run python -m src.cli all`（rc=0）→ `uv run python -m pytest tests/ -q -m "not llm"` = **197 passed / 1 deselected**（历史记录；当前工作区为 **549 passed / 8 skipped** 实测（相对第六轮 545 增加 4 项跨文件重复行与 artifacts 稳定性测试），带 PG **572 passed / 1 skipped / 1 deselected**（2026-11-04 实测）；2026-11-04 新增 0.4.5 发行物干净 venv 演练：只装 wheel + 带哈希锁，在仓库外 venv 内对四个第七轮包（engine-only、confirmed、cross-db、reverse-order）执行 `wca-verify`/`wca replay`，五项外部门禁齐全才 `RESULT OK`；`SHA256SUMS.sig` 验签通过；但这**不是**全量 pytest 干净环境复跑，A6 仍按上述历史记录，不冒充复验）；三元组与本机库逐字符一致。需求文档已同步修订到 **v2.1**（US-EV-01/NFR-07 的验收命令改为 uv，裁决 D-07），所以这不是「实现偏离需求」，是需求本身按决定改了；换 uv 之前那一趟走的是 `pip install -r requirements.txt`，那段历史保留在 `reports/干净环境复跑.md`；
  且旧版 `export --sign-as → replay → 包内 verify.py` 整条复核链同一趟跑通（`reports/干净环境复跑.md`；历史记录；现独立验算用发行 wheel 的 `wca-verify`，包内 `verify.py` 只是便利脚本；旧命令名现为 `--record-delivery-as`，`--sign-as` 仍保留为迁移别名、非密码学签名） |
| A7 行级可追溯 | **已达成** | `tests/test_ingest_quality.py` + 举证包 `findings.csv` 的 `source_rel_path/source_line_no` |
| A8 举证包可复核 | **已达成** | `test_exported_package_reproduces_same_triple`（同输入重跑）+ `tests/test_replay.py`（**把包内输入喂回引擎逐项比三元组**，改输入必须报不一致）；`tests/test_signature.py` 15 项守住 v3 签名/输入摘要/结论集哈希/外部 pin/旧包兼容；`tests/test_projection.py` 5 项守住投影字段清单/裁剪/replay；`tests/test_anchor_projection.py` 5 项守住五段锚点；`tests/test_producer.py` 2 项守住 producer 版本指纹与 `PRODUCER FAIL` 失败关闭；`tests/test_package_binding.py` 28 项守住工件逐文件哈希/`artifacts_digest`/包内 `verify.py` 哈希/findings 反算摘要/额外文件失败关闭/七种坏包/五项门禁/早退状态/`--anchor-file` 兜底/evidence 环境变量与显式优先级；`tests/test_evidence_digest.py` 13 项守住 `conclusion_digest` 稳定为 `5dc46558…`（0.4.8 单批形状）、同 run 重导与重复确认的 `artifacts_digest` 稳定（旧 `01bd` 含 DB `file_id`，仅历史）、跨 run/跨库/反向导入 `inputs_digest` 与四联值稳定、QUAL/OFF 行引用只用相对路径、单条 evidence 只改 evidence 摘要、删除 evidence 失败关闭、旧包分档与 24 条清单；`tests/test_cross_file_duplicates.py` 2 项守住多 punch 文件重复行在两种导入顺序下四联值相同（含 >20 行聚合路径）；另 4 项守住结论集纪律、交付登记人入链、责任区块与未覆盖清单随包给出。2026-11-04 0.4.5 发行物干净 venv 实测：四个第七轮包 `wca-verify` 输出 `RESULT OK`（必须五项外部门禁齐全），`EVIDENCE DIGEST OK ... / external=OK`，`wca replay` 三元组逐项 `=`；`handoff/20261104-第七轮整改/` 的 engine-only（116/0）、confirmed（116/2）、cross-db（116/0）、reverse-order（116/0）四包均验通；包内 `policies/` 5 个文件纳入工件哈希/签名，`ARTIFACTS OK checked=14`；`未覆盖清单.md` 逐条列 24 条证据定位（6/17/1） |
| A9 性能口径诚实 | **已达成** | `docs/口径声明.md` 每个数字标实测/设计值/未测；`tests/test_acceptance.py` 检查 |
| A10 ★ 无虚假宣称 | **已达成** | `tests/test_acceptance.py::test_no_false_claims_in_docs_and_code` 扫 README/docs/src/evals/data，禁词命中数=0 |
| A11 合成数据如实标注 | **部分** | 生成器与 README 已明示合成+seed；**「字段语义取得人事部门口径确认」这句不成立**（F-001 未完成，见下） |
| A12 演示脚本自洽 | **待盲跑** | 脚本内命令已机械校验存在；仍需真人按脚本盲跑一遍计时 |

## 当前状态（2026-11-02，规则包 v5）

- **P0 闸门 OW-02 条文依据**：**通过**——J1~J6 全部核到条号级 + 原文逐字摘录 + 生效/修订日期 + 可点开 URL，
  核对日期 2026-10-08，13 项未核实单独列出（见 `docs/字段口径与条文依据.md` 第五节与 `reports/P0-闸门.md`）。
- **P0 闸门 OW-01 字段口径**：**通过**——抽 10 个字段 10 个有公开出处（其中 6 个只到厂商公开文档级）；
  用户 2026-10-08 裁定"厂商公开文档级计入公开出处"，故按 10/10 通过。
  若改天只认法规/官方模板级，则实际 3/10，按需求 §7.3-1 应判不通过并停手（判据已写在
  `docs/字段口径与条文依据.md` 第六节 C-1，改口径要重跑闸门）。
  字段语义来源是公开资料，**未经 HR 访谈核对**（本项目不做访谈，此类确认表述永久禁写）。
- **本轮已完成**：判据收窄（引擎去金额、综合/不定时退出并改记 SCOPE-02/03）→ 规则包 v3；
  三市分档（`config/region_profile.json` + `src/region_profile.py`，未建档城市记 `SCOPE-04`）→ 规则包 v4；
  无凭证可跑（`pytest.ini` + `llm` 标记 + 云不可达打桩测试）、外发最小化（出站白名单视图）、
  评测集按新判据重算（70 条，含三市题与跨城隔离回归）、支撑文档补齐、
  **Web 界面 3 视图 + 最小登录**（`src/web/`：服务端判权、scrypt 口令、HttpOnly 会话、身份取自会话）、
  **举证包收口**：新增对外结论集 `conclusions_final.csv`（只收已登记具名人工结论）、责任区块
  `responsibility.json`（机器/AI/人/交付登记人各做了什么）、`not_covered.json` + `未覆盖清单.md`，
  交付事件登记入口为 `record_delivery_event()`（CLI `--record-delivery-as`；旧别名
  `sign_package()`/`--sign-as`），**只写 `evidence.sign` 审计事件，不做密码学签名**；
  **举证包再自含本次结论依赖的原始 CSV（`inputs/`）**，
  新增 `python -m src.cli replay <包>` 把输入喂回引擎重比三元组（US-EX-01 由「要别人做」变成「我已自验」）。
- **干净环境复跑已做**（`reports/干净环境复跑.md`）：新建 venv、仓库副本里**不放 `.env`**、数据现场生成，
  两条命令跑通且三元组与本机库一致。这一趟还挖出并修掉一个真实缺陷：`src.cli all` 因手工拼参数包
  在导出步 `AttributeError`（测试全绿但 README 第一条命令跑不通），现改为逐步复用子命令自己的解析结果，
  并由 `tests/test_cli_surface.py`（20 项）机械对账"注册了什么参数 / 函数读了什么参数"。
- **仍未做**：界面在真实浏览器里的**真人点击与可用性观察**（本轮用真实 uvicorn 服务 + 页面内脚本取服务端响应，
  不是人机工程）；第二人按演示脚本盲跑计时；1,000 个真实员工规模。
- 检索/端到端 P95、导出耗时：本地离线 stub 轨**已实测**；云端与向量后端**未测**。
- 云 API 与 embedding 单价：**未取一手价**，所以本 README 不出现任何成本数字。

## 界面（P6）：3 视图 + 最小登录

```bash
uv run python tools/start_services.py   # 起 API：http://127.0.0.1:9763（必须用 uv run，见下）
uv run python tools/stop_services.py    # 优雅停止
```

Web 监听与 TLS 相关配置（默认值都在 `.env.example`）：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `WCA_HOST` | `127.0.0.1` | `src.api_server` 读取的进程环境变量；服务管理器的实际绑定以 `config/services.json` 的 `host` 为准（启动时注入同名变量）。默认只绑本机。改成 `0.0.0.0`/局域网地址时，启动期会检查配置账号与数据库 `app_user`，仍有 `wca-demo-*` 演示口令就拒绝启动。直接 `uvicorn` CLI 以 `--host` 为准，本变量不参与绑定。 |
| `WCA_HTTPS_MODE` | `false` | 反向代理终止 TLS 时**必须显式设为 `true`**：即使请求 scheme 是 `http`，会话 Cookie 也带 `Secure`。它只影响 Cookie/传输判定，不会改变 `scope["server"]` 的绑定判定。 |
| `WCA_HSTS` | `false` | 只有真实 HTTPS（`scheme=https`）且显式 `true` 才下发 `Strict-Transport-Security`；HTTP 部署保持 `false`，默认不加 `includeSubDomains`。 |

请求层还有一道演示口令闸门：直接 `uvicorn src.api:app --host 0.0.0.0` 启动时，`create_app` 拿不到真实绑定地址，因此请求层以 **ASGI `scope["server"]` 的服务端地址**判定——非回环/通配绑定会复检配置与数据库，命中演示口令（或检查本身不可用）返回 **503**，不提供服务。`scope["server"]` 缺失或非法时同样 **503 失败关闭**。**`Host` / `X-Forwarded-Host` 只写日志，不参与放行判断**，请求方伪造 `Host: 127.0.0.1` 不能绕过。注意：若反向代理从本机回环连入，`scope["server"]` 可能显示回环地址；公网代理场景仍应先改掉演示口令，不能只依赖这道闸。

| 视图 | 路径 | 谁能用 | 干什么 |
|---|---|---|---|
| ① 导入与异常 | `/` | OP / AD | 上传 CSV → 质量门禁与异常清单（可展开到 `文件:行号`）；选**城市档**发起校验 |
| ② 复核台 | `/review` | RV / AD | 逐条登记具名人工结论、**录入金额**、登记交付事件并导出举证包（非密码学签名） |
| ③ 制度问答 | `/qa` | 全部角色 | 带可点开出处与证据覆盖率的解释；金额类只解释不给数；页面标"内容由 AI 生成" |

演示账号（`config/users.json`，库里只存 scrypt 哈希；口令仅对应本机合成数据）：
`op1/wca-demo-op1`（OP+EM，绑 E001）、`rv1/wca-demo-rv1`（RV，绑主管 E008）、
`em1/wca-demo-em1`（EM，绑 E004）、`ad1/wca-demo-ad1`（AD，绑 E002）。
**先跑过 `python -m src.cli all`** 再登录：账号要绑定已导入的员工主数据，空库登录会被明确拒绝并说明原因。

一条必须记住的坑：**别用系统/全局 python 直接跑 `tools/start_services.py`**。
它会把 `<python>` 换成"自己是谁就用谁"，于是服务子进程继承那个环境、死在 `ImportError` 上。
现在预检会**在启动之前**拦住并给出处置命令（`missing-interpreter-deps`），不再等 30 秒后误指"端口被占"。

三条刻意的取舍：
- 权限只在服务端判——用 OP 会话直连 `/review` 或复核接口是 **403**，不是"前端把按钮藏了"；
- 提问主体只来自会话，接口**没有** `as_emp` 这类可自报身份的参数；
- 界面的导入/校验/导出**调用脚本用的同一批函数**，不存在第二套实现（结果不一致时以脚本为准，界面当天退回）。

## 隐私声明（方案 R4）

全程合成数据，不含任何真实个人信息：姓名用化名，薪酬/考勤为虚构数值。
本项目**不导入**人脸、指纹、行踪轨迹等敏感数据；文档中引用的《个人信息保护法》条文
只是判据依据，不代表任何合规资质或备案结论。举证包与数据库产物默认不入库（见 `.gitignore`）。

## 读代码的建议顺序

`docs/字段口径与条文依据.md` → `src/rules/rulepack.py`（判据）→ `src/guard.py`（红线怎么执行）
→ `src/kb/acl.py` + `src/retrieve.py`（权限怎么下推）→ `evals/judge.py`（怎么打分）
→ `tools/mutation_test.py`（怎么证明测试有鉴别力）→ `tools/perf_probe.py` + `reports/优化验证.md`
（怎么把「优化了多少」变成一条可复跑的命令）。

## 已知局限（不用你问，我先说）

1. 一天只取首末卡，多段班次不拼接；
2. 综合计算工时与不定时工时**不判**（v3 起退出范围），只出 `SCOPE-02/03` 未覆盖标记；
3. 夜班只统计分钟数，无夜班津贴判定依据（国家无统一标准）；
4. 评测的意图命中率建立在离线 stub 上，换真模型必须重测；
5. 字段口径取自公开资料、**未经 HR 访谈核对**；跨零点归属与出差计时长无法规依据（参数为自设）；
6. 界面只做到"能走完三条闭环的操作路径"：3 视图 + 最小登录，无美化、无图表、无响应式适配，
   会话与口令是本机演示用（真实企业要换目录服务与正式会话后端）。


