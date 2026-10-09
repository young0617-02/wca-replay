# 工时合规校验 + 制度问答 Agent（MVP 原型）

> **一句话**：这不是考勤系统，是**一条不会赔钱的判断链**——加班倍数、月上限、法定节假日
> 认定全部由确定性引擎算出，AI 只负责把提问理解成查询计划、把已算好的事实叙述成人话，
> 出口还有数字白名单与「重大事项只解释不给数」两道闸。
>
> **定位**：求职作品集项目，单人自主。数据 **100% 合成**（seed 可复现），法条基准 **公开可查**，
> **没有任何真实用人主体**，也**没有**生产环境运行记录。
>
> 简历口径（照方案 §4.8 钉死）：`工时合规校验 Agent（合成数据 + 公开法条基准，单人自主，无真实用人主体）`

---

## 30 秒跑起来

```bash
uv sync                                                  # 唯一的依赖通道：按 uv.lock 精确重建 .venv（校验 sha256）
uv run python -m src.cli status                          # 用 `uv run` 就不用记 .venv 的路径
# 依赖只走 uv（2026-10-09 决定）。`uv sync` 建的 .venv 里没有 pip；
# 需求文档已同步修订到 v2.1：US-EV-01 / NFR-07 的验收命令就是上面这条（裁决 D-07）。
# 下面所有命令都等价于先 `source .venv/bin/activate` 再 `python -m …`。
cp .env.example .env                                     # 不填也能跑：默认全离线
uv run python -m src.cli all                             # 生成→导入→建库→校验→报表→举证包
uv run python -m pytest tests/ -q -m "not llm"           # 193 项，约 45 秒，无网络、无云凭证
uv run python evals/judge.py --write-report              # 70 条评测集打分
uv run python tools/mutation_test.py                     # 注入 20 个缺陷，看测试抓不抓得住
uv run python tools/perf_probe.py --export --amplify 1000  # 规模与导出耗时（在库副本上测）
uv run python -m src.cli replay var/packages/<run_id>.zip  # 拿包自己重放：重导输入→重跑引擎→比三元组
```

核心校验链路只依赖 **Python 标准库 + pytest**；只有 Web 界面与只读接口需要 FastAPI（没装时界面测试如实 skip，
`python -m src.cli ask` 走的是同一条链路）。
向量检索默认**不启用**（未下载 embedding 模型），启用不了时代码会如实降级成 BM25 并在结果里标注。

演示路径与讲解词：`docs/演示脚本-30分钟.md`。

## 现在就能看到的结果（本机实测，2026-10-08，规则包 v4）

| 指标 | 实测 |
|---|---|
| 测试 | `193 passed / 1 deselected`（`-m "not llm"`，离线；唯一被筛掉的用例需要真实云凭证） |
| 干净环境复跑 | 三轮，全部在**无 `.env`** 的仓库副本里跑：前两轮走 pip（175 passed），第三轮起**只走 uv**（`uv sync` → **193 passed / 1 deselected**，43.9 s），`cli all` rc=0、三元组与本机库逐字符一致，`export --sign-as → replay → 独立 verify.py` 整条复核链同样在新环境跑通（`reports/干净环境复跑.md`） |
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
| 结论条数与对账 | v2 110 条 → v3/v4 **101 条**，差值逐条可解释（`reports/判据修订.md`） |
| 外部重放（US-EX-01） | 包内自带 `inputs/` 原始 CSV；`replay` 把输入喂回引擎重比三元组；改一个打卡时间必须报 `≠`（`tests/test_replay.py` 7 项 + 变异体 M20） |
| 对外结论集 | 演示库 101 条异常里**只有 2 条**有人工结论进了对外结论集，其余 99 条留在 `findings.csv` 等处置——这是纪律，不是漏数 |
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

## 它能做什么

1. **举证级工时合规校验**（价值核心，规则包 `rp-2026.10.gd-pilot-standard.v4`）
   16 条确定性规则，只判 **8 小时标准工时**：工作日延长工时、休息日与补休、法定节假日当天 300%、
   每日/每月加班上限、每周至少休息一日、周 40/44 小时、跨零点切分、夜间时段、数据质量、
   内部制度预警、年度日历未核标记、**工时制未覆盖标记（SCOPE-02/03）**。
   每条异常给三级分级（**可申辩 / 需复核 / 明显违规**）+ 触发规则 ID + 条文依据 + 原始行号。
   城市分三档（`config/region_profile.json`）：广州、佛山适用《广东省工资支付条例》第 20 条，深圳适用特区条例第 18 条，未建档城市只出国家层面结论并记 `SCOPE-04`。
   **引擎不产出任何应付金额**（需求 D-03）：只出小时数与法定倍数档位，金额由 HR 负责人具名录入。
   综合计算工时与不定时工时的周期超额/豁免判定**已退出本期范围**，命中只记未覆盖，不套用标准工时硬判。
2. **不可篡改的举证包**
   审计 hash 链 + 一次导出生成「规则版本 + 输入指纹 + 结论摘要」三元组；包内含独立 `verify.py`，
   复核方不需要相信我——自己重算链即可，改一条就会在第一个断点报错。
   包内另附**对外结论集**（只收已登记具名人工结论的条目）、**责任区块**（机器算了什么、AI 碰过什么、
   人确认了什么、谁签的字）、**未覆盖清单**（本期不判什么、哪些没测，自己先说），
   以及**本次结论真正依赖的原始 CSV**（`inputs/`）。
   所以复核方拿着包就能自己走完两步：`verify.py` 独立重算链与输入哈希（只用标准库），
   `python -m src.cli replay <包>` 把包内输入喂回引擎、比对三元组——**不必回头向我索要数据**。
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
│   └── perf_probe.py             # 性能探针：SQL 计数 + 多次采样中位耗时（在库副本上测）
├── tests/                        # 193 项：判据/质量门禁/ACL/守卫/接口/界面权限/城市档/启停/CLI 表面/重放/依赖口径/验收（含文档链接自检）
└── reports/                      # 评测结果.md、变异测试.md、优化验证.md、判据修订.md、
                                  # 性能探针.json、P0-闸门.md、异常报表 CSV
```

## 输入 / 输出

| 环节 | 输入 | 输出 |
|---|---|---|
| 导入 | `data/raw/*.csv` 或程序化 `list[dict]` | 事实表（每行带 `file_id+line_no`+文件 sha256）+ 质量问题表 + 审计事件 |
| 校验 | 事实 + 员工主数据 + 节假日日历 + 规则包版本 | `run` 三元组、`finding`（分级/整数指标/条文/行级来源）、复核单、异常报表 CSV |
| 举证 | 一个 `run` | zip：`manifest.json` + `findings.csv` + **`conclusions_final.csv`（只收已人工确认的条目）** + `input_files.csv` + `audit_chain.jsonl` + `quality_issues.csv` + **`responsibility.json`（责任区块）** + **`not_covered.json` / `未覆盖清单.md`** + **`inputs/`（本次结论真正依赖的原始 CSV + `inputs/manifest.json`）** + 独立 `verify.py`；重放：`python -m src.cli replay <包>` |
| 问答 | 一句自然语言 + 提问主体 `emp_id` | 答案 + 门禁决策（ANSWERED/EXPLAIN_ONLY/ESCALATED/REFUSED_ACL/REFUSED_NO_EVIDENCE）+ 可点开出处 + 置信/覆盖率 + 分段耗时 |
| HTTP | 会话 Cookie（**没有** `as_emp` 这类可自报身份的参数）：`GET /ask?q=…`、`GET /evidence/{run_id}`；界面 `POST /api/import` `/api/check` `/api/review/{id}/decision` `/api/export` `/api/ask` | JSON；zip 下载（响应头带三元组与链校验结果）；权限一律在服务端判 |

命令行都走同一条链路，接口只是它的一张皮：

```bash
python -m src.cli check --start 2025-09-01 --end 2026-04-30
python -m src.cli report && python -m src.cli export
python -m src.cli ask "国庆当天上班加班费按几倍算" --as E004
python -m src.cli verify                        # 审计链自检
```

## 一键启动 / 一键停止（`tools/`，配置化服务清单）

```bash
python tools/start_services.py            # 检测在跑？→ 先全停 → 再按顺序起
python tools/stop_services.py             # 优雅停止 + 端口核对 + WAL 落盘
python tools/stop_services.py --status    # 只看状态，不动任何东西
python tools/start_services.py --json     # 机器可读结果（退出码 0/1/2）
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
| A5 ★ 测试有鉴别力 | **已达成** | `python tools/mutation_test.py`：注入 20 捕获 20，还原 MD5 一致（工装自身曾报出一条**不存在的漏网**，修法与记录见 `reports/优化验证.md` 第四节的 `tools/mutation_test.py` 出处） |
| A6 测试可跑且可复现 | **已达成** | 仓库副本 + **无 `.env`**，依赖走 `uv sync`：`uv run python -m src.cli all`（rc=0）→ `uv run python -m pytest tests/ -q -m "not llm"` = **193 passed / 1 deselected**；三元组与本机库逐字符一致。需求文档已同步修订到 **v2.1**（US-EV-01/NFR-07 的验收命令改为 uv，裁决 D-07），所以这不是「实现偏离需求」，是需求本身按决定改了；换 uv 之前那一趟走的是 `pip install -r requirements.txt`，那段历史保留在 `reports/干净环境复跑.md`；
  且 `export --sign-as → replay → 独立 verify.py` 整条复核链同一趟跑通（`reports/干净环境复跑.md`） |
| A7 行级可追溯 | **已达成** | `tests/test_ingest_quality.py` + 举证包 `findings.csv` 的 `source_rel_path/source_line_no` |
| A8 举证包可复核 | **已达成** | `test_exported_package_reproduces_same_triple`（同输入重跑）+ `tests/test_replay.py`（**把包内输入喂回引擎逐项比三元组**，改输入必须报不一致）；另 4 项守住结论集纪律、签发人入链、责任区块与未覆盖清单随包给出 |
| A9 性能口径诚实 | **已达成** | `docs/口径声明.md` 每个数字标实测/设计值/未测；`tests/test_acceptance.py` 检查 |
| A10 ★ 无虚假宣称 | **已达成** | `tests/test_acceptance.py::test_no_false_claims_in_docs_and_code` 扫 README/docs/src/evals/data，禁词命中数=0 |
| A11 合成数据如实标注 | **部分** | 生成器与 README 已明示合成+seed；**「字段语义取得人事部门口径确认」这句不成立**（F-001 未完成，见下） |
| A12 演示脚本自洽 | **待盲跑** | 脚本内命令已机械校验存在；仍需真人按脚本盲跑一遍计时 |

## 当前状态（2026-10-08，规则包 v4）

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
  `responsibility.json`（机器/AI/人/签发人各做了什么）、`not_covered.json` + `未覆盖清单.md`，
  签发入口 CLI 与界面共用同一个 `sign_package`；**举证包再自含本次结论依赖的原始 CSV（`inputs/`）**，
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
python tools/start_services.py        # 起 API：http://127.0.0.1:8000
python tools/stop_services.py         # 优雅停止
```

| 视图 | 路径 | 谁能用 | 干什么 |
|---|---|---|---|
| ① 导入与异常 | `/` | OP / AD | 上传 CSV → 质量门禁与异常清单（可展开到 `文件:行号`）；选**城市档**发起校验 |
| ② 复核台 | `/review` | RV / AD | 逐条登记具名人工结论、**录入金额**、签发并导出举证包 |
| ③ 制度问答 | `/qa` | 全部角色 | 带可点开出处与证据覆盖率的解释；金额类只解释不给数；页面标"内容由 AI 生成" |

演示账号（`config/users.json`，库里只存 scrypt 哈希；口令仅对应本机合成数据）：
`op1/wca-demo-op1`（OP+EM，绑 E001）、`rv1/wca-demo-rv1`（RV，绑主管 E008）、
`em1/wca-demo-em1`（EM，绑 E004）、`ad1/wca-demo-ad1`（AD，绑 E002）。
**先跑过 `python -m src.cli all`** 再登录：账号要绑定已导入的员工主数据，空库登录会被明确拒绝并说明原因。

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
