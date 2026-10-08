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
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # 不填也能跑：默认全离线
python -m src.cli all                                    # 生成→导入→建库→校验→报表→举证包
python -m pytest tests/ -q                               # 118 项，约 46 秒，无网络无模型
python evals/judge.py --write-report                     # 66 条评测集打分
python tools/mutation_test.py                            # 注入 17 个缺陷，看测试抓不抓得住
python tools/perf_probe.py --reference --repeat 5        # 性能前后对照（在库副本上测）
```

核心校验链路只依赖 **Python 标准库 + pytest**；只有 2 个只读 HTTP 接口需要 FastAPI。
向量检索默认**不启用**（未下载 embedding 模型），启用不了时代码会如实降级成 BM25 并在结果里标注。

演示路径与讲解词：`docs/演示脚本-30分钟.md`。

## 现在就能看到的结果（本机实测，2026-10-07）

| 指标 | 实测 |
|---|---|
| 测试 | `118 passed`（离线，含启停真进程用例；系统 Python 缺 FastAPI 时接口 5 项如实跳过） |
| 变异测试 | 注入 17 个缺陷，**捕获 17**，还原 MD5 全部一致 |
| 意图 Top-1 / Hit@5 / MRR | 66/66 · 34/34 · 0.689 |
| 数值工具首次成功率 / 引用忠实率 | 30/30 · 66/66 |
| **错承诺条数（红线）** | **0** |
| **越权召回条数（红线）** | **0** |
| 检索段 P95 / 端到端 P95 | 5.3 ms / 7.0 ms（58 条语料、离线 stub） |
| 整轮校验（12 员工 × 242 天 = 2,904 员工日） | **冷表首轮 429.4 ms**；稳态墙钟中位 199.8 ms（样本 129.3–342.4） |
| 整轮 SQL 语句数 | 3,229 条（读侧仅 85 条，其余是每日一行的落库写入） |
| 举证包导出 | 110 行 74.5 ms（5 次采样中位，样本 70.2–141.9）；复制到 1,000 行 159.1 ms |
| 服务启停 | 启动到就绪 1.40 / 1.42 s；优雅停止 0.78 / 0.89 s（两轮各测一次）；停止后端口已释放、状态文件为空、WAL 已落盘 |

以上数字的前提条件、以及**哪些是设计值、哪些根本没测**，全部写在
[`docs/口径声明.md`](docs/口径声明.md)。云端延迟、token 账单、向量检索收益、真实字段口径：**未测**。
V1 → V1.1 优化的前后对照（含没达成的目标）在 [`reports/优化验证.md`](reports/优化验证.md)；
判据为什么必须升版本（规则包 v1 → v2）记在 [`reports/判据修订.md`](reports/判据修订.md)。

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

1. **举证级工时合规校验**（价值核心）
   20 条确定性规则：工作日延长工时、休息日与补休、法定节假日当天 300%、每日/每月加班上限、
   每周至少休息一日、周 40/44 小时、综合计算工时周期超额、不定时工时豁免（含深圳更严的节假日口径）、
   特殊工时审批缺失、岗位适用性、跨零点切分、夜间时段、数据质量、内部制度预警。
   每条异常给三级分级（**可申辩 / 需复核 / 明显违规**）+ 触发规则 ID + 条文依据 + 原始行号。
2. **不可篡改的举证包**
   审计 hash 链 + 一次导出生成「规则版本 + 输入指纹 + 结论摘要」三元组；包内含独立 `verify.py`，
   复核方不需要相信我——自己重算链即可，改一条就会在第一个断点报错。
3. **带 ACL 的制度问答**
   权限谓词在检索层下推（SQL 的 WHERE/JOIN），未授权条目**进不了候选集**；
   答案必须带可点开出处、证据覆盖率与置信度门禁；「该付多少加班费」这类重大事项**只解释规则、
   不给最终数额承诺**，并自动开人工复核单。
4. **可审计的评测**
   66 条三档评测集（纯检索 26 / 数值校验 24 / 混合 16），每条标准答案都有**手工推导式**与条文号，
   判分器逐条比对，红线不为 0 时退出码非 0。

## 它明确不做什么

不做 SaaS、多租户、审批流引擎、排班优化、社保与薪酬核算、私有化交付、考勤硬件对接、前端界面；
不追求任何真实用人主体。**下判决也不做**：系统只出「分级 + 测算明细（`authorized_final=0`）」，
因为 AI 结论在劳动争议里不构成安全证据。

> 关于「薪酬」的边界要说清楚：我算了加班报酬的**参考测算明细**（举证链需要数值可溯），
> 但没做工资表、个税、社保、实发，所以这叫测算明细，不叫薪酬模块。

---

## 目录结构

```
worktime-compliance-agent/
├── README.md
├── requirements.txt              # 锁版本，必含 pytest
├── .env.example                  # 全部待填项集中在这里，带 TODO
├── 项目方案-*.md                  # 方案与优化方案（受禁词扫描覆盖）
├── 项目汇报-*.md                  # 成本收益与方向判断（同受扫描覆盖）
├── docs/
│   ├── 字段口径与条文依据.md      # F-001 F-002（本项目合法性的根，含 P0 闸门状态）
│   ├── 口径声明.md                # 实测 / 设计值 / 未测 三态
│   ├── 架构图.md                  # 模块边界 + 数据结构 + 异常处理策略
│   ├── 待确认清单.md              # 17 条需要人回答的问题，我不猜
│   ├── 服务启停.md                # 一键启动/停止的行为边界与恢复建议
│   ├── 需求文档.md                # 用户故事 + 验收标准 + 边界与异常（从代码逆向整理）
│   ├── 技术文档.md                # 技术栈、分层架构、调用关系、数据流、异常矩阵
│   ├── 架构图-Python版.md         # 分层骨架不变，Java 系技术逐层换成本仓库 Python 方案
│   ├── 简历-AI应用开发工程师.md   # 以本项目为核心的简历（量化项只用实测数字）
│   └── 演示脚本-30分钟.md
├── config/
│   └── services.json              # 服务清单（启停工具读它，加服务不改代码）
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
│   ├── golden_set_v1.jsonl       # F-011 66 条，三档，含手工推导
│   └── judge.py                  # F-012 判分器
├── tools/
│   ├── start_services.py         # 一键启动
│   ├── stop_services.py          # 一键优雅停止（含 --status）
│   ├── mutation_test.py          # F-012 变异测试（MD5 基线校验 + 字节码缓存清理）
│   └── perf_probe.py             # 性能探针：SQL 计数 + 多次采样中位耗时（在库副本上测）
├── tests/                        # 118 项：判据/质量门禁/ACL/守卫/接口/启停/优化回归/验收机械检查
└── reports/                      # 评测结果.md、变异测试.md、优化验证.md、判据修订.md、
                                  # 性能探针.json、P0-闸门.md、异常报表 CSV
```

## 输入 / 输出

| 环节 | 输入 | 输出 |
|---|---|---|
| 导入 | `data/raw/*.csv` 或程序化 `list[dict]` | 事实表（每行带 `file_id+line_no`+文件 sha256）+ 质量问题表 + 审计事件 |
| 校验 | 事实 + 员工主数据 + 节假日日历 + 规则包版本 | `run` 三元组、`finding`（分级/整数指标/条文/行级来源）、复核单、异常报表 CSV |
| 举证 | 一个 `run` | zip：`manifest.json` + `findings.csv` + `input_files.csv` + `audit_chain.jsonl` + `quality_issues.csv` + 独立 `verify.py` |
| 问答 | 一句自然语言 + 提问主体 `emp_id` | 答案 + 门禁决策（ANSWERED/EXPLAIN_ONLY/ESCALATED/REFUSED_ACL/REFUSED_NO_EVIDENCE）+ 可点开出处 + 置信/覆盖率 + 分段耗时 |
| HTTP | `GET /ask?q=…&as_emp=…`；`GET /evidence/{run_id}` | JSON；zip 下载（响应头带三元组与链校验结果） |

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

1. **数值不由 LLM 计算**：算钱只有一个入口 `rules/quantities.overtime_pay_cents`；
   工时全部整数分钟，金额全部整数分，判定链**禁止浮点**（`util.canonical_json` 遇 float 直接抛）。
2. **报酬类规则不下违规结论**：规则元数据 `severity_kind="pay"` 的，结构上无法产出 VIOLATION
   ——是否足额支付需要工资台账，而本项目按范围声明不做薪酬核算。上限/资质类规则才可以判违规。
3. **口径有歧义就降级**：年度日历未核实、地方裁口径不一致时，严重级自动降为「需复核」，
   并把差异写进解释文本。
4. **权限只在检索层**：ACL 编译进 SQL 的 WHERE/JOIN；`RetrievalResult.candidates` 暴露进入打分的
   全部 doc_id，测试断言「无权文档连候选都不是」。
5. **结论必挂条文**：`Finding` 没有 citations 就构造失败；评测集每条 `basis` 都要能在语料里解析。
6. **审计链只追加**：genesis 绑定 engine+rule_pack；已有复核结论不许覆盖，只能追加新单。
7. **接口只 2 个**：路由数量被测试钉死；`openapi_url` 都关了，就是为了让这条约束可机械验证。
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
| A5 ★ 测试有鉴别力 | **已达成** | `python tools/mutation_test.py`：注入 17 捕获 17，还原 MD5 一致（工装自身的一处假漏网已在 `reports/优化验证.md` §5 记录并修掉） |
| A6 测试可跑且可复现 | **已达成** | 新虚拟环境 `pip install -r requirements.txt && python -m pytest tests/ -q` → 118 passed |
| A7 行级可追溯 | **已达成** | `tests/test_ingest_quality.py` + 举证包 `findings.csv` 的 `source_rel_path/source_line_no` |
| A8 举证包可复核 | **已达成** | `tests/test_evidence_chain.py::test_exported_package_reproduces_same_triple` |
| A9 性能口径诚实 | **已达成** | `docs/口径声明.md` 每个数字标实测/设计值/未测；`tests/test_acceptance.py` 检查 |
| A10 ★ 无虚假宣称 | **已达成** | `tests/test_acceptance.py::test_no_false_claims_in_docs_and_code` 扫 README/docs/src/evals/data，禁词命中数=0 |
| A11 合成数据如实标注 | **部分** | 生成器与 README 已明示合成+seed；**「与 HR 对过字段语义」这句不成立**（F-001 未完成，见下） |
| A12 演示脚本自洽 | **待盲跑** | 脚本内命令已机械校验存在；仍需真人按脚本盲跑一遍计时 |

## 当前状态：P0 闸门还没过（重要）

- **F-002 条文依据**：已完成，联网核实到条号级，未核到项全部标注（见 `docs/待确认清单.md`）。
- **F-001 真实字段口径**：**未取得**。当前字段语义是从通用考勤形态反推的合成口径，
  只能证明代码自洽，不能证明与真实排班对齐。方案 §6 的停手判据（拿不到 → 切方向二）
  **既没满足也没被推翻**，取决于 B3 访谈。详见 `reports/P0-闸门.md`。
- 检索/端到端 P95、导出耗时：本地离线链路**已实测**，云端与向量后端**未测**。
- 云 API 与 embedding 单价：**未取一手价**，所以本 README 不出现任何成本数字。

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
2. 综合计算工时只做了周期超额，没做跨周期结转；
3. 夜班只统计分钟数，无夜班津贴判定依据（国家无统一标准）；
4. 评测的意图命中率建立在离线 stub 上，换真模型必须重测；
5. 字段口径未经真实排班表验证——这是唯一一个可能让方向整体停手的项。
