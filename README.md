# 工时合规校验与制度问答 Agent

> **一句话**：这不是考勤系统，而是一条“算得准、查得回、验得出”的判断链——加班倍数、日/月上限、法定节假日认定由确定性引擎计算；AI 只负责理解问题与组织解释，出口还有数字白名单和“重大事项只解释、不给数”两道闸。

- 当前版本：**0.4.19**（`pyproject.toml`）
- 技术栈：Python 3.12、FastAPI、PostgreSQL 18（默认）/ SQLite（显式回退）、uv 依赖管理
- 默认规则包：`rp-2026.11.gd-pilot-standard.v6`（`src/config.py` 默认值；v5 / v4 可显式选择）
- 数据：**100% 合成**（seed 固定、可复现）；法条基准来自公开可查文本
- 定位：单人自主的求职作品集与 PoC 验证工具，**没有任何真实用人主体**，也没有生产环境运行记录

> **PoC 边界**：本交付是“验证工具 + 样例举证包”的 PoC，不构成合规结论，也不能作为生产就绪依据。信任根、真实具名确认、法律文本充分性、数据合规四项尚未闭合，详见 [docs/安全与证据链现状.md](docs/安全与证据链现状.md) 与 [docs/已知残留与未闭合项.md](docs/已知残留与未闭合项.md)。

---

## 项目简介

本项目面向“多班次、多城市、标准/综合等多种工时制”的工时合规场景，演示一条完整的证据链：

1. 导入项目方已有的打卡、请假、出差、补卡与排班 CSV；
2. 用确定性规则引擎输出分级发现（可申辩 / 需复核 / 明显违规），每条带规则 ID、条文依据与原始行号；
3. 导出可离线验签、可重放的举证包，复核方无需信任导出方即可自行验算；
4. 提供带权限控制的制度问答，金额类问题只解释规则、不给最终数字；
5. 附带可审计的评测集与变异测试，用来证明测试本身有鉴别力。

系统**只输出小时数、倍数档位与三级分级**，不输出应付金额、不作违法定性。

## 核心功能

### 1. 确定性工时合规校验

- 默认规则包 v6，保留 v5 / v4 旧包回放能力；规则覆盖工作日延长工时、休息日与补休、法定节假日、日/月加班上限、每周休息、周工时、跨零点切分、夜间时段、数据质量、城市档位、审批台账覆盖、综合工时周期统计、多段班次、离线补传冲突等。
- 每条发现包含：规则 ID、严重级、整数分钟指标、条文引用、`rel_path:line_no` 行级来源。
- 城市分档由 `config/region_profile.json` 驱动；未建档城市只出国家层面结论并记未覆盖标记。
- 引擎不产出任何金额字段，规则层禁止浮点运算。

### 2. 可验签、可重放的举证包

- 一次导出生成“规则版本 + 输入指纹 + 结论摘要”三元组，并写入审计 hash 链。
- 包内包含：`manifest.json`、`findings.csv`、已确认结论集、责任区块、未覆盖清单、审计链、质量问题、本次结论依赖的原始 CSV（`inputs/`）以及便利脚本 `verify.py`。
- 支持 Ed25519 签名（schema v3）：`artifact_sha256`、`artifacts_digest`、`inputs_digest`、`evidence_digest` 等字段共同约束包体与输入。
- 复核方使用发行 wheel 的 `wca-verify` 做独立验算（不执行包内 `verify.py`），再用 `wca replay` 把包内输入喂回引擎比对三元组。

### 3. 带 ACL 的制度问答

- 权限谓词下推到检索层（SQL 的 WHERE / JOIN），无权条目不会进入候选集。
- 答案必须带可点开出处、证据覆盖率与置信度门禁；无出处拒答，覆盖率不足时只解释。
- 涉及金额、赔偿等重大事项时只解释规则并转人工复核，不给出数额承诺。
- 发往模型后端的上下文使用最小视图，不含姓名、薪酬基数、原始打卡行等字段。

### 4. 可审计的评测

- 三档评测集（纯检索 / 数值校验 / 混合），每条标准答案带手工推导式与条文号。
- 判分器逐条比对，红线指标不为 0 时退出码非 0。
- 变异测试向代码注入缺陷，验证测试能否捕获。

### 5. Web 复核界面

- 服务端判权的 3 个视图：导入与异常、复核台、制度问答；无前端框架、无构建链。
- 最小登录：口令只存 scrypt 摘要，身份来自 HttpOnly 会话；写接口强制 CSRF 校验。

### 明确不做

不做 SaaS、多租户、审批流引擎、排班优化、社保与薪酬核算、考勤硬件对接；不判断是否违法，也不计算应付金额。

## 安装与运行

### 前置条件

| 依赖 | 要求 |
|---|---|
| Python | 3.12 及以上 |
| 依赖管理 | 仅使用 `uv`（不要用 pip 直接装本项目） |
| 数据库 | PostgreSQL 18（默认）；无 PostgreSQL 时可用 SQLite 显式回退 |
| 操作系统 | Windows / Linux / macOS 均可，Web 启动脚本以 Windows 为主测环境 |

### 安装

```bash
uv sync                                   # 按 uv.lock 精确重建 .venv
cp .env.example .env                      # 再按 TODO 填写 WCA_DATABASE_URL 等配置
```

### 初始化与端到端运行

```bash
uv run python -m src.cli status           # 查看服务与配置状态
uv run python -m src.cli all              # 生成→导入→建库→校验→报表→导出
```

无 PostgreSQL 的离线环境，在 `.env` 中显式改为：

```dotenv
WCA_DB_BACKEND=sqlite
WCA_DB_PATH=var/worktime.sqlite3
```

SQLite 只是回退路径，默认后端仍是 PostgreSQL 18；配置缺失时启动会明确报错，不会静默回退。

### 启动 Web 界面

```bash
uv run python tools/start_services.py     # 默认监听 http://127.0.0.1:9763
uv run python tools/stop_services.py      # 优雅停止
uv run python tools/stop_services.py --status
```

服务清单在 `config/services.json`，增减服务只改配置，不改代码。启动前必须先用 `uv run`，不要用系统 Python 直接跑脚本。

### 命令行入口

除 `python -m src.cli` 外，安装后还提供三个控制台入口：`wca`、`wca-replay`、`wca-verify`。常用子命令：

| 子命令 | 作用 |
|---|---|
| `init` | 建库 |
| `gen` | 生成合成数据（`--seed` 可复现） |
| `ingest` | 导入 CSV（含质量门禁） |
| `kb` | 构建知识库与检索索引 |
| `check` | 运行确定性合规校验 |
| `report` | 导出异常报表 CSV |
| `export` | 导出举证包 |
| `replay` | 用包内输入重放并比对三元组 |
| `keygen` | 生成 Ed25519 签名密钥 |
| `verify` | 校验审计 hash 链 |
| `audit-scan` | 只读自检审计链（断裂、跳号、截断等） |
| `ask` | 单次制度问答 |
| `covers` | 规则命中覆盖表 |
| `users` | 配置界面账号（只写 scrypt 摘要） |
| `approval` / `approval-doc` / `approval-migrate` | 审批台账登记、只读查询与迁移 |
| `db-target` | 查看或显式重置 PostgreSQL 身份（切库唯一入口） |
| `start` / `stop` / `status` | 服务启停与状态 |
| `all` | 一键复跑全流程 |

## 主要配置

所有需要人工填写的项集中在 [.env.example](.env.example)，此处只列主要分组。

| 分组 | 变量 | 说明 |
|---|---|---|
| 数据库 | `WCA_DB_BACKEND` | `postgres`（默认）或 `sqlite` |
| 数据库 | `WCA_DATABASE_URL` | PostgreSQL 连接串，只放本地 `.env`，禁止提交 |
| 数据库 | `WCA_DB_IDENTITY_PATH` / `WCA_DB_PATH` | 库身份标记文件 / SQLite 文件路径 |
| 规则 | `WCA_RULE_PACK` | 规则包版本，代码默认 v6；改判据必须升版本号 |
| 范围 | `WCA_REGION_CODE` / `WCA_REGION_LABEL` / `WCA_WORKTIME_REGIME` | 城市与工时制锁定 |
| 模型 | `WCA_LLM_PROVIDER` | `stub`（默认，离线） / `ollama` / `cloud` |
| 模型 | `WCA_CLOUD_BASE_URL` / `WCA_CLOUD_API_KEY` / `WCA_LLM_MODEL` | 云 API 仅演示档；密钥只进 `.env` |
| 检索 | `WCA_EMBEDDING_BACKEND` | `bm25`（默认） / `exact` / `vector`，不可用时如实降级 |
| 检索 | `WCA_RETRIEVAL_TOP_K` / `WCA_MIN_EVIDENCE_COVERAGE_PERMILLE` / `WCA_CONFIDENCE_THRESHOLD_PERMILLE` | 检索与出口门禁阈值 |
| Web | `WCA_HOST` / `WCA_HTTPS_MODE` / `WCA_HSTS` | 绑定地址、反向代理 TLS、HSTS |
| 导入 | `WCA_IMPORT_WRITE_MODE` / `WCA_IMPORT_BATCH_SIZE` | 写入方式（默认 `single`）与分块行数 |
| 导出 | `WCA_EXPORT_ROW_BUDGET` | 单次导出预算行数 |

口径类参数（日/周标准工时、加班上限、跨零点切分、夜班窗口等）也可配置，但一改就要重跑评测与重建规则包版本。

## 使用示例

```bash
# 只跑校验与报表
uv run python -m src.cli check --start 2025-09-01 --end 2026-04-30
uv run python -m src.cli report
uv run python -m src.cli export

# 生成密钥并导出 v3 签名包
uv run python -m src.cli keygen --out var/keys/ed25519.key --public-out var/keys/ed25519.pub
uv run python -m src.cli export --run <run_id> --signing-key var/keys/ed25519.key

# 独立验算与重放
uv run wca-verify var/packages/<包>.zip --expect-anchor <四元组或五元组> --public-key var/keys/ed25519.pub
uv run python -m src.cli replay var/packages/<包>.zip

# 制度问答与审计链自检
uv run python -m src.cli ask "国庆当天上班加班费按几倍算" --as E004
uv run python -m src.cli verify
uv run python -m src.cli audit-scan --json
```

`wca-verify` 的退出码含义：

| 退出码 | 标签 | 处置 |
|---|---|---|
| 0 | `RESULT OK` | 包体、工件、审计链、输入、签名与外部锚点全部一致，可通过 |
| 1 | `RESULT FAIL` | 同版本同 schema 下存在真实不符或篡改，必须阻断 |
| 2 | `RESULT PARTIAL` | 外部门禁缺失或包未签名，**不得当通过** |
| 3 | `RESULT INCOMPARABLE` | 跨规则包版本或跨 schema，转人工核对，不应当作篡改 |

> **对外演示注意**：`wca all` 在不提供签名密钥时导出的是 v2 无签名包。v2 没有输入契约，不会因缺少 `inputs_digest` 这一项门禁而判 `FAIL`（该门禁记 `NOT CHECKED`），整体结果最多为 `RESULT PARTIAL`（exit 2）；但其他任何真实篡改仍判 FAIL（exit 1），加 `--require-signature` 时无签名即 `SIGNATURE FAIL`（exit 1）。因此对外演示“删除输入被拦截”必须使用带外部锚点的 v3 包，否则容易造成“删了也没事”的误解。

### 摘要口径与可比性

- **四主包口径**：0.4.8 批次语义后四主包 `conclusion_digest` 统一为 `5dc46558…`；其余包按各自批次口径记录，不按“八包统一”表述。
- **门禁先后**：使用带 `package_sha256` 的完整锚点文件验跨版本包时，包 SHA 门禁先于可比性判定；任一不匹配即报 `PACKAGE SHA256 FAIL`（exit 1），不会降级为 `RESULT INCOMPARABLE`。
- **旧 wheel 边界**：0.4.4–0.4.8 旧 wheel 不做 `comparability_scope` 判定，其 `RESULT OK` 不表示可比性已核验；验旧包必须配对应版本的旧 wheel。
- **无签名包**：未配置私钥时仍导出 v2 无签名包，验算结果最多为 `RESULT PARTIAL`（exit 2），不能作为完整验收。
- **可比范围**：摘要只在同 `rule_pack_version` 且同 evidence schema 下可比；跨版本或跨 schema 返回 `RESULT INCOMPARABLE`（exit 3），既不得当通过，也不应当作篡改。

## 目录结构

```
worktime-compliance-agent/
├── README.md
├── pyproject.toml            # 依赖声明与三个控制台入口
├── uv.lock                   # 唯一锁文件
├── pytest.ini                # llm / slow 标记注册
├── .env.example              # 全部待填配置的集中处
├── config/
│   ├── services.json         # 服务清单（启停工具读取）
│   ├── region_profile.json   # 城市档位与适用条文
│   └── users.json            # 界面账号（仅 scrypt 摘要）
├── data/
│   ├── generator/make_synthetic.py
│   └── raw/                  # 合成 CSV 与场景说明
├── docs/                     # 需求、口径、签名、交付、运维等文档
├── evals/                    # 评测集与判分器
├── policies/                 # 规则包定义、条文引用与口径声明
├── reports/                  # 各轮实测、整改与审查记录
├── scripts/                  # 发行构建、交接目录生成与一致性检查
├── src/
│   ├── cli.py                # 命令行入口
│   ├── config.py             # 配置与环境变量
│   ├── ingest.py             # 导入与质量门禁
│   ├── rules/                # 规则包与判据
│   ├── engine.py             # 校验编排与 run 三元组
│   ├── evidence.py           # 审计链与举证包
│   ├── signing.py            # Ed25519 签名与验签
│   ├── verify_pkg.py         # 独立验算器 wca-verify
│   ├── replay.py             # 举证包重放
│   ├── kb/                   # 知识库与 ACL
│   ├── retrieve.py           # 检索
│   ├── llm.py                # 模型提供方抽象
│   ├── guard.py              # 数字白名单与重大事项拒诺
│   ├── agent.py              # 问答编排
│   ├── web/                  # 3 视图与最小登录
│   └── schema.sql            # 数据库结构
├── tests/                    # 单元、集成、验收与文档护栏
└── tools/                    # 启停、变异测试、性能探针
```

## 测试方式

```bash
uv run pytest -q -m "not llm"             # 离线全量（默认，不需要模型与数据库服务）
uv run pytest -q                          # 含 llm 标记用例
uv run python evals/judge.py --write-report
uv run python tools/mutation_test.py
uv run python tools/perf_probe.py --employees 1000 --dense
```

PostgreSQL 全量测试需要维护库连接：

```powershell
$env:WCA_TEST_POSTGRES_URL="postgresql://root:<本地口令>@127.0.0.1:5927/postgres"
uv run pytest -q -m "not llm"
```

测试分为若干层：规则与判据、质量门禁、ACL 越权、守卫红线、接口权限、举证包验签与绑定、重放、审计链、数据库身份校验、导入事务与并发、文档一致性护栏等。文档护栏会检查 README 与文档中的命令、数字、路径是否与实物一致。

## 贡献说明

- 本项目为单人自主作品集与 PoC，并非开放协作项目；仓库当前为私有，未建立公开的贡献流程。
- 外部贡献指南、代码风格约定与评审流程：**待补充**。
- 在补充之前，任何改动请至少满足：`uv run pytest -q -m "not llm"` 全绿；不修改已冻结的规则语义与摘要算法；文档描述与实物一致（含命令、路径、计数）；不得提交真实个人信息、密钥或数据库连接串。

## 许可证

- 仓库内**未包含** `LICENSE` 文件，`pyproject.toml` 也未声明 `license` 字段。
- 因此许可证信息：**待补充**。在明确授权之前，默认保留所有权利，不得视为开源许可。
- 文档中引用的法律法规条文仅作为判据依据，不构成法律意见。

## 已知局限

1. 一天只取首末卡，多段班次不拼接；
2. 综合计算工时与不定时工时不作违规判定，只输出未覆盖标记与周期统计；
3. 夜班只统计分钟数，无夜班津贴判定依据；
4. 评测的意图命中率建立在离线 stub 上，更换真实模型必须重测；
5. 字段口径取自公开资料，未经 HR 访谈核对；跨零点归属与出差计时长无法规依据，相关参数为自设；
6. 界面只做到能走完三条闭环操作路径，无美化、无图表、无响应式适配；真实企业需替换目录服务与正式会话后端。
