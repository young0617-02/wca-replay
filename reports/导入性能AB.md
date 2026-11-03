# 导入写入方式 A/B：single / executemany / COPY（2026-11-03）

> 目标：针对约 **132,900 行 punch** 导入（原 single 路径约 189–233 s）比较三种写入方式。
> 只使用 `wca_perf_*` 临时库；连接后经 `db_guard` 实际库名复核，活动库 `wca_worktime` 未读写。
> 默认仍是 `single`，本轮只加可选开关，没有切默认。

## 一、实验设置

| 项 | 值 |
|---|---|
| 输入 | `var/dense3000-phase8/data/`：employee 3,000、schedule 66,000、punch 132,900、org 1 |
| 判据 | v5 规则包；校验区间 2025-09-01 ~ 2025-09-30 |
| 每组 | 先导入 org/employee/schedule；punch 连续导入 **3 次**（第 1 次冷，第 2–3 次热） |
| 计时 | `time.perf_counter()`，毫秒；每轮均重导同一文件（旧行先按 raw_file 清理） |
| 内存 | `tracemalloc` Python 堆峰值；**不是 RSS**，也未测 PG 服务端内存 |
| 失败重试 | 全部 **0**；无失败样本 |
| 临时库 | `wca_perf_import_single_20261103`<br>`wca_perf_import_exec5000_20261103`<br>`wca_perf_import_copy_20261103` |

写入方式：
- **single**：默认逐行 `INSERT ... ON CONFLICT DO NOTHING`，保留原行为；
- **executemany**：校验后先批量写 `punch_stage`（5,000 行/批），再一条 `INSERT ... SELECT ... ON CONFLICT DO NOTHING RETURNING source_line_no`；
- **copy**：同样写 `punch_stage`，但用 psycopg `COPY ... FROM STDIN`，之后走同一条最终 INSERT。

## 二、耗时（实测）

| 组 | 冷（ms） | 热 1（ms） | 热 2（ms） | 热中位（ms） | 三轮中位（ms） | 三轮均值（ms） |
|---|---:|---:|---:|---:|---:|---:|
| single | 222,056.1 | 232,817.7 | 229,650.9 | 231,234.3 | **229,650.9** | 228,174.9 |
| executemany 5,000 | **44,842.3** | 43,497.7 | 52,509.3 | 48,003.5 | **44,842.3** | 46,949.8 |
| copy | **24,574.4** | 22,640.3 | 32,021.4 | 27,330.8 | **24,574.4** | 26,412.0 |

- 相对 single 三轮中位：**executemany 快 5.12×；COPY 快 9.35×**。
- 冷启动相对 single：executemany **4.95×**；COPY **9.04×**。
- 注意：热样本第 3 次均出现上浮（exec 52.5 s、copy 32.0 s），与旧行清理/表膨胀/后台 autovacuum 有关；**没有拿单次最好值当结论**，同时给出热中位和三轮中位。
- 单次最好值（exec 43.5 s、copy 22.6 s）不作为结论；最差值也不掩盖。

## 三、一致性核对（三组逐项相同）

| 项 | single | executemany | copy | 结论 |
|---|---:|---:|---:|---|
| employee | 3,000 | 3,000 | 3,000 | 一致 |
| punch | 132,900 | 132,900 | 132,900 | 一致 |
| shift_plan | 66,000 | 66,000 | 66,000 | 一致 |
| raw_file | 4 | 4 | 4 | 一致 |
| input_fingerprint | `2b3cc73cbadd8608…` | 同左 | 同左 | **逐字节一致** |
| conclusion_digest | `0611500cb58b24d1…` | 同左 | 同左 | **逐字节一致** |
| 结论条数 | 5,100 | 5,100 | 5,100 | 一致 |
| 分级 | 1,200 / 3,000 / 900 | 同左 | 同左 | 一致 |
| 员工/天数 | 3,000 / 90,000 | 同左 | 同左 | 一致 |
| 丢弃/重试 | 0 / 0 | 0 / 0 | 0 / 0 | 一致 |

**没有任何不一致**，因此未触发“发现不一致立即停止”。

## 四、内存

| 组 | Python 堆峰值（字节） | 约 |
|---|---:|---:|
| single | 110,692,085 ~ 110,831,437 | ~106 MiB |
| executemany | 198,998,048 ~ 199,483,104 | ~190 MiB |
| copy | 198,973,685 ~ 199,468,095 | ~190 MiB |

- 两种批量方式内存相近，约比 single 高 **80 MiB**；主要来自先收集校验后的 payload 列表。
- 这是 **Python 堆峰值（tracemalloc）**，不是进程 RSS，也不含 PG 服务端内存；不能当成“导入总内存”。
- 132,900 行在当前机器上未触发内存失败。

## 五、复杂度与可维护性

| 方案 | 代码代价 | 依赖 | 运行边界 | 回退 |
|---|---|---|---|---|
| single | 现有路径，零改动 | 无 | SQLite/PG | — |
| executemany | 约 20 行：预载 employee、payload 列表、临时表、批量 flush、最终 INSERT RETURNING | 无新依赖（标准 DB-API executemany） | **仅 PostgreSQL**；SQLite 选择时报错，不会静默换路径 | `WCA_IMPORT_WRITE_MODE=single` |
| copy | 在 executemany 基础上约 8 行：`conn.raw.cursor().copy(...)` + `write_row` | 无新依赖（psycopg 已有） | **仅 PostgreSQL**；依赖 psycopg COPY 行为 | 同上，或改用 executemany |

- 两种批量方式都把 punch 先写临时表，再统一 `ON CONFLICT` 入正式表；重复行通过 `RETURNING source_line_no` 精确识别，避免 `executemany` 无法按行拿 rowcount 的语义缺口。
- **共同风险**：临时表在事务内 `ON COMMIT DROP`；批量路径只在 PG 生效，默认 SQLite 仍走 single。
- 本轮没有做分卷/导入 COPY 优化以外的界面或业务变更；12 MiB/11.5/10.5 预算未动。

## 六、结论与建议

1. **性能**：COPY 最快，三轮中位 24.6 s；executemany 44.8 s；single 229.7 s。两种批量方式都远低于原 189 s 量级的目标瓶颈描述（本机 single 实测更慢，为 222–233 s）。
2. **一致性**：三组行数、`input_fingerprint`、`conclusion_digest`、结论条数、分级逐项一致；可安全做可选路径。
3. **默认建议**：**暂不切默认**，等用户确认。若决定切换：
   - **首选 COPY**：性能最好，无新依赖，代价是 pg 专用 + raw cursor + 临时表；
   - **保守选 executemany**：少一段 raw COPY，仍快 5.1×；
   - 两者都能用 `WCA_IMPORT_WRITE_MODE` 回退到 `single`。
4. **验证进展**：COPY 的并发导入、异常中断、重复跨文件语义已在第九节（REV-32）专项复测并修复；PG 服务端内存/磁盘膨胀与更大规模仍未专项压测，切默认前仍需补。
5. **实测/估算**：表内耗时、内存、行数、指纹、摘要均为实测；189 s 是需求描述的历史值，本机 single 实测 222–233 s，二者不混用。

## 七、原始数据

- `var/import-ab/result-single.json`
- `var/import-ab/result-executemany.json`
- `var/import-ab/result-copy.json`
- 运行脚本：`var/import-ab/run_import_ab.py`

## 八、加固验证（2026-11-03，REV-31）

### 1. 并发导入（COPY，两个进程同时启动）

| 场景 | 数据库 | 结果 | 耗时 |
|---|---|---|---:|
| 同一文件 `punch.csv` ×2 | `wca_perf_import_conc_same_20261103_2` | 一个进程成功（6,620.8 ms、132,900 行、0 issue）；另一个 **UniqueViolation**（`raw_file(sha256,rel_path)` 冲突），rc=1；最终 punch 132,900、raw_file 3、重复 issue 0、`punch_stage` 0 | 总 7,276.2 ms |
| 不同文件 `punch.csv` + `punch_copy.csv`（内容相同） | `wca_perf_import_conc_diff_20261103` | 两个进程都 rc=0；最终 punch **132,900**（不是 265,800）；`raw_file` 4；`QUAL-DUP` issue **132,900**（全部挂在后完成文件 `punch.csv`，line_no 2–132,901）；`punch_stage` 0 | 总 16,774.2 ms；子进程 16,154.4 / 5,854.1 ms |

判断：**同文件并发不是安全失败-重试语义，也不是串行化成功**，而是第二个进程在 raw_file 唯一键上直接失败；不同文件同内容时去重正确、无重复行，但会产生 132,900 条 QUAL-DUP 记录，膨胀明显。

### 2. 中断与重跑（COPY，flush 后抛异常）

| 项 | 实测 |
|---|---|
| 异常点 | `_write_punch_bulk` 完成 stage COPY 与最终 INSERT 后抛 `RuntimeError` |
| 导入前 | employee 3,000 / punch 0 / shift_plan 66,000 / raw_file **3** |
| 回滚后 | punch **0**（正确回滚）；`punch_stage` 同连接查询 **0**；ingest_issue 0 |
| **raw_file** | **4，未回到 3**（`_register_file` 在导入事务外，回滚不覆盖） |
| 重跑 | 7,957.6 ms；punch 132,900；重复 issue **0**；raw_file 4 |
| 重跑一致性 | `input_fingerprint`、`conclusion_digest`、5,100 条结论与正常 copy 逐项相同 |

判断：punch 数据和 stage 可回滚，但 **raw_file 登记泄漏**；不满足“行数回到导入前”的完整回滚要求。该登记边界与写入方式无关，single/executemany/copy 都受影响。

### 3. 跨文件重复与膨胀

- 跨文件同内容：`QUAL-DUP` 按 `source_line_no` 正确落到 2–132,901，首三条分别对应 CSV 第 2–4 行（`P0001|2025-09-01T09:00...in` 等）；没有重复行入 `punch`。
- 连续重导（COPY 前 3 轮为性能 A/B，后 2 轮为本次；同一 `wca_perf_import_copy_20261103`）：

| 轮次 | 耗时（ms） | punch | raw_file | stage 残留 | 表 total 字节 | heap 字节 | n_dead_tup | autovacuum_count |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 导入前（已 3 轮） | — | 132,900 | 4 | 0 | 100,122,624 | 74,235,904 | 0 | 1（last 02:46:33） |
| 第 4 轮 | 7,027.0 | 132,900 | 4 | 0 | 100,122,624 | 74,235,904 | 132,900 | 1 |
| 第 5 轮 | 7,041.5 | 132,900 | 4 | 0 | 100,876,288 | 74,235,904 | 265,800 | 1 |

- 前 3 轮耗时 24,574.4 / 22,640.3 / 32,021.4 ms；第 4–5 轮降到约 7.0 s，波动大，不能拿单次最好值。
- `punch_stage` 每轮结束均为 0；autovacuum 在前 3 轮后运行过 1 次，第 4–5 轮尚未再次触发，dead tuple 累积到 265,800，总表大小仅增加约 0.75 MiB。

### 4. COPY 是否可切默认

**结论：不可以。默认继续 single，也不建议退到 executemany。** 原因：

1. 同文件并发导入会触发 raw_file 唯一键冲突，一个进程失败，不是串行化安全；
2. 中断后 punch 回滚正常，但 raw_file 不回滚（登记在事务外）；executemany 共用同一结构，不能解决；
3. 不同文件同内容去重正确，但 132,900 条 QUAL-DUP 和对应膨胀需要额外治理；
4. COPY 的 9.35× 性能优势只在单进程、无并发、无中断的干净场景成立。

切默认前至少还需要：
- 把 `_register_file`/`_purge_file_rows` 纳入同一事务，或提供可回滚的登记补偿；
- 对同 `(rel_path, sha256)` 导入加 advisory lock/幂等 upsert，处理并发唯一冲突；
- 为并发/中断/重跑补自动化测试（当前只有一致性测试）；
- 对大文件重导的 QUAL-DUP 做聚合或上限，避免 issue 表膨胀；
- 明确 autovacuum/维护策略；
- 修完后优先用简单的 executemany 验证，再评估 COPY。

**实测/推算区分**：并发耗时、冲突、行数、issue、stage、raw_file、回滚、重跑指纹、表大小/autovacuum 均为实测；“9.35×”是干净单进程 A/B 实测，不能外推到并发场景。

## 九、修复后复测（2026-11-03，REV-32）

本轮不切默认写入方式、不切默认规则包、不提交 Git、不写活动库；只修缺陷并重跑同一批实验。
新增/变更的临时库全部保留，未删除旧库或备份。

### 1. 修法与影响面

| # | 缺陷 | 修法 | 影响面 |
|---|---|---|---|
| 1 | `raw_file` 登记在导入事务外，中断后泄漏 | `import_csv_file` / `import_rows` 把 `_acquire_import_lock`、`_register_file`、`_purge_file_rows`、派生行与审计包进同一事务；`_ingest_rows` 用 `manage_transaction=False` 防止嵌套提交 | single/executemany/COPY 共用同一事务边界；SQLite 同步生效 |
| 2 | 同 `(rel_path, sha256)` 并发触发 `raw_file` 唯一键失败 | PG `pg_advisory_xact_lock(hashtext('wca.import:rel#sha'))` 串行化同文件导入；`_register_file` 返回 `(file_id, reimported)` | 第二个进程等待后幂等成功，不再抛未处理 `UniqueViolation` |
| 3 | 单文件重复行产出 132,900 条 `QUAL-DUP` | 按“员工×文件”聚合为一条摘要（`detail` 保存按天 count、前 3 个样本、前 5 个行号、line_min/max）；引擎 `build_scope` 按天展开，QUAL-01 的 `issue_count`/样本/行号与治理前一致 | `ingest_issue` 行数 132,900 → 3,000；结论条数/分级/指纹/摘要不变 |
| 4 | （复测中新暴露）回滚后 `raw_file` 序列跳号，OFF-01/QUAL-01 metric 里的 `file_id` 变化导致摘要漂移 | `_register_file` 改为显式 `MAX(file_id)+1` 取号（回滚后重取同号），并用 `ON CONFLICT DO NOTHING RETURNING` + 重试处理不同文件并发取号 | 正常单进程仍是 file_id 4，A/B 基线指纹/摘要不变；中断重跑复用原主键 |
| 5 | （复测中新暴露）不同文件并发导入抢同一个 `audit_event.seq`/`prev_hash` | `append_audit` 内加 PG 事务级 advisory lock（固定键 `wca.audit.append`）；导入事务内等待，随提交/回滚释放 | 并发导入不再报 `audit_event_pkey` 冲突；审计链保持单链 |
| 6 | （复测中新暴露）v4→v5/v6 首次导入时 `ensure_audit_epoch` 在导入事务内再开事务：SQLite 直接 `cannot start a transaction within a transaction`，PG 会提前 COMMIT 把 punch/raw_file 落库 | 新增 `in_transaction()` 判断：已在导入/审批事务内就复用外层事务，否则才自开事务；首次建段使用同一把 audit advisory lock 并二次复查 | 首次切包导入不再嵌套事务；失败导入连 epoch 一起回滚，库仍停留在可验证的 v4 链；重跑成功后才进入 v5 段 |

### 2. 并发导入：修复前 / 修复后

| 场景 | 修复前（REV-31） | 修复后（实测） |
|---|---|---|
| 同一文件两进程（COPY） | 一个成功 6,620.8 ms；另一个 **UniqueViolation**，rc=1；总 7,276.2 ms；punch 132,900、raw_file 3、dup 0、stage 0 | 两个都 rc=0；12,626.9 / 6,051.6 ms；总 13,152.7 ms；punch 132,900、raw_file 3、dup 0、stage 0；无异常 |
| 不同文件同内容两进程（COPY） | 两个 rc=0；总 16,774.2 ms；punch 132,900、raw_file 4、`QUAL-DUP` **132,900**、stage 0 | 两个 rc=0；11,617.3 / 6,060.3 ms；总 12,119.9 ms；punch 132,900、raw_file 4、`QUAL-DUP` **3,000**、stage 0 |
| 临时库 | `..._conc_same_20261103_2`、`..._conc_diff_20261103` | `..._conc_same_20261103_5`、`..._conc_diff_20261103_4` |

耗时受机器状态、文件缓存、进程先后影响，只作为同一轮的相对参考，不拿单次最好值当结论。

### 3. 中断与重跑：修复前 / 修复后

| 项 | 修复前（REV-31） | 修复后（实测） |
|---|---|---|
| 异常点 | `_write_punch_bulk` 完成 stage COPY 与最终 INSERT 后抛 `RuntimeError` | 同左 |
| 导入前 | punch 0 / raw_file **3** / shift_plan 66,000 | punch 0 / raw_file **3** / shift_plan 66,000 |
| 回滚后 | punch 0、ingest_issue 0、stage 0；**raw_file 4（泄漏）** | punch 0、ingest_issue 0、stage 0；**raw_file 3（一并回滚）** |
| 重跑 | 7,957.6 ms；punch 132,900；raw_file 4；dup 0 | 6,961.7 ms；punch 132,900；raw_file 4；dup 0 |
| 重跑三元组 | fingerprint `2b3cc73c…` / digest `0611500c…` / 5,100 条，与正常 copy 一致 | 同左，逐项一致 |
| 临时库 | `wca_perf_import_crash_20261103` | `wca_perf_import_crash_20261103_4` |

修复前“重跑一致”是因为 raw_file 行没回滚、file_id 仍是 4；一旦把 raw_file 纳入事务，PG identity 序列跳号会让 file_id 变成 5，OFF-01 的 metric 随之变化，摘要就不再一致。第 4 项修法正是为同时满足“完整回滚”和“摘要不漂移”。

### 4. QUAL-DUP 治理后的数量变化（132,900 行跨文件重复）

在 `wca_perf_import_conc_diff_20261103_3` 上，对同一份 `punch_copy.csv` 分别以“逐行”和“汇总”导入，再各跑一次 v5 校验：

| 项 | 逐行存储 | 汇总存储 | 结论 |
|---|---:|---:|---|
| `ingest_issue` 中 `QUAL-DUP` 行数 | **132,900** | **3,000** | 降至 1/44.3 |
| 汇总可计数重复数 | 132,900 | 132,900（按 detail 求和） | 不丢计数 |
| 行号范围 | 2–132,901 | 2–132,901 | 一致 |
| 多天摘要数 | — | 3,000（每员工一条，覆盖多天） | 可按天展开 |
| `input_fingerprint` | `0b523c70e395b7c3…` | 同左 | 一致 |
| `conclusion_digest` | `2606bc69…` | 同左 | **一致** |
| 结论条数 / 分级 | 183,150（104,250 / 70,650 / 8,250） | 同左 | 一致 |
| 校验耗时 | 143,733.1 ms | 143,116.6 ms | 基本持平 |

- 该库的 183,150 条结论包含跨文件重复触发的 90,000 条 QUAL-01，因此摘要 `2606bc69…` 与“干净单文件”基线 `0611500c…` 不同；这里比较的是**同一库、同一批事实**在汇总前后，不是跨库基线。
- 行号可追溯性抽样实测：P0001 的 `line_min=2`、`line_max=45` 分别落回 CSV 第 2 行 `P0001,2025-09-01T09:00:00+08:00,in,DEV-PERF` 与第 45 行 `P0001,2025-09-30T18:00:00+08:00,out,DEV-PERF`；P0002/P0003 同样命中。
- 汇总行里保存的是前 3 个样本与前 5 个行号引用；引擎按 detail 的按天计数展开，QUAL-01 只取每天前 3 个样本、前 5 个行号，故结论与逐行存储逐项相同。
- 副作用：举证包 `quality_issues.csv` 与 manifest 的 `quality_issues` 计数从 132,900 变为 3,000；结论集不受影响。依赖“逐行 issue”的下游需要改为读取 summary 的 days/line_refs。

### 5. 正常单进程三模式回归（复用 A/B 临时库，各重导一次）

| 模式 | 重导耗时（ms） | 行数 | raw_file | 指纹 | 摘要 | 结论条数 | 分级 | 与 A/B 期望一致 |
|---|---:|---:|---:|---|---:|---:|---|---|
| single | 104,678.0 | 132,900 | 4 | `2b3cc73c…` | `0611500c…` | 5,100 | 1,200 / 3,000 / 900 | 是 |
| executemany | 15,290.4 | 132,900 | 4 | 同左 | 同左 | 5,100 | 同左 | 是 |
| COPY | 7,053.9 | 132,900 | 4 | 同左 | 同左 | 5,100 | 同左 | 是 |

- 三次都是 `reimported=True`、`file_id=4`、issue 0；punch / shift_plan / employee / raw_file 行数与 A/B 相同。
- 这里的耗时是**已建库、已预热后的重导**，且未启用 `tracemalloc`；与第二节（冷库 + tracemalloc）不可直接对比，不用于性能排名。

### 6. COPY 是否已具备切默认条件

**结论：仍不具备。** 已解决：结果一致性、同文件并发幂等、中断完整回滚、QUAL-DUP 膨胀、file_id 漂移、并发导入的审计 seq 冲突。
切默认前仍缺：

1. **SQLite 自动降级**：`executemany`/`copy` 在 SQLite 上直接 `ValueError`；默认切 COPY 会让 SQLite 开发/测试路径立即失败。需要按后端自动选 `single`，或把默认值语义改成 `auto`；
2. **内存上限/分块**：批量路径把整文件 payload 留在内存，132,900 行约 190 MiB Python 堆；未做流式/分块，也没有按文件大小拒绝或降级；
3. **COPY 中途失败**：当前自动化只测“flush 完成后抛异常”，没有测 COPY 写入中途断开/编码错误；
4. **并发校验的审计串行化**：`append_audit` 的 advisory lock 只在事务内有效；`run_check` 目前在 run/finding 事务提交后才 append，两个并发校验仍可能抢同一个 seq（与导入无关，但属于审计链风险）；
5. **生产规模/维护策略**：只验证到 3,000 员工月 / 132,900 行；autovacuum、磁盘膨胀、长事务与更大的单文件未做专项。

### 7. 实测/推算区分

- 并发/中断的行数、raw_file、stage、issue、file_id、指纹、摘要、结论条数：**实测**（PG 18，本机）。
- QUAL-DUP 132,900 / 3,000、行号抽样、两次校验 183,150 条：**实测**。
- 三模式重导耗时：**实测但非同条件**（热库、无 tracemalloc），只用于“结果仍一致”的回归，不用于性能结论。
- “COPY 9.35×”来自 REV-30 的干净单进程 A/B，本轮不重算、不外推到并发/中断场景。
- 生产更大规模的内存/时间：**推算未测**。

### 8. 本轮新增风险

1. **显式 `MAX(file_id)+1` 取号**：依赖导入事务与 `ON CONFLICT DO NOTHING` 重试；只压测了 2 个并发进程，更多并发下可能需要重试多于一次（上限 8 次，超过会显式报错而不是静默错号）。生产代码没有删除 `raw_file` 的路径；若人工删除最高 id 且派生行已清空，该 id 可能被复用。
2. **QUAL-DUP 汇总改变 quality_issues.csv 形态**：结论不变，但报表从逐行变为“每员工一条 + days/line_refs”；外部若按行号逐条消费该 CSV 需要适配。
3. **审计锁作用域**：`append_audit` 用事务级 advisory lock，调用方不在事务内时锁随语句释放；REV-32 时 `run_check` 属于这种调用（REV-33 已把它的 append 移入事务）。
4. **既有问题（未本轮修改）**：`import_csv_file` 写 `raw_file.row_count` 时用的是表头列数（如 employee.csv 为 8），不是数据行数；因为会改变既有输入指纹，本轮未动，避免破坏 A/B 基线。它不影响本次事务/并发/摘要修复，但会让指纹里的 `rows` 语义失真。
5. **批量模式仍是 PG-only**：SQLite 路径继续只支持 single；REV-32 时未加自动降级（REV-33 已补）。
6. **QUAL-DUP 汇总的例外**：同一员工在同一文件里若还混有其他质量问题（如 QUAL-TZ），该员工保持逐行 QUAL-DUP，以保持 QUAL-01 的样本/行号顺序不变。这类员工如果重复量特别大，issue 仍可能膨胀；治理只覆盖“纯重复”员工（本轮的 132,900 行场景属于后者）。

## 十、COPY 切默认前四道门复测（2026-11-03，REV-33）

默认仍 `single`、规则包仍 v5、未提交 Git、未写活动库；本轮只补四道门并复测。

### 1. SQLite 自动降级

| 请求方式 | 实际方式 | 日志 | 结果 |
|---|---|---|---|
| `executemany` | `single` | 1 条 WARNING（含请求方式与 rel_path） | 与 single 三元组一致 |
| `copy` | `single` | 1 条 WARNING | 与 single 三元组一致 |

- `ImportResult` 新增 `requested_write_mode` / `write_mode` / `degraded_from` / `chunk_rows`，CLI、网页导入响应与审计 payload 均可见；不报错、不静默伪装批量。
- 测试：`test_sqlite_bulk_mode_degrades_to_single`（参数化 2 个模式）。

### 2. 分块前后内存（132,900 行，tracemalloc Python 堆）

| 组 | 分块前（REV-30 冷导入） | 分块后（默认 5,000 行/块） | 降幅 |
|---|---:|---:|---:|
| COPY | 199,468,095 字节（190.2 MiB） | **76,236,933 字节（72.7 MiB）** | **-61.8%** |
| executemany | 199,483,104 字节（190.2 MiB） | **76,112,083 字节（72.6 MiB）** | **-61.8%** |
| COPY（20,000 行硬上限） | — | 91,522,555 字节（87.3 MiB） | 相对分块前 -54.1% |
| COPY 重复密集（132,900 条 QUAL-DUP） | 未测同场景 | 121,965,760 字节（116.3 MiB） | — |

- 分块前数据来自 `result-copy.json` / `result-executemany.json` 的冷导入样本；分块后来自 `var/import-ab/memory-chunked-result.json`，口径相同（只对 punch 导入段 tracemalloc）。
- 配置：`WCA_IMPORT_BATCH_SIZE` 默认 **5,000**，硬上限 **20,000**；超过上限截断为 20,000 并输出 WARNING。分块只约束 payload/块，**raw bytes + 解码文本仍整体读入**（132,900 行约 6 MB，百万行会放大）。
- 耗时（同口径实测）：COPY 分块后 29,682.0 ms（分块前冷导入 24,574.4 ms，约 +20.8%，仍远快于 single）；executemany 42,524.5 ms（分块前 44,842.3 ms）；20,000 行块 27,027.8 ms。
- 重复密集变体（先导 `punch.csv`，再用同内容 `punch_copy.csv` 触发 132,900 条 QUAL-DUP）：峰值 **121,965,760 字节（116.3 MiB）**，耗时 50,576.0 ms，最终 3,000 条 summary issue；该场景**没有分块前的同口径测量**，不能与上面的干净导入直接相减。
- 测试：`test_postgres_copy_chunk_sizes_keep_same_triple` 覆盖 1 / 5 / 20（大于 12 行）/ 20,000 上限，行数与三元组一致。

### 3. COPY 中途失败回滚

| 失败类型 | 构造 | punch | raw_file | punch_stage | ingest_issue | 重跑 |
|---|---|---:|---:|---:|---:|---|
| 中途断连 | COPY 写一半后抛 `OperationalError` | 0 | 回到导入前 | 0 | 0 | 复用原 file_id，三元组与正常 COPY 一致 |
| 字段数非法 | 第二行少一列 `write_row` | 0 | 回到导入前 | 0 | 0 | 同上 |

- 测试：`test_postgres_copy_midstream_failure_rolls_back_and_retry_matches` 参数化 2 类；重跑行数 4，fingerprint/digest/结论条数与正常 COPY 逐项一致。
- 说明：断连是**在 COPY 流中途抛 `OperationalError` 模拟**，不是物理拔网线/杀连接；真实网络断开时连接不可再用，需靠数据库事务回滚，本轮未做物理断连演练。

### 4. 并发 check 审计串行化

- `run_check` 的 `append_audit` 移入 run/finding 事务内，advisory lock 持有到提交。
- 离线：`test_run_check_appends_audit_inside_transaction` 断言 append 时 `in_transaction=True`。
- PG：`test_postgres_concurrent_checks_serialize_audit` 两个线程并发 run_check；无 `audit_event` 主键冲突，`audit_event` 恰好 +2，`run` +2，`verify_chain` 通过。未记录并发耗时。

### 5. 四道门后的 132,900 行复测

| 场景 | 实测 |
|---|---|
| 同文件两进程 COPY | 两进程 rc=0；14,660.7 / 7,071.0 ms，总 15,165.7 ms；punch 132,900、raw_file 3、dup 0、stage 0 |
| 不同文件同内容两进程 COPY | 两进程 rc=0；6,517.8 / 22,735.1 ms，总 23,256.9 ms；punch 132,900、raw_file 4、QUAL-DUP 3,000、stage 0 |
| 中断重跑 | 回滚后 punch 0、raw_file 3、stage 0；重跑 6,459.7 ms，fingerprint `2b3cc73c…` / digest `0611500c…` / 5,100 条与正常 COPY 一致 |
| QUAL-DUP 逐行 vs 汇总 | 132,900 → 3,000 条；两次校验同指纹 `0b523c70…`、同摘要 `2606bc69…`、同 183,150 条（104,250 / 70,650 / 8,250）；校验耗时 145,215.9 / 142,339.2 ms；重导 15,562.5 / 15,544.5 ms |
| 三模式重导 | single 115,753.7 ms、executemany 14,825.8 ms、COPY 7,284.6 ms；三者 punch 132,900、raw_file 4、fingerprint `2b3cc73c…`、digest `0611500c…`、5,100 条（1,200 / 3,000 / 900）一致 |

### 6. COPY 是否可作默认：最终建议

**四道门在 132,900 行 / 3,000 员工规模内全部通过，COPY 已具备 PostgreSQL 默认候选资格；本轮仍不建议立即改默认。**

仍缺 / 仍不确定：

1. **百万行级规模**：本轮最大 132,900 行；`import_csv_file` 仍整体读 raw bytes + 文本，百万行会放大，需要流式哈希/逐行解码；
2. **维护策略**：重复密集场景会先把 132,900 条逐行 QUAL-DUP 落库、再删除汇总，产生写放大与死元组；autovacuum、磁盘膨胀、长事务未专项验证；
3. **真实断连**：COPY 中途测试是模拟 `OperationalError`，不是物理断网/杀连接；
4. **其他审计写入方**：agent/auth/export 若不在事务内 append，仍有理论 seq 竞态；本轮只保证 run_check 与导入；
5. **SQLite 性能**：降级可用，但 SQLite 仍只有 single 路径，不在 COPY 加速范围内。

若决定切，方案只给开关、不改默认：

- 新增 `WCA_IMPORT_WRITE_MODE=auto`（PG→`copy`，SQLite→`single`），或直接把默认值设为 `auto`；
- 保留 `WCA_IMPORT_WRITE_MODE=single` 作为回退；
- 分块上限保持 20,000 行；超过时告警截断；
- 上线前用百万行级数据复跑内存、autovacuum、磁盘与重导压测。

### 7. 实测 / 推算区分

- 内存、耗时、行数、issue、rollback、stage、fingerprint/digest、并发 check 审计计数：**均为实测**（本机 PG 18 / SQLite）。
- “百万行会放大”是**推算未测**；本轮只验证到 132,900 行。
- 分块前内存来自 REV-30 同数据同口径；不是本轮重跑旧代码。
- 三模式耗时是热库重导、无 tracemalloc，不与 REV-30 冷导入直接排名。

### 8. 本轮新增风险

1. **文件体仍整体读入**：分块只解决 punch payload；raw bytes + 文本仍占内存（REV-34 已改流式读取/哈希）。
2. **重复密集写放大**：132,900 条逐行 QUAL-DUP 先落库再删除汇总，增加 I/O 与死元组；结论不变。
3. **分块 COPY 开销**：比单次 COPY 多约 20.8%，仍远快于 single；块越小调用越多。
4. **硬上限截断**：`WCA_IMPORT_BATCH_SIZE>20000` 会被截断并告警，配置不会按字面生效。
5. **其他 audit 调用方**：只保证了导入与 run_check 在事务内；agent/auth/export 仍需后续统一（REV-34 已补）。

## 十一、流式读取/哈希与审计事务边界（2026-11-03，REV-34）

默认仍 `single`、规则包仍 v5、未提交 Git、未写活动库；本轮不改产品行为、不改 `raw_file.row_count` 语义。

### 1. 流式改法与指纹一致性

- 哈希：`_stream_sha256(path, 1 MiB)` 按块读二进制并更新 sha256，等价于整文件 `sha256_hex(read_bytes())`。
- 解析：第二遍用 `open(encoding='utf-8-sig', errors='replace', newline='\n')` 交给 `csv.DictReader`，newline 语义与旧 `io.StringIO(text)` 一致（只按 `\n` 分行、保留裸 `\r`）。
- 文件内重复键：`seen_keys` 由 Python `set[tuple]`（O(行数)）改为 DB 临时表 `punch_seen` + 块级暂存 `punch_seen_stage`。

指纹一致性证据（同一份 132,900 行 punch.csv）：

| 项 | 值 |
|---|---|
| sha256（流式 = 整文件 = 库内 raw_file.sha256） | `a12f94f964c687a494d5b25b8f34d436858729853bb11b73cbc3e6778c18ff64` |
| input_fingerprint（三模式重导） | `2b3cc73cbadd86086d72afc004fb97f5d7bfdb2f911ff9479e223415337aad1d` |
| conclusion_digest | `0611500cb58b24d1fe686d97922561cbd3384b13e3071c107b12b782de7c8f6d` |
| 结论条数 / 分级 | 5,100（1,200 / 3,000 / 900） |
| 501,000 行流式 vs legacy sha256 | 同为 `2acdcf50c86a2f57edb93ee79a8b06690a620f9c29e7a7212c3787965fa05c0b`，行数同 501,000 |

### 2. 两个规模的内存对照（tracemalloc Python 堆，只测 punch 导入段）

| 变体 | 132,900 行 | 501,000 行 | 说明 |
|---|---:|---:|---|
| 改造前（整文件读 + Python seen set） | 76,248,466 字节（72.7 MiB） | 273,169,253 字节（260.5 MiB） | 随文件线性增长 |
| 仅流式（仍保留 Python seen set） | 40,625,274 字节（38.7 MiB） | 139,425,602 字节（133.0 MiB） | 仍随文件线性增长 |
| 仅 DB seen（legacy 整文件读 + DB seen） | 44,582,111 字节（42.5 MiB） | 142,850,459 字节（136.2 MiB） | 隔离出“读取方式”的贡献 |
| **最终（流式 + DB seen）** | **9,109,210 字节（8.7 MiB）** | **9,110,318 字节（8.7 MiB）** | **两规模基本持平** |

- 全部为实测，口径相同（COPY、分块 5,000、setup 不计、只对 punch 导入段 tracemalloc）。
- 501,000 行文件 22,293,037 字节；132,900 行文件 5,914,237 字节。
- 耗时（含 tracemalloc，仅作参考）：132,900 行 legacy 36.9 s / 流式 37.6 s；501,000 行 legacy 164.7 s / 流式 162.9 s。
- 测试：`test_stream_sha256_matches_full_read_across_chunk_boundaries`（块 1/7/4096/1 MiB）、`test_streaming_csv_matches_legacy_sha_rows_and_triple`（BOM/CRLF/引号逗号/中文/非法 UTF-8 字节）。
- 501,000 行数据由 `var/import-ab/stream_memory.py` 按 3,000 名员工 × 167 行合成，落在临时库 `wca_perf_stream_501k_*_20261103_3`；纯合成、非真实个人数据。

### 3. 审计调用点盘点

| 调用点 | 改造前事务边界 | 处理 | 例外理由 |
|---|---|---|---|
| `ingest.import_csv_file` / `_ingest_rows` | 已在导入事务内 | 复用，不变 | — |
| `engine.run_check` | 已在 run/finding 事务内（REV-33） | 复用，不变 | — |
| `rules/approval_docs.py`（draft / edit / import / publish） | 已在各自事务内 | 复用，不变 | — |
| `rules/approval_migration.py`（apply） | 已在迁移事务内 | 复用，不变 | — |
| `agent.ComplianceAgent._persist`（agent.answer） | **事务外**（question_log/span/review 各自 autocommit） | 显式包 `transaction_if_needed`，与审计同事务 | — |
| `anomaly.decide_review`（review.decision） | **事务外**（UPDATE 与审计分开） | 显式包 `transaction_if_needed` | — |
| `auth.sync_users`（auth.users.sync） | **事务外** | 显式包 `transaction_if_needed` | — |
| `evidence.export_package`（evidence.export） | **事务外**（包登记与审计分开） | 显式包 `transaction_if_needed` | zip/文件已落盘，DB 失败时文件可能残留，但不出现“登记包无审计” |
| `evidence.sign_package`（evidence.sign） | **事务外** | 改为由 `append_audit` 自动包事务 | 只写审计，没有其他业务写；自动事务已足够 |
| `append_audit` 自身 | — | 统一用 `transaction_if_needed` 包住 append + advisory lock | 调用方已在事务内则复用；否则自开一个，锁持有到提交 |

### 4. 并发审计测试结果

| 用例 | 场景 | 结果 |
|---|---|---|
| `test_postgres_concurrent_agent_answers_serialize_audit` | 两线程真实 `ComplianceAgent.ask` 并发 | 无主键冲突；`audit_event` +2、`question_log` +2；`verify_chain` 通过 |
| `test_postgres_concurrent_exports_serialize_audit` | 两个不同 run 并发 `export_package` | 无主键冲突；`evidence_package` +2、`audit_event` +2；`verify_chain` 通过 |
| `test_postgres_concurrent_checks_serialize_audit`（原有） | 两线程并发 `run_check` | 无主键冲突；`run` +2、`audit_event` +2；`verify_chain` 通过 |
| `test_postgres_same_file_concurrent_import_serializes`（原有） | 同文件两连接并发导入 | 一真一重导；`verify_chain` 通过 |

### 5. 三模式回归（132,900 行，流式 + DB seen 之后）

| 模式 | 重导耗时（ms） | 行数 | raw_file | 指纹 | 摘要 | 结论条数 | 与 A/B 期望一致 |
|---|---:|---:|---:|---|---:|---:|---|
| single | 138,332.6 | 132,900 | 4 | `2b3cc73c…` | `0611500c…` | 5,100 | 是 |
| executemany | 27,406.1 | 132,900 | 4 | 同左 | 同左 | 5,100 | 是 |
| COPY | 10,723.4 | 132,900 | 4 | 同左 | 同左 | 5,100 | 是 |

- 三组均 `reimported=True`、`file_id=4`、issue 0；punch 132,900、shift_plan 66,000、employee 3,000。
- 与 REV-33 相比耗时上浮（COPY 7.3 s → 10.7 s；single 115.8 s → 138.3 s），主要来自 `punch_seen` 键表写入；仍是热库重导口径，不作跨轮性能排名。

### 6. 实测 / 推算区分

- 两规模内存峰、耗时、sha256、行数、fingerprint、digest、并发审计计数：**实测**。
- “内存不随文件大小增长”是本次 132,900 / 501,000 两个规模的实测结论；百万行以上未测，属**推算**。
- DB `punch_seen` 的 PG 临时空间占用未单独测量；501k 行键表大小属**推算未测**。

### 7. 本轮新增风险

1. **文件读两遍**（哈希 + 解析），I/O 约 2×；不再把文件体留在内存。
2. **`punch_seen` 临时表**：501k 行会在 PG 临时空间留一份键表，随行数增长（换来 Python 堆恒定）。
3. **seen 键写入开销**：COPY 132k 由 7.3 s 升到 10.7 s，single 由 115.8 s 升到 138.3 s；可用更好的批量策略再优化。
4. **`append_audit` 自动开事务的边界**：调用方若先在 autocommit 里写业务、再调 append，两者可能仍是两个事务；本轮已把 agent/auth/anomaly/export 显式合并，sign 只写审计。
5. **export 残留**：zip/文件先落盘，DB 或审计失败时文件可能残留，需要运维清理（不影响链完整性）。

## 十二、同 run 导出锁、临时空间实测与维护策略（2026-11-03，REV-35）

默认仍 `single`、规则包仍 v5、未提交 Git、未写活动库。

### 1. 同 run 并发导出：修复前 / 修复后

| 项 | 修复前 | 修复后（实测） |
|---|---|---|
| 锁 | 无 | 进程内 per-run `threading.Lock` + PG `pg_try_advisory_lock(hashtext('wca.export:{run_id}'))`；SQLite 原子锁文件 |
| 第二个请求 | 同时写同一 `work` 目录与同一 zip，可能残缺/覆盖 | 立即 `ExportBusyError`：“该 run 正在导出…”，不触碰 work/zip |
| zip 写入 | 直接写最终 `{run_id}.zip`，失败会留半个包 | 先写 `.{run_id}.zip.tmp`，成功后 `os.replace`；失败删除临时文件 |
| 网页入口 | 未处理 | `/api/export` 捕获 `ExportBusyError` 返回 **409** |
| 测试 | — | 两线程同 run：恰好 1 成功 + 1 busy；最终 zip `testzip()` 通过；解压后 `verify.py` rc=0、`CHAIN OK`、`INPUTS OK`；manifest fingerprint/digest/findings 与 run 行一致 |

### 2. `punch_seen` / `punch_seen_stage` 临时空间实测

采样点：每块 `TRUNCATE punch_seen_stage` 前，用 `pg_total_relation_size(to_regclass(...))`；COPY、分块 5,000。

| 规模 | punch_seen 最大字节 | 行数 | punch_seen_stage 最大字节 | stage 行数 | punch 表字节 | seen / punch |
|---|---:|---:|---:|---:|---:|---:|
| 132,900 | 21,782,528（20.8 MiB） | 132,900 | 663,552（0.63 MiB） | 5,000 | 40,738,816 | 53.5% |
| 501,000 | 84,041,728（80.1 MiB） | 501,000 | 663,552（0.63 MiB） | 5,000 | 146,096,128 | 57.5% |

- 趋势：`punch_seen` 随唯一键行数近似线性（132,900→501,000 约 3.86×，行数 3.77×）；501k 约 0.168 KB/行。
- `punch_seen_stage` 每块 `TRUNCATE`，最大只与 chunk 5,000 行有关，不随文件增长。
- `pg_stat_database.temp_bytes`：全新 132k/501k 导入库均为 **0**（本次未记录到临时文件写出）；历史 copy 库累计 139,253,712、diff 库 23,126,016，属多次导入累计。
- 结论：当前不需要为 `punch_seen` 设硬上限，但需监控；若将来要压上限，可把 4 个文本 key 哈希为 16/32 字节，或对超大文件拒绝/分批。

### 3. 维护策略成文

新增 `docs/维护策略.md`，依据：

- REV-31 连续重导：132,900 dead tuple/轮，autovacuum 能回收但表文件不缩回；
- 当前统计：`punch` 多次重导后 87,416,832 字节（全新 40,738,816）；`ingest_issue` 3,000 live 行对应 92,659,712 字节（404,700 插入 / 401,700 删除，dead=0）；
- 表级 autovacuum 建议（`punch`/`ingest_issue` 降低 scale factor）、重导频率、监控指标（dead tuple/表大小/temp_bytes/临时表）、人工 `VACUUM` 触发条件；只写建议，**未修改任何数据库参数**。

### 4. 实测 / 推算区分

- 同 run 导出锁行为、zip 完整性、`verify.py`、临时表字节、punch 表字节、`temp_bytes`：**实测**。
- 百万行 `punch_seen` 约 160–170 MB：**推算未测**（按 0.168 KB/行线性外推）。
- PG advisory lock 跨**进程**由数据库保证，但本轮测试是两线程/两连接；跨进程未单独演练。
- SQLite 锁文件崩溃残留未演练；PG session lock 在进程断开时自动释放。

### 5. 本轮新增风险

1. **SQLite 锁文件残留**：进程崩溃可能留下 `.export-*.lock`，后续同 run 导出会被拒绝，需要人工清理；PG 无此问题。
2. **临时空间线性增长**：`punch_seen` 501k 约 80 MiB；百万行推算约 160–170 MiB，需要监控 PG 临时空间。
3. **导出锁只防并发**：导出失败后 `work` 目录/临时 zip 可能残留；最终 zip 有原子替换保护。
4. **同一 run 顺序重导**：锁释放后再导出会重新生成并原子覆盖，行为正常；但会重复写审计事件。
5. **维护参数建议未验证**：autovacuum 参数是建议稿，未在活动库执行，需按硬件/审批复核。
