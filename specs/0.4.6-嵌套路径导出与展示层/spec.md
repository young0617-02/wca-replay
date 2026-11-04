# 0.4.6 规格：嵌套路径导出、验算对账与展示层去 DB 编号

- 状态：待确认（未写生产代码）
- 依据：第九轮预注册判据 A1–A13；审计方补充的 F1–F4 失败形态
- 交付目录：`handoff/20261104-第八轮整改/`；发行物 `dist/wca-replay-0.4.6/`
- 硬边界：不改第六/七轮 handoff；不改活动库；不改默认规则包；不 push

## 0. 实测结论（本轮已复现，非推断）

**实测 1｜默认流程 F1 必崩**

在仓库根目录按 CLI 默认入参执行 `gen --seed 20260106 → ingest --dir data/raw → check → export`：

- `gen` 前后 `git status data/raw` 无变化，可复现；
- `ingest` 写入的 `rel_path` 为 `data/raw/*.csv`（默认目录天然带层级）；
- `export` 在 [evidence.py](file:///d:/project/worktime-compliance-agent/src/evidence.py#L1187-L1190) 的
  `shutil.copyfile(e["source"], work / e["arcname"])` 抛出：

```text
FileNotFoundError: ...\packages\run-...\inputs\data\raw\correction.csv
```

exit 1，暂存目录留下 16 个根工件与 `inputs/manifest.json`，没有 zip。与审计方报法一致。

**实测 2｜F2 不可自愈**

在暂存目录手工创建 `inputs/data/` 后重跑 `export`：

```text
File "src\evidence.py", line 1116, in _export_package_locked
PermissionError: [WinError 5] 拒绝访问。: ...\inputs\data
```

exit 1；重跑仍失败。根因是 stale 清理只按“文件”处理（`stale.unlink()`），遇到目录即失败。

**实测 3｜根因定位**

- F1：**物化 `inputs/` 时未创建父目录**，不是 `arcname` 推导错误。`input_arcnames` 已正确产出
  `inputs/data/raw/punch.csv`；`_trim_input_entry`（[evidence.py](file:///d:/project/worktime-compliance-agent/src/evidence.py#L595-L616)）
  反而已调用 `mkdir(parents=True)`，正常复制分支漏了。
- F2：stale 清理未区分文件/目录，且暂存目录跨次复用。
- 附加缺陷：`_resolve_input_path`（[evidence.py](file:///d:/project/worktime-compliance-agent/src/evidence.py#L905-L915)）
  只尝试 `PROJECT_ROOT/rel_path`、`cwd/rel_path`、`data_dir/文件名`，缺 `data_dir/rel_path`；
  绝对路径与 `..` 在导入期不校验，导致“缺项但 exit 0”。

**待实测（编码前先补）**：F3 绝对路径、F4 `..` 的当前行为与审计方描述逐字对齐；
记录 exit code、缺项数、verify/replay 结果。若与本规格推断不符，先更新本规格再改代码。

## 1. 目标与不变量

1. `wca export` 对任意合法相对 `rel_path`（含多层、空格、中文）成功还原 `inputs/<rel_path>` 层级。
2. 缺任何应打包输入时，`export` 非零退出，且不留下 zip、不留下暂存目录。
3. `rel_path` 为绝对路径或含 `..` 时，在**导入期**拒绝，中文错误，非零退出。
4. `verify` 能检出“`input_files.csv` 列了 N 个输入，包内 inputs 少 M 个”，明确 FAIL。
5. 四个平铺 `punch.csv` 包的四联值不变：
   `b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`。
6. Web/API 客户可见位置不再出现裸 DB `file_id`；DB `finding.source_refs` 本轮不动。

## 2. 生产代码改动（精确到函数）

### 2.1 `src/package_inputs.py`

新增 `validate_input_rel_path(value) -> str`：

- `inline://` 前缀原样返回（兼容 `import_rows` 的既有契约）；
- 反斜杠归一为 `/`；
- 拒绝绝对路径：以 `/` 开头、`//`、或盘符 `X:`；
- 拒绝空路径与任何 `..` 段；
- 错误消息统一为中文，示例：
  `输入文件 rel_path 必须是项目内相对路径（拒绝绝对路径）：'D:/x/punch.csv'`；
  `输入文件 rel_path 不允许包含 ..：'../x/punch.csv'`。
- `normalize_rel_path` 保持现状（验算旧包仍需宽松读取；拒绝逻辑只加在导入入口）。

### 2.2 `src/ingest.py`

- `import_csv_file`：在 `rel = rel_path if rel_path else _rel_path(...)` 之后调用
  `validate_input_rel_path(rel)`，再做任何登记/事务。
- `import_rows`：对显式 `rel_path` 同样调用；`inline://` 放行。
- 不在 `_register_file` 内校验，避免绕过错误上下文；导入入口统一失败关闭。
- `_rel_path` 保持“cwd 外回退 basename”的归一化行为；归一化后仍不可解析的文件在导出期失败关闭。

### 2.3 `src/evidence.py`

1. `_resolve_input_path`：候选增加 `cfg.data_dir / p`（完整相对路径），并保留 `cfg.data_dir / p.name`
   兼容旧包；顺序：绝对路径原样、`PROJECT_ROOT/p`、`cwd/p`、`data_dir/p`、`data_dir/p.name`。
2. `_export_package_locked` 暂存目录自愈：
   - 计算 `work = cfg.packages_dir / run_id` 后，若存在则 `shutil.rmtree(work)`，再 `mkdir`；
   - 删除原 `inputs_dir.glob("*") + unlink()` 的 stale 逻辑，改为随整目录重建；
   - 保留 `policies` 复制与后续步骤。
3. 物化 `inputs/`：复制前 `target.parent.mkdir(parents=True, exist_ok=True)`；
   仍用 `shutil.copyfile`（不改变字节语义）。
4. 失败关闭：`collect_package_inputs` 返回后，若 `collected["missing"]` 中存在非 `inline://` 项，
   抛出 `ValueError`，消息列出全部缺项与原因，例如：
   `导出失败：本 run 引用 7 个输入，其中 1 个无法按 rel_path 定位：...；拒绝生成残缺包`。
   `inline://` 项保留在 manifest 的 `missing` 说明中，但不阻断导出（无实体文件可打包）。
5. `export_package` 外层保护：
   - `try: return _export_package_locked(...)`
   - `except Exception: shutil.rmtree(cfg.packages_dir / run_id, ignore_errors=True); raise`
   - zip 只在全部成功后才 `os.replace`；失败时删除 tmp zip（已有逻辑保留）。
6. 不改 `input_fingerprint` 算法、不改 `input_arcnames` 命名规则、不改 `artifacts_digest` 组成。

### 2.4 `src/package_verify.py`（验算补洞）

新增 `check_inputs_completeness(root, manifest, schema_ver) -> dict`：

- `schema_ver < 3` → `status=NOT CHECKED`，不参与门禁（旧包兼容）。
- 读 `input_files.csv`（本 run 引用输入清单，受 `input_fingerprint` 覆盖），构造期望多重集
  `(rel_path, sha256, kind)`；读 `inputs/manifest.json` 的 `entries`，构造声明多重集。
- 逐项核对：
  1. 期望有、声明无 → 缺少；
  2. 声明有、期望无 → 多出（同样 FAIL，防伪造补件）；
  3. `rel_path` 相同但 `sha256`/`kind` 不同 → 不一致；
  4. 按 `input_arcnames` 推导包内路径，文件必须存在且实际 sha256 与该条目一致。
- 失败标签：
  `INPUTS COMPLETENESS FAIL 输入清单列了 N 个，包内 inputs 缺少 M 个：...`
  （消息中明确 N/M 与具体 rel_path）。
- 在 `verify_package` 中新增检查项 `inputs_completeness`，放在 `inputs` 摘要检查**之前**执行，
  使其先报“静默残缺”，而不是只报摘要不一致。
- 内部门禁加入 `inputs_completeness`；`NOT CHECKED` 不计入 OK。
- `src/verify_pkg.py` 输出增加该状态行；`wca-verify` 退出码随 FAIL 变为非零。

### 2.5 展示层（P1，排在导出修复之后）

- `src/web/templates/index.html`：
  - 异常表来源行：`{{ ref.rel_path }}:{{ ref.line_no }}`，`title` 保留完整路径；
  - 质量问题表：显示 `i.rel_path`，不再显示 `i.file_id`。
- `src/web/routes.py`：
  - 首页质量问题查询改为 `ingest_issue i JOIN raw_file f ON f.file_id=i.file_id`，
    SELECT `f.rel_path`，去掉 `i.file_id`；
  - `_decorate_review_row` 的 `line_refs` 改为 `rel_path:line_no`；
  - API 序列化前对 `refs` 做展示裁剪：删除 `file_id` 键，保留 `rel_path/line_no`；
  - DB `finding.source_refs` 读写路径不动。
- 测试断言 Web HTML 与 API JSON 中不出现裸 `file_id` 键/数值展示。

## 3. 测试（先红后绿）

新增 `tests/test_nested_export.py`，逐项覆盖：

| 用例 | 断言 |
|---|---|
| 平铺对照 | 成功；四联值等于已知常量 |
| `a/punch.csv` | 包内 `inputs/a/punch.csv` 存在；verify 内部检查全 OK；replay ok |
| `2025-09/门店A/punch.csv` | 两层成功；zip 解包路径正确 |
| 目录名含空格 | 成功 |
| 目录名含中文 | 成功 |
| `a/punch.csv` 与 `b/punch.csv` 同名 | 两份都在包内，互不覆盖 |
| 跨子目录重复行 | a→b / b→a 四联值相同；包内两份 punch 都在 |
| `rel_path` 含 `..` | 导入期 ValueError，中文消息 |
| 绝对路径 | 导入期 ValueError，中文消息 |
| 缺源文件 | export 抛错；无 zip；暂存目录已清理 |
| `inputs/` 预置子目录 | 重跑自愈成功 |
| verify 对账 | 删一个 `inputs/<rel>` 后 verify 报 `INPUTS COMPLETENESS FAIL` 且 N/M 正确 |
| 默认流程 | `gen→ingest→check→export` 产出可 verify/replay 的包 |

新增/扩展 Web/API 测试：

- 页面 HTML 不含 `>{{ ...file_id }}` 形态的来源列；
- `/api/anomalies`（按实际路由名）返回的 `source_refs` 无 `file_id` 键。

回归：

- `tests/test_evidence_digest.py` 四联值常量与跨库/反向顺序测试全绿；
- `tests/test_cross_file_duplicates.py` 全绿；
- 全量 pytest。

## 4. 交付物

1. `handoff/20261104-第八轮整改/README.md`：
   - 只引用实际随包交付的文件；
   - 披露 Web/API `source_refs` 现状、影响、0.4.6 修复与“包内数据不含 DB 编号，但界面/API 曾显示”的区别。
2. 交接目录内新增：
   - 默认流程包（`rel_path=data/raw/*.csv`），verify/replay 均 `RESULT OK`；
   - 双 punch 不同子目录包，包内两份 punch，两种导入顺序四联值相同；
   - `docs/签名方案.md`（完整副本）；
   - 报告 `reports/0.4.6-嵌套路径导出与展示层.md`；
   - 旧 wheel 说明与位置。
3. `dist/wca-replay-0.4.6/`、`SHA256SUMS`、Ed25519 签名；干净 venv 复验四包 + 新增两包。
4. `KEY-NOTE.txt` 轮换记录：原因、生效版本、旧 key 处置、旧包需配旧 wheel；
   明确“旧包用 0.4.5 wheel 是 `PRODUCER FAIL` + `SIGNATURE NOT CHECKED（早退）`，不是验签失败”。
5. 文档：
   - `docs/签名方案.md`、`docs/交付与验收SOP.md` 写明
     `conclusion_digest` 只覆盖 findings 九字段，不含已确认结论；后者由
     `conclusions_final.csv` 工件哈希 + 包签名绑定；
   - `policies/CONFIDENCE.md` 版本按当前 `ENGINE_VERSION` 生成；加测试防止陈旧；
   - 若密钥属意外丢失重生成，单独写入 `docs/安全与证据链现状.md`。

## 5. P3 密钥轮换的判定规则（先取证，再落字）

取证项：

- `WCA_SIGNING_KEY_FILE` 指向文件是否存在、创建/修改时间；
- 0.4.4 与 0.4.5 构建时间、key_id；
- 是否存在旧 key 备份（`var/`、用户目录、交接目录）；
- 构建日志/命令历史是否记录 keygen。

判定：

- 若旧 key 文件在同一位置、可读、时间早于 0.4.4 → **计划内轮换**；
- 若旧 key 缺失且新 key 在 0.4.5 构建前后生成 → **意外丢失重生成**，按安全事件写
  `docs/安全与证据链现状.md`，并写明影响（旧包仍可验，但旧 key 不可复用）。

禁止只写“已轮换”。

## 6. P4 聚合形状（只回答，不改代码）

用实测包检查“1 条聚合 `issue_count=48` + 1 条逐日 `issue_count=1`”对应的
`rule_id/severity/period_key/line_refs/evidence.aggregation`，判断逐日条是否属于
另一条独立规则（如缺卡）而非未吸收的重复行。

- 若逐日条是独立规则/独立语义 → 保留，说明定位价值；
- 若逐日条本应被汇总吸收 → 属规则语义变更，先报用户确认，并评估对
  `conclusion_digest`/`evidence_digest` 与四联值的影响，不得直接改。

## 7. 验收与提交

- 先补 F3/F4 实测并把结果写入报告；
- 测试先红后绿，保留红/绿输出；
- 代码与文档分开提交；不 push；
- 报告开头先给结论，明确区分“实测 / 推断”；
- 单节列四包四联值未变，并给出四个包逐项值；
- 干净 venv 用 0.4.6 wheel 复验四包 + 默认流程包 + 双 punch 子目录包；
- 不改第六/七轮 handoff，交付前用哈希确认两目录未变。

## 8. 待用户确认

请回复“确认方案，开始写代码”。确认后按 `tasks.md` 顺序执行；
若 P4 判定需要改规则语义，或 P3 判定为安全事件，会在对应节点单独汇报后再动代码。
