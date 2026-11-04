# 0.4.6 验收检查清单

## 导出与失败关闭

- [x] 默认流程（不指定数据目录）`gen → ingest → check → export` 成功，包内为 `inputs/data/raw/*.csv`
- [x] 单层 `a/punch.csv`、两层 `2025-09/门店A/punch.csv`、空格、中文目录均可导出并 verify/replay
- [x] 不同目录同名文件（`a/punch.csv` 与 `b/punch.csv`）两份都在包内且不互相覆盖
- [x] `rel_path` 含 `..` 在导入期被拒绝，中文错误，非零退出
- [x] cwd 外绝对路径在导入期被拒绝（或归一化），不得 exit 0 造出残缺包
- [x] 缺任一应打包输入时 `export` 非零退出，且不留 zip、不留暂存目录
- [x] `inputs/` 内已有子目录时重跑可自愈，不再 `PermissionError`

## 验算补洞

- [x] `wca-verify` 输出 `INPUTS COMPLETENESS` 状态行
- [x] 删除包内某个 `inputs/<rel>` 后报 `INPUTS COMPLETENESS FAIL`，含“清单 N 个、包内缺 M 个”和具体 rel_path
- [x] `INPUTS COMPLETENESS` 先于 `INPUTS DIGEST` 报出，退出码非零
- [x] schema < 3 的旧包该检查为 `NOT CHECKED`，不误判 FAIL

## 展示层

- [x] Web 异常表来源显示 `rel_path:line_no`，无裸 `file_id`
- [x] Web 质量问题表显示 `rel_path`，无裸 `file_id`
- [x] API `source_refs` 序列化不含 `file_id` 键
- [x] DB `finding.source_refs` 未改动（兼容读取仍可）

## 四包不变量

- [x] 四个平铺包四联值与基线一致：`b9cc6fd0… / 01cb5aeb… / aad527d1… / 8b3b54a0…`
- [x] 若变化，已逐 finding/字段归因并停止交付（实测未变化）

## 文档

- [x] 交接 README 只引用实际随包交付的文件
- [x] README 披露 Web/API `source_refs` 风险与 0.4.6 修复
- [x] `policies/CONFIDENCE.md` 按当前 `ENGINE_VERSION` 渲染，含测试防陈旧
- [x] `docs/签名方案.md` 与 SOP 写明 `conclusion_digest` 只覆盖 findings 九字段，不含已确认结论
- [x] `KEY-NOTE.txt` 含轮换原因、生效版本、旧 key 处置、旧包需配旧 wheel
- [x] `KEY-NOTE.txt` 明确写明“旧包用 0.4.5 wheel 是 `PRODUCER FAIL` + `SIGNATURE NOT CHECKED（早退）`”
- [x] P4 聚合形状判断写入报告，未擅自改规则语义

## 发行与交接

- [x] `dist/wca-replay-0.4.6/` 含 wheel、`requirements.lock.txt`、`SHA256SUMS`、`SHA256SUMS.sig`、`RELEASE.json`、`README-验收.md`
- [x] `handoff/20261104-第八轮整改/` 含默认流程包与两个双 punch 子目录包
- [x] 双 punch 包两种导入顺序四联值相同，包内同时含两份 punch
- [x] 交接目录含 `docs/签名方案.md`、两份报告、`OLD-WHEELS.md` 与旧 wheel
- [x] 干净 venv 用 0.4.6 wheel 复验七个包，verify/replay 均 `RESULT OK`
- [x] 第六/七轮 handoff 目录未改动（最新文件时间早于本轮构建）
- [x] 代码与文档分开提交，未 push
- [x] 报告结论先行，实测与推断分开，四包值未变独立一节
