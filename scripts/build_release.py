"""构建可独立验算的发行物：`dist/wca-replay-<版本>/`。

发行物只包含 wheel、含哈希的锁定清单、SHA256SUMS、RELEASE.json 与一页验收说明；
不包含源码仓库、私钥、数据库或样例数据。构建前强制要求工作树干净，保证
`RELEASE.json.git_commit` 能唯一对应 wheel 内 `src._release_info.BUILD_COMMIT`。

用法：
    uv run python scripts/build_release.py
    uv run python scripts/build_release.py --force   # 覆盖已存在的同版本目录
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from docfacts import generated_block, release_facts, table  # noqa: E402
from src import ENGINE_VERSION  # noqa: E402
from src import signing  # noqa: E402
from src.rules.rulepack import (RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6,  # noqa: E402
                                RULE_PACK_VERSION)
from src.util import (EVIDENCE_PACKAGE_SCHEMA_V1, EVIDENCE_PACKAGE_SCHEMA_V2,  # noqa: E402
                      EVIDENCE_PACKAGE_SCHEMA_V3)

RELEASE_PREFIX = "wca-replay-"
RELEASE_INFO_SOURCE = ROOT / "src" / "_release_info.py"
SUPPORTED_RULE_PACKS = [RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6]
# 发行物签名钥是客户验“wheel 是谁发的”的外部锚点：必须持久，不能每版更换。
# 0.4.1–0.4.5 使用该钥；0.4.6 误用了包签名钥 b07741b2…（第九轮 A7），0.4.7 恢复。
EXPECTED_RELEASE_KEY_ID = "ed25519:5e797e18"
SCHEMA_VERSIONS = [EVIDENCE_PACKAGE_SCHEMA_V1, EVIDENCE_PACKAGE_SCHEMA_V2,
                   EVIDENCE_PACKAGE_SCHEMA_V3]


def _run(cmd: list[str], *, cwd: Path = ROOT) -> None:
    print("+ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def _capture(cmd: list[str], *, cwd: Path = ROOT) -> str:
    out = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(data["project"]["version"])
    engine = ENGINE_VERSION.removeprefix("wca-")
    if engine != version:
        raise SystemExit(
            f"版本不一致：pyproject={version}，src.ENGINE_VERSION={ENGINE_VERSION}")
    return version


def _require_clean_tree() -> str:
    if RELEASE_INFO_SOURCE.exists():
        raise SystemExit(
            f"{RELEASE_INFO_SOURCE} 已存在；它是构建临时文件，不应留在源码树里")
    status = _capture(["git", "status", "--porcelain"])
    if status:
        raise SystemExit(
            "工作树不干净，拒绝构建发行物（发行物必须能唯一对应一个 commit）：\n" + status)
    commit = _capture(["git", "rev-parse", "HEAD"])
    if len(commit) != 40:
        raise SystemExit(f"无法取得完整 git commit：{commit!r}")
    return commit


def _render_release_facts(facts: dict) -> str:
    """机制 1：发行物事实由产物计算，人不得手写（生成区有标记，测试会复核）。"""
    rows: list[list[str]] = []
    for item in facts["files"]:
        if item["name"] == facts["self_reference"]:
            rows.append([f"`{item['name']}`（本文件）", "自引用（见下）",
                         "见同目录 `SHA256SUMS` 对应行"])
        else:
            rows.append([f"`{item['name']}`", f"{item['bytes']:,}",
                         f"`{item['sha256']}`"])
    covered = "、".join(f"`{item['name']}`" for item in facts["covered"])
    body = "\n".join([
        "## 0. 发行物实物（构建时生成，禁止人工编辑）",
        "",
        "本区由 `scripts/build_release.py` 读取实际产物后填入；任何数字、哈希、路径都"
        "不是手写的，护栏测试 `tests/test_doc_facts_guard.py` 会逐条与实物比对。",
        "",
        f"- 版本：`{facts['version']}`；构建时间：`{facts['build_time']}`；"
        f"git commit：`{facts['git_commit']}`",
        f"- wheel：`{facts['wheel']}`；Python 要求：`{facts['python_requires']}`",
        f"- 支持规则包：{', '.join('`' + p + '`' for p in facts['supported_rule_pack_versions'])}",
        f"- 证据包 schema：{', '.join('`' + s + '`' for s in facts['evidence_schema_versions'])}",
        f"- 受签名覆盖的顶层文件：**{facts['file_count']} 个**；"
        f"`SHA256SUMS` 共 **{facts['covered_count']} 行**，逐行对应：{covered}",
        f"- 除本文件外的 {facts['file_count'] - 1} 个文件，合计 "
        f"**{facts['others_bytes_total']:,} 字节**",
        "",
        table(["文件", "字节", "SHA-256"], rows),
        "",
        "自引用说明：`README-验收.md` 的字节与 SHA-256 无法写进自身（写入即改变自身哈希），"
        "故表中不重复，统一由 `SHA256SUMS` 对应行给出；护栏测试用它反向核对本文件"
        "**实际**字节与哈希。这正是“哈希覆盖自身”时唯一自洽的写法。",
    ])
    return generated_block("release-facts", body)


def _readme(version: str, commit: str, wheel: str, build_time: str, facts: dict) -> str:
    return f"""# wca-replay {version} 验算发行物（验收一页）

本目录用于**不拿源码仓库**的第三方复核：装 wheel + 锁定依赖，再对你手上的举证包
跑 `verify` 与 `replay`。发行物本身不含源码仓库、私钥、数据库或样例数据。

**PoC 边界（先读）**：本交付是**验证工具 + 样例包**的 PoC（样例包数量与清单由交接
README 的生成区给出，本发行目录不含包），**不构成合规结论**，
**不可作为生产就绪依据**。四项未闭合：**信任根**（包外固定公钥需独立渠道交付）、
**真实具名确认**（样例为合成数据、无真实具名工具人签认）、**法律文本充分性**（条文为
对外精简版，不替代律师判断）、**数据合规**（未做真实个人信息处理评估）。详见
`docs/安全与证据链现状.md` 第 3 节。

## 对外演示注意（销售/演示者必读）

对外演示“删输入被拦截”**必须用带外部锚点的 v3 包**。证据包**不在本发行物目录**：本目录只含 wheel、锁定依赖、校验清单与说明文件。当本 README 随交接目录交付、位于其 `release/` 子目录时，证据包在**相对本文件**的 `../package/`（该目录实际有几个包，由交接 README 的生成区给出，本文件不猜）；单包锚点文件在相对本文件的 `../` 根目录。默认 `wca all` 在不提供签名钥时导出的是 **v2 无签名包**：它没有输入契约，验算最多得到 `RESULT PARTIAL`（exit 2），删掉输入后也**不会**变成 `FAIL`。用它演示会给人“删了没事”的错觉。


{_render_release_facts(facts)}

## 摘要与边界（先读）







- **摘要边界**：`conclusion_digest` 只覆盖 `rule_id, rule_version, emp_id, work_date,
  period_key, severity, metric, citations, explanation` 九个规范字段；`source_rel_path`、
  `source_line_no`、`severity_label` 由 `artifact_sha256["findings.csv"]` 负责。
  **单个 `FINDINGS DIGEST OK` 不等于整张 `findings.csv` 未变**，必须同时 `ARTIFACTS OK`。
- **数据库自增 ID 不进摘要**：0.4.4 起 `QUAL-01/QUAL-02` 的 `metric.line_refs` 与
  `OFF-01` 的 `metric.conflicts.sources` 只记包内相对路径（`rel_path`）与行号，
  不再记数据库 `file_id`；`source_refs` 仍可保留 `file_id` 供行级反查，但它不参与
  `conclusion_digest`。同一批 CSV 换新库重导、或 punch/schedule 反向导入顺序，
  `inputs_digest` 与 `conclusion_digest` 都必须相同。
- **跨文件重复行归属**：0.4.5 起同一条打卡内容出现在多个 punch CSV 时，`QUAL-DUP`
  的行级引用按 `rel_path` 字典序确定唯一 canonical 引用，全部来源写入 detail 并纳入
  包内输入；两种导入顺序的 `conclusion_digest`/`evidence_digest`/`inputs_digest`/
  `input_fingerprint` 必须相同。单 `punch.csv` 场景的四联值保持 0.4.4 不变。
- **嵌套输入路径**：0.4.6 起导出按 `rel_path` 建父目录，包内保留层级（如
  `inputs/data/raw/*.csv`、`inputs/2025-09/门店A/punch.csv`）；目录名含空格/中文、
  不同目录同名文件均支持且互不覆盖。`inputs/` 暂存目录每次整体重建，重跑可自愈。
- **输入完整性对账**：0.4.6 起 `wca-verify` 新增 `INPUTS COMPLETENESS` 检查，把
  `input_files.csv` 声明的输入与包内 `inputs/manifest.json` 及实际文件双向对账；
  失败先于 `INPUTS DIGEST` 报出 `INPUTS COMPLETENESS FAIL`，并明确列出“清单 N 个、
  包内缺 M 个”及缺失 `rel_path`。
- **导入边界**：`rel_path` 含 `..`、绝对路径、盘符路径在导入期即拒绝（中文错误）；
  导出时缺输入直接失败关闭（非零退出）且不留下半成品包。
- **包内不带 DB 主键**：0.4.7 起包内所有 CSV 的**数据值**不含 `file_id`/
  `related_file_ids`/`run_id`/`segment_id`；跨文件多来源只写
  `来源: rel_path:line_no`。这些列仅保留在数据库中用于输入选择，不进入任何 CSV 数据值。
- **`manifest.json` 顶层的 1 个 `run_id`**：它只用于把包回指到库内 run 与审计段，
  便于定位交付事件；它**不参与** `conclusion_digest`、`evidence_digest`、`inputs_digest`、
  `input_fingerprint`、`artifacts_digest` 的计算，四联值本身不含它。旧表述
  “不进入任何导出工件”容易与这一事实冲突，已按本条改写。
- **导出包唯一命名**：0.4.7 起导出文件名为 `<run_id>-<时间戳>-<短随机>.zip`；
  目标已存在时拒绝覆盖，不静默改写旧包。
- **审批台账规范化披露**：0.4.7 起包内审批台账是数据库重导出（UTF-8 无 BOM、LF），
  不是上传原始字节；顶层 manifest 的 `inputs.approval_export` 记录该事实与原始字节
  是否保留，读者不应把包内字节当作原始上传件。
- **证据定位摘要**：`evidence_digest` 单独覆盖全部 finding 的 `evidence` 块
  （`tables/window/rules/aggregation`，固定字段序、空值 `null`、路径 `/`），**不进入**
  `conclusion_digest`。0.4.3 起（0.4.4 延续）新包必须有该字段；旧包缺失按 `NOT CHECKED` 分档，
  且不能因此给 `RESULT OK`。签名者可能作恶或私钥失窃，**必须**用包外
  `--expect-evidence-digest` 锚定，不能只看包内 manifest。
- **两层输入摘要**：`input_fingerprint` 是内容与范围指纹（输入文件内容/引用范围/规则参数）；
  `inputs_digest` 是包内 `inputs/` 实际文件字节（已不含 `run_id` 与 DB `file_id`；
  文件名由 `rel_path` 推导）。同一批输入跨 run/跨库导包，`inputs_digest` 应相同。
- **规则版本**：`rule_version` 是单条规则版本，不等于 rule pack 版本；v5 包内可同时有
  v4/v5 规则，分布见 `manifest.counts.rule_versions` 与包内 `policies/RULE-PACK.md`。
- **policies/ 用途**：包内 `policies/` 提供规则包定义（rule_id/版本/条文号/阈值/生效日期）、
  条文稳定引用、口径声明、13 项存疑逐条与 `CONFIDENCE.md`，供外部做“规则→条文→阈值→事实”
  的实质审查；它是**对外精简版，不是全文法条库**，也不替代律师判断。
- **默认流程可从 wheel 复现**：0.4.7 起 wheel 内含 `data/generator/make_synthetic.py`；
  `wca gen` 在当前目录写出 `data/raw/*.csv`，随后不指定数据目录即可依次跑
  `ingest → check → export → verify → replay`，交付方已用干净 venv 实测。
- **重复批次语义**：0.4.8 起同一员工同一实际发生日的重复行合并为 1 条 `QUAL-01` finding，
  `work_date = period_key =` 实际发生日；`metric` 带 `batch_id`、`batch_size`、`sources`
  （全部来源，不截断）。`batch_id` 只由 `rel_path:line_no` 集合内容派生，换库重导、反向导入、
  不同机器均相同，禁用 DB 自增/`file_id`/`run_id`/计数器/时间戳。
- **计数口径**：`manifest.counts` 新增 `findings_total` / `findings_batched` / `issues_total`；
  三处计数（manifest、`policies/CONFIDENCE.md`、`未覆盖清单.md`）必须一致。统计重复类问题时
  不要直接数 `findings.csv` 行数，见 README“如何正确统计重复类问题”。
- **规则包 v6**：0.4.8 起默认 `rp-2026.11.gd-pilot-standard.v6`（切换日 2026-11-04；
  v5/v4 仍可用显式 `WCA_RULE_PACK` 选择与回放）。包内 `manifest.producer.version` 必须与
  你所装 wheel 的版本一致；**版本不一致即 `PRODUCER FAIL`（exit 1）**，应按
  `OLD-WHEELS.md` 换用对应版本 wheel，不要按“v5/v6 固定配对某版本”推断。
- **跨后端可复算**：同一输入用 SQLite 或 PostgreSQL 18 导出，`conclusion_digest`、
  `evidence_digest`、`inputs_digest`、`input_fingerprint`、`artifacts_digest` 逐字节相同。
  导出侧行序全部在 Python 显式排序，不依赖 SQL 的 NULL 顺序或文本 collation；回归用例
  `tests/test_postgres_integration.py::test_sqlite_and_postgres_export_five_digests_identical`。

## 前置条件（缺一不可）

1. **Python 3.12**（`py -3.12 --version` 能跑）。
2. **依赖来源**：能联网访问 PyPI；或提前准备与 `requirements.lock.txt` 同版本的
   wheel 缓存。空气隙环境请自行搭建本地索引，本发行物不承诺离线自足。
3. **包外信任根**：你方保管的固定公钥（pin）与四/五段锚点。它们不应从包内取；
   只用包内公钥只能做 `package self-check`，不能证明来源。
4. **待验举证包**：真实签名包（zip 或已解包目录）。发行物不自带证据包；样例数据
   也不在 wheel 内。

## 1. 先核对发行物本身

```powershell
# 在发行物目录内；UTF-8 读取，避免中文文件名乱码
Get-Content SHA256SUMS -Encoding UTF8 | ForEach-Object {{
  $hash, $name = $_ -split '\\s+', 2
  $actual = (Get-FileHash $name -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $hash) {{ throw "SHA256 不匹配：$name" }}
  "OK $name"
}}
Get-Content RELEASE.json -Encoding UTF8 | ConvertFrom-Json
```

`RELEASE.json` 至少要核对：`version`、`build_time`、`git_commit`、
`python_requires`、`supported_rule_pack_versions`、`evidence_schema_versions`。
`SHA256SUMS` 只覆盖构建时的 **5 个顶层文件**：`{wheel}`、`requirements.lock.txt`、
`README-验收.md`、`RELEASE.json`、`VERIFY-SIGNATURE.txt`。`old-wheels/`、
`old-packages/` 与签发后追加的文件（如后续补入的覆盖范围说明）**不在 `SHA256SUMS.sig`
保护范围内**；旧 wheel/旧包须另行核对它们各自的 `旧发行物-SHA256清单.md`。

## 2. 建干净 venv 并安装（不要复用项目 .venv）

```powershell
py -3.12 -m venv .venv-clean
.venv-clean\\Scripts\\python -m pip install --require-hashes -r requirements.lock.txt
.venv-clean\\Scripts\\python -m pip install --no-deps {wheel}
```

`--require-hashes` 要求锁定清单里每个包都带哈希；安装失败即说明依赖与清单不一致，
不要绕过。wheel 用 `--no-deps` 安装，避免 pip 重新解析依赖树。

## 3. 字节层：独立 `wca-verify`（不执行包内代码）

```powershell
.venv-clean\\Scripts\\wca-verify.exe <包.zip> --public-key <固定公钥文件> --expect-anchor "<四/五段>" `
  --expect-package-sha256 <包SHA256> --expect-artifacts-digest <artifacts_digest> `
  --expect-evidence-digest <evidence_digest>
```

期望：`MANIFEST CHECKSUM OK`、`ARTIFACTS OK`、`VERIFY SCRIPT OK`、`FINDINGS DIGEST OK`、
`EVIDENCE DIGEST OK`、`COUNTS 发现（未签认）... / 已确认结论 ...`、`CHAIN OK`、
`INPUTS COMPLETENESS OK`、`INPUTS DIGEST OK`、`SIGNATURE OK / pinned`、`ANCHOR CHECK OK`、`RESULT OK`。
它证明包字节、工件绑定、发现反算摘要、证据定位摘要、输入摘要、签名与外部锚点一致；
**不证明结论正确**。

**`RESULT OK` 五项门禁**：签名 `pinned` + 外部锚点 + 外部 `package_sha256` + 外部
`artifacts_digest` + 外部 `evidence_digest` 必须同时通过；缺一项 → `RESULT PARTIAL`（exit 2），
任一项不匹配 → `RESULT FAIL`（exit 1）。`--anchor-file <单包 anchor.json>` 可一次提供
`anchor`/`package_sha256`/`artifacts_digest`/`evidence_digest`，**显式参数优先 > 环境变量 >
文件兜底**；证据摘要环境变量为 `WCA_EXPECT_EVIDENCE_DIGEST`。

**无签名 v2 包**：未提供 `--signing-key`/`WCA_SIGNING_KEY_FILE`/`WCA_SIGNING_KEY_B64` 时
导出的是 v2 无签名包；`wca-verify` 对其最多输出 `RESULT PARTIAL`（exit 2），
**不能作为完整验收**。
v2 包**不会因缺少 `inputs_digest` 这一项门禁**而被判 `RESULT FAIL`：该门禁对 v2 记
`INPUTS DIGEST NOT CHECKED`（版本缺失，不是篡改）；schema v3 缺该字段才是 `INPUTS FAIL`。
**这只是限定语义，不是“v2 不会失败”**：包内其他字节一旦被改（清单、工件、发现等），
仍会 `RESULT FAIL`（exit 1）；`--require-signature` 下无签名即 `SIGNATURE FAIL`（exit 1）。

**跨版本可比性（0.4.9）**：摘要只在同 `rule_pack_version` + 同 evidence schema 下可比。
外部包 SHA / evidence / artifacts 门禁**先于可比性判定**：
- 只传显式 `--expect-anchor`（或 `--expect-triple`）串时，版本/schema 不同 →
  `RESULT INCOMPARABLE`（**exit 3**）；
- 传**完整单包锚点文件**时，文件里的 `package_sha256` / `evidence_digest` /
  `artifacts_digest` 先比对，任一不匹配 → `RESULT FAIL`（**exit 1**），不会走到可比性判定。
  例：用 v6 包的完整锚点文件验 v5 包，先报 `PACKAGE SHA256 FAIL`（exit 1），不是 exit 3。

同版本同 schema 摘要不符仍 `FAIL`（exit 1），缺字段/缺签名仍失败关闭。锚点文件带
`comparability_scope`（`rule_pack_version` + `schema`），旧锚点按版本命名
（`anchor-<version>-<role>.json`）、不覆盖。退出码：0 OK / 1 FAIL / 2 PARTIAL / 3 INCOMPARABLE。
**`PRODUCER FAIL` ≠ 篡改**：新版 wheel 验旧包会先报 `PRODUCER FAIL` 并早退签名检查，应改用
对应版本旧 wheel。

**旧 wheel 不做 scope 判定（0.4.11）**：0.4.4–0.4.8 的 wheel 不识别 `comparability_scope`，
其 `RESULT OK` **仅表示旧口径（签名/锚点/包 SHA/工件摘要）通过**，**不表示可比性已核验**；
0.4.9 起才有该判定。旧包必须配对应版本旧 wheel（清单见交接包 `OLD-WHEELS.md`）；用新 wheel
验旧包会先报 `PRODUCER FAIL`，不是篡改。

**`NOT CHECKED` / `SKIPPED` 含义**：`NOT CHECKED` 只表示早退时尚未走到该检查，
**不等于“缺失/不符”**；已传入锚点但前序失败时输出 `ANCHOR SKIPPED (early exit)`，与
“未提供锚点”的 `ANCHOR NOT CHECKED（未传外部锚点）` 彻底分开。`ARTIFACTS FAIL` 行会带具体
失败文件名；`FINDINGS DIGEST OK` 会带后缀 `(9 fields; source_* not covered by digest)`；
`EVIDENCE DIGEST` 在 0.4.3+ 新包上内部必须 `OK`，且外部 `evidence_digest` 必须匹配；
新版本包缺字段会 `FAIL` 失败关闭，无 producer 或 producer.version < 0.4.3 的旧包输出
`NOT CHECKED`（明确不能给 `RESULT OK`）。
`input_fingerprint` 与 `inputs_digest` 的分工见上；`inputs_digest` 不含 `run_id`/DB `file_id`，
同一批输入跨 run/跨库稳定。

**anchor 文件与环境变量**：组合式 `anchor.json` 的 `packages` 是**数组**，元素为包对象
（每个元素是含 `role/file/bytes/sha256/anchor/…` 的单包记录），不是 `key → 记录` 的映射。
**数量口径**：数组长度等于该批交付的举证包数量，与每个元素的 `role` 一一对应；本批次为
8 个元素（4 个主包 + default-flow + dup 两个 + clean-wheel），不是目录数或 run 数。
`--anchor-file` 只接受单包扁平 JSON（`anchor`/`package_sha256`/`artifacts_digest`/
`evidence_digest`），组合式 `anchor.json` 会被拒绝（避免把 A 包哈希套到 B 包）。环境变量入口：
`WCA_EXPECT_ANCHOR`（锚点）与 `WCA_EXPECT_EVIDENCE_DIGEST`（证据定位摘要）；包 SHA 与
`artifacts_digest` 只能走显式参数或单包 anchor 文件。优先级：显式参数 > 环境变量 > anchor 文件。

## 4. 字段层：同版本 `replay`

```powershell
.venv-clean\\Scripts\\wca.exe replay <包.zip> --public-key <固定公钥文件> --expect-anchor "<四/五段>" `
  --expect-package-sha256 <包SHA256> --expect-artifacts-digest <artifacts_digest> `
  --expect-evidence-digest <evidence_digest>
```

期望：`工件逐文件：OK`、`发现摘要：一致`、`EVIDENCE DIGEST OK`、三元组逐项 `=`、
`发现（未签认）`条数一致、`RESULT OK`。裁剪包会显示 `≠ input_fingerprint`（预期），
但投影指纹、结论摘要与证据定位摘要必须一致。

## 5. 版本核对（决定“该用哪个版本复算”）

从包内 `manifest.json` 读 `producer`：

- `producer.version` 必须等于 `RELEASE.json.version`；
- `producer.commit` 必须等于 `RELEASE.json.git_commit`；
- `producer.rule_pack_version` 必须在 `RELEASE.json.supported_rule_pack_versions` 内。

`replay` 已把 `producer` 的前三项与当前代码逐一核对，不一致直接
`PRODUCER FAIL`（失败关闭）。`producer.python` 是**导出时**解释器版本，只作
记录；跨补丁版本复算不因它失败，但必须在验收记录里写明实际复算解释器。

**跨版本复算属于例外流程**：包内 commit 与发行物不一致时拒收；确需复算时由
双方书面标注“跨版本、使用 commit X 复算 commit Y 的包”，并同时保留包外锚点，
不得把它写成同版本可复算。

## 6. 发行物自身签名（若目录内有 `SHA256SUMS.sig`）

- `SHA256SUMS.sig` 是对 `SHA256SUMS` 原始字节的 Ed25519 签名；`VERIFY-SIGNATURE.txt`
  给出 key_id、公钥副本与一段可执行的验证代码。
- `SHA256SUMS` 只覆盖构建时的 **5 个顶层文件**（与 §1 一致）：`{wheel}`、
  `requirements.lock.txt`、`README-验收.md`、`RELEASE.json`、`VERIFY-SIGNATURE.txt`。
  `SHA256SUMS.sig` 是 detached 签名，既不覆盖自身，也不覆盖 `.sig`；
  `old-wheels/`、`old-packages/` 与签发后追加的文件**都不在保护范围**。
- 该签名只证明“SHA256SUMS 与私钥匹配”；**pinned 不等于来源身份已核验**，仍须双方通过
  独立渠道核验 key_id。
- 本发行物只说明构建方法，**未实现/未验证可复现构建**；不声称 wheel 可逐字节重建。

## 7. 仍不覆盖什么

- `wca-verify` 只证明字节/工件绑定/发现反算摘要/签名/锚点，不跑引擎，不重算投影。
- 包内 `verify.py` 只是便利脚本，不是信任依据；不校验工件绑定与 findings 反算摘要。
- `replay` 依赖本发行物这一版代码与仓库默认口径；包内未记录的参数沿用代码默认值，
  不读你的本机 `.env`。
- 公钥与包外锚点同时被替换仍会失守；发行物不解决信任根分发问题。
- 不覆盖原始 CSV 的业务真实性、上游系统权限与数据保留期限。
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建 wca-replay 验算发行物")
    parser.add_argument("--out-root", default=str(ROOT / "dist"),
                        help="发行物输出根目录，默认 dist/")
    parser.add_argument("--force", action="store_true",
                        help="覆盖已存在的同版本发行目录")
    parser.add_argument("--signing-key", default=os.environ.get("WCA_RELEASE_SIGNING_KEY"),
                        help="Ed25519 私钥路径；给出时生成 SHA256SUMS.sig 与 "
                             "VERIFY-SIGNATURE.txt（也可用 WCA_RELEASE_SIGNING_KEY）")
    parser.add_argument("--allow-key-rotation", default="", metavar="理由",
                        help="显式允许发行钥轮换，并把理由写入 RELEASE.json；"
                             "不给理由时 key_id 不匹配会直接失败")
    args = parser.parse_args(argv)

    version = _project_version()
    commit = _require_clean_tree()
    build_time = datetime.now().astimezone().isoformat(timespec="seconds")
    wheel_name = f"worktime_compliance_agent-{version}-py3-none-any.whl"
    out_root = Path(args.out_root).resolve()
    release_dir = out_root / f"{RELEASE_PREFIX}{version}"
    if release_dir.exists() and not args.force:
        raise SystemExit(f"发行目录已存在：{release_dir}（确认覆盖请加 --force）")
    if release_dir.exists():
        shutil.rmtree(release_dir)
    release_dir.mkdir(parents=True, exist_ok=False)

    build_dir = Path(tempfile.mkdtemp(prefix=".wca-release-build-", dir=out_root))
    RELEASE_INFO_SOURCE.write_text(
        '"""构建时自动生成；不要提交到源码树。"""\n'
        f'BUILD_COMMIT = "{commit}"\n',
        encoding="utf-8",
    )
    try:
        _run(["uv", "build", "--wheel", "--out-dir", str(build_dir)])
        built = list(build_dir.glob("*.whl"))
        if len(built) != 1:
            raise SystemExit(f"期望 1 个 wheel，实际 {[p.name for p in built]}")
        if built[0].name != wheel_name:
            raise SystemExit(f"wheel 名称与预期不一致：{built[0].name} != {wheel_name}")
        shutil.copy2(built[0], release_dir / wheel_name)
    finally:
        RELEASE_INFO_SOURCE.unlink(missing_ok=True)
        shutil.rmtree(build_dir, ignore_errors=True)

    lock = release_dir / "requirements.lock.txt"
    _run(["uv", "export", "--frozen", "--all-groups", "--format", "requirements.txt",
          "--no-emit-project", "--output-file", str(lock)])
    lock_text = lock.read_text(encoding="utf-8")
    if "--hash=sha256:" not in lock_text:
        raise SystemExit("requirements.lock.txt 不含哈希；拒绝生成发行物")

    readme = release_dir / "README-验收.md"
    # 先占位：README 必须晚于 RELEASE.json/VERIFY-SIGNATURE.txt 才能读取实物事实，
    # 又必须先于 SHA256SUMS 写出（否则自引用成环）。占位不写内容，只占文件名，
    # 使“顶层文件数”从真实目录得到 5，而不是靠记忆。
    readme.touch()

    release = {
        "release": release_dir.name,
        "version": version,
        "build_time": build_time,
        "git_commit": commit,
        "python_requires": ">=3.12",
        "python_built_with": platform.python_version(),
        "supported_rule_pack_versions": SUPPORTED_RULE_PACKS,
        "default_rule_pack_version": RULE_PACK_VERSION,
        "evidence_schema_versions": SCHEMA_VERSIONS,
        "wheel": wheel_name,
        "lock_file": lock.name,
        "lock_hashes": True,
        "entry_points": {
            "wca": "src.cli:main",
            "wca-replay": "src.cli:main",
            "wca-verify": "src.verify_pkg:main",
        },
    }
    signing_key = signing.load_signing_key(args.signing_key) if args.signing_key else None
    if args.signing_key and signing_key is None:
        raise SystemExit(f"无法读取发行签名私钥：{args.signing_key}")
    if signing_key is not None:
        public_b64 = signing.public_key_b64(signing_key.verify_key.encode())
        key_id = signing.key_id_for_public_key(signing_key.verify_key.encode())
        if not key_id.startswith(EXPECTED_RELEASE_KEY_ID):
            if not args.allow_key_rotation:
                raise SystemExit(
                    f"发行签名钥 key_id={key_id} 与记录的发行钥 "
                    f"{EXPECTED_RELEASE_KEY_ID}… 不一致。\n"
                    "发行钥是客户的信任锚点，禁止静默轮换；请改用 "
                    "`--signing-key var/release-keys/ed25519.key`。\n"
                    "确需轮换时传 --allow-key-rotation \"<原因>\"，并同步更新 KEY-NOTE.")
        release["release_signature"] = {
            "file": "SHA256SUMS.sig",
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key_b64": public_b64,
            "signed_file": "SHA256SUMS",
            "scope": ("SHA256SUMS 仅覆盖构建时的 5 个顶层发行文件"
                      "（wheel/requirements.lock.txt/README-验收.md/RELEASE.json/"
                      "VERIFY-SIGNATURE.txt）；old-wheels/、old-packages/ 及签发后追加"
                      "文件不在保护范围"),
            "note": "签名只证明 SHA256SUMS 与私钥匹配；来源身份需独立核验 key_id",
        }
        if args.allow_key_rotation:
            release["release_signature"]["rotation_reason"] = args.allow_key_rotation
    release_json = release_dir / "RELEASE.json"
    release_json.write_text(json.dumps(release, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    if signing_key is not None:
        verify_txt = release_dir / "VERIFY-SIGNATURE.txt"
        verify_txt.write_text(
            "发行物签名说明（SHA256SUMS.sig）\n"
            "================================\n"
            "算法：Ed25519（PyNaCl）。签名对象：本目录 SHA256SUMS 的原始字节。\n"
            f"key_id：{key_id}\n"
            f"public_key_b64：{public_b64}\n\n"
            "验证（在发行物目录内，使用已安装 requirements.lock.txt 的 Python）：\n"
            "  from pathlib import Path\n"
            "  import base64\n"
            "  from nacl.signing import VerifyKey\n"
            "  sums = Path('SHA256SUMS').read_bytes()\n"
            "  sig = base64.b64decode(Path('SHA256SUMS.sig').read_text().strip())\n"
            "  VerifyKey(base64.b64decode('" + public_b64 + "')).verify(sums, sig)\n"
            "  print('SHA256SUMS SIGNATURE OK')\n\n"
            "口径：pinned 只表示“与随附公钥副本匹配”；只有通过独立渠道核验 key_id 后，\n"
            "才能说来源身份已核验。本签名不证明构建可复现，也不证明 wheel 未被替换——\n"
            "SHA256SUMS.sig 只签 SHA256SUMS，SHA256SUMS 不包含自身与 .sig。\n",
            encoding="utf-8")
    facts = release_facts(release_dir)
    readme.write_text(_readme(version, commit, wheel_name, build_time, facts),
                      encoding="utf-8")
    sums = release_dir / "SHA256SUMS"
    lines = []
    for path in sorted(release_dir.iterdir(), key=lambda p: p.name):
        if path.name in (sums.name, "SHA256SUMS.sig") or not path.is_file():
            continue
        lines.append(f"{_sha256(path)}  {path.name}")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if signing_key is not None:
        signature = signing_key.sign(sums.read_bytes()).signature
        (release_dir / "SHA256SUMS.sig").write_text(
            base64.b64encode(signature).decode("ascii") + "\n", encoding="utf-8")

    print(f"\n发行物：{release_dir}")
    for path in sorted(release_dir.iterdir(), key=lambda p: p.name):
        print(f"  {path.name:36s} {path.stat().st_size:>12,} 字节")
    print(f"  git commit {commit}")
    print(f"  版本 {version} / Python {platform.python_version()} / "
          f"规则包 {RULE_PACK_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
