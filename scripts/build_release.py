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

from src import ENGINE_VERSION  # noqa: E402
from src import signing  # noqa: E402
from src.rules.rulepack import (RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6,  # noqa: E402
                                RULE_PACK_VERSION)
from src.util import (EVIDENCE_PACKAGE_SCHEMA_V1, EVIDENCE_PACKAGE_SCHEMA_V2,  # noqa: E402
                      EVIDENCE_PACKAGE_SCHEMA_V3)

RELEASE_PREFIX = "wca-replay-"
RELEASE_INFO_SOURCE = ROOT / "src" / "_release_info.py"
SUPPORTED_RULE_PACKS = [RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6]
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


def _readme(version: str, commit: str, wheel: str, build_time: str) -> str:
    return f"""# wca-replay {version} 验算发行物（验收一页）

本目录用于**不拿源码仓库**的第三方复核：装 wheel + 锁定依赖，再对你手上的举证包
跑 `verify` 与 `replay`。发行物本身不含源码仓库、私钥、数据库或样例数据。

- 版本：`{version}`；构建时间：`{build_time}`；git commit：`{commit}`
- wheel：`{wheel}`
- Python 要求：`>=3.12`（本项目在 3.12.8 上构建与实测）
- 支持规则包：{", ".join("`" + p + "`" for p in SUPPORTED_RULE_PACKS)}
- 证据包 schema：{", ".join("`" + s + "`" for s in SCHEMA_VERSIONS)}
- **摘要边界**：`conclusion_digest` 只覆盖 `rule_id, rule_version, emp_id, work_date,
  period_key, severity, metric, citations, explanation` 九个规范字段；`source_rel_path`、
  `source_line_no`、`severity_label` 由 `artifact_sha256["findings.csv"]` 负责。
  **单个 `FINDINGS DIGEST OK` 不等于整张 `findings.csv` 未变**，必须同时 `ARTIFACTS OK`。
- **规则版本**：`rule_version` 是单条规则版本，不等于 rule pack 版本；v5 包内可同时有
  v4/v5 规则，分布见 `manifest.counts.rule_versions` 与包内 `policies/RULE-PACK.md`。

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
`SHA256SUMS` 覆盖本目录内除自身外的全部文件。

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
  --expect-package-sha256 <包SHA256> --expect-artifacts-digest <artifacts_digest>
```

期望：`MANIFEST CHECKSUM OK`、`ARTIFACTS OK`、`VERIFY SCRIPT OK`、`FINDINGS DIGEST OK`、
`COUNTS 发现（未签认）... / 已确认结论 ...`、`CHAIN OK`、`INPUTS DIGEST OK`、
`SIGNATURE OK / pinned`、`ANCHOR CHECK OK`、`RESULT OK`。它证明包字节、工件绑定、
发现反算摘要、输入摘要、签名与外部锚点一致；**不证明结论正确**。
不传 `--expect-anchor` 只输出 `ANCHOR NOT CHECKED` + `RESULT PARTIAL`（exit 2）。

## 4. 字段层：同版本 `replay`

```powershell
.venv-clean\\Scripts\\wca.exe replay <包.zip> --public-key <固定公钥文件> --expect-anchor "<四/五段>"
```

期望：`工件逐文件：OK`、`发现摘要：一致`、三元组逐项 `=`、
`发现（未签认）`条数一致、`RESULT OK`。裁剪包会显示 `≠ input_fingerprint`（预期），
但投影指纹与结论摘要必须一致。

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
- `SHA256SUMS` 覆盖除自身与 `SHA256SUMS.sig` 之外的发行文件；`.sig` 是 detached，
  不会被自身覆盖。
- 该签名只证明“SHA256SUMS 与私钥匹配”；**pinned 不等于来源可信**，仍须双方通过
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
    readme.write_text(_readme(version, commit, wheel_name, build_time), encoding="utf-8")

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
        release["release_signature"] = {
            "file": "SHA256SUMS.sig",
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key_b64": public_b64,
            "signed_file": "SHA256SUMS",
            "scope": "SHA256SUMS 覆盖除 SHA256SUMS.sig 与自身外的发行文件",
            "note": "签名只证明 SHA256SUMS 与私钥匹配；来源可信需独立核验 key_id",
        }
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
            "才能说来源可信。本签名不证明构建可复现，也不证明 wheel 未被替换——\n"
            "SHA256SUMS.sig 只签 SHA256SUMS，SHA256SUMS 不包含自身与 .sig。\n",
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
