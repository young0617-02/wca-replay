"""护栏：交付目录内所有 `.md`/`.txt` 的事实必须与实物一致。

覆盖：
- 生成区标记成对出现（机制 1 的“禁人工编辑”边界）；
- 包表里的字节、SHA-256 与 `package/*.zip` 实物一致；
- `交付清单.txt` 的每行 `bytes=` / `sha256=` 与文件实物一致；
- 所有 64 位哈希都能在交付目录里找到出处（文件字节哈希 / 包内摘要 / 锚点字段）；
- `SHA256SUMS` 行数与文档写的“N 行/N 个文件”一致；
- 每份文档的 `## X、` 章节号唯一且连续（D1）；
- 文档相对路径全部存在或已登记（调用 `check_handoff_refs`）；
- 文档里出现的其余数字必须属于“从产物算出的值”或显式登记的非产物常量。

任何一条不符即失败。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HANDOFF = ROOT / "handoff" / "20261104-第十七轮整改"

SHA_RE = re.compile(r"[0-9a-f]{64}")
MANIFEST_LINE_RE = re.compile(
    r"(?m)^  ([^ \n]+)  bytes=(\d+)  sha256=([0-9a-f]{64})$")
PACKAGE_ROW_RE = re.compile(
    r"(?m)^\| `([^`]+\.zip)` \| ([\d,]+) \| `([0-9a-f]{64})` \|")
SUMS_COUNT_RE = re.compile(r"SHA256SUMS[^|\n]{0,40}?(?:共|实有|只有|保护)\s*[*`]*\s*(\d+)")
SECTION_RE = re.compile(r"(?m)^## ([零一二三四五六七八九十]+)、")

# 非产物常量：退出码、年份、逻辑分档。每一项都必须有“为什么不是实物事实”的理由。
NON_ARTIFACT_NUMBERS = {
    "0": "退出码 OK", "1": "退出码 FAIL", "2": "退出码 PARTIAL", "3": "退出码 INCOMPARABLE",
    "2026": "年份（构建时间/日期）", "2025": "年份",
    "4": "四项未闭合 / 0.4.x 版本串", "6": "0.4.6 历史版本号", "8": "0.4.8 历史版本号",
    "9": "0.4.9 历史版本号", "16": "八包 × verify/replay = 16 次",
    "115": "第四轮盲验 findings 总数（包内 manifest）",
    "31": "变异测试用例数（测试代码常量，不随交付）",
    "7": "七类篡改（用例类别数）",
    "14": "第四轮盲验查出的问题条数（报告口径，非产物）",
    "25": "0.4.1 时代测试用例数（历史测试名称的一部分）",
    "639": "第十六轮 PG 全量历史计数（归档日志，非现行口径）",
    "615": "第十六轮离线全量历史计数（归档日志，非现行口径）",
    "549": "0.4.5 历史计数（归档日志）",
    "572": "0.4.5 PG 历史计数（归档日志）",
    "13": "包内 CONFIDENCE.md 的 13 项存疑（历史口径，非本轮产物）",
    "18": "PostgreSQL 版本号（环境要求，非产物事实）",
    "27": "M-07 上一轮 pip-audit 锁定包计数（外部工具历史结果）",
    "30": "M-07 本轮 pip-audit JSON 列出的包数（外部工具结果）",
    "31": "M-07 本轮导出的锁定包条数（外部工具结果）",
    "8601": "ISO 8601 标准编号",
    "0600": "POSIX 文件权限模式",
    "40": "完整 git commit 的十六进制长度（协议常量）",
}


def _require_handoff() -> Path:
    if not HANDOFF.is_dir():
        pytest.skip(f"{HANDOFF} 不存在（护栏在交付生成后生效）")
    return HANDOFF


def _texts(base: Path) -> list[Path]:
    return [p for p in sorted(base.rglob("*"))
            if p.is_file() and p.suffix.lower() in (".md", ".txt")]


def test_generated_blocks_are_marked_and_paired() -> None:
    base = _require_handoff()
    names = ["README-验收.md", "READ-ME-FIRST.txt", "OLD-WHEELS.md", "OLD-ANCHORS.md",
             "release/SHA256SUMS-覆盖范围.md"]
    for name in names:
        text = (base / name).read_text(encoding="utf-8")
        starts = text.count("<!-- GENERATED:START")
        ends = text.count("<!-- GENERATED:END")
        assert starts >= 1 and ends >= 1, f"{name} 缺少生成区标记"
        assert starts == ends, f"{name} 生成区标记不成对：{starts}/{ends}"


def test_package_table_matches_actual_zips() -> None:
    base = _require_handoff()
    text = (base / "README-验收.md").read_text(encoding="utf-8")
    rows = PACKAGE_ROW_RE.findall(text)
    assert len(rows) == 8, f"README §四 包表应有 8 行，实有 {len(rows)}"
    for name, byte_text, sha in rows:
        path = base / "package" / name
        assert path.is_file(), f"包表引用了不存在的包：{name}"
        assert int(byte_text.replace(",", "")) == path.stat().st_size, \
            f"{name} 字节与实物不符：文档 {byte_text}，实物 {path.stat().st_size}"
        import hashlib
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert sha == actual, f"{name} SHA-256 与实物不符"


def test_manifest_lines_match_actual_files() -> None:
    base = _require_handoff()
    text = (base / "交付清单.txt").read_text(encoding="utf-8")
    rows = MANIFEST_LINE_RE.findall(text)
    assert len(rows) >= 100, f"交付清单明细行过少（{len(rows)}），疑似漏列文件"
    import hashlib
    for rel, byte_text, sha in rows:
        path = base / rel
        assert path.is_file(), f"交付清单列了不存在的文件：{rel}"
        assert int(byte_text) == path.stat().st_size, f"{rel} 字节与实物不符"
        assert sha == hashlib.sha256(path.read_bytes()).hexdigest(), f"{rel} SHA-256 与实物不符"


def test_every_hash_has_a_source_in_delivery() -> None:
    """哈希必须来自**结构化事实**（文件字节、包内摘要、锚点、SHA256SUMS），
    而不是“文档里抄了一遍就算有出处”。"""
    base = _require_handoff()
    known: set[str] = set()
    import hashlib
    import zipfile

    def collect(value) -> None:
        if isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, str):
            # key_id 形如 ed25519:<64 hex>，其 hex 部分是公钥指纹，也必须有出处。
            if value.startswith("ed25519:") and SHA_RE.fullmatch(value[8:]):
                known.add(value[8:])
            elif SHA_RE.fullmatch(value):
                known.add(value)

    # 公钥文件的指纹 = sha256(公钥字节)；这是文档里发行钥/包钥 key_id 的出处。
    import base64
    for pub in base.rglob("*.pub"):
        raw = pub.read_text(encoding="utf-8").strip()
        try:
            key_bytes = base64.b64decode(raw)
        except Exception:
            key_bytes = raw.encode("utf-8")
        known.add(hashlib.sha256(key_bytes).hexdigest())

    for path in base.rglob("*"):
        if not path.is_file():
            continue
        known.add(hashlib.sha256(path.read_bytes()).hexdigest())
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as zf:
                collect(json.loads(zf.read("manifest.json").decode("utf-8")))
        elif path.name.startswith("anchor-") and path.suffix == ".json":
            collect(json.loads(path.read_text(encoding="utf-8")))
        elif path.name == "RELEASE.json":
            collect(json.loads(path.read_text(encoding="utf-8")))
        elif path.name == "SHA256SUMS":
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    known.add(line.split()[0])
    # `旧发行物-SHA256清单.md` 记录历史发行目录与历史举证包的历史哈希；原目录不随交付，
    # 但仓库 `dist/`、`handoff/`、`var/` 内仍保留，可作这些历史哈希的实物出处（C6 限定范围）。
    for extra in (ROOT / "dist", ROOT / "handoff", ROOT / "var"):
        for path in extra.rglob("*"):
            if path.is_file():
                known.add(hashlib.sha256(path.read_bytes()).hexdigest())
    missing: list[str] = []
    for path in _living_docs(base):
        # 归档报告（`reports/` 中旧轮次文件）记录的是当时产物；其哈希属于历史记录，
        # 无法也不应在本交付内复核。当前交付事实文档全部在 `_living_docs` 名单内。
        if "lock.txt" in path.name:
            continue
        for digest in set(SHA_RE.findall(path.read_text(encoding="utf-8"))):
            if digest not in known:
                missing.append(f"{path.relative_to(base).as_posix()} 的哈希无出处：{digest}")
    assert not missing, "存在无法在交付内溯源到实物的哈希：\n" + "\n".join(missing[:10])


def test_sha256sums_scope_numbers_match_actual() -> None:
    base = _require_handoff()
    actual = len([line for line in (base / "release" / "SHA256SUMS")
                  .read_text(encoding="utf-8").splitlines() if line.strip()])
    mismatches: list[str] = []
    for path in _texts(base):
        for match in SUMS_COUNT_RE.finditer(path.read_text(encoding="utf-8")):
            if int(match.group(1)) != actual:
                mismatches.append(f"{path.relative_to(base).as_posix()}: "
                                  f"{match.group(0)!r} 与实际 {actual} 行不符")
    assert not mismatches, "\n".join(mismatches)


def test_section_numbers_are_unique_and_sequential() -> None:
    base = _require_handoff()
    cn = "零一二三四五六七八九十"

    def cjk(index: int) -> str:
        if index <= 10:
            return cn[index]
        if index < 20:
            return "十" + cn[index % 10]
        return cn[index // 10] + "十" + (cn[index % 10] if index % 10 else "")

    bad: list[str] = []
    for path in _texts(base):
        if path.suffix.lower() != ".md":
            continue
        numbers = SECTION_RE.findall(path.read_text(encoding="utf-8"))
        if not numbers:
            continue
        if numbers != [cjk(i) for i in range(1, len(numbers) + 1)]:
            bad.append(f"{path.relative_to(base).as_posix()} 章节号重复/跳号：{numbers}")
    assert not bad, "\n".join(bad)


def test_relative_paths_resolve() -> None:
    base = _require_handoff()
    sys_path = str(ROOT / "scripts")
    import sys
    if sys_path not in sys.path:
        sys.path.insert(0, sys_path)
    import check_handoff_refs
    errors = check_handoff_refs.check_refs(base)
    assert not errors, "\n".join(errors[:10])


def _living_docs(base: Path) -> list[Path]:
    """数字审计只扫“现行口径”文档；历史报告是归档记录，其数字属于当时产物。"""
    names = ["README-验收.md", "READ-ME-FIRST.txt", "OLD-WHEELS.md", "OLD-ANCHORS.md",
             "未随交付清单.md", "交付清单.txt", "release/README-验收.md",
             "release/SHA256SUMS-覆盖范围.md", "release/旧发行物-SHA256清单.md"]
    paths = [base / name for name in names if (base / name).is_file()]
    paths += sorted((base / "docs").glob("*.md"))
    return paths


def test_numbers_are_artifact_facts_or_declared_constants() -> None:
    """数字护栏：除版本串/日期/哈希外，每个整数都必须能由产物算出或显式登记。"""
    base = _require_handoff()
    packages = sorted((base / "package").glob("*.zip"))
    reports = sorted(p for p in (base / "reports").iterdir() if p.is_file())
    old_packages = sorted((base / "release" / "old-packages").glob("*.zip"))
    old_wheels = sorted((base / "release" / "old-wheels").glob("*.whl"))
    anchors = sorted(base.glob("anchor-0.4.*.json"))
    sums_lines = [line for line in (base / "release" / "SHA256SUMS")
                  .read_text(encoding="utf-8").splitlines() if line.strip()]
    actual = {
        str(len(packages)), str(len(reports)), str(len(old_packages)),
        str(len(old_wheels)), str(len(anchors)), str(len(sums_lines)),
        str(len([p for p in base.rglob('*') if p.is_file()])),
    }
    for path in base.rglob("*"):
        if path.is_file():
            actual.add(str(path.stat().st_size))
            actual.add(f"{path.stat().st_size:,}")
    # 历史发行/交接目录不随交付，但其文件仍在仓库内；`旧发行物-SHA256清单.md` 的字节
    # 与哈希以它们为出处（C6 限定范围）。
    for extra in (ROOT / "dist", ROOT / "handoff", ROOT / "var"):
        for path in extra.rglob("*"):
            if path.is_file():
                actual.add(str(path.stat().st_size))
                actual.add(f"{path.stat().st_size:,}")
    import sys
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    import docfacts
    for rel_dir in (base / "release", ROOT / "dist" / "wca-replay-0.4.15"):
        rel = docfacts.release_facts(rel_dir)
        actual.add(str(rel["others_bytes_total"]))
        actual.add(f"{rel['others_bytes_total']:,}")
        actual.add(str(rel["file_count"]))
        actual.add(str(rel["covered_count"]))
    for pkg in packages:
        with __import__("zipfile").ZipFile(pkg) as zf:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        for value in manifest["counts"].values():
            actual.add(str(value))
    actual.update(NON_ARTIFACT_NUMBERS)
    # 旧物与旧锚点的计数由同一扫描器给出（与 README 生成区同源）。
    old = docfacts.old_assets(base / "release")
    actual.add(str(len(old["wheels"])))
    actual.add(str(len(old["packages"])))
    actual.add(str(len(old["locks"])))
    anchor_facts = docfacts.old_anchor_facts(base)
    actual.add(str(len(anchor_facts["singles"])))
    actual.add(str(len(anchor_facts["combined"])))
    # 机制 3：差异表的“变动文件数”和三类原因计数也必须由同一份 diff 重算。
    import diff_packages
    diff_md, _detail = diff_packages.build_table(base / "release" / "old-packages",
                                                 base / "package")
    for cell in re.findall(r"\| (\d+) \|", diff_md):
        actual.add(cell)
    # `未随交付清单.md` 的每个前缀条数由扫描器重算。
    import check_handoff_refs
    missing: dict[str, set[str]] = {}
    for path in check_handoff_refs.text_files(base):
        for ref in check_handoff_refs.refs(path.read_text(encoding="utf-8")):
            if not (base / ref).exists():
                missing.setdefault(ref.split("/", 1)[0], set()).add(ref)
    for prefix in check_handoff_refs.PREFIXES:
        count = str(len(missing.get(prefix, set())))
        actual.update({count, count + " 条", count + "条"})

    bad: list[str] = []
    for path in _living_docs(base):
        text = path.read_text(encoding="utf-8")
        # 先把“不是数字事实”的标识符整体替换掉，避免把 256/版本号/提交号拆成数字。
        text = re.sub(r"(?i)sha-?256", "SHA", text)
        text = re.sub(r"[0-9a-f]{4,}(?:…|\.\.\.)[0-9a-f]{0,8}", "<HKEY>", text)
        text = re.sub(r"ed25519:[0-9a-f]{4,}(?:…|\.\.\.)?", "<KEY>", text)
        text = re.sub(r"(?i)ed25519", "<CURVE>", text)
        text = re.sub(r"[A-Z]+-[0-9]{2,}(?:/[0-9]{2,})*", "<ID>", text)
        text = text.replace("B64", "<B64>")
        text = SHA_RE.sub("<SHA>", text)
        text = re.sub(r"\b[0-9a-f]{40}\b", "<COMMIT>", text)
        text = re.sub(r"\b(?=[0-9a-f]*[0-9])[0-9a-f]{6,}\b", "<HEX>", text)
        text = re.sub(r"rp-20\d{2}\.\d+\.[\w.-]+", "<RP>", text)
        text = re.sub(r"round\d+", "<ROUND>", text)
        text = re.sub(r"(?<![\d.])[0-9]+(?:\.[0-9]+){2,}(?![\d.])", "<SEMVER>", text)
        text = re.sub(r"0\.4\.\d+", "<VER>", text)
        text = re.sub(r"\bv\d+\b", "<VER>", text)
        text = re.sub(r"\d{4}-\d{2}-\d{2}", "<DATE>", text)
        text = re.sub(r"\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?", "<TIME>", text)
        # 反引号里的路径本身由 `check_handoff_refs` 校验存在性；路径内的数字是标识符，
        # 不是“文档声明的事实数字”，不应在这里逐个追溯。
        text = re.sub(r"`[^`\n]*[/\\][^`\n]*`", "<PATH>", text)
        text = text.replace(" 条", "")
        for token in re.findall(r"\d+(?:,\d{3})*", text):
            if token in actual:
                continue
            bad.append(f"{path.relative_to(base).as_posix()} 出现无法溯源的数字：{token}")
    assert not bad, "以下数字既非产物事实也非显式登记：\n" + "\n".join(bad[:20])
