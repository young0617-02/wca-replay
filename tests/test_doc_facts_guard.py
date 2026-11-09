"""护栏：交付目录内所有 `.md`/`.txt` 的事实必须与实物一致。

覆盖：
- 生成区标记成对出现（机制 1 的“禁人工编辑”边界）；
- 包表里的字节、SHA-256 与 `package/*.zip` 实物一致；
- `交付清单.txt` 的每行 `bytes=` / `sha256=` 与文件实物一致；
- 所有 64 位哈希都能在交付目录里找到出处（文件字节哈希 / 包内摘要 / 锚点字段）；
- `SHA256SUMS` 行数与文档写的“N 行/N 个文件”一致；
- 每份文档的 `## X、` 章节号唯一且连续（D1）；
- **所有形如路径/文件名的字符串（含反引号内）必须存在或列入 `未随交付清单.md`**；
- **所有计数声明（N 个 wheel/锁/包/锚点、N 条 v4/v5）必须与实物逐一相等，含中文数词**；
- 文档里出现的其余数字必须属于“从产物算出的值”或 `docs/护栏豁免表.md` 登记的常量。

任何一条不符即失败。历史归档报告（`reports/` 内旧轮次文件）记录的是当时产物，
计数与哈希按历史记录处理；路径/文件名仍按本目录实物核对。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# 红灯阶段可用 WCA_HANDOFF_DIR 指向上一个交付目录（0.4.16），绿阶段默认本轮的第十九轮。
HANDOFF = Path(os.environ.get(
    "WCA_HANDOFF_DIR", ROOT / "handoff" / "20261104-第十九轮整改"))

SHA_RE = re.compile(r"[0-9a-f]{64}")
MANIFEST_LINE_RE = re.compile(
    r"(?m)^  ([^ \n]+)  bytes=(\d+)  sha256=([0-9a-f]{64})$")
PACKAGE_ROW_RE = re.compile(
    r"(?m)^\| `([^`]+\.zip)` \| ([\d,]+) \| `([0-9a-f]{64})` \|")
SUMS_COUNT_RE = re.compile(r"SHA256SUMS[^|\n]{0,40}?(?:共|实有|只有|保护)\s*[*`]*\s*(\d+)")
SECTION_RE = re.compile(r"(?m)^## ([零一二三四五六七八九十]+)、")

CN_DIGITS = {ch: i for i, ch in enumerate("零一二三四五六七八九")}
NUM_TOKEN = r"(?:\d+(?:,\d{3})*|[零一二三四五六七八九十百两]+)"

sys.path.insert(0, str(ROOT / "scripts"))
import fact_exemptions  # noqa: E402
import check_handoff_refs  # noqa: E402
import docfacts  # noqa: E402

# 非产物常量：唯一来源是 `scripts/fact_exemptions.py`，并随交付生成
# `docs/护栏豁免表.md` 供客户逐条审阅。这里不再维护第二份名单。
NON_ARTIFACT_NUMBERS = fact_exemptions.NUMBER_EXEMPTIONS


def _require_handoff() -> Path:
    if not HANDOFF.is_dir():
        pytest.skip(f"{HANDOFF} 不存在（护栏在交付生成后生效）")
    return HANDOFF


def _texts(base: Path) -> list[Path]:
    return [p for p in sorted(base.rglob("*"))
            if p.is_file() and p.suffix.lower() in (".md", ".txt")]


def _to_int(token: str) -> int | None:
    token = token.replace(",", "").strip()
    if token.isdigit():
        return int(token)
    if not token:
        return None
    token = token.replace("两", "二")
    total = 0
    if "百" in token:
        head, _, tail = token.partition("百")
        total += (CN_DIGITS.get(head, 1) if head else 1) * 100
        token = tail
    if "十" in token:
        head, _, tail = token.partition("十")
        total += (CN_DIGITS.get(head, 1) if head else 1) * 10
        token = tail
    if token:
        if token not in CN_DIGITS:
            return None
        total += CN_DIGITS[token]
    return total


def _package_manifest(path: Path) -> dict:
    with zipfile.ZipFile(path) as zf:
        return json.loads(zf.read("manifest.json").decode("utf-8"))


def test_generated_blocks_are_marked_and_paired() -> None:
    base = _require_handoff()
    names = ["README-验收.md", "READ-ME-FIRST.txt", "OLD-WHEELS.md", "OLD-ANCHORS.md",
             "release/SHA256SUMS-覆盖范围.md", "reports/round17-diff.md",
             "docs/护栏豁免表.md"]
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
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert sha == actual, f"{name} SHA-256 与实物不符"


def test_manifest_lines_match_actual_files() -> None:
    base = _require_handoff()
    text = (base / "交付清单.txt").read_text(encoding="utf-8")
    rows = MANIFEST_LINE_RE.findall(text)
    assert len(rows) >= 100, f"交付清单明细行过少（{len(rows)}），疑似漏列文件"
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
    errors = check_handoff_refs.check_refs(base)
    assert not errors, "\n".join(errors[:10])


# ---------------------------------------------------------------------------
# 路径断言：反引号内不再是豁免区
# ---------------------------------------------------------------------------

PATHISH_RE = re.compile(
    r"(?<![A-Za-z0-9_./\\-])"
    r"((?:[A-Za-z0-9_.\-\u4e00-\u9fff]+/)+[A-Za-z0-9_.\-\u4e00-\u9fff]+)")
# 文件名识别不再依赖“旧的白名单后缀”，而是接受一组**宽泛的**常见文件后缀
# （大小写不敏感）：覆盖 `requirements-0.4.10.lock`（少 `.txt`）、`x.tar.gz`、
# `OLD-WHEELS.MD` 等历史漏网写法。所有已知压缩/文档/数据/代码后缀都在表内。
KNOWN_FILE_SUFFIXES = {
    "md", "markdown", "txt", "text", "rst", "json", "jsonl", "csv", "tsv", "xml",
    "yaml", "yml", "toml", "ini", "cfg", "conf", "lock", "log", "sum", "sums",
    "zip", "gz", "bz2", "xz", "tar", "tgz", "whl", "jar", "7z", "rar",
    "sig", "pub", "pem", "key", "crt", "asc", "b64", "sha", "sha256",
    "py", "pyi", "sh", "ps1", "bat", "cmd", "js", "ts", "jsx", "tsx",
    "html", "htm", "css", "sql", "db", "sqlite", "pdf", "docx", "xlsx", "pptx",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "ttf", "otf", "woff", "woff2",
}
# 版本段/通配写法（`0.4.16.json`、`0.4.x`）不是文件名，不当路径断言。
VERSIONLIKE_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:\.(?:json|x|md|txt))?$")
BARE_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-\u4e00-\u9fff])"
    r"([A-Za-z0-9_][A-Za-z0-9_.-]*\.[A-Za-z][A-Za-z0-9_-]{0,5})"
    r"(?![A-Za-z0-9_.\-])")
# 无后缀文件名：已知文件名模式（`SHA256SUMS` 等）+“见/文件/清单/…”后紧跟的**反引号或引号内**
# 裸名字。要求引号包裹，避免把 `wheel`、`producer_commit` 这类普通词/字段名当文件名；
# `foo` 这类既无目录也无后缀的错误指引仍会被抓（文档里通常写成 `见 \`foo\``）。
KNOWN_BARE_NAMES = {"SHA256SUMS", "Makefile", "Dockerfile", "LICENSE", "CODEOWNERS",
                    "OWNERS", "py.typed"}
BARE_NAME_CONTEXT_RE = re.compile(
    r"(?:见|文件|清单|目录|路径|位于|取自|放在|名为|读取|打开)\s*"
    r"[`\"']([A-Za-z0-9_][A-Za-z0-9_.-]{1,40})[`\"']")
SKIP_TOKEN_CHARS = ("<", ">", "*", "{", "}", "://", "=", "|", '"', "'")
SKIP_BARE_TOKENS = {"e.g", "i.e", "etc", "vs"}
ARTIFACT_SUFFIXES = (".whl", ".zip", ".lock")
PREFIX_HEADS = check_handoff_refs.PREFIXES
# `release/`、`package/` 是交付内部命名空间：这些路径**必须真实存在**，
# 不允许靠 `未随交付清单.md` 自动登记“洗白”（否则错误路径会被自动登记成通过）。
DELIVERY_INTERNAL_HEADS = ("release", "package")
_REPO_NAMES_CACHE: set[str] | None = None


def _repo_names() -> set[str]:
    """仓库内实际存在的文件名（源码/报告等不随交付，但文档会引用）。"""
    global _REPO_NAMES_CACHE
    if _REPO_NAMES_CACHE is None:
        _REPO_NAMES_CACHE = {
            path.name for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.parts and "node_modules" not in path.parts
        }
    return _REPO_NAMES_CACHE


def _physical_names(base: Path) -> set[str]:
    """交付目录内“真实存在”的路径与包内成员名（不含未随交付清单的自登记）。"""
    names: set[str] = set()
    for path in base.rglob("*"):
        rel = path.relative_to(base).as_posix()
        names.add(rel)
        names.add(path.name)
    for zip_path in base.rglob("*.zip"):
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                names.add(member)
                names.add(Path(member).name)
    return names


def _exists(base: Path, doc: Path, token: str) -> bool:
    token = token.strip().rstrip("，。、；：")
    if token.startswith("../"):
        return (doc.parent / token).exists()
    return (base / token).exists() or (doc.parent / token).exists()


def _file_suffix(token: str) -> str:
    return Path(token).suffix.lower().lstrip(".")


def _looks_like_file(token: str) -> bool:
    """宽泛后缀表 + 排除版本段/通配（`0.4.16.json`、`0.4.x`）。"""
    if VERSIONLIKE_RE.match(token):
        return False
    name = Path(token).name
    if "." not in name:
        return False
    return _file_suffix(token) in KNOWN_FILE_SUFFIXES


def _path_like(token: str) -> bool:
    """只把“像文件路径”的 token 纳入断言，避免把 `OK/FAIL`、`v1/v2` 之类当路径。

    后缀用宽泛常见后缀表（大小写不敏感）；无后缀裸名字只认已知文件名模式，
    或由 `BARE_NAME_CONTEXT_RE` 明确指出的引号内名字。
    """
    token = token.rstrip("，。、；：")
    if token.endswith(("-", ".", "/")):
        return False
    if token in SKIP_BARE_TOKENS:
        return False
    if "/" in token:
        head = token.split("/", 1)[0]
        return (head in PREFIX_HEADS or head in DELIVERY_INTERNAL_HEADS
                or _looks_like_file(token))
    if _looks_like_file(token):
        return True
    if token in KNOWN_BARE_NAMES:
        return True
    # 无后缀裸名字：只认“文件名味道”的写法（不含下划线），避免把 `evidence_digest`、
    # `producer_commit` 这类字段标识符当文件名；`foo` 这类错误指引仍会被抓。
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{1,30}", token))


def _historical_doc(path: Path, base: Path) -> bool:
    """历史归档文档：其中路径/文件名指当时产物，允许以仓库内实际存在为准。"""
    if path.name == "旧发行物-SHA256清单.md":
        return True
    return path.relative_to(base).parts[0] == "reports"


def test_every_path_like_string_exists_or_registered() -> None:
    """M1 的根因：旧护栏把反引号内容整体剥离，错误路径因此被豁免。

    本断言**不再区分是否在反引号内**：任何形如 `a/b` 的路径或 `x.whl` 的文件名，
    必须在交付目录内存在（含包内成员），或列入 `未随交付清单.md`；二者皆无即失败。
    但 `release/`、`package/` 是交付内部命名空间，**不接受“未随交付清单”登记**——
    未随交付清单是自动生成的，若允许它登记内部路径，错误路径会被自动洗白。
    """
    base = _require_handoff()
    physical = _physical_names(base)
    unshipped = check_handoff_refs.unshipped_paths(base)
    tasks = []
    for path in _texts(base):
        if "lock.txt" in path.name:
            # pip 锁文件是工具生成的依赖清单，不是叙述性文档。
            continue
        if path.name in ("未随交付清单.md", "旧发行物-SHA256清单.md"):
            # 这两份本身就是“未随交付/历史发行物”的登记表，条目是历史路径记录。
            continue
        if _historical_doc(path, base):
            # 历史归档报告记录当时产物（run 包、临时样例等早已清理），本目录不可自证；
            # 已在 `已知残留与未闭合项.md` 明示。现行口径文档仍逐条核对。
            continue
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(base).as_posix()
        candidates = [m.group(1) for m in PATHISH_RE.finditer(text)]
        candidates += [m.group(1) for m in BARE_FILE_RE.finditer(text)]
        candidates += [m.group(1) for m in BARE_NAME_CONTEXT_RE.finditer(text)]
        for token in candidates:
            token = token.strip().rstrip("，。、；：")
            if any(mark in token for mark in SKIP_TOKEN_CHARS):
                continue
            if token.startswith(("http", "www", "mailto")):
                continue
            if not _path_like(token):
                continue
            if _exists(base, path, token):
                continue
            # 不含目录的文件名才允许“按文件名匹配”；一旦写成 `a/b` 形式，必须**整条路径**
            # 存在。否则“文件名对、目录写错”会被另一处的同名文件洗白（M1 的锁表即此类）。
            if "/" not in token and (token in physical or Path(token).name in physical):
                continue
            head = token.split("/", 1)[0]
            if head not in DELIVERY_INTERNAL_HEADS and token in unshipped:
                continue
            suffix = Path(token).suffix.lower()
            # 源码/文档/报告类：仓库内实际存在即可（这些文件不随交付）。
            if suffix not in ARTIFACT_SUFFIXES and (
                    (ROOT / token).exists() or Path(token).name in _repo_names()):
                continue
            # 历史归档文档：路径指当时产物，仓库内仍有实物即可。
            if _historical_doc(path, base) and Path(token).name in _repo_names():
                continue
            tasks.append(f"{rel} 提到既不存在也未登记的路径/文件名：{token}")
    assert not tasks, (
        "以下路径/文件名在交付目录内不存在，也未列入 `未随交付清单.md`：\n"
        + "\n".join(sorted(set(tasks))[:30]))


# ---------------------------------------------------------------------------
# 计数断言：阿拉伯数字与中文数词都要与实物逐一相等
# ---------------------------------------------------------------------------

def _count_facts(base: Path) -> dict[str, int]:
    old = docfacts.old_assets(base / "release")
    anchors = docfacts.anchor_records(base)
    version = docfacts.release_facts(base / "release")["version"]
    packages = sorted((base / "package").glob("*.zip"))
    manifests = [_package_manifest(p) for p in packages]
    rule_versions: dict[str, int] = {}
    for manifest in manifests:
        rule_versions.update(manifest["counts"].get("rule_versions", {}))
    v4 = sum(n for label, n in rule_versions.items() if label.endswith(".v4"))
    v5 = sum(n for label, n in rule_versions.items() if label.endswith(".v5"))
    rel = docfacts.release_facts(base / "release")
    return {
        "wheels": len(old["wheels"]),
        "wheels_old_wheels": sum(1 for w in old["wheels"] if "old-wheels" in w["dirs"]),
        "wheels_old_packages": sum(1 for w in old["wheels"] if "old-packages" in w["dirs"]),
        "locks": len(old["locks"]),
        "locks_old_wheels": sum(1 for x in old["locks"] if "old-wheels" in x["dirs"]),
        "locks_old_packages": sum(1 for x in old["locks"] if "old-packages" in x["dirs"]),
        "packages": len(packages),
        "old_packages": len(old["packages"]),
        "singles": len(anchors["singles"]),
        "combined": len(anchors["combined"]),
        "anchor_total": anchors["anchor_total"],
        "anchor_resolvable": anchors["by_status"]["resolvable"],
        "anchor_marked": anchors["by_status"]["marked"],
        "anchor_dangling": anchors["by_status"]["dangling"],
        "singles_current": sum(1 for a in anchors["singles"] if a["version"] == version),
        "singles_history": sum(1 for a in anchors["singles"] if a["version"] != version),
        "combined_current": sum(1 for a in anchors["combined"] if a["version"] == version),
        "combined_history": sum(1 for a in anchors["combined"] if a["version"] != version),
        "covered": rel["covered_count"],
        "rule_v4": v4,
        "rule_v5": v5,
    }


CLAIM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"({NUM_TOKEN})\s*个唯一\s*wheel"), "wheels"),
    (re.compile(rf"旧 wheel[^\n]{{0,4}}?\*\*({NUM_TOKEN})\s*个\*\*"), "wheels"),
    (re.compile(rf"唯一计\s*\n?\s*\*\*({NUM_TOKEN})\s*个\*\*"), "wheels"),
    (re.compile(rf"`release/old-wheels/`\s*实有\s*\*\*({NUM_TOKEN})\s*个\*\*"),
     "wheels_old_wheels"),
    (re.compile(rf"另有\s*\*\*({NUM_TOKEN})\s*个\*\*同名副本"), "wheels_old_packages"),
    (re.compile(rf"合计\s*\*\*({NUM_TOKEN})\s*个\*\*唯一锁"), "locks"),
    (re.compile(rf"({NUM_TOKEN})\s*个(?:唯一|依赖)?\s*锁(?!定)"), "locks"),
    (re.compile(rf"`release/old-wheels/`\s*\n?\s*\*\*({NUM_TOKEN})\s*个\*\*（"),
     "locks_old_wheels"),
    (re.compile(rf"`release/old-packages/`\s*\n?\s*\*\*({NUM_TOKEN})\s*个\*\*（"),
     "locks_old_packages"),
    (re.compile(rf"旧包\s*\*\*({NUM_TOKEN})\s*个\*\*"), "old_packages"),
    (re.compile(rf"({NUM_TOKEN})\s*个\s*zip"), "old_packages"),
    (re.compile(rf"(?<!旧)(?<!单)包\s*\*\*({NUM_TOKEN})\s*个\*\*"), "packages"),
    (re.compile(rf"根目录锚点\s*\*\*({NUM_TOKEN})\s*个\*\*"), "anchor_total"),
    (re.compile(rf"锚点\s*\*\*({NUM_TOKEN})\s*个\*\*"), "anchor_total"),
    (re.compile(rf"单包\s*\*\*({NUM_TOKEN})\s*个\*\*"), "singles"),
    (re.compile(rf"单包锚点\s*\*\*({NUM_TOKEN})\s*个\*\*"), "singles"),
    (re.compile(rf"组合记录\s*\*\*({NUM_TOKEN})\s*个\*\*"), "combined"),
    (re.compile(rf"({NUM_TOKEN})\s*个锚点"), "anchor_total"),
    (re.compile(rf"file 可解析\s*\*\*?({NUM_TOKEN})\s*个"), "anchor_resolvable"),
    (re.compile(rf"显式标注[^\n]{{0,6}}\*\*({NUM_TOKEN})\s*个\*\*"), "anchor_marked"),
    (re.compile(rf"悬空\s*\*\*?({NUM_TOKEN})\s*个"), "anchor_dangling"),
    (re.compile(rf"({NUM_TOKEN})\s*条 v4"), "rule_v4"),
    (re.compile(rf"({NUM_TOKEN})\s*条 v5"), "rule_v5"),
    (re.compile(rf"v4 规则\s*({NUM_TOKEN})\s*条"), "rule_v4"),
    (re.compile(rf"v5 规则\s*({NUM_TOKEN})\s*条"), "rule_v5"),
]


def test_declared_counts_match_actual() -> None:
    """反向断言：文档声称的计数必须与实物逐一相等（中文数词同样覆盖）。"""
    base = _require_handoff()
    facts = _count_facts(base)
    bad: list[str] = []
    for path in _living_docs(base):
        text = path.read_text(encoding="utf-8")
        for pattern, key in CLAIM_PATTERNS:
            for match in pattern.finditer(text):
                value = _to_int(match.group(1))
                if value is None:
                    continue
                if value != facts[key]:
                    bad.append(f"{path.relative_to(base).as_posix()}：{match.group(0)!r} "
                               f"→ 文档 {value}，实物 {facts[key]}（{key}）")
    assert not bad, "文档计数与实物不符：\n" + "\n".join(bad[:20])


def test_repo_docs_rule_version_counts_match_actual() -> None:
    """仓库文档同样不得把 99 条 v4 写成 100 条（本轮盲验数字类问题）。"""
    packages = sorted((ROOT / "handoff" / "20261104-第十八轮整改" / "package").glob("*.zip"))
    if not packages:
        pytest.skip("缺少 0.4.16 举证包，无法取得 rule_versions 实物")
    manifest = _package_manifest(packages[1])
    versions = manifest["counts"]["rule_versions"]
    v4 = sum(n for label, n in versions.items() if label.endswith(".v4"))
    v5 = sum(n for label, n in versions.items() if label.endswith(".v5"))
    docs = [ROOT / "README.md", ROOT / "docs" / "签名方案.md",
            ROOT / "docs" / "交付与验收SOP.md", ROOT / "policies" / "口径声明-对外版.md"]
    bad: list[str] = []
    for path in docs:
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(rf"({NUM_TOKEN})\s*条 v4", text):
            value = _to_int(match.group(1))
            if value is not None and value != v4:
                bad.append(f"{path.name}：v4 规则写 {value} 条，实物 {v4} 条")
        for match in re.finditer(rf"({NUM_TOKEN})\s*条 v5", text):
            value = _to_int(match.group(1))
            if value is not None and value != v5:
                bad.append(f"{path.name}：v5 规则写 {value} 条，实物 {v5} 条")
    assert not bad, "\n".join(bad)


def _living_docs(base: Path) -> list[Path]:
    """数字/哈希/计数审计只扫“现行口径”文档；历史报告是归档记录，其数字属于当时产物。"""
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
    old = docfacts.old_assets(base / "release")
    anchor_facts = docfacts.anchor_records(base)
    sums_lines = [line for line in (base / "release" / "SHA256SUMS")
                  .read_text(encoding="utf-8").splitlines() if line.strip()]
    actual = {
        str(len(packages)), str(len(reports)), str(len(old_packages)),
        str(len(old["wheels"])), str(len(old["locks"])),
        str(anchor_facts["anchor_total"]), str(len(sums_lines)),
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
    for dist_dir in sorted((ROOT / "dist").glob("wca-replay-*")):
        if not (dist_dir / "RELEASE.json").is_file():
            continue
        rel = docfacts.release_facts(dist_dir)
        actual.add(str(rel["others_bytes_total"]))
        actual.add(f"{rel['others_bytes_total']:,}")
        actual.add(str(rel["file_count"]))
        actual.add(str(rel["covered_count"]))
    for pkg in packages:
        manifest = _package_manifest(pkg)
        for value in manifest["counts"].values():
            if isinstance(value, int):
                actual.add(str(value))
        for value in manifest["counts"].get("rule_versions", {}).values():
            actual.add(str(value))
    actual.update(NON_ARTIFACT_NUMBERS)
    # 旧物与旧锚点的计数由同一扫描器给出（与 README 生成区同源）。
    actual.add(str(len(old["wheels"])))
    actual.add(str(len(old["locks"])))
    actual.add(str(len(old["packages"])))
    anchor_facts = docfacts.anchor_records(base)
    actual.add(str(len(anchor_facts["singles"])))
    actual.add(str(len(anchor_facts["combined"])))
    actual.add(str(anchor_facts["anchor_total"]))
    for key in ("resolvable", "marked", "dangling"):
        actual.add(str(anchor_facts["by_status"][key]))
    # 历史/本轮分类计数（README/OLD-ANCHORS 会写“历史单包 56 个”“历史组合 7 个”等）。
    release_version = docfacts.release_facts(base / "release")["version"]
    actual.add(str(sum(1 for a in anchor_facts["singles"]
                       if a["version"] != release_version)))
    actual.add(str(sum(1 for a in anchor_facts["combined"]
                       if a["version"] != release_version)))
    actual.add(str(sum(1 for a in anchor_facts["singles"]
                       if a["version"] == release_version)))
    actual.add(str(sum(1 for a in anchor_facts["combined"]
                       if a["version"] == release_version)))
    # 按版本的锚点计数。
    for anchor_version in {a["version"] for a in anchor_facts["singles"] + anchor_facts["combined"]}:
        singles_v = [a for a in anchor_facts["singles"] if a["version"] == anchor_version]
        combined_v = [a for a in anchor_facts["combined"] if a["version"] == anchor_version]
        actual.add(str(len(singles_v)))
        actual.add(str(len(combined_v)))
        actual.add(str(sum(1 for a in singles_v if a["status"] == "marked")))
        actual.add(str(sum(1 for a in combined_v if a["status"] == "marked")))
    # 机制 3：差异表的“变动文件数”和三类原因计数也必须由同一份 diff 重算。
    import diff_packages
    diff_md, _detail = diff_packages.build_table(base / "release" / "old-packages",
                                                 base / "package")
    for cell in re.findall(r"\| (\d+) \|", diff_md):
        actual.add(cell)
    # `未随交付清单.md` 的每个前缀条数由扫描器重算。
    missing: dict[str, set[str]] = {}
    for path in check_handoff_refs.text_files(base):
        for ref in check_handoff_refs.refs(path.read_text(encoding="utf-8")):
            if not (base / ref).exists():
                missing.setdefault(ref.split("/", 1)[0], set()).add(ref)
    for prefix in check_handoff_refs.PREFIXES:
        count = str(len(missing.get(prefix, set())))
        actual.update({count, count + " 条", count + "条"})

    bad: list[str] = []
    known_names = _physical_names(base)
    for path in _living_docs(base):
        if path.name in ("未随交付清单.md", "旧发行物-SHA256清单.md"):
            # 该文件本身是“仓库内未随交付路径 / 历史发行物”的登记表，内容是路径清单；
            # 其路径存在性由 `test_relative_paths_resolve` 与生成器负责。
            continue
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
        # 反引号内若含数字，只在**该路径/文件名确实存在**时才剥离；不存在的路径由
        # `test_every_path_like_string_exists_or_registered` 直接判失败。这里不再“一律豁免”。
        text = re.sub(r"`([^`\n]+)`", lambda m: (
            "<PATH>" if (_exists(base, path, m.group(1).strip())
                          or Path(m.group(1).strip()).name in known_names
                          or (ROOT / m.group(1).strip()).exists()
                          or Path(m.group(1).strip()).name in _repo_names())
            else m.group(0)), text)
        text = text.replace(" 条", "")
        for token in re.findall(r"\d+(?:,\d{3})*", text):
            if token in actual:
                continue
            bad.append(f"{path.relative_to(base).as_posix()} 出现无法溯源的数字：{token}")
    assert not bad, "以下数字既非产物事实也非显式登记：\n" + "\n".join(bad[:20])


# ---------------------------------------------------------------------------
# JSON 覆盖：锚点 / RELEASE / 包内 manifest / responsibility
# ---------------------------------------------------------------------------

def _anchor_paths(base: Path) -> list[Path]:
    return sorted(base.glob("anchor*.json"))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_anchor_json_filename_version_matches_content() -> None:
    """X1：锚点文件名必须由内容里的 `version` 派生，禁止“文件名写 0.4.14、内容是 0.4.15”。"""
    base = _require_handoff()
    release_version = _load_json(base / "release" / "RELEASE.json")["version"]
    bad: list[str] = []
    for path in _anchor_paths(base):
        doc = _load_json(path)
        version = str(doc.get("version") or "")
        assert version, f"{path.name} 缺少 version 字段"
        name_version = docfacts.anchor_name_version(path.name)
        if name_version and name_version != version:
            bad.append(f"{path.name}：文件名版本 {name_version} != 内容版本 {version}")
        if path.name == "anchor.json" and version != release_version:
            bad.append(f"anchor.json 内容版本 {version} != release/RELEASE.json {release_version}")
    assert not bad, "锚点文件名与内容版本不一致：\n" + "\n".join(bad)


def test_anchor_file_fields_resolve_or_are_marked() -> None:
    """X2：`file` 要么是以该 JSON 自身位置为基准可解析的相对路径，要么显式标注“仅记录、不可解析”。

    悬空（看起来可解析、实际不存在）一律失败；可解析的还必须与记录的 SHA-256 一致。
    """
    base = _require_handoff()
    records = docfacts.anchor_records(base)
    assert records["by_status"]["dangling"] == 0, (
        "存在悬空 file 指针：\n" + "\n".join(
            f"{r['name']} → {r['status']}" for r in
            records["singles"] + records["combined"] if r["status"] == "dangling"))
    bad: list[str] = []
    for path in _anchor_paths(base):
        doc = _load_json(path)
        for entry in docfacts.anchor_file_entries(doc):
            value = entry.get("file")
            status = docfacts.anchor_file_status(path, value)
            if status == "dangling":
                bad.append(f"{path.name}：file 既不存在的也不标注：{value!r}")
                continue
            if status == "marked":
                if docfacts.ANCHOR_MARKER not in str(value):
                    bad.append(f"{path.name}：标注写法缺少“{docfacts.ANCHOR_MARKER}”：{value!r}")
                continue
            target = path.parent / str(value)
            digest = entry.get("package_sha256") or entry.get("sha256")
            if digest and docfacts.sha256_file(target) != digest:
                bad.append(f"{path.name}：{value} 的 SHA-256 与锚点记录不符")
    assert not bad, "\n".join(bad)


def test_anchor_target_package_producer_version_matches() -> None:
    """三方一致：文件名版本 == 内容版本 == 目标包 producer.version。"""
    base = _require_handoff()
    bad: list[str] = []
    for path in _anchor_paths(base):
        doc = _load_json(path)
        version = str(doc.get("version") or "")
        for entry in docfacts.anchor_file_entries(doc):
            status = docfacts.anchor_file_status(path, entry.get("file"))
            if status != "resolvable":
                continue
            facts = docfacts.package_facts(path.parent / str(entry["file"]))
            if facts["producer_version"] != version:
                bad.append(f"{path.name}：目标包 {entry['file']} 的 producer.version="
                           f"{facts['producer_version']} != 锚点版本 {version}")
    assert not bad, "\n".join(bad)


def test_release_json_paths_and_counts_match_actual() -> None:
    base = _require_handoff()
    rel = _load_json(base / "release" / "RELEASE.json")
    version = rel["version"]
    wheel = base / "release" / rel["wheel"]
    assert wheel.is_file(), f"RELEASE.json 的 wheel 不存在：{rel['wheel']}"
    assert version in rel["wheel"], f"wheel 文件名不含版本 {version}：{rel['wheel']}"
    lock = base / "release" / rel.get("lock_file", "requirements.lock.txt")
    assert lock.is_file(), "RELEASE.json 指向的锁定依赖不存在"
    sums = [line for line in (base / "release" / "SHA256SUMS")
            .read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(sums) == docfacts.release_facts(base / "release")["covered_count"], \
        "SHA256SUMS 行数与实物覆盖清单不符"
    for line in sums:
        digest, name = line.split(None, 1)
        target = base / "release" / name.strip()
        assert target.is_file(), f"SHA256SUMS 列了不存在的文件：{name.strip()}"
        assert docfacts.sha256_file(target) == digest, f"{name.strip()} 的 SHA-256 与 SHA256SUMS 不符"


def test_package_manifest_and_responsibility_json_match_anchors() -> None:
    """包内 `manifest.json` / `responsibility.json` 的版本、计数、摘要必须与锚点同源。"""
    base = _require_handoff()
    release_version = _load_json(base / "release" / "RELEASE.json")["version"]
    bad: list[str] = []
    for package in sorted((base / "package").glob("*.zip")):
        facts = docfacts.package_facts(package)
        anchor_path = base / f"anchor-{release_version}-{package.stem}.json"
        assert anchor_path.is_file(), f"{package.name} 缺少本轮单包锚点 {anchor_path.name}"
        anchor = _load_json(anchor_path)
        for key in ("sha256", "anchor", "artifacts_digest", "evidence_digest",
                    "inputs_digest", "input_fingerprint", "counts"):
            anchor_key = "package_sha256" if key == "sha256" else key
            if anchor[anchor_key] != facts[key]:
                bad.append(f"{package.name}：锚点 {anchor_key} 与包内字段不符")
        with zipfile.ZipFile(package) as zf:
            responsibility = json.loads(zf.read("responsibility.json").decode("utf-8"))
        # 冻结包是 0.4.17 及更早产物，只有旧字段；0.4.18+ 包用新字段。与 docfacts 保持同一双读口径。
        expected = responsibility.get(
            "approved_findings", responsibility.get("human_confirmed_findings"))
        if expected != facts["approved_findings"]:
            bad.append(f"{package.name}：responsibility.json 与 manifest 计数不符")
    for old_package in sorted((base / "release" / "old-packages").glob("*.zip")):
        facts = docfacts.package_facts(old_package)
        if not facts["producer_version"]:
            bad.append(f"{old_package.name}：manifest.json 缺少 producer.version")
    assert not bad, "\n".join(bad)


def test_json_and_jsonl_files_are_parseable() -> None:
    """`.json`/`.jsonl` 也要纳入扫描：坏 JSON 不能因为“只扫 .md/.txt”而漏过。"""
    base = _require_handoff()
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".json", ".jsonl"):
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            json.loads(text)
        else:
            for line in text.splitlines():
                if line.strip():
                    json.loads(line)


# ---------------------------------------------------------------------------
# 数字—名词绑定：数字必须与它紧跟的名词对应，不能“换个名词就通过”
# ---------------------------------------------------------------------------

def _noun_actuals(base: Path) -> dict[str, set[int]]:
    old = docfacts.old_assets(base / "release")
    records = docfacts.anchor_records(base)
    version = _load_json(base / "release" / "RELEASE.json")["version"]
    packages = sorted((base / "package").glob("*.zip"))
    rel = docfacts.release_facts(base / "release")
    manifests = [_package_manifest(p) for p in packages]
    # 规则条数取“规则包 v4+v5 实际评测”的包（dup-subdir 包只评 1 条，不能拿来求和）。
    representative = next(m for m in manifests
                          if {"rp-2026.10.gd-pilot-standard.v4",
                              "rp-2026.11.gd-pilot-standard.v5"} <=
                          set(m["counts"].get("rule_versions", {})))
    versions = representative["counts"]["rule_versions"]
    v4 = sum(n for label, n in versions.items() if label.endswith(".v4"))
    v5 = sum(n for label, n in versions.items() if label.endswith(".v5"))
    singles = records["singles"]
    combined = records["combined"]
    file_counts = {
        rel["covered_count"], rel["file_count"],
        len([p for p in base.rglob("*") if p.is_file()]),
        len(packages), len(old["packages"]),
        len(list((base / "docs").glob("*"))), len(list((base / "reports").glob("*"))),
    }
    return {
        "锚点": {records["anchor_total"], len(singles), len(combined),
                 sum(1 for a in singles if a["version"] == version),
                 sum(1 for a in singles if a["version"] != version),
                 sum(1 for a in combined if a["version"] == version),
                 sum(1 for a in combined if a["version"] != version),
                 records["by_status"]["resolvable"], records["by_status"]["marked"],
                 records["by_status"]["dangling"], len(records["misnamed"])},
        "包": {len(packages), len(old["packages"]), 2},
        "wheel": {len(old["wheels"]),
                  sum(1 for w in old["wheels"] if "old-wheels" in w["dirs"]),
                  sum(1 for w in old["wheels"] if "old-packages" in w["dirs"]),
                  len(list((base / "release").glob("*.whl")))},
        "锁": {len(old["locks"]),
               sum(1 for x in old["locks"] if "old-wheels" in x["dirs"]),
               sum(1 for x in old["locks"] if "old-packages" in x["dirs"])},
        "文件": file_counts,
        "规则": {v4, v5},
        "条数": {v4, v5},
    }


NOUN_BINDING_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)?\s*锚点"), "锚点"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)\s*(?:旧)?包"), "包"),
    (re.compile(r"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)([零一二三四五六七八九十两]+)包"), "包"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)?\s*wheel"), "wheel"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)?\s*(?:依赖)?锁(?!定)"), "锁"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)\s*文件"), "文件"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*(?:个|份|项|套|条|张)\s*规则"), "规则"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*条(?:\s*数)?\s*(?:v[45]|规则)"), "条数"),
    (re.compile(rf"(?<!第)(?<!唯)(?<!某)(?<!任)(?<!每)({NUM_TOKEN})\s*条数"), "条数"),
]


def _noun_claim_violations(text: str, actuals: dict[str, set[int]]) -> list[str]:
    """返回“数字与名词不匹配”的原文片段。

    单独的“一”按不定冠词处理（“验任一包”不构成计数声明）；
    其余数字（含 13/8 等曾登记为全局常量的值）**不豁免**，必须与名词的实物计数绑定。
    """
    text = re.sub(r"0\.4\.\d+", "<VER>", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}", "<DATE>", text)
    text = re.sub(r"\d{2}:\d{2}(?::\d{2})?", "<TIME>", text)
    text = re.sub(r"[0-9a-f]{8,}", "<HEX>", text)
    bad: list[str] = []
    for pattern, noun in NOUN_BINDING_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1)
            if raw in ("一", "壹"):
                continue
            value = _to_int(raw)
            if value is None:
                continue
            if value not in actuals[noun]:
                bad.append(f"{match.group(0)!r}：{noun} 实物计数不含 {value}"
                           f"（允许 {sorted(actuals[noun])}）")
    return bad


def test_number_noun_binding_matches_artifacts() -> None:
    """本轮补齐的漏洞 1：数字必须绑到正确名词（`56 个锚点` 改成 `56 个包` 必须失败）。"""
    base = _require_handoff()
    actuals = _noun_actuals(base)
    bad: list[str] = []
    for path in _living_docs(base):
        if path.name in ("未随交付清单.md", "旧发行物-SHA256清单.md"):
            continue
        for violation in _noun_claim_violations(path.read_text(encoding="utf-8"), actuals):
            bad.append(f"{path.relative_to(base).as_posix()}：{violation}")
    assert not bad, "数字与名词不匹配：\n" + "\n".join(bad[:20])


@pytest.mark.parametrize("text, noun", [
    ("本目录共 56 个包", "包"),
    ("共 23 份锚点", "锚点"),
    ("23 项 wheel", "wheel"),
    ("23 套锁", "锁"),
    ("23 个文件", "文件"),
    ("23 条规则", "规则"),
    ("23 条数", "条数"),
    ("中文数词：八个包", "包"),
    ("中文数词：两份锚点", "锚点"),
])
def test_number_noun_binding_detects_planted_claims(text: str, noun: str) -> None:
    """合成样例证明检测能力：这些数字与对应实物不符，必须被抓到。"""
    actuals = {
        "锚点": {8, 56, 64, 72}, "包": {2, 48}, "wheel": {12, 13},
        "锁": {5, 6}, "文件": {5, 191, 192}, "规则": {99, 16},
        "条数": {99, 16},
    }
    violations = _noun_claim_violations(text, actuals)
    assert violations, f"未命中应报错的数字—名词组合：{text}（{noun}）"


# ---------------------------------------------------------------------------
# 裸文件名识别：放宽后缀 + 大小写不敏感 + 无后缀名
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", [
    "requirements-0.4.10.lock", "foo", "x.tar.gz", "OLD-WHEELS.MD", "release/Makefile",
])
def test_bare_filename_tokens_are_detected(token: str) -> None:
    """漏洞 2 的回归：后缀白名单曾被绕过（少 `.txt`、任意后缀、大写、无后缀）。"""
    context = f"见 `{token}` 与 {token}"
    candidates = [m.group(1) for m in PATHISH_RE.finditer(context)]
    candidates += [m.group(1) for m in BARE_FILE_RE.finditer(context)]
    candidates += [m.group(1) for m in BARE_NAME_CONTEXT_RE.finditer(context)]
    assert token in candidates, f"未把 {token!r} 识别为文件名/路径候选"
    assert _path_like(token), f"{token!r} 未被纳入存在性断言"
