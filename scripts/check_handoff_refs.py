"""断言交接目录文档里出现的仓库路径，要么在交付目录内真实存在，要么已列入未随交付清单。

用法：
    uv run python scripts/check_handoff_refs.py handoff/20261104-第十四轮整改
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# 只扫文档类文件；package/*.zip 与 release/*.whl 是二进制，不在此列。
TEXT_SUFFIXES = (".md", ".txt")
# C1：前缀必须覆盖仓库里所有会被文档引用的目录，否则“全表”不成立。
PREFIXES = ("docs", "scripts", "tests", "src", "data", "var", "reports",
            "rules", "tools", "dist", "handoff")
# 0.4.12–0.4.14 及更早的交接只扫描下面这个旧前缀集；为遵守“不改已交付交接”，
# 旧目录继续按旧口径校验，只有带生成标记的新清单才按全前缀校验。
LEGACY_PREFIXES = ("docs", "scripts", "tests", "src", "data", "var")
UNSHIPPED = "未随交付清单.md"
GENERATED_MARKER = "GENERATED:START unshipped"


def text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def refs(text: str, prefixes: tuple[str, ...] = PREFIXES) -> set[str]:
    pattern = re.compile(
        r"(?<![\w./-])(?:" + "|".join(prefixes)
        + r")/[A-Za-z0-9_./\-\u4e00-\u9fff]+")
    return {m.group(0).rstrip("./") for m in pattern.finditer(text)}


def active_prefixes(root: Path) -> tuple[str, ...]:
    doc = root / UNSHIPPED
    if doc.is_file() and GENERATED_MARKER in doc.read_text(encoding="utf-8"):
        return PREFIXES
    return LEGACY_PREFIXES


def unshipped_paths(root: Path) -> set[str]:
    doc = root / UNSHIPPED
    if not doc.is_file():
        return set()
    found = set()
    for line in doc.read_text(encoding="utf-8").splitlines():
        if line.startswith("- `") and "`" in line[3:]:
            found.add(line[3:].split("`", 1)[0].strip())
    return found


def check_refs(root: Path) -> list[str]:
    """返回错误清单；空列表表示所有仓库路径都已交付或已列明未交付。"""
    listed = unshipped_paths(root)
    prefixes = active_prefixes(root)
    errors: list[str] = []
    # 清单本身不得撒谎：列在“未交付”的路径如果实际存在，同样判失败。
    for ref in sorted(listed):
        if (root / ref).exists():
            errors.append(f"{UNSHIPPED} 把已交付的路径写成了未交付：{ref}")
    seen: set[tuple[str, str]] = set()
    for path in text_files(root):
        rel = path.relative_to(root).as_posix()
        for ref in sorted(refs(path.read_text(encoding="utf-8"), prefixes)):
            if (root / ref).exists() or ref in listed:
                continue
            key = (rel, ref)
            if key in seen:
                continue
            seen.add(key)
            errors.append(f"{rel} 引用了既未交付也未列明的仓库路径：{ref}")
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    errors = check_refs(root)
    if errors:
        for msg in errors:
            print(f"FAIL {msg}")
        return 1
    print(f"OK {root}：文档中的仓库路径均已交付或已列入 {UNSHIPPED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
