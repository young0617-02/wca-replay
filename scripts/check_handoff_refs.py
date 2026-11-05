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
PREFIXES = ("docs", "scripts", "tests", "src", "data", "var")
REF_RE = re.compile(
    r"(?<![\w./-])(?:docs|scripts|tests|src|data|var)/[A-Za-z0-9_./\-\u4e00-\u9fff]+")
UNSHIPPED = "未随交付清单.md"


def text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def refs(text: str) -> set[str]:
    return {m.group(0).rstrip("./") for m in REF_RE.finditer(text)}


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
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for path in text_files(root):
        rel = path.relative_to(root).as_posix()
        for ref in sorted(refs(path.read_text(encoding="utf-8"))):
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
