"""断言交接目录文档里出现的仓库路径与交付文件名都真实存在。

两类检查：
1. 仓库路径：要么在交付目录内真实存在，要么已列入未随交付清单；
2. 交付文件名（`anchor-*.json` / `anchor.json` / `anchor.txt` / `*.zip` / `*.whl` / `*.pub`）：
   必须在同目录、交付根目录，或其说明的相对位置（如 `package/`、`release/`）真实存在。
   第三次出现“文档指名不存在的文件”（`docs/口径声明.md`、`anchor-0.4.19.json`）之后加的，
   防止手写文件名再次漂移。

用法：
    uv run python scripts/check_handoff_refs.py handoff/20261110-第二十一轮整改
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# 只扫文档类文件；package/*.zip 与 release/*.whl 是二进制，不在此列。
TEXT_SUFFIXES = (".md", ".txt", ".json", ".jsonl")
# C1：前缀必须覆盖仓库里所有会被文档引用的目录，否则“全表”不成立。
PREFIXES = ("docs", "scripts", "tests", "src", "data", "var", "reports",
            "rules", "tools", "dist", "handoff", "policies")
# 0.4.12–0.4.14 及更早的交接只扫描下面这个旧前缀集；为遵守“不改已交付交接”，
# 旧目录继续按旧口径校验，只有带生成标记的新清单才按全前缀校验。
LEGACY_PREFIXES = ("docs", "scripts", "tests", "src", "data", "var")
UNSHIPPED = "未随交付清单.md"
GENERATED_MARKER = "GENERATED:START unshipped"


def text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def _is_prefix_listing(ref: str, prefixes: tuple[str, ...]) -> bool:
    """判断该串是不是“前缀词按扫描顺序拼接”的说明句，而非真实路径。

    `docs/scripts/tests/src/.../handoff` 是文档在列举扫描前缀，不是文件路径；
    但 `src/rules` 这类真实的仓库子目录仍要照常校验，所以要求至少 3 段且顺序连续。
    """
    parts = ref.split("/")
    if len(parts) < 3 or any(part not in prefixes for part in parts):
        return False
    order = [prefixes.index(part) for part in parts]
    return all(back == front + 1 for front, back in zip(order, order[1:]))


def refs(text: str, prefixes: tuple[str, ...] = PREFIXES) -> set[str]:
    pattern = re.compile(
        r"(?<![\w./-])(?:" + "|".join(prefixes)
        + r")/[A-Za-z0-9_./\-\u4e00-\u9fff]+")
    found = {m.group(0).rstrip("./") for m in pattern.finditer(text)}
    return {ref for ref in found if not _is_prefix_listing(ref, prefixes)}


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


# 交付文件名：锚点、包、wheel、公钥。`<包.zip>` 这类占位符因前一个字符是 `<` 而不匹配。
DELIVERY_PATTERN = re.compile(
    r"(?<![<\w./\\-])((?:[\w.\-]+[\\/])*[\w.\-]+\.(?:zip|whl|pub)"
    r"|anchor[\w.\-]*\.(?:json|txt))")


def check_delivery_files(root: Path) -> list[str]:
    """文档里点名的交付文件必须真实存在（同目录 / 根目录 / 其说明的相对位置）。

    裸文件名允许在交付目录内任意子目录命中（`engine-only.zip` 在 `package/`、
    wheel 在 `release/`），这样“同目录或其说明的相对位置”都算数；
    但只要全目录找不到同名文件，就是文档写错了。

    范围例外（写死并说明理由，避免把历史取证当成现交付）：
    - `reports/` 与 `release/旧发行物-SHA256清单.md` 是历史快照，里面的文件名属于
      当时产物，不承诺仍在本交付目录里；
    - 以仓库前缀（`var/`、`handoff/`、`dist/` 等）开头的路径由 `check_refs` 负责，
      这里跳过，避免同一问题报两遍。
    """
    names: set[str] = {p.name for p in root.rglob("*") if p.is_file()}
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for doc in text_files(root):
        rel = doc.relative_to(root).as_posix()
        if rel.startswith("reports/") or rel == "release/旧发行物-SHA256清单.md":
            continue
        text = doc.read_text(encoding="utf-8")
        for match in DELIVERY_PATTERN.finditer(text):
            token = match.group(1)
            key = (rel, token)
            if key in seen:
                continue
            seen.add(key)
            normalized = token.replace("\\", "/")
            if normalized.split("/", 1)[0] in PREFIXES:
                continue
            candidates = (doc.parent / normalized, root / normalized,
                          doc.parent.parent / normalized)
            if any(path.is_file() for path in candidates):
                continue
            if "/" not in normalized and normalized in names:
                continue
            errors.append(f"{rel} 指名了不存在的交付文件：{token}")
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    errors = check_refs(root) + check_delivery_files(root)
    if errors:
        for msg in errors:
            print(f"FAIL {msg}")
        return 1
    print(f"OK {root}：仓库路径与交付文件名均真实存在或已列入 {UNSHIPPED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
