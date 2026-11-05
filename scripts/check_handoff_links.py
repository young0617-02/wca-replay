"""交接目录自检：确认 README 引用的每个相对路径都真实存在。

用法：
    uv run python scripts/check_handoff_links.py handoff/20261104-第十四轮整改

只校验交付目录内可达性，不校验内容正确性；路径不存在则非零退出并列出缺失项。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_RE = re.compile(r"\]\(([^)]+)\)")
WHEEL_RE = re.compile(r"`(release/old-wheels/[^`]+\.whl)`")


def check(root: Path) -> list[str]:
    readme = root / "README-验收.md"
    if not readme.is_file():
        return [f"缺少 README-验收.md：{root}"]
    errors: list[str] = []
    text = readme.read_text(encoding="utf-8")

    links = [raw.split("#", 1)[0].strip() for raw in LINK_RE.findall(text)]
    links = [raw for raw in links if raw and not raw.startswith(
        ("http://", "https://", "mailto:"))]
    if not links:
        errors.append("README 未给出任何相对路径链接（至少应链接 docs/安全与证据链现状.md）")
    for rel in links:
        if not (root / rel).is_file():
            errors.append(f"README 引用的相对路径不存在：{rel}")

    old_wheels = root / "OLD-WHEELS.md"
    if not old_wheels.is_file():
        errors.append("缺少 OLD-WHEELS.md")
    else:
        old_text = old_wheels.read_text(encoding="utf-8")
        if "dist/" in old_text:
            errors.append("OLD-WHEELS.md 仍引用客户收不到的 dist/ 路径")
        for rel in WHEEL_RE.findall(old_text):
            if not (root / rel).is_file():
                errors.append(f"OLD-WHEELS.md 引用的 wheel 不存在：{rel}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("用法：python scripts/check_handoff_links.py <交接目录>")
        return 2
    root = Path(argv[1]).resolve()
    errors = check(root)
    if errors:
        for msg in errors:
            print(f"FAIL {msg}")
        return 1
    print(f"OK {root}：README 相对路径与旧 wheel 清单全部可达")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
