"""0.4.12 交付可用性修补：模板版本无关与交接目录可点性断言（先红后绿）。"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HANDOFF = ROOT / "handoff" / "20261104-第十四轮整改"
DIST = ROOT / "dist" / "wca-replay-0.4.12"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# 必修 1：模板与已生成 README 均不得再有硬编码版本配对。
def test_release_template_has_no_hardcoded_wheel_pairing() -> None:
    src = _read("scripts/build_release.py")
    assert "v5 旧包继续配 0.4.7 wheel" not in src
    assert "v6 新包配 0.4.8 wheel" not in src
    assert "producer.version" in src
    assert "版本不一致即 `PRODUCER FAIL`" in src or "不一致即 `PRODUCER FAIL`" in src
    if DIST.is_dir():
        readme = (DIST / "README-验收.md").read_text(encoding="utf-8")
        for bad in ("v5 旧包继续配 0.4.7 wheel", "v6 新包配 0.4.8 wheel", "0.4.8 wheel"):
            assert bad not in readme


# 必补 3/4：模板与已生成 README 首页必须有 PoC 边界段，含四项未闭合与第 3 节。
def test_release_template_has_honest_poc_boundary() -> None:
    targets = [_read("scripts/build_release.py")]
    if DIST.is_dir():
        targets.append((DIST / "README-验收.md").read_text(encoding="utf-8"))
    if HANDOFF.is_dir():
        targets.append((HANDOFF / "README-验收.md").read_text(encoding="utf-8"))
    for text in targets:
        assert "不构成合规结论" in text
        assert "不可作为生产就绪依据" in text
        for item in ("信任根", "真实具名确认", "法律文本充分性", "数据合规"):
            assert item in text
        assert "docs/安全与证据链现状.md" in text
        assert "第 3 节" in text


# 必修 2：交接 README 不得把 wheel 指向 dist，必须指向 release/old-wheels/。
def test_handoff_readme_uses_delivery_relative_wheel_paths() -> None:
    if not HANDOFF.is_dir():
        pytest.skip("第十四轮交接目录尚未生成")
    readme = (HANDOFF / "README-验收.md").read_text(encoding="utf-8")
    old_wheels = (HANDOFF / "OLD-WHEELS.md").read_text(encoding="utf-8")
    assert "dist/" not in old_wheels
    assert "0.4.10 wheel 保留在本目录" not in readme
    assert "v5 旧包继续配 0.4.7 wheel" not in readme
    assert "v6 新包配 0.4.8 wheel" not in readme
    assert "release/old-wheels/" in readme
    assert "release/old-wheels/" in old_wheels


# 必补 3：README 里出现的每个相对路径都必须真实存在（含安全现状文档）。
def test_handoff_readme_relative_links_resolve() -> None:
    if not HANDOFF.is_dir():
        pytest.skip("第十四轮交接目录尚未生成")
    readme = (HANDOFF / "README-验收.md").read_text(encoding="utf-8")
    links = [m for m in re.findall(r"\]\(([^)]+)\)", readme)]
    assert links, "README 至少应给出 docs/安全与证据链现状.md 的可点链接"
    for raw in links:
        target = raw.split("#", 1)[0].strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (HANDOFF / target).is_file(), f"README 引用的相对路径不存在：{raw}"
    assert (HANDOFF / "docs" / "安全与证据链现状.md").is_file()


# 冻结说明必须改为指向 0.4.12，并交代 0.4.11 曾冻结但未对外。
def test_freeze_note_points_to_0412_and_explains_0411() -> None:
    note = _read("docs/冻结版本说明.md")
    assert "0.4.12" in note
    assert "0.4.11" in note
    assert "未对外" in note
