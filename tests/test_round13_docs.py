"""0.4.11 文档收口：模板与对外文档的一致性断言（先红后绿）。

这些测试只校验文档/生成脚本的事实口径，不触碰引擎与规则语义。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# P3-1：模板必须把组合式 anchor.json 的 packages 写成数组，并写明数量口径。
def test_release_template_declares_packages_as_array_with_count_semantics() -> None:
    src = _read("scripts/build_release.py")
    assert "`packages` 是**数组**" in src
    assert "元素为包对象" in src
    assert "数组长度" in src
    assert "是**对象**（key → 单包记录）" not in src


# P3-2：跨版本描述必须写清门禁先后，不能笼统写成“跨版本 → INCOMPARABLE”。
def test_release_template_cross_version_describes_gate_precedence() -> None:
    src = _read("scripts/build_release.py")
    assert "PACKAGE SHA256 FAIL" in src
    assert "先于可比性判定" in src
    assert "RESULT INCOMPARABLE" in src


# P3-3：模板必须声明旧 wheel 不做 scope 判定，RESULT OK 仅旧口径通过。
def test_release_template_documents_old_wheel_scope_limit() -> None:
    src = _read("scripts/build_release.py")
    assert "旧 wheel" in src
    assert "不做 scope 判定" in src
    assert "不表示可比性已核验" in src


# P3-4：README 的 0.4.8 摘要句必须限定为“四主包”，不能读成八包统一。
def test_readme_batch_semantics_is_scoped_to_four_primary_packages() -> None:
    readme = _read("README.md")
    assert "0.4.8 批次语义后四主包 `conclusion_digest` 统一为" in readme
    assert "0.4.8 批次语义后 `conclusion_digest` 统一为" not in readme


# P3-2/3：主 README 同样要给出准确的门禁先后与旧 wheel 声明。
def test_readme_documents_gate_precedence_and_old_wheel_limit() -> None:
    readme = _read("README.md")
    assert "PACKAGE SHA256 FAIL" in readme
    assert "旧 wheel" in readme
    assert "不表示可比性已核验" in readme


# P3-5：历史行保留，但必须加作废标注并指向 0.4.11。
def test_remediation_table_marks_d11_row_superseded() -> None:
    table = _read("docs/整改回应表.md")
    d11 = next(line for line in table.splitlines() if "D11 anchor" in line)
    assert "已作废" in d11
    assert "0.4.11" in d11


# 冻结说明必须存在，并写明“仅文档与脚本变更 / 无规则语义变更”。
def test_freeze_note_states_docs_and_scripts_only() -> None:
    note = _read("docs/冻结版本说明.md")
    assert "0.4.11" in note
    assert "仅文档与生成脚本" in note
    assert "无规则语义变更" in note
