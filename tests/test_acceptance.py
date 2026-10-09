"""验收项的机械化检查：A2 / A9 / A10 / A11 / A12 + F-011 结构完整性。

能把验收标准写成断言的，就不要写在文档里靠自觉；剩下必须人工的（如盲跑演示）
在 docs/演示脚本-30分钟.md 里逐步骤标注。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A10 禁词（用拼接构造，避免本文件自身成为命中项）
FORBIDDEN_LITERALS = [
    "企业" + "级",
    "客" + "户",
    "上" + "线",
    "部署" + "完成",
    "验证" + "通过",
]
# A11（2026-10-08 需求 D-01 新增）：本项目不做 HR 访谈，任何成果性文本都不得出现
# 「已与 HR 核对」这类表述。基线扫描器原本没有这一条，在这里补上。
FORBIDDEN_HR_PATTERNS = [
    re.compile(r"(已与|已经|和|同|与)\s*HR\s*(访谈过|核对|确认|对过)"),
    re.compile(r"HR\s*(访谈|核对)\s*(过|完成|无误)"),
]
FORBIDDEN_PATTERNS = [re.compile(r"支持\s*\d+\s*人"), re.compile(r"\bSLA\s*99\.")]
# 本检查覆盖 README、docs、src、evals、data、tools、config，以及根目录的方案文档；
# tests 目录排除在外：那里是「写断言的地方」，禁词字面量必须能出现在扫查逻辑里
SCANNED_DIRS = ["README.md", "docs", "src", "evals", "data", "tools", "config"]
SCANNED_ROOT_GLOBS = ["项目方案-*.md", "项目汇报-*.md"]
# DEC-01（2026-10-08 用户拍板）：规范性文档的职责就是**列出**禁用词，因此对它们跳过
# 字面量与 HR 表述检查；但「支持 N 人」「SLA 99.x」这类量化宣称**照扫**。
# 新增豁免文件必须显式登记到这里，不允许按目录通配。
NORMATIVE_EXEMPT = {
    "docs/需求文档-用户故事.md",
    "docs/项目定义-一页.md",
}


def _is_exempt(rel: Path) -> bool:
    return rel.as_posix() in NORMATIVE_EXEMPT


def _scan_targets() -> list[Path]:
    out: list[Path] = []
    for rel in SCANNED_DIRS:
        p = ROOT / rel
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [f for f in p.rglob("*")
                    if f.is_file() and f.suffix in {".md", ".py", ".jsonl", ".json", ".txt", ".sql"}]
    for pattern in SCANNED_ROOT_GLOBS:
        out += [f for f in ROOT.glob(pattern) if f.is_file()]
    return out


def test_no_false_claims_in_docs_and_code():
    """A10 + A11：宣称类表述与 HR 核对类表述的命中数必须为 0（规范性文档仅跳字面量）。"""
    hits = []
    for f in _scan_targets():
        rel = f.relative_to(ROOT)
        exempt = _is_exempt(rel)
        text = f.read_text(encoding="utf-8", errors="replace")
        if not exempt:
            for word in FORBIDDEN_LITERALS:
                if word in text:
                    for n, line in enumerate(text.splitlines(), start=1):
                        if word in line:
                            hits.append(f"{rel}:{n} 命中 {word}")
            for pat in FORBIDDEN_HR_PATTERNS:
                for n, line in enumerate(text.splitlines(), start=1):
                    if pat.search(line):
                        hits.append(f"{rel}:{n} 命中 HR 核对类表述")
        for pat in FORBIDDEN_PATTERNS:
            for n, line in enumerate(text.splitlines(), start=1):
                if pat.search(line):
                    hits.append(f"{rel}:{n} 命中模式 {pat.pattern}")
    assert not hits, "发现不可举证的宣称表述：\n" + "\n".join(hits[:20])


def test_normative_exempt_list_is_minimal():
    """豁免面必须保持最小：只允许两份规范性文档，且文件必须真实存在。"""
    assert NORMATIVE_EXEMPT == {"docs/需求文档-用户故事.md", "docs/项目定义-一页.md"}
    for rel in NORMATIVE_EXEMPT:
        assert (ROOT / rel).is_file(), f"豁免清单指向不存在的文件：{rel}"


def test_readme_separates_measured_from_design_values():
    """A9：性能口径必须三态标注（实测 / 设计值 / 未测）。"""
    text = (ROOT / "docs" / "口径声明.md").read_text(encoding="utf-8")
    for metric in ("检索段 P95", "端到端 P95", "举证包导出"):
        assert metric in text, f"口径声明缺少 {metric}"
    assert "实测" in text and "设计值" in text and "未测" in text


def test_golden_set_structure_and_size():
    """F-011：≥60 条、三档齐、每条有可复核标准答案。"""
    items = _golden_items()
    assert len(items) >= 60, f"评测集只有 {len(items)} 条，未达 ≥60 的要求"
    tiers = {i["tier"] for i in items}
    assert {"retrieval", "numeric", "mixed"} <= tiers, tiers
    for it in items:
        assert it.get("question"), it
        assert it.get("gold", {}), f"{it['id']} 缺标准答案"
        assert it.get("basis"), f"{it['id']} 缺条文依据（A2）"
        if it["tier"] == "numeric":
            assert it.get("derivation"), f"{it['id']} 数值题必须写手工推导过程，避免引擎自证"


def test_golden_set_citations_resolve_to_corpus():
    """A2：每条标准答案的依据都能在知识库语料里定位到条目。"""
    corpus_ids = set()
    for line in (ROOT / "src" / "kb" / "corpus" / "kb_doc.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            corpus_ids.add(json.loads(line)["doc_id"])
    missing = []
    for it in _golden_items():
        for doc_id in it["basis"]:
            if doc_id not in corpus_ids:
                missing.append(f"{it['id']} -> {doc_id}")
    assert not missing, "评测集引用了不存在的条文条目：\n" + "\n".join(missing)


def test_every_golden_numeric_expectation_is_int_or_str():
    for it in _golden_items():
        for key, value in it.get("gold", {}).items():
            if isinstance(value, float):
                raise AssertionError(f"{it['id']}.{key} 是浮点，判定链禁止浮点")


def test_field_and_article_doc_exists():
    """F-001/F-002 的产物必须真实存在且写到条号级别（中文数字或阿拉伯数字均可）。"""
    text = (ROOT / "docs" / "字段口径与条文依据.md").read_text(encoding="utf-8")
    anchors = {
        "劳动法36": r"(第三十六条|第\s*36\s*条)",
        "劳动法38": r"(第三十八条|第\s*38\s*条)",
        "劳动法41": r"(第四十一条|第\s*41\s*条)",
        "劳动法44": r"(第四十四条|第\s*44\s*条)",
        "503号文": r"503",
        "489号文": r"489",
        "放假办法文号": r"795",
    }
    for name, pat in anchors.items():
        assert re.search(pat, text), f"字段口径与条文依据文档缺少 {name}"
    assert "未完成" in text or "尚未取得" in text, "P0 闸门状态必须如实写明（是否拿到 HR 口径）"


MD_REF = re.compile(r"\]\(([^)\s]+\.md)(?:#[^)]*)?\)")            # markdown 链接
MD_TICK = re.compile(r"`((?:docs|reports|src|config|evals|tools)/[^`\s]+\.md)`")  # 行内代码里的路径
TREE_MD = re.compile(r"^\s*[│├└\s]*[├└]──\s*([^\s#]+\.md)")      # README 目录树里的文件名


def _resolve(ref: str, base: Path) -> Path:
    p = Path(ref)
    if p.is_absolute() or re.match(r"^[A-Za-z]:", ref):
        return p
    return (base / p).resolve() if str(base) != str(ROOT) else (ROOT / p).resolve()


def test_doc_links_resolve_to_real_files():
    """文档里指向本地 .md 的每一条链接都必须真存在（悬空链接＝交付完整性缺陷）。"""
    dead = []
    for path in _scan_targets():
        if path.suffix != ".md":
            continue
        base = path.parent if path.parent != ROOT else ROOT
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            for ref in MD_REF.findall(line) + MD_TICK.findall(line):
                if ref.startswith(("http", "mailto")) or "<" in ref or "*" in ref:
                    continue
                if "{" in ref or "}" in ref:      # `reports/{A,B}.md` 这类简写不是真实路径
                    continue
                target = _resolve(ref, base)
                if not target.is_file() and not (ROOT / ref).is_file():
                    dead.append(f"{path.relative_to(ROOT)}: {ref}")
    assert not dead, "以下 .md 链接指向不存在的文件：" + " | ".join(dead[:12])


def test_readme_tree_lists_only_files_that_exist():
    """README 的目录结构是**对仓库现状的陈述**，不是计划：列了就必须存在。"""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    missing = []
    for line in text.splitlines():
        m = TREE_MD.match(line)
        if not m:
            continue
        name = m.group(1)
        if "*" in name or "<" in name:
            continue
        hits = list(ROOT.glob(name)) + list((ROOT / "docs").glob(name)) + \
            list((ROOT / "reports").glob(name))
        if not hits:
            missing.append(name)
    assert not missing, f"README 目录树里列了不存在的文件：{missing}"



def test_demo_script_commands_are_real():
    """A12 的一半：演示脚本里的每条命令都必须在 CLI 中存在。"""
    text = (ROOT / "docs" / "演示脚本-30分钟.md").read_text(encoding="utf-8")
    from src.cli import SUBCOMMAND_NAMES

    known = set(SUBCOMMAND_NAMES)
    used = set(re.findall(r"python(?:\.exe)? -m src\.cli (\w+)", text))
    assert used, "演示脚本没有可执行命令"
    unknown = used - known
    assert not unknown, f"演示脚本引用了不存在的子命令：{sorted(unknown)}"
    assert re.search(r"python -m pytest tests/ -q", text), "演示脚本必须包含跑测试这一步"


def test_synthetic_data_is_declared_and_reproducible():
    """A11：合成数据必须声明来源、种子与不可指向真人。"""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "合成数据" in readme
    assert "--seed" in readme or "seed" in readme
    gen = (ROOT / "data" / "generator" / "make_synthetic.py").read_text(encoding="utf-8")
    assert "random.Random(seed)" in gen, "生成器必须使用可复现种子的随机源"
    manifest = ROOT / "data" / "raw" / "MANIFEST.json"
    if manifest.is_file():
        m = json.loads(manifest.read_text(encoding="utf-8"))
        assert m.get("seed"), "MANIFEST 必须记录种子"
        assert "合成" in m.get("privacy", "")


def test_schema_has_no_float_columns_for_decisions():
    sql = (ROOT / "src" / "schema.sql").read_text(encoding="utf-8")
    for bad in ("REAL", "FLOAT", "DOUBLE", "DECIMAL"):
        assert bad not in sql.upper(), f"schema 出现 {bad}：判定数值必须用整数分/分钟"


def test_rules_all_reference_kb_corpus_entries():
    """规则命中挂的条文 id 必须都在语料里，否则 A2 会在举证时断链。"""
    from src.kb.loader import load_corpus_rows
    from src.rules.citations import ALL_CITATIONS

    ids = {d["doc_id"] for d in load_corpus_rows()}
    missing = [c for c in ALL_CITATIONS if not c.startswith("personnel.") and c not in ids]
    assert not missing, f"引用了不存在的条文条目：{missing}"


def _golden_items() -> list[dict]:
    path = ROOT / "evals" / "golden_set_v1.jsonl"
    if not path.is_file():
        raise AssertionError("评测集缺失：evals/golden_set_v1.jsonl")
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            items.append(json.loads(line))
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids)), "评测集存在重复 id"
    return items
