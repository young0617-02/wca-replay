"""机制 3：`artifacts_digest` 变化原因由**逐包逐文件、逐字段比对**生成。

不允许写“仅因版本号”。本脚本对每个 role 打开新旧两个 zip，逐成员比 SHA-256，
对变化的文本文件再逐段比对，把原因分成三类：

- `版本号文本`：把 0.4.x 版本串与 40 位 commit 归一后内容相同；
- `真实时间戳`：再把 ISO-8601 时间戳归一后内容相同（即时间戳真的变了）；
- `文档更新`：`.md`/`.txt`/`README` 等非数据工件的内容差异；
- `内容变化（需人工说明）`：以上都不成立，必须补说明，禁止默认归因。

用法：
    python scripts/diff_packages.py --old <旧包目录> --new <新包目录> --out <md 路径>
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

_DIGEST_KEYS = ("conclusion_digest", "evidence_digest", "inputs_digest",
                "input_fingerprint")
_VERSION_RE = re.compile(r"0\.4\.\d+")
_COMMIT_RE = re.compile(r"\b[0-9a-f]{40}\b")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+[0-9:]+)")
_DOC_SUFFIXES = (".md", ".txt", ".rst")


def _read_members(zip_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(zip_path) as zf:
        return {name: zf.read(name) for name in zf.namelist() if not name.endswith("/")}


def _digests(members: dict[str, bytes]) -> dict:
    manifest = json.loads(members["manifest.json"].decode("utf-8"))
    triple = manifest["triple"]
    out = {key: triple.get(key) for key in _DIGEST_KEYS}
    out["artifacts_digest"] = manifest.get("artifacts_digest")
    out["producer_version"] = manifest.get("producer", {}).get("version")
    out["producer_commit"] = manifest.get("producer", {}).get("commit")
    return out


_TS_KEY_RE = re.compile(r"(?i)(time|timestamp|_at$|date|ts$)")
_HASH_KEY_RE = re.compile(r"(?i)(digest|sha256|hash|signature|checksum|bytes|size)")
_VERSION_KEY_RE = re.compile(r"(?i)version|producer\.commit|^commit$")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_HEX40_RE = re.compile(r"[0-9a-f]{40}")


def _leaf_reason(key: str, old, new) -> str:
    text = str(old) + str(new)
    if _VERSION_KEY_RE.search(key):
        return "版本号文本"
    if _TS_KEY_RE.search(key) or key == "run_id" or _TS_RE.fullmatch(str(old)) \
            or _TS_RE.fullmatch(str(new)):
        return "真实时间戳"
    if (isinstance(old, str) and isinstance(new, str)
            and (_HEX64_RE.fullmatch(old) or _HEX40_RE.fullmatch(old)
                 or _HEX64_RE.fullmatch(new) or _HEX40_RE.fullmatch(new))):
        return "派生哈希（随内容重算）"
    if _HASH_KEY_RE.search(key) or text.count("0") > 20:
        return "派生哈希（随内容重算）"
    return "内容变化（需人工说明）"


def _diff_json(old, new, path: str, reasons: set[str]) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            child = f"{path}.{key}" if path else key
            if key not in old or key not in new:
                reasons.add("内容变化（需人工说明）")
                continue
            _diff_json(old[key], new[key], child, reasons)
        return
    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            reasons.add("内容变化（需人工说明）")
            return
        for index, (item_old, item_new) in enumerate(zip(old, new)):
            _diff_json(item_old, item_new, f"{path}[{index}]", reasons)
        return
    if old != new:
        reasons.add(_leaf_reason(path.rsplit(".", 1)[-1], old, new))


def _diff_csv(old_text: str, new_text: str, reasons: set[str]) -> bool:
    import csv
    import io
    old_rows = list(csv.reader(io.StringIO(old_text)))
    new_rows = list(csv.reader(io.StringIO(new_text)))
    if old_rows[:1] != new_rows[:1] or len(old_rows) != len(new_rows):
        return False
    header = old_rows[0]
    for row_old, row_new in zip(old_rows[1:], new_rows[1:]):
        for index, (cell_old, cell_new) in enumerate(zip(row_old, row_new)):
            if cell_old != cell_new:
                column = header[index] if index < len(header) else "col"
                reasons.add(_leaf_reason(column, cell_old, cell_new))
    return True


def _classify(name: str, old: bytes, new: bytes) -> list[str]:
    try:
        old_text = old.decode("utf-8-sig")
        new_text = new.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ["内容变化（二进制，需人工说明）"]

    reasons: set[str] = set()
    try:
        if name.endswith(".json"):
            _diff_json(json.loads(old_text), json.loads(new_text), "", reasons)
        elif name.endswith(".jsonl"):
            old_lines = [json.loads(x) for x in old_text.splitlines() if x.strip()]
            new_lines = [json.loads(x) for x in new_text.splitlines() if x.strip()]
            _diff_json(old_lines, new_lines, "", reasons)
        elif name.endswith(".csv"):
            if not _diff_csv(old_text, new_text, reasons):
                reasons.add("内容变化（需人工说明）")
        elif name.lower().endswith(_DOC_SUFFIXES):
            if _TS_RE.sub("<TS>", _VERSION_RE.sub("<VER>", old_text)) == \
                    _TS_RE.sub("<TS>", _VERSION_RE.sub("<VER>", new_text)):
                reasons.add("版本号文本")
                if old_text != new_text:
                    reasons.add("真实时间戳")
            else:
                reasons.add("文档更新")
        else:
            reasons.add("内容变化（需人工说明）")
    except (json.JSONDecodeError, TypeError):
        reasons.add("内容变化（需人工说明）")
    return sorted(reasons) if reasons else ["内容变化（需人工说明）"]


def _role_of(stem: str) -> str:
    """`confirmed-0.4.14` 与 `confirmed` 是同一角色的新旧命名。"""
    return re.sub(r"-0\.4\.\d+$", "", stem)


def build_table(old_dir: Path, new_dir: Path) -> tuple[str, list[str]]:
    old_files = {_role_of(p.stem): p for p in old_dir.glob("*.zip")}
    new_files = {_role_of(p.stem): p for p in new_dir.glob("*.zip")}
    if set(old_files) != set(new_files):
        raise SystemExit(f"新旧包 role 不一致：仅旧 {sorted(set(old_files) - set(new_files))}；"
                         f"仅新 {sorted(set(new_files) - set(old_files))}")
    rows: list[list[str]] = []
    detail: list[list[str]] = []
    invariant_rows: list[list[str]] = []
    reason_counts: dict[str, int] = {}
    unchanged_by_role: dict[str, set[str]] = {}
    for role in sorted(new_files):
        old_members = _read_members(old_files[role])
        new_members = _read_members(new_files[role])
        old_d = _digests(old_members)
        new_d = _digests(new_members)
        changed = sorted(set(old_members) | set(new_members))
        names: list[str] = []
        for name in changed:
            old_bytes = old_members.get(name)
            new_bytes = new_members.get(name)
            if old_bytes == new_bytes:
                continue
            names.append(name)
            if old_bytes is None or new_bytes is None:
                kind = ["仅出现在一侧"]
            else:
                kind = _classify(name, old_bytes, new_bytes)
            for item in kind:
                reason_counts[item] = reason_counts.get(item, 0) + 1
            detail.append([role, name, "、".join(kind), _explain(kind, name)])
        same = [key for key in _DIGEST_KEYS if old_d[key] == new_d[key]]
        unchanged_by_role[role] = {
            name for name in set(old_members) & set(new_members)
            if old_members[name] == new_members[name]}
        rows.append([
            role,
            f"`{str(old_d['artifacts_digest'])[:12]}…` → `{str(new_d['artifacts_digest'])[:12]}…`",
            str(len(names)),
            "、".join(same) or "（无）",
        ])
        invariant_rows.append([
            role,
            "相同" if same == list(_DIGEST_KEYS) else f"**不同：{set(_DIGEST_KEYS) - set(same)}**",
        ])
    body = [
        "### 逐包摘要（`artifacts_digest` 允许变，其余四项必须逐包相同）",
        "",
        "| 包 | artifacts_digest（旧 → 新） | 变动文件数 | 保持不变的四项摘要 |",
        "| --- | --- | --- | --- |",
    ]
    body += ["| " + " | ".join(row) + " |" for row in rows]
    body += [
        "",
        "### 逐包逐文件差异（只列真正变化的成员）",
        "",
        "| 包 | 包内文件 | 原因分类 | 说明 |",
        "| --- | --- | --- | --- |",
    ]
    body += ["| " + " | ".join(row) + " |" for row in detail]
    body += [
        "",
        "### 四联摘要不变量核对",
        "",
        "| 包 | conclusion / evidence / inputs / input_fingerprint |",
        "| --- | --- |",
    ]
    body += ["| " + " | ".join(row) + " |" for row in invariant_rows]
    common = set.intersection(*unchanged_by_role.values()) if unchanged_by_role else set()
    body += [
        "",
        f"### 逐字节未变的成员（在全部 {len(unchanged_by_role)} 个包内都未变）",
        "",
        "| 包内文件 | 包数 |",
        "| --- | --- |",
    ]
    body += [f"| `{name}` | {len(unchanged_by_role)} |" for name in sorted(common)]
    body += [
        "",
        "### 三类原因汇总（按文件计数）",
        "",
        "| 原因 | 出现次数 |",
        "| --- | --- |",
    ]
    body += [f"| {key} | {value} |" for key, value in sorted(reason_counts.items())]
    return "\n".join(body), [f"{row[0]}/{row[1]}: {row[2]}" for row in detail]


def _explain(kinds: list[str], name: str) -> str:
    parts: list[str] = []
    if "版本号文本" in kinds:
        parts.append("版本号/commit 文本变化")
    if "真实时间戳" in kinds:
        parts.append("真实时间戳变化（连带哈希链、签名与摘要重算）")
    if "派生哈希（随内容重算）" in kinds:
        parts.append("摘要/签名字段随内容重算")
    if "文档更新" in kinds:
        parts.append("文档内容更新（非数据工件）")
    if "内容变化（需人工说明）" in kinds or "内容变化（二进制，需人工说明）" in kinds:
        parts.append(f"{name} 存在版本/时间戳/摘要之外的内容差异，必须逐字段说明")
    if "仅出现在一侧" in kinds:
        parts.append("该成员只在新包或旧包中存在")
    return "；".join(parts) if parts else "无变化"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="逐包逐文件比对 artifacts_digest 变化原因")
    parser.add_argument("--old", required=True, type=Path)
    parser.add_argument("--new", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    table_md, _ = build_table(args.old, args.new)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        f"# 包内工件差异（{args.old.name} → {args.new.name}）\n\n"
        "> 本表由 `scripts/diff_packages.py` 逐包逐文件、逐字段比对生成；"
        "禁止手工改写成“仅因版本号”。\n\n" + table_md + "\n",
        encoding="utf-8")
    print(f"已生成：{args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
