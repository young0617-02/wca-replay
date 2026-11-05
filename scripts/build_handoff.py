"""生成交接目录：README 事实区、清单、锚点、覆盖范围全部由实物计算。

机制 1 的落点：
- `README-验收.md`、`READ-ME-FIRST.txt`、`OLD-WHEELS.md`、`OLD-ANCHORS.md`、
  `release/SHA256SUMS-覆盖范围.md`、`交付清单.txt`、`未随交付清单.md` 的事实都从产物读取；
- 生成区用 `<!-- GENERATED:START key -->` / `<!-- GENERATED:END key -->` 标记，禁止人工编辑；
- 章节号按出现顺序重编（D1），目录由同一份标题列表生成。

用法：
    uv run python scripts/build_handoff.py \
      --dist dist/wca-replay-0.4.17 --summary var/handoff-packages/summary.json \
      --prev handoff/20261104-第十八轮整改 --out handoff/20261104-第十九轮整改
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import docfacts  # noqa: E402
import diff_packages  # noqa: E402
import check_handoff_refs  # noqa: E402

ROLES = [
    ("engine-only", ("engine_only",), "engine-only.zip",     "零人工确认：全部 finding 为 unsigned_pending"),
    ("confirmed", ("confirmed",), "confirmed.zip",
     "两条人工确认：final_conclusions=2，审计链追加确认与交付事件"),
    ("cross-db", ("cross_db", "package"), "cross-db.zip",
     "换新库、同序重导：验证摘要不依赖 DB 自增 ID"),
    ("reverse-order", ("cross_db_reverse", "package"), "reverse-order.zip",
     "换新库、punch/schedule 反序导入：验证导入顺序不改变摘要"),
    ("default-flow", ("default_flow", "package"), "default-flow.zip",
     "默认流程（data/raw）：合成数据全链路可验可回放"),
    ("dup-subdir-a-then-b", ("dup_subdir", "packages", 0), "dup-subdir-a-then-b.zip",
     "跨目录同名/重复行，a 先 b 后：单批 finding + 全来源 + 保留行"),
    ("dup-subdir-b-then-a", ("dup_subdir", "packages", 1), "dup-subdir-b-then-a.zip",
     "同批数据 b 先 a 后：batch_id 与结论摘要一致"),
    ("clean-wheel-default-flow", ("cross_run", "package"), "clean-wheel-default-flow.zip",
     "仓库外干净 venv 仅装交付版 wheel，默认流程 v6 产出"),
]

CN_NUM = "零一二三四五六七八九十"


def cjk_number(index: int) -> str:
    if index <= 10:
        return CN_NUM[index]
    if index < 20:
        return "十" + CN_NUM[index % 10]
    return CN_NUM[index // 10] + "十" + (CN_NUM[index % 10] if index % 10 else "")


def _dig(summary: dict, path: tuple):
    value = summary
    for key in path:
        value = value[key]
    return value


def _path_of(summary: dict, spec: tuple) -> Path:
    value = _dig(summary, spec)
    return Path(value) if isinstance(value, str) else Path(value["path"])


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _gen(key: str, body: str) -> str:
    return docfacts.generated_block(key, body)


def renumber_sections(text: str) -> tuple[str, list[str]]:
    """把 `## X、标题` 按出现顺序重编，返回 (新文本, 标题列表)。"""
    titles: list[str] = []
    lines = text.splitlines()
    counter = 0
    for index, line in enumerate(lines):
        match = re.match(r"^## (?:[零一二三四五六七八九十]+)、(.+)$", line)
        if match:
            counter += 1
            title = match.group(1).strip()
            titles.append(title)
            lines[index] = f"## {cjk_number(counter)}、{title}"
    return "\n".join(lines), titles


def _round_label(name: str) -> str:
    match = re.search(r"第([零一二三四五六七八九十]+)轮整改", name)
    return match.group(1) if match else "本轮"


def _anchor_counts(anchors: dict, version: str) -> tuple[int, int, int, int]:
    """单包锚点的“本轮/历史”拆分；旧锚点表与 README 共用同一扫描结果。"""
    current = sum(1 for a in anchors["singles"] if a["version"] == version)
    history = len(anchors["singles"]) - current
    current_combined = sum(1 for a in anchors["combined"] if a["version"] == version)
    history_combined = len(anchors["combined"]) - current_combined
    return current, history, current_combined, history_combined


def _read_anchor_doc(path: Path) -> tuple[str, str, dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return str(doc.get("version") or ""), docfacts.anchor_kind(doc), doc


def _handoff_search_dirs(prev: Path, out: Path) -> list[Path]:
    """锚点候选来源：`--prev` 优先，其余交接目录按修改时间新→旧。"""
    prev_resolved = prev.resolve()
    out_resolved = out.resolve()
    others = [d for d in (ROOT / "handoff").iterdir()
              if d.is_dir() and d.resolve() not in (prev_resolved, out_resolved)]
    others.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return [prev] + others


def _collect_anchor_candidates(prev: Path, out: Path,
                               allowed_versions: set[str]) -> tuple[dict, list[dict]]:
    """收集历史锚点：同一 (类型, 版本, 角色) 只取第一个来源（prev 优先）。

    只收 **prev 交付过的版本 + 本目录旧包实有版本 + 本轮版本**；更早轮次
    （0.4.4–0.4.9）的锚点不在本交付范围，避免把“无包可解析”的历史锚点重新带进来。
    """
    chosen: dict[tuple[str, str, str], tuple[Path, dict]] = {}
    sources: list[dict] = []
    for directory in _handoff_search_dirs(prev, out):
        for path in sorted(directory.glob("anchor*.json")):
            try:
                anchor_version, kind, doc = _read_anchor_doc(path)
            except (OSError, ValueError):
                continue
            if not anchor_version or kind not in ("single", "combined"):
                continue
            if anchor_version not in allowed_versions:
                continue
            key = (kind, anchor_version, str(doc.get("role") or ""))
            if key in chosen:
                continue
            chosen[key] = (path, doc)
            sources.append({
                "source": path,
                "version": anchor_version,
                "kind": kind,
                "name_version": (docfacts.anchor_name_version(path.name)
                                 or path.name),
            })
    return chosen, sources


def _entry_sha(entry: dict) -> str:
    return str(entry.get("package_sha256") or entry.get("sha256") or "")


def _locate_target(out: Path, anchor_version: str, role: str, version: str) -> Path:
    if anchor_version == version:
        return out / "package" / f"{role}.zip"
    return out / "release" / "old-packages" / f"{role}-{anchor_version}.zip"


def _repair_anchor_doc(doc: dict, anchor_version: str, out: Path, version: str) -> dict:
    """把历史锚点的 `file` 改成**以 JSON 自身位置为基准**的可解析相对路径；
    目录内确实没有对应包的，显式标注“仅记录、不可解析”，不留“看似可解析”的路径。
    """
    repaired = json.loads(json.dumps(doc))
    entries = (repaired["packages"] if docfacts.anchor_kind(repaired) == "combined"
               else [repaired])
    for entry in entries:
        role = str(entry.get("role") or "")
        original = entry.get("file")
        entry["original_file"] = original
        target = _locate_target(out, anchor_version, role, version)
        if target.is_file() and docfacts.sha256_file(target) == _entry_sha(entry):
            entry["file"] = target.relative_to(out).as_posix()
            entry["file_status"] = "可解析（本目录内）"
        else:
            entry["file"] = (f"{docfacts.ANCHOR_MARKER}（原记录：{original}；"
                             "获取方式见 OLD-ANCHORS.md）")
            entry["file_status"] = "仅记录、不可解析"
    return repaired


def _assert_anchor_file(path: Path, out: Path) -> None:
    """三方一致断言：文件名版本 == 内容版本 == 目标包 `producer.version`。

    目标包不可解析（显式标注）时不参与 producer 比对，但仍校验“文件名==内容”。
    任何一项不一致直接失败，构建不得继续。
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    anchor_version = str(doc.get("version") or "")
    if not anchor_version:
        raise SystemExit(f"{path.name} 缺少 version 字段")
    name_version = docfacts.anchor_name_version(path.name)
    if name_version and name_version != anchor_version:
        raise SystemExit(
            f"锚点文件名版本 {name_version} != 内容版本 {anchor_version}：{path.name}")
    for entry in docfacts.anchor_file_entries(doc):
        status = docfacts.anchor_file_status(path, entry.get("file"))
        if status != "resolvable":
            continue
        facts = docfacts.package_facts(path.parent / entry["file"])
        if facts["producer_version"] != anchor_version:
            raise SystemExit(
                f"{path.name}: 目标包 {entry['file']} 的 producer.version="
                f"{facts['producer_version']} != 锚点版本 {anchor_version}")
        if facts["sha256"] != _entry_sha(entry):
            raise SystemExit(f"{path.name}: 目标包 {entry['file']} 的 SHA-256 与锚点不符")



def _scan_version_mismatches(prev: Path, out: Path) -> dict:
    """全目录扫描“文件名版本 != 内容版本”的锚点与清单，供 OLD-ANCHORS.md 逐条列出。

    扫描不做修改：历史交接目录保持只读；“处置”一列只说明本轮如何按内容重新命名。
    """
    anchor_rows: list[dict] = []
    manifest_rows: list[dict] = []
    for directory in _handoff_search_dirs(prev, out):
        for path in sorted(directory.glob("anchor*.json")):
            try:
                content_version, _kind, _doc = _read_anchor_doc(path)
            except (OSError, ValueError):
                continue
            name_version = docfacts.anchor_name_version(path.name)
            if name_version and name_version != content_version:
                anchor_rows.append({
                    "path": path.relative_to(ROOT).as_posix(),
                    "name_version": name_version,
                    "content_version": content_version,
                    "disposition": "按内容版本改名另存；本目录不沿用该文件名",
                })
        manifest = directory / "交付清单.txt"
        release_json = directory / "release" / "RELEASE.json"
        if manifest.is_file() and release_json.is_file():
            try:
                claimed = manifest.read_text(encoding="utf-8").splitlines()[0].split()[0]
                actual = json.loads(release_json.read_text(encoding="utf-8"))["version"]
            except (IndexError, ValueError, KeyError):
                continue
            if claimed != actual:
                manifest_rows.append({"path": manifest.relative_to(ROOT).as_posix(),
                                      "claimed": claimed, "actual": actual})
    return {"anchors": anchor_rows, "manifests": manifest_rows}


def build(args: argparse.Namespace) -> int:
    version = args.version
    dist: Path = Path(args.dist).resolve()
    out: Path = Path(args.out).resolve()
    prev: Path = Path(args.prev).resolve()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    release = json.loads((dist / "RELEASE.json").read_text(encoding="utf-8"))
    if out.exists():
        if not args.force:
            raise SystemExit(f"{out} 已存在；确认重建请加 --force")
        shutil.rmtree(out)
    out.mkdir(parents=True)

    # 1) 包
    (out / "package").mkdir()
    for role, key_path, filename, _desc in ROLES:
        shutil.copy2(_path_of(summary, key_path), out / "package" / filename)
    new_pkg_dir = out / "package"

    # 2) 发行物 + 旧物
    shutil.copytree(dist, out / "release")
    for name in ("old-wheels", "old-packages"):
        shutil.copytree(prev / "release" / name, out / "release" / name)
    prev_release = prev / "release"
    prev_version = json.loads((prev_release / "RELEASE.json").read_text(encoding="utf-8"))["version"]
    prev_wheel = json.loads((prev_release / "RELEASE.json").read_text(encoding="utf-8"))["wheel"]
    shutil.copy2(prev_release / prev_wheel, out / "release" / "old-wheels" / prev_wheel)
    shutil.copy2(prev_release / "requirements.lock.txt",
                 out / "release" / "old-wheels" / f"requirements-{prev_version}.lock.txt")
    for role, _key, filename, _desc in ROLES:
        shutil.copy2(prev / "package" / filename,
                     out / "release" / "old-packages" / f"{role}-{prev_version}.zip")

    # 3) 公钥、历史锚点：文件名一律由“内容里的 version”派生，不沿用源文件名。
    for name in ("trusted-public-key.pub", "release-public-key.pub"):
        shutil.copy2(prev / name, out / name)
    allowed_versions = {version}
    for path in prev.glob("anchor*.json"):
        try:
            allowed_versions.add(str(json.loads(path.read_text(
                encoding="utf-8")).get("version") or ""))
        except (OSError, ValueError):
            continue
    for path in (out / "release" / "old-packages").glob("*.zip"):
        allowed_versions.add(docfacts._version_from_name(path.name))
    allowed_versions.discard("")
    anchor_candidates, anchor_sources = _collect_anchor_candidates(
        prev, out, allowed_versions)
    historical_versions = sorted({v for (_kind, v, _role) in anchor_candidates
                                  if v != version})
    for anchor_version in historical_versions:
        for kind in ("single", "combined"):
            if not any(k == kind and v == anchor_version
                       for (k, v, _role) in anchor_candidates):
                raise SystemExit(f"历史锚点缺失：{anchor_version} 的 {kind} 汇总未找到")
    for (kind, anchor_version, role), (source_path, source_doc) in sorted(
            anchor_candidates.items()):
        if anchor_version == version:
            continue  # 本轮锚点在第 5 步由新包生成
        filename = (f"anchor-{anchor_version}-{role}.json" if kind == "single"
                    else f"anchor-{anchor_version}.json")
        target = out / filename
        if target.exists():
            raise SystemExit(f"锚点目标文件重复：{filename}（来源 {source_path}）")
        repaired = _repair_anchor_doc(source_doc, anchor_version, out, version)
        _write(target, json.dumps(repaired, ensure_ascii=False, indent=2))
        _assert_anchor_file(target, out)

    # 4) 文档与报告（仓库内为唯一来源）
    (out / "docs").mkdir()
    for name in ("签名方案.md", "安全与证据链现状.md", "冻结版本说明.md"):
        shutil.copy2(ROOT / "docs" / name, out / "docs" / name)
    shutil.copy2(ROOT / "docs" / "已知残留与未闭合项.md", out / "已知残留与未闭合项.md")
    import fact_exemptions
    _write(out / "docs" / "护栏豁免表.md",
           _gen("exemptions", fact_exemptions.render_markdown(version)))
    shutil.copy2(ROOT / "policies" / "RULE-PACK.md", out / "RULE-PACK.md")
    (out / "reports").mkdir()
    for path in sorted((ROOT / "reports").iterdir()):
        if path.suffix == ".md" or path.name.startswith("round"):
            if path.is_file():
                shutil.copy2(path, out / "reports" / path.name)

    # 5) 新锚点
    invariants = {key: summary["confirmed"][key] for key in
                  ("conclusion_digest", "evidence_digest", "inputs_digest")}
    invariants["input_fingerprint"] = summary["confirmed"]["triple"]["input_fingerprint"]
    packages_json = []
    for role, key_path, filename, desc in ROLES:
        pkg = docfacts.package_facts(new_pkg_dir / filename)
        single = {
            "version": version,
            "role": role,
            "file": f"package/{filename}",
            "file_status": "可解析（本目录内）",
            "anchor": pkg["anchor"],
            "package_sha256": pkg["sha256"],
            "artifacts_digest": pkg["artifacts_digest"],
            "evidence_digest": pkg["evidence_digest"],
            "inputs_digest": pkg["inputs_digest"],
            "input_fingerprint": pkg["input_fingerprint"],
            "comparability_scope": {
                "rule_pack_version": pkg["rule_pack_version"],
                "schema": pkg["schema"],
            },
            "counts": pkg["counts"],
        }
        _write(out / f"anchor-{version}-{role}.json",
               json.dumps(single, ensure_ascii=False, indent=2))
        _assert_anchor_file(out / f"anchor-{version}-{role}.json", out)
        packages_json.append({
            "role": role,
            "file": f"package/{filename}",
            "file_status": "可解析（本目录内）",
            **{key: pkg[key] for key in
               ("bytes", "sha256", "anchor", "conclusion_digest", "evidence_digest",
                "inputs_digest", "input_fingerprint", "artifacts_digest")},
            "rule_pack_version": pkg["rule_pack_version"],
            "schema": pkg["schema"],
            "key_id": pkg["key_id"],
            "counts": pkg["counts"],
            "description": desc,
        })
    combined = {
        "version": version,
        "producer_commit": release["git_commit"],
        "comparability_scope": {
            "definition": "摘要只在同 rule_pack_version + 同 evidence schema 下可比",
            "schema": "wca-evidence-package-v3",
            "rule_pack_versions": sorted({p["rule_pack_version"] for p in packages_json}),
            "note": ("组合式 anchor.json 仅作汇总记录，不在任何签名保护范围，也不能直接用于"
                     f"单包验算；单包请用 anchor-{version}-<role>.json"),
        },
        "invariants": invariants,
        "packages": packages_json,
        "release": {
            "dir": "release/",
            "wheel": release["wheel"],
            "wheel_sha256": docfacts.sha256_file(out / "release" / release["wheel"]),
            "release_key_id": release["release_signature"]["key_id"],
            "build_time": release["build_time"],
            "sha256sums_scope": release["release_signature"]["scope"],
        },
        "package_key_id": summary["key_id"],
    }
    _write(out / "anchor.json", json.dumps(combined, ensure_ascii=False, indent=2))
    _assert_anchor_file(out / "anchor.json", out)
    anchor_txt = [f"# {version} 本轮 anchor 速查；四联摘要不变量见首段", ""]
    anchor_txt += [f"{k}={v}" for k, v in invariants.items()]
    anchor_txt.append("")
    anchor_txt += [f"{p['file']} sha256={p['sha256']} anchor={p['anchor']}"
                   for p in packages_json]
    _write(out / "anchor.txt", "\n".join(anchor_txt))

    # 6) 覆盖范围（从实际 SHA256SUMS 读行）
    rel_facts = docfacts.release_facts(out / "release")
    coverage_lines = [
        f"# SHA256SUMS 保护范围（{version}，由实物生成）",
        "",
        f"`release/SHA256SUMS` 实际有 **{rel_facts['covered_count']} 行**，"
        f"`release/SHA256SUMS.sig` 只保护这 {rel_facts['covered_count']} 个文件：",
        "",
    ]
    coverage_lines += [f"{i}. `{row['name']}`" for i, row in
                       enumerate(rel_facts["covered"], 1)]
    coverage_lines += [
        "",
        "## 不在保护范围的文件",
        "",
        "- `release/old-wheels/`、`release/old-packages/` 下的旧物",
        "- `release/旧发行物-SHA256清单.md`、本说明文件",
        "- 交接根目录的 `package/*.zip`、`anchor*.json`、`docs/`、`reports/`",
        "",
        "这些文件的完整性由各自的包签名、锚点记录或 `交付清单.txt` 的逐文件 SHA-256 负责。",
    ]
    _write(out / "release" / "SHA256SUMS-覆盖范围.md",
           _gen("sha256sums-scope", "\n".join(coverage_lines)))

    # 7) 逐包逐文件差异（机制 3）
    diff_md, diff_detail = diff_packages.build_table(prev / "package", new_pkg_dir)
    _write(out / "reports" / "round17-diff.md",
           _gen("diff", f"# {prev_version} → {version} 包内工件差异（机制 3，逐包逐文件生成）\n\n"
                        "> 由 `scripts/diff_packages.py` 生成。禁止改写成“仅因版本号”。\n\n"
                        + diff_md))

    # 8) 旧物清单（从实物生成）
    old = docfacts.old_assets(out / "release")
    for item in old["wheels"] + old["locks"]:
        for d in item["dirs"]:
            target = out / "release" / d / item["name"]
            if not target.is_file():
                raise SystemExit(f"旧物表登记了不存在的路径：{target}")
    wheel_rows = [[f"`{w['name']}`", f"{w['bytes']}", f"`{w['sha256']}`",
                   "、".join(f"`release/{d}/`" for d in w["dirs"])]
                  for w in old["wheels"]]
    lock_rows = [[f"`{x['name']}`", f"{x['bytes']}", f"`{x['sha256']}`",
                  "、".join(f"`release/{d}/`" for d in x["dirs"])]
                 for x in old["locks"]]
    old_wheels_md = "\n".join([
        _gen("old-wheels", "\n".join([
            f"# 旧 wheel 与依赖锁（{version} 交接，由实物生成）",
            "",
            f"`release/old-wheels/` 与 `release/old-packages/` 实有 **{len(old['wheels'])} 个唯一 wheel**、"
            f"**{len(old['locks'])} 个依赖锁**；同名文件只列一次，并标出真实所在目录。"
            "哈希由文件字节计算，非手写。",
            "",
            docfacts.table(["文件", "字节", "SHA-256", "所在目录"], wheel_rows),
            "",
            "依赖锁：",
            "",
            docfacts.table(["文件", "字节", "SHA-256", "所在目录"], lock_rows) if lock_rows else "（无）",
            "",
            "**0.4.6 签名钥疑点**：该版发行钥 `ed25519:b07741b2…` 是包签名钥的误用；本目录只带",
            "0.4.6 wheel，不带该版 `SHA256SUMS`/`.sig`，因此**目录内不可验证**该版发行签名，",
            "原因如实写明，不声称“已核验”。",
        ])),
    ])
    _write(out / "OLD-WHEELS.md", old_wheels_md)

    # 8.1 锚点：file 指针逐条判定（可解析 / 显式标注 / 悬空），并找出“未随本目录交付”的包源
    anchors = docfacts.anchor_records(out)
    status_text = {"resolvable": "可解析（本目录内）",
                   "marked": "仅记录、不可解析", "dangling": "悬空"}
    acquisitions: dict[tuple[str, str], str] = {}
    for name in [a["name"] for a in anchors["singles"] + anchors["combined"]
                 if a["status"] == "marked"]:
        anchor_path = out / name
        doc = json.loads(anchor_path.read_text(encoding="utf-8"))
        for entry in docfacts.anchor_file_entries(doc):
            if docfacts.anchor_file_status(anchor_path, entry.get("file")) != "marked":
                continue
            role = str(entry.get("role") or "")
            anchor_version = str(doc.get("version") or "")
            if (anchor_version, role) in acquisitions:
                continue
            for directory in _handoff_search_dirs(prev, out):
                candidate = directory / "package" / f"{role}.zip"
                if not candidate.is_file():
                    continue
                if docfacts.sha256_file(candidate) != _entry_sha(entry):
                    continue
                if docfacts.package_facts(candidate)["producer_version"] != anchor_version:
                    continue
                acquisitions[(anchor_version, role)] = candidate.relative_to(ROOT).as_posix()
                break
    anchor_rows = [[f"`{a['name']}`", f"{a['version']}",
                    "单包" if a["kind"] == "single" else "组合",
                    status_text[a["status"]], f"{a['bytes']}", f"`{a['sha256']}`"]
                   for a in anchors["singles"] + anchors["combined"]]
    anchor_versions = sorted({a["version"] for a in
                              anchors["singles"] + anchors["combined"]})
    version_rows = []
    for anchor_version in anchor_versions:
        singles_v = [a for a in anchors["singles"] if a["version"] == anchor_version]
        combined_v = [a for a in anchors["combined"] if a["version"] == anchor_version]
        singles_marked = sum(1 for a in singles_v if a["status"] == "marked")
        combined_marked = sum(1 for a in combined_v if a["status"] == "marked")
        shipped = "是" if not (singles_marked or combined_marked) else "否（见下表）"
        version_rows.append([anchor_version,
                             f"{len(singles_v)}（标注 {singles_marked}）",
                             f"{len(combined_v)}（标注 {combined_marked}）", shipped])
    missing_rows = []
    for anchor_version in anchor_versions:
        for name in [a["name"] for a in anchors["singles"] if a["version"] == anchor_version
                     and a["status"] == "marked"]:
            doc = json.loads((out / name).read_text(encoding="utf-8"))
            role = str(doc.get("role") or "")
            source = acquisitions.get((anchor_version, role))
            missing_rows.append([
                anchor_version, role, "本目录无对应包（`package/` 与 `release/old-packages/` 均无）",
                (f"`{source}`（不随本目录交付；sha 与锚点实测一致）" if source
                 else "未找到可核对的源包；本目录不可自证")])
    source_rows = []
    for anchor_version in anchor_versions:
        if anchor_version == version:
            continue
        for item in [s for s in anchor_sources
                     if s["version"] == anchor_version and s["kind"] == "combined"]:
            rel = item["source"].relative_to(ROOT).as_posix()
            note = ("源文件名与内容版本一致"
                    if item["name_version"] == item["version"]
                    else f"源文件名写 {item['name_version']}，内容实为 {item['version']}；"
                         "已按内容改名")
            source_rows.append([anchor_version, "组合", f"`{rel}`", note])
        single_items = [s for s in anchor_sources
                        if s["version"] == anchor_version and s["kind"] == "single"]
        if single_items:
            dirs = sorted({s["source"].parent.relative_to(ROOT).as_posix() for s in single_items})
            source_rows.append([anchor_version, f"单包（{len(single_items)} 个）",
                                "、".join(f"`{d}/`" for d in dirs), "按内容版本逐一改名"])
    mismatches = _scan_version_mismatches(prev, out)
    mismatch_rows = [[f"`{row['path']}`", row["name_version"], row["content_version"],
                      row["disposition"]] for row in mismatches["anchors"]]
    manifest_rows = [[f"`{row['path']}`", row["claimed"], row["actual"]]
                     for row in mismatches["manifests"]]
    old_anchors_md = "\n".join([
        _gen("old-anchors", "\n".join([
            f"# 锚点实物与 `file` 可达性（{version} 交接，由扫描器生成）",
            "",
            f"本目录根下实有锚点 **{anchors['anchor_total']} 个**（单包 "
            f"**{len(anchors['singles'])} 个**、组合记录 **{len(anchors['combined'])} 个**）。",
            f"**扫描器断言**：按锚点计（每个 `file` 字段都以**该 JSON 自身位置**为基准核对，"
            f"锚点内全部指针可解析才算可解析）——可解析 "
            f"**{anchors['by_status']['resolvable']} 个**、显式标注“仅记录、不可解析” "
            f"**{anchors['by_status']['marked']} 个**、悬空 **{anchors['by_status']['dangling']} 个**。"
            f"按指针计（组合锚点每包一条）：可解析 **{anchors['pointer_by_status']['resolvable']} 条**、"
            f"标注 **{anchors['pointer_by_status']['marked']} 条**、悬空 "
            f"**{anchors['pointer_by_status']['dangling']} 条**。"
            "本结论由扫描器覆盖全部 `anchor*.json` 后生成，不是手写声明。",
            "",
            "## 按版本汇总（是否随本目录交付）",
            "",
            docfacts.table(["版本", "单包锚点", "组合锚点", "包是否随本目录交付"],
                           version_rows),
            "",
            "## 历史记录：锚点已交付、对应包未随本目录交付",
            "",
            (docfacts.table(["版本", "角色", "缺失实物", "获取方式"],
                            missing_rows) if missing_rows else "（无：本目录内全部锚点均可解析）"),
            "",
            "## 历史锚点来源与改名前后的核对",
            "",
            "> 文件名一律由**内容里的 `version`** 生成；构建时断言“文件名版本 == 内容版本 ==",
            "> 目标包 `producer.version`”，任一不一致直接失败。",
            "",
            (docfacts.table(["版本", "类型", "来源", "说明"], source_rows)
             if source_rows else "（无历史锚点）"),
            "",
            "## 全目录同名错版扫描（历史锚点 / 交付清单 / 旧发行物清单）",
            "",
            "扫描范围：`handoff/` 下全部交接目录（含未随本目录交付的历史轮次）。",
            "",
            "**锚点文件名版本 != 内容版本：**",
            "",
            (docfacts.table(["文件", "文件名版本", "内容版本", "处置"], mismatch_rows)
             if mismatch_rows else "（无）"),
            "",
            "**交付清单首行版本 != 该目录 `RELEASE.json` 版本：**",
            "",
            (docfacts.table(["文件", "清单写", "实物版本"], manifest_rows)
             if manifest_rows else "（无）"),
            "",
            "旧发行物清单：本轮重建时去掉重复的“目录（生成）”块，并把章节号按出现顺序重编；",
            "表内历史哈希仍只作记录，可复核范围见该文件头部。",
            "",
            "## 锚点表（逐文件，哈希由字节计算）",
            "",
            docfacts.table(["文件", "版本", "类型", "file 状态", "字节", "SHA-256"],
                           anchor_rows),
            "",
            "组合式 `anchor-<版本>.json` / `anchor.json` 只是**汇总值记录**，不在任何签名保护范围，",
            "也不能当作单包锚点使用（`--anchor-file` 只接受单包扁平 JSON）。",
        ])),
    ])
    _write(out / "OLD-ANCHORS.md", old_anchors_md)

    # 9) 旧发行物清单：限定范围 + 章节号重编 + 目录
    legacy = (prev / "release" / "旧发行物-SHA256清单.md").read_text(encoding="utf-8")
    # 上一版会把生成目录也复制进来，形成两个“目录（生成）”块；先删掉旧块再重排。
    legacy = re.sub(r"(?ms)^## 目录（生成）\n\n(?:[0-9]+\. [^\n]*\n)+\n", "", legacy)
    legacy = re.sub(
        r"(?m)^.*仍可独立核验.*$",
        "> **可复核范围（{v}）**：只有本交付内实际存在的 `release/old-wheels/`、"
        "`release/old-packages/` 文件能逐字节复核；0.4.0–0.4.12 的发行目录本身**不随交付**，"
        "其哈希仅作历史记录，需向交付方索取原目录后才能核对。".replace("{v}", version),
        legacy, count=1)
    legacy, titles = renumber_sections(legacy)
    toc = "\n".join(f"{i}. {t}" for i, t in enumerate(titles, 1))
    legacy = re.sub(r"(?m)^# (.+)$",
                    lambda m: f"# {m.group(1)}\n\n## 目录（生成）\n\n{toc}", legacy, count=1)
    _write(out / "release" / "旧发行物-SHA256清单.md", legacy)

    # 10) 未随交付清单（扫描器驱动；无遗漏才允许写“全表”）
    unshipped = write_unshipped(out)
    _write(out / "未随交付清单.md", unshipped)

    # 11) README / READ-ME-FIRST / KEY-NOTE
    _write(out / "README-验收.md",
           build_readme(version, release, rel_facts, packages_json, old, anchors,
                        diff_md, diff_detail, out.name, prev_version))
    _write(out / "READ-ME-FIRST.txt",
           build_first(version, packages_json, old, anchors, diff_detail, out.name))
    key_note = (prev / "KEY-NOTE.txt").read_text(encoding="utf-8").replace(prev_version, version)
    round_label = re.search(r"第([零一二三四五六七八九十]+)轮整改", out.name)
    old_label = re.search(r"第([零一二三四五六七八九十]+)轮交接", key_note)
    if round_label and old_label:
        key_note = key_note.replace(old_label.group(0), f"第{round_label.group(1)}轮交接")
    # 旧包/旧 wheel 的落点必须与 OLD-WHEELS.md 的“所在目录”同源，不靠记忆。
    old_versions_text = "、".join(sorted({p["version"] for p in old["packages"]
                                         if p.get("version")}))
    wheels_ow_versions = sorted({w["version"] for w in old["wheels"]
                                 if "old-wheels" in w["dirs"] and w["version"]})
    wheels_op_versions = sorted({w["version"] for w in old["wheels"]
                                 if "old-packages" in w["dirs"] and w["version"]})
    locks_ow_versions = sorted({x["version"] for x in old["locks"]
                                if "old-wheels" in x["dirs"] and x["version"]})
    locks_op_versions = sorted({x["version"] for x in old["locks"]
                                if "old-packages" in x["dirs"] and x["version"]})
    only_ow = [v for v in wheels_ow_versions if v not in wheels_op_versions]
    key_note = re.sub(
        r"(?s)旧包必须配.*?本轮新包（[^）]+）用本目录 release/ 的 [\d.]+ wheel。",
        "旧包必须配**同版本** wheel。本目录的旧包只有 "
        f"{old_versions_text} 共 {len(old['packages'])} 个 zip（版本不连续，0.4.12 没有包）。\n"
        "  0.4.10/0.4.11 的 wheel 在 release/old-wheels/ 与 release/old-packages/ 各有一份"
        "（同名同字节）；"
        + (f"{only_ow[0]}–{only_ow[-1]} 的 wheel 只在 release/old-wheels/。"
           if only_ow else "其余旧 wheel 只在 release/old-wheels/。")
        + "\n  **0.4.10/0.4.11 的依赖锁只在 release/old-packages/**，"
        f"0.4.13–0.4.16 的锁在 release/old-wheels/（实有 {len(locks_ow_versions)} 个版本）。"
        "按 OLD-WHEELS.md 的“所在目录”列找即可，不要按目录名猜。\n"
        f"  本轮新包（{version}）用本目录 release/ 的 {version} wheel。",
        key_note, flags=re.S)
    _write(out / "KEY-NOTE.txt", key_note)

    # 12) 交付清单（排除自身）
    write_manifest(out, version, release, invariants, packages_json)
    errors = check_handoff_refs.check_refs(out)
    if errors:
        raise SystemExit("未随交付清单未覆盖全部引用：\n" + "\n".join(errors[:20]))
    print(f"OK {out}：{len(packages_json)} 包，文件 "
          f"{sum(1 for p in out.rglob('*') if p.is_file())} 个")
    return 0


def write_unshipped(out: Path) -> str:
    """扫描交付目录全部 .md/.txt，把未交付的仓库路径按前缀逐条登记。"""
    missing: dict[str, set[str]] = {}
    for path in check_handoff_refs.text_files(out):
        for ref in check_handoff_refs.refs(path.read_text(encoding="utf-8")):
            if not (out / ref).exists():
                missing.setdefault(ref.split("/", 1)[0], set()).add(ref)
    lines = [
        "# 未随交付清单",
        "",
        "> 本表由 `scripts/check_handoff_refs.py` 扫描**本交付目录内全部 `.md`/`.txt`**生成：",
        "> 凡文档里出现、但本目录不存在的仓库路径，全部逐条列在下面。扫描前缀覆盖",
        f"{'、'.join('`' + p + '/`' for p in check_handoff_refs.PREFIXES)}。"
        "**只有扫描器无遗漏时，本表才成立**；`交付清单.txt` 与本文件不参与验算。",
        "",
    ]
    for prefix in check_handoff_refs.PREFIXES:
        refs_for = sorted(missing.get(prefix, set()))
        lines.append(f"## {prefix}/（{len(refs_for)} 条）")
        lines.append("")
        if not refs_for:
            lines.append("（无）")
        else:
            lines += [f"- `{ref}`" for ref in refs_for]
        lines.append("")
    return _gen("unshipped", "\n".join(lines))


def build_readme(version: str, release: dict, rel: dict, packages: list[dict],
                 old: dict, anchors: dict, diff_md: str, diff_detail: list[str],
                 handoff_name: str, prev_version: str) -> str:
    current_count, history_count, current_combined, history_combined = \
        _anchor_counts(anchors, version)
    rp_unchanged = not any("policies/RULE-PACK.md" in item for item in diff_detail)
    ts_files = sorted({item.split(":", 1)[0].split("/", 1)[1] for item in diff_detail
                       if item.startswith("confirmed/") and "真实时间戳" in item
                       and "内容变化" not in item})
    diff_conclusion = (
        ("`policies/RULE-PACK.md` 在全部 8 个包内逐字节未变（上表“逐字节未变的成员”列出）；"
         if rp_unchanged else "`policies/RULE-PACK.md` 本轮有变化（见上表）；")
        + "真实变化的是 "
        + ("、".join(f"`{n}`" for n in ts_files) if ts_files else "（无时间戳文件）")
        + " 的时间戳，以及包内 `CONFIDENCE.md` 的版本串；其余为版本号文本、派生哈希与文档更新。"
        "不得概括为“仅因版本号”。")
    rows = [[f"`{p['file'].split('/')[-1]}`", f"{p['bytes']:,}", f"`{p['sha256']}`",
             f"`{p['conclusion_digest'][:8]}…`", f"`{p['evidence_digest'][:8]}…`",
             f"`{p['inputs_digest'][:8]}…`", f"`{p['input_fingerprint'][:8]}…`"]
            for p in packages]
    counts = packages[1]["counts"]
    old_versions = sorted({p["version"] for p in old["packages"] if p.get("version")})
    old_versions_text = " / ".join(old_versions)
    wheels_ow = [w for w in old["wheels"] if "old-wheels" in w["dirs"]]
    wheels_op = [w for w in old["wheels"] if "old-packages" in w["dirs"]]
    locks_ow = [x for x in old["locks"] if "old-wheels" in x["dirs"]]
    locks_op = [x for x in old["locks"] if "old-packages" in x["dirs"]]
    wheels_ow_count = len(wheels_ow)
    wheels_op_count = len(wheels_op)
    locks_ow_count = len(locks_ow)
    locks_op_count = len(locks_op)
    wheels_op_text = "、".join(sorted(w["version"] for w in wheels_op)) or "（无）"
    locks_ow_text = "、".join(sorted(x["version"] for x in locks_ow)) or "（无）"
    locks_op_text = "、".join(sorted(x["version"] for x in locks_op)) or "（无）"
    header = _gen("handoff-header", "\n".join([
        "本目录实测事实（构建时生成，禁止人工编辑）：",
        "",
        f"- 版本 `{version}`；包 **{len(packages)} 个**；`release/SHA256SUMS` "
        f"**{rel['covered_count']} 行**；旧 wheel **{len(old['wheels'])} 个**；"
        f"旧包 **{len(old['packages'])} 个**；根目录锚点 **{anchors['anchor_total']} 个**"
        f"（单包 {len(anchors['singles'])}、组合 {len(anchors['combined'])}；"
        f"file 可解析 {anchors['by_status']['resolvable']}、"
        f"显式标注 {anchors['by_status']['marked']}、悬空 {anchors['by_status']['dangling']}）",
        f"- producer commit `{release['git_commit']}`；构建时间 `{release['build_time']}`",
        f"- 包签名钥 `{packages[0]['key_id'].split(':')[1][:12]}…`；"
        f"发行钥 `{release['release_signature']['key_id'].split(':')[1][:12]}…`",
    ]))
    return f"""# {version} 交付验收包（第{_round_label(handoff_name)}轮整改）

**交付边界（先读）**：本目录之外的 `scripts/`、`tests/`、`docs/交付与验收SOP.md` 等属
仓库内开发参考，**不随交付提供**；**验算与回放只依赖本目录内文件**。步骤见
[release/README-验收.md](release/README-验收.md) 第 2–4 节；锚点、公钥与样例包均在本目录。
`src/` 源码随 wheel 提供（可用于 diff 复核），仓库内测试/脚本不随交付。
文档里出现的仓库路径，要么在本目录内真实存在，要么逐条列在
[未随交付清单.md](未随交付清单.md)（该表由扫描器生成，覆盖 `docs/ scripts/ tests/ src/`
`data/ var/ reports/ rules/ tools/ dist/ handoff/` 全部前缀）。

{header}

**PoC 边界（先读）**：本交付是**验证工具 + {len(packages)} 个样例包**的 PoC，
**不构成合规结论**，**不可作为生产就绪依据**。四项未闭合：**信任根**、**真实具名确认**、
**法律文本充分性**、**数据合规**。逐项现状见
[docs/安全与证据链现状.md](docs/安全与证据链现状.md) 第 3 节。

## 0. 对外演示注意（销售/演示者必读）

演示“删输入被拦截”**必须用带外部锚点的 v3 包**：本目录 `package/` 下
{len(packages)} 个包，配 `anchor-{version}-<role>.json` 与 `trusted-public-key.pub`。
**不要**用自己现场 `wca all` 生成的默认包来演示，除非显式提供了签名钥。

原因：默认 `wca all` 在不提供签名钥时导出的是 **v2 无签名包**，它没有输入契约（无
`inputs_digest`）。对这类包删掉一个输入，**只有“输入摘要”这一项门禁不适用**（记
`NOT CHECKED`，不参与判定），所以结果可能仍是 `ARTIFACTS OK`、`RESULT PARTIAL`（exit 2）；
**包内其他字节一旦被改（清单、工件、发现等），仍会 `RESULT FAIL`（exit 1）**。
边界：`--require-signature` 下无签名即 `SIGNATURE FAIL`（exit 1），与是否缺
`inputs_digest` 无关。用它演示会给人“删了也没事”的错觉；演示请用 v3 包。

## 一、结论先行

{version} 是**当前对外 PoC 冻结版**，本轮**不逐句修补文档，改建机制**：

- **机制 1**：README/清单中的文件数、字节、逐文件 SHA-256、包表、SHA256SUMS 覆盖清单、
  旧物与旧锚点，全部由 `scripts/docfacts.py` 从产物计算后填入（生成区有标记）；
- **机制 2**：文档里每条 `wca-verify`/`wca replay` 示例命令由
  `tests/test_doc_commands.py` 真跑，退出码与 `RESULT` 标签必须与文档一致；
- **机制 3**：`artifacts_digest` 变化原因由 `scripts/diff_packages.py` 逐包逐文件比对生成
  （本文件 §四），不再写“仅因版本号”。

第三/四轮盲验的功能门槛全过：默认流程 `RESULT PARTIAL` exit 2（非 FAIL）、可自行走到
`OK` exit 0、同版本七类篡改全部 `FAIL` exit 1、旧包可验。第六轮盲验的 2 条阻断都在锚点上，
本轮处置见 `reports/0.4.17-锚点纠正与扫描器扩展.md`；上一轮的 16 条见
`reports/0.4.16-护栏加固与残留页.md`。

八包重导后 `conclusion_digest`、`evidence_digest`、`inputs_digest`、`input_fingerprint`
与 0.4.15/0.4.16 **逐包相同**；只有 `artifacts_digest` 因包内文档变化（原因见 §四）。
四主包不变量：conclusion `{packages[1]['conclusion_digest'][:8]}…`、
evidence `{packages[1]['evidence_digest'][:8]}…`、
inputs `{packages[1]['inputs_digest'][:8]}…`、
fingerprint `{packages[1]['input_fingerprint'][:8]}…`（实测）。

## 二、三步先跑通

```powershell
# 1) 建干净环境（仅本目录 wheel + 锁定依赖）
py -3.12 -m venv .venv-clean
.venv-clean\\Scripts\\python -m pip install --require-hashes -r release\\requirements.lock.txt
.venv-clean\\Scripts\\python -m pip install --no-deps release\\{release['wheel']}

# 2) 验任一包（锚点、包 SHA、工件摘要、证据摘要一次给全）
.venv-clean\\Scripts\\wca-verify.exe package\\engine-only.zip `
  --anchor-file anchor-{version}-engine-only.json `
  --public-key trusted-public-key.pub
# 期望：RESULT OK，exit 0

# 3) 回放同一个包
.venv-clean\\Scripts\\wca.exe replay package\\engine-only.zip `
  --anchor-file anchor-{version}-engine-only.json `
  --public-key trusted-public-key.pub
# 期望：RESULT OK，exit 0
```

八个包逐一替换 `engine-only` 为对应角色名即可；实物 SHA 见 §四。

## 三、退出码与默认流程（统一口径）

| 退出码 | 标签 | 含义 | 脚本处置 |
| --- | --- | --- | --- |
| 0 | `RESULT OK` | 内容检查 + 签名 pin + 外部锚点/包 SHA/工件摘要/证据摘要全通过 | 当通过 |
| 1 | `RESULT FAIL` | **有证据的不一致/篡改**；以及 **schema v3 缺 `inputs_digest`** | 当失败，阻断 |
| 2 | `RESULT PARTIAL` | 不完整：缺外部项、未 pin，或**无签名 v2 包** | 不得当通过 |
| 3 | `RESULT INCOMPARABLE` | 跨 `rule_pack_version` / 跨 evidence schema | 既不当通过，也不当篡改 |

默认 `wca all` 的产物：不给签名钥 → v2 无签名 → `RESULT PARTIAL` exit 2；
给签名钥但不给外部项 → `PARTIAL` exit 2；补齐五项外部门禁 → `RESULT OK` exit 0。
**v2 包不会因缺少 `inputs_digest` 这一项门禁而被判 `FAIL`**：该门禁对 v2 记
`NOT CHECKED`（版本缺失，不是篡改）；**其他任何真实篡改仍判 `FAIL`（exit 1）**。
边界：`--require-signature` 下无签名即 `SIGNATURE FAIL`（exit 1）。

## 四、八个包与逐包逐文件差异

### 包表（字节与 SHA-256 由实物生成）

{docfacts.table(["包", "字节", "SHA-256", "conclusion", "evidence", "inputs", "fingerprint"], rows)}

### artifacts_digest 变化原因

{diff_md}

> 结论（由上表生成，不是手写）：{diff_conclusion}

## 五、计数口径

`manifest.counts` 本包实测：`findings_total={counts['findings_total']}`、
`findings_batched={counts['findings_batched']}`、`issues_total={counts['issues_total']}`、
`quality_issues={counts['quality_issues']}`。关系：
`issues_total = findings_total - findings_batched + Σ batch_size`。

## 六、干净环境验证与默认流程实测

仓库外干净 venv（仅安装 {version} wheel + 锁定依赖）对八个包逐个执行 `wca-verify` 与
`wca replay`，逐条原始输出（含 `RESULT` 行与 exit code）记录在
`reports/round19-techcheck.txt`（**计数只写该日志一处**）。
默认流程三档（无钥 v2 / 有钥 v3 缺外部项 / 补齐五项）同样记录在该日志。

## 七、测试

- 离线全量：`uv run pytest -q -m "not llm"`；
- PostgreSQL 18 全量：同一条命令 + `WCA_TEST_POSTGRES_URL` 环境变量。
- **计数只在 `reports/round19-techcheck.txt` 写一次**，本文件不复制数字，避免两个口径。
- 同版本七类篡改回归仍全部 `FAIL` exit 1；schema v3 缺 `inputs_digest` 仍 `FAIL`，
  schema v2 缺字段才 `NOT CHECKED`。

## 八、密钥（两把，禁止混用）

| 用途 | key_id | 私钥位置（不随交付） |
| --- | --- | --- |
| 发行物 `SHA256SUMS.sig` | `{release['release_signature']['key_id']}` | `var/release-keys/ed25519.key` |
| 举证包 `manifest.signature` | `{packages[0]['key_id']}` | `var/handoff-keys/ed25519.key` |

## 九、旧包、旧 wheel 与旧锚点（本目录内可复现）

- **旧包实物**：`release/old-packages/` 实有 **{len(old['packages'])} 个** zip
  （{old_versions_text} 八个角色），逐文件哈希见 `交付清单.txt`。
- **旧 wheel**：`release/old-wheels/` 实有 **{wheels_ow_count} 个**；`release/old-packages/`
  另有 **{wheels_op_count} 个**同名副本（{wheels_op_text}）。按文件名唯一计
  **{len(old['wheels'])} 个**，清单见 `OLD-WHEELS.md`（逐行标出真实所在目录）。
- **依赖锁**：合计 **{len(old['locks'])} 个**唯一锁——`release/old-wheels/`
  **{locks_ow_count} 个**（{locks_ow_text}），`release/old-packages/`
  **{locks_op_count} 个**（{locks_op_text}）。`old-wheels/` 里没有 0.4.10/0.4.11
  的锁，它们在 `old-packages/`；按表找文件即可，不依赖记忆。
- **旧锚点**：根目录实有锚点 **{anchors['anchor_total']} 个**（单包
  **{len(anchors['singles'])} 个**、组合记录 **{len(anchors['combined'])} 个**）。
  按锚点计，每个 `file` 字段都以该 JSON 自身位置为基准核对：**可解析
  {anchors['by_status']['resolvable']} 个**、显式标注“仅记录、不可解析”
  {anchors['by_status']['marked']} 个、**悬空 {anchors['by_status']['dangling']} 个**。
  0.4.12 的 8 个包未随本目录交付，对应锚点已显式标注；获取方式见 `OLD-ANCHORS.md`
  的“历史记录”表（已实测源包 sha 与锚点一致）。逐文件哈希与来源见该文件（由扫描器生成）。
- **{version} 新包**：用本目录 `release/` 的 {version} wheel 与
  `anchor-{version}-<role>.json`。
- **0.4.6 签名钥疑点**：该版发行钥 `ed25519:b07741b2…` 是包签名钥的误用；本目录不带该版
  `SHA256SUMS`/`.sig`，因此**目录内不可验证**该版发行签名，原因已写明。

## 十、目录结构

```text
交接目录：{handoff_name}/
  README-验收.md / READ-ME-FIRST.txt / KEY-NOTE.txt / 交付清单.txt
  未随交付清单.md            # 扫描器生成的仓库路径全表（验算不需要）
  已知残留与未闭合项.md      # 不可自证的历史声明 + 四项流程/法律未闭合
  RULE-PACK.md / OLD-WHEELS.md / OLD-ANCHORS.md
  anchor.json / anchor.txt   # 汇总记录，无签名保护
  anchor-{version}-<role>.json   # {len(packages)} 个新包单包锚点（file 指向 package/）
  anchor-0.4.10 … 0.4.16-<role>.json   # 历史单包锚点（实有 {history_count} 个）
  anchor-0.4.10 … 0.4.16.json          # 历史组合锚点（实有 {history_combined} 个）
  trusted-public-key.pub / release-public-key.pub
  package/                   # {len(packages)} 个 {version} 包
  release/                   # {version} 发行物 + old-wheels/ + old-packages/
  docs/                      # 签名方案 / 安全与证据链现状 / 冻结版本说明 / 护栏豁免表
  reports/                   # 历史报告 + round19-techcheck.txt + round17-diff.md
```

## 十一、运行环境与默认输出路径

**默认数据库后端是 PostgreSQL 18**；必须提供 `WCA_DATABASE_URL`，否则启动期直接报错退出，
**不会静默退回 SQLite**。无 PG 的离线机器需显式切到 SQLite（`WCA_DB_BACKEND=sqlite`）。
**默认输出路径落在 wheel 安装目录（venv 的 `site-packages`）**，可用 `WCA_REPORTS_DIR` /
`WCA_PACKAGES_DIR` 覆盖为绝对路径；`wca report` / `wca export` 没有 `--out` 参数。

## 十二、可独立复现边界

| README 结论 | 可否独立复现 | 说明 |
| --- | --- | --- |
| 八包 {version} 各 `verify`/`replay` 均 `RESULT OK` | 可 | 包、锚点、公钥、wheel 全在本目录 |
| {prev_version}→{version} 四联摘要逐包相同（`artifacts_digest` 除外） | 可 | 用 `release/old-packages/` 的 {prev_version} 包与 {prev_version} wheel 对照 |
| 旧包配旧 wheel 可验可回放 | 可 | §九 旧物表给出每个文件的真实目录；本轮未重跑 {len(old['packages'])} 包矩阵，原始记录见 `已知残留与未闭合项.md` |
| 退出码 0/1/2/3 分档 | 可 | 按 §三参数变体照做 |
| 无签名 v2 包 → `RESULT PARTIAL` exit 2 | 可 | 用 {version} wheel 导出无钥包后验算 |
| 跨后端（SQLite vs PostgreSQL 18）五摘要相同 | 需自备 PG 18 | 交付不含数据库 |
| 离线/PG 测试计数 | **不可** | 测试不随交付；计数只在 `reports/round19-techcheck.txt` |
| `reports/` 中对 `dist/` 的引用 | 出处引用 | 历史发行目录不随交付，不影响验算 |

## 十三、`SHA256SUMS` 只保护 {rel['covered_count']} 个文件

`release/SHA256SUMS` 实有 {rel['covered_count']} 行，`SHA256SUMS.sig` 只保护这
{rel['covered_count']} 个顶层文件：{('、'.join('`' + row['name'] + '`' for row in rel['covered']))}。
**不在保护范围**：`release/old-wheels/`、`release/old-packages/`、
`release/旧发行物-SHA256清单.md`、`release/SHA256SUMS-覆盖范围.md` 本身，以及交接根目录的
`package/*.zip`、`anchor*.json`、`docs/`、`reports/`。逐条见
`release/SHA256SUMS-覆盖范围.md`（同样由实物生成）。

## 十四、文档事实单一来源

机制 1–3、0.4.16 护栏加固与 0.4.17 锚点纠正见
`reports/0.4.17-锚点纠正与扫描器扩展.md`；上一轮 14 条关闭表见
`reports/0.4.15-文档事实单一来源.md`。
`reports/` 为历史归档（部分源文件不随交付）；本交付内可复核的部分：§四差异表由
`reports/round17-diff.md` 原样给出，计数只在 `reports/round19-techcheck.txt` 出现一次。
"""


def build_first(version: str, packages: list[dict], old: dict, anchors: dict,
                diff_detail: list[str], handoff_name: str) -> str:
    current_count, history_count, current_combined, history_combined = \
        _anchor_counts(anchors, version)
    # 第 4 条完全由差异表的实测结果拼出：未变/时间戳变化都不是手写的。
    rp_unchanged = not any("policies/RULE-PACK.md" in item for item in diff_detail)
    ts_files = sorted({item.split(":", 1)[0].split("/", 1)[1] for item in diff_detail
                       if item.startswith("confirmed/") and "真实时间戳" in item
                       and "内容变化" not in item})
    if rp_unchanged:
        rp_text = (f"`policies/RULE-PACK.md` 在 {len(packages)} 个包内逐字节未变"
                   "（差异表不出现该成员）")
    else:
        rp_text = "`policies/RULE-PACK.md` 本轮发生变化，见差异表"
    ts_text = ("、".join(f"`{name}`" for name in ts_files) if ts_files else "（无）")
    return _gen("read-me-first", "\n".join([
        f"{version} 交付验收包（第{_round_label(handoff_name)}轮整改）——先读这一页",
        "",
        "1) 先读 README-验收.md §0（演示必须用 v3 包）与 §二（三步先跑通）；",
        f"2) 包在 package/（{len(packages)} 个），单包锚点 anchor-{version}-<role>.json，",
        "   公钥 trusted-public-key.pub；验算与回放只依赖本目录；",
        f"3) 旧物：old-wheels {len(old['wheels'])}、old-packages {len(old['packages'])}、",
        f"   锚点 {anchors['anchor_total']} 个（本轮 {current_count + current_combined} + 历史 "
        f"{history_count + history_combined}）；file 可解析 {anchors['by_status']['resolvable']}、"
        f"显式标注 {anchors['by_status']['marked']}、悬空 {anchors['by_status']['dangling']}；",
        "4) artifacts_digest 的变化原因见 README §四（逐包逐文件），不要概括为“仅因版本号”：",
        f"   {rp_text}；confirmed 包 {ts_text} 的时间戳真实变化；",
        "   其余变化为版本号文本、派生哈希与包内文档更新。",
    ]))


def write_manifest(out: Path, version: str, release: dict, invariants: dict,
                   packages: list[dict]) -> None:
    files = sorted((p for p in out.rglob("*")
                    if p.is_file() and p.name != "交付清单.txt"),
                   key=lambda p: p.relative_to(out).as_posix())
    reports = sorted({p.relative_to(out).as_posix() for p in out.rglob("reports/*")})
    lines = [
        f"{version} 第{_round_label(out.name)}轮交付清单",
        f"producer_commit={release['git_commit']}",
        f"release_key_id={release['release_signature']['key_id']}",
        f"package_key_id={packages[0]['key_id']}",
        "",
        "包级不变量（四联摘要，八包同值）：",
    ]
    lines += [f"  {key}={value}" for key, value in invariants.items()]
    lines += ["", f"八个包（{len(packages)} 个）："]
    for pkg in packages:
        lines.append(f"  {pkg['file'].split('/')[-1]}  sha256={pkg['sha256']}  "
                     f"bytes={pkg['bytes']}")
        lines.append(f"    anchor={pkg['anchor']}")
        lines.append(f"    artifacts_digest={pkg['artifacts_digest']}")
    lines += [
        "",
        "发行物：",
        f"  wheel={release['wheel']}",
        f"  build_time={release['build_time']}",
        "",
        f"报告（{len(reports)} 个）：" + ", ".join(reports),
        "锚点：anchor.json, anchor.txt, "
        f"anchor-{version}-<role>.json（{len(packages)} 个）, OLD-ANCHORS.md",
        "旧发行物：release/旧发行物-SHA256清单.md, OLD-WHEELS.md, "
        "release/old-wheels/, release/old-packages/",
        "",
        "交付目录文件哈希（不含本清单自身）：",
    ]
    for path in files:
        lines.append(f"  {path.relative_to(out).as_posix()}  "
                     f"bytes={path.stat().st_size}  sha256={docfacts.sha256_file(path)}")
    _write(out / "交付清单.txt", "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--prev", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    return build(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
