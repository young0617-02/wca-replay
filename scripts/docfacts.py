"""文档事实单一来源（机制 1）：所有事实只从产物计算，不从记忆抄写。

约定：

- 本模块**只接受实物路径**（发行目录、包 zip、交接目录），不读任何硬编码清单；
- 文档中的事实区必须用 `<!-- GENERATED:START <key> -->` / `<!-- GENERATED:END <key> -->`
  标记包围，生成后禁止人工编辑（护栏测试会逐条与实物比对）；
- 自引用（README 自身字节/哈希）不可内嵌，一律指向 `SHA256SUMS` 对应行，不伪造。

用法（仅生成器内部使用，不产生面向用户的输出）：

    from docfacts import release_facts, package_facts, old_assets
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

MARK_START = "<!-- GENERATED:START {key} -->"
MARK_END = "<!-- GENERATED:END {key} -->"
_SHA_RE = re.compile(r"[0-9a-f]{64}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def file_fact(path: Path, *, name: str | None = None) -> dict:
    path = Path(path)
    return {
        "name": name or path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def parse_sha256sums(path: Path) -> list[dict]:
    """解析 `SHA256SUMS`：每行 `<sha>  <name>`；行数即覆盖文件数。"""
    rows: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        rows.append({"sha256": digest.strip(), "name": name.strip()})
    return rows


def release_facts(release_dir: Path) -> dict:
    """发行目录事实：顶层文件、字节、SHA-256、SHA256SUMS 覆盖清单。

    `README-验收.md` 的字节与哈希是自引用（哈希覆盖自身内容），**不可内嵌**，
    统一由 `self_reference` 指向 `SHA256SUMS` 对应行。
    """
    release_dir = Path(release_dir)
    release = json.loads((release_dir / "RELEASE.json").read_text(encoding="utf-8"))
    sums_path = release_dir / "SHA256SUMS"
    top_files = [p for p in sorted(release_dir.iterdir(), key=lambda p: p.name)
                 if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig")]
    facts = [file_fact(p) for p in top_files]
    self_name = "README-验收.md"
    others = [f for f in facts if f["name"] != self_name]
    if sums_path.is_file():
        covered = parse_sha256sums(sums_path)
        sums_bytes: int | None = sums_path.stat().st_size
        sums_sha: str | None = sha256_file(sums_path)
    else:
        # README 必须先于 SHA256SUMS 写出（否则自引用成环）；此时覆盖清单由实际
        # 顶层文件推导，与随后写出的 SHA256SUMS 行一一对应。
        covered = [{"sha256": f["sha256"], "name": f["name"]} for f in facts]
        sums_bytes = None
        sums_sha = None
    return {
        "version": release["version"],
        "build_time": release["build_time"],
        "git_commit": release["git_commit"],
        "wheel": release["wheel"],
        "python_requires": release["python_requires"],
        "supported_rule_pack_versions": release["supported_rule_pack_versions"],
        "evidence_schema_versions": release["evidence_schema_versions"],
        "files": facts,
        "file_count": len(facts),
        "others_bytes_total": sum(f["bytes"] for f in others),
        "self_reference": self_name,
        "covered": covered,
        "covered_count": len(covered),
        "sha256sums_bytes": sums_bytes,
        "sha256sums_sha256": sums_sha,
        "sig_present": (release_dir / "SHA256SUMS.sig").is_file(),
        "release_signature": release.get("release_signature"),
    }


def package_facts(zip_path: Path) -> dict:
    """举证包事实：逐包字节/哈希/四联摘要/工件摘要/规则包/schema/计数/签名钥。"""
    zip_path = Path(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        responsibility = json.loads(zf.read("responsibility.json").decode("utf-8"))
        conclusions = zf.read("conclusions_final.csv").decode("utf-8-sig")
    triple = manifest["triple"]
    schema = str(manifest["schema"]).rsplit("-v", 1)[1]
    return {
        "file": zip_path.name,
        "role": zip_path.stem,
        "bytes": zip_path.stat().st_size,
        "sha256": sha256_file(zip_path),
        "schema_version": schema,
        "schema": str(manifest["schema"]),
        "rule_pack_version": triple["rule_pack_version"],
        "anchor": ",".join([schema, triple["rule_pack_version"],
                            triple["input_fingerprint"], triple["conclusion_digest"]]),
        "conclusion_digest": triple["conclusion_digest"],
        "evidence_digest": manifest.get("evidence_digest", ""),
        "inputs_digest": manifest.get("inputs_digest", ""),
        "input_fingerprint": triple["input_fingerprint"],
        "artifacts_digest": manifest["artifacts_digest"],
        "key_id": manifest["signature"]["key_id"],
        "producer_version": manifest["producer"]["version"],
        "producer_commit": manifest["producer"]["commit"],
        "counts": manifest["counts"],
        "human_confirmed_findings": responsibility["human_confirmed_findings"],
        "conclusions_rows": max(0, len(conclusions.splitlines()) - 1),
    }


def old_assets(release_dir: Path) -> dict:
    """旧物事实：old-wheels/、old-packages/ 实有文件（版本从文件名解析）。"""
    release_dir = Path(release_dir)
    out: dict[str, list[dict]] = {"wheels": [], "packages": [], "locks": []}
    wheel_dir = release_dir / "old-wheels"
    if wheel_dir.is_dir():
        for path in sorted(wheel_dir.iterdir()):
            if path.suffix == ".whl":
                out["wheels"].append({**file_fact(path, name=path.name),
                                      "version": _version_from_name(path.name),
                                      "dir": "old-wheels"})
            elif path.suffix == ".txt":
                out["locks"].append({**file_fact(path, name=path.name),
                                     "version": _version_from_name(path.name),
                                     "dir": "old-wheels"})
    pkg_dir = release_dir / "old-packages"
    if pkg_dir.is_dir():
        for path in sorted(pkg_dir.iterdir()):
            if path.suffix == ".zip":
                out["packages"].append({**file_fact(path, name=path.name),
                                        "version": _version_from_name(path.name),
                                        "role": path.stem.rsplit("-", 1)[0]})
            elif path.suffix == ".whl":
                out["wheels"].append({**file_fact(path, name=path.name),
                                      "version": _version_from_name(path.name),
                                      "dir": "old-packages"})
            elif path.suffix == ".txt":
                out["locks"].append({**file_fact(path, name=path.name),
                                     "version": _version_from_name(path.name),
                                     "dir": "old-packages"})
    # 同一个 wheel/锁可能在 old-wheels 与 old-packages 各有一份；按文件名唯一化，
    # 并标出它真实所在的全部目录，避免“同一文件列两次、客户按表找不到”的误导。
    for key in ("wheels", "locks"):
        merged: dict[str, dict] = {}
        for item in out[key]:
            name = item["name"]
            if name in merged:
                merged[name]["dirs"].append(item["dir"])
            else:
                merged[name] = {**item, "dirs": [item["dir"]]}
        out[key] = sorted(merged.values(), key=lambda x: x["name"])
    return out


def _version_from_name(name: str) -> str:
    match = re.search(r"(0\.4\.\d+)", name)
    return match.group(1) if match else ""


def old_anchor_facts(handoff_dir: Path) -> dict:
    """旧锚点事实：根目录 `anchor-<版本>-<role>.json` 与 `anchor-<版本>.json`。"""
    handoff_dir = Path(handoff_dir)
    singles: list[dict] = []
    combined: list[dict] = []
    for path in sorted(handoff_dir.glob("anchor-0.4.*.json")):
        version = _version_from_name(path.name)
        if re.match(rf"anchor-{re.escape(version)}-[A-Za-z0-9-]+\.json", path.name):
            singles.append({**file_fact(path, name=path.name), "version": version})
        else:
            combined.append({**file_fact(path, name=path.name), "version": version})
    # `anchor.json` 同样是一份“汇总值记录”（本轮的组合锚点），文件名不带版本号，
    # 上一版扫描器把它漏在计数外，导致“组合记录 N 个”与实际文件数差一。
    root_anchor = handoff_dir / "anchor.json"
    if root_anchor.is_file():
        try:
            version = json.loads(root_anchor.read_text(encoding="utf-8"))["version"]
        except (KeyError, ValueError):
            version = ""
        combined.append({**file_fact(root_anchor, name=root_anchor.name),
                         "version": str(version)})
    return {"singles": singles, "combined": combined}


def test_counts(techcheck_path: Path) -> dict:
    """从技术核对日志读测试计数（文档不得与日志写两个口径）。"""
    text = Path(techcheck_path).read_text(encoding="utf-8")
    offline = re.search(r"离线全量.*?→\s*(\d+) passed, (\d+) skipped, (\d+) deselected",
                        text, re.S)
    pg = re.search(r"PostgreSQL 18 全量.*?→\s*(\d+) passed, (\d+) skipped, (\d+) deselected",
                   text, re.S)
    if not offline or not pg:
        raise ValueError(f"技术核对日志缺少测试计数：{techcheck_path}")
    return {
        "offline": f"{offline.group(1)} passed / {offline.group(2)} skipped / "
                   f"{offline.group(3)} deselected",
        "pg": f"{pg.group(1)} passed / {pg.group(2)} skipped / {pg.group(3)} deselected",
    }


def known_digests(root: Path) -> set[str]:
    """交接目录内所有可核对的 64 位哈希：文件字节哈希 + 包内摘要字段 + 锚点字段。"""
    root = Path(root)
    found: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in (".zip", ".whl"):
            found.add(sha256_file(path))
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path) as zf:
                    for name in ("manifest.json",):
                        try:
                            manifest = json.loads(zf.read(name).decode("utf-8"))
                        except KeyError:
                            continue
                        _collect_digests(manifest, found)
            continue
        try:
            found.update(_SHA_RE.findall(path.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            found.add(sha256_file(path))
    return found


def _collect_digests(value, found: set[str]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _collect_digests(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_digests(item, found)
    elif isinstance(value, str) and _SHA_RE.fullmatch(value):
        found.add(value)


ANCHOR_MARKER = "仅记录、不可解析"
ANCHOR_NAME_RE = re.compile(r"anchor-(0\.4\.\d+)(?:-([A-Za-z0-9._-]+))?\.json$")


def anchor_name_version(name: str) -> str:
    """从锚点文件名取版本号；`anchor.json` 无名版本，返回空串。"""
    match = ANCHOR_NAME_RE.match(name)
    return match.group(1) if match else ""


def anchor_kind(doc: dict) -> str:
    if isinstance(doc.get("packages"), list):
        return "combined"
    return "single" if doc.get("role") else "unknown"


def anchor_file_status(doc_path: Path, value) -> str:
    """判定锚点 `file` 字段：resolvable / marked / dangling。

    - 显式写有 `仅记录、不可解析` 的，算 marked；
    - 其余必须是**以该 JSON 自身位置为基准**可解析的相对路径，否则算 dangling；
    - 绝对路径、URL、含 `..` 的路径一律不算可解析（本交付只允许目录内相对路径）。
    """
    if not isinstance(value, str) or not value.strip():
        return "dangling"
    if ANCHOR_MARKER in value:
        return "marked"
    if value.startswith(("http://", "https://", "/", "\\")) or ".." in value:
        return "dangling"
    return "resolvable" if (Path(doc_path).parent / value).is_file() else "dangling"


def anchor_file_entries(doc: dict) -> list[dict]:
    """单包锚点返回一条，组合锚点返回 `packages[]` 每包一条。"""
    if anchor_kind(doc) == "combined":
        return list(doc["packages"])
    return [doc]


def anchor_records(handoff_dir: Path) -> dict:
    """扫描交接目录全部 `anchor*.json`，给出 file 指针可解析性与错版名单。

    计数口径：按锚点文件计（一个组合锚点算 1 个）；同时给出指针级计数，
    便于报告同时说明“N 个锚点”和“N 个 file 指针”。
    """
    handoff_dir = Path(handoff_dir)
    singles: list[dict] = []
    combined: list[dict] = []
    misnamed: list[dict] = []
    for path in sorted(handoff_dir.glob("anchor*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        version = str(doc.get("version") or "")
        kind = anchor_kind(doc)
        name_version = anchor_name_version(path.name)
        if name_version and name_version != version:
            misnamed.append({"name": path.name, "name_version": name_version,
                             "content_version": version})
        entries = anchor_file_entries(doc)
        statuses = [anchor_file_status(path, entry.get("file")) for entry in entries]
        if "dangling" in statuses:
            status = "dangling"
        elif "marked" in statuses:
            status = "marked"
        else:
            status = "resolvable"
        record = {
            "name": path.name,
            "version": version,
            "kind": kind,
            "status": status,
            "pointer_statuses": statuses,
            "roles": [str(entry.get("role") or "") for entry in entries],
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        (combined if kind == "combined" else singles).append(record)

    anchor_total = len(singles) + len(combined)
    by_status = {key: sum(1 for r in singles + combined if r["status"] == key)
                 for key in ("resolvable", "marked", "dangling")}
    pointer_total = sum(len(r["pointer_statuses"]) for r in singles + combined)
    pointer_by_status = {
        key: sum(sum(1 for s in r["pointer_statuses"] if s == key)
                 for r in singles + combined)
        for key in ("resolvable", "marked", "dangling")
    }
    return {
        "singles": singles,
        "combined": combined,
        "anchor_total": anchor_total,
        "by_status": by_status,
        "pointer_total": pointer_total,
        "pointer_by_status": pointer_by_status,
        "misnamed": misnamed,
    }


def generated_block(key: str, body: str) -> str:
    return f"{MARK_START.format(key=key)}\n{body.rstrip()}\n{MARK_END.format(key=key)}"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)
