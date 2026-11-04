"""独立验算器：只读包内文件，不执行包内 `verify.py`。

职责边界：
  * 校验 manifest 自校验和、producer、链、输入摘要、签名；
  * 校验工件逐文件哈希（`artifact_sha256`）与工件清单摘要（`artifacts_digest`）；
  * 校验包内 `verify.py` 的哈希（`verify_script_sha256`），但**不执行它**；
  * 从 `findings.csv` 按公开规范化算法反算 `conclusion_digest`；
  * 校验锚点、包文件 SHA-256 与可选的文件清单摘要。

它是 `wca-verify` 的实现；`replay` 复用其中的工件/发现绑定检查。
"""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from pathlib import Path

from . import producer, signing
from .evidence_digest import evidence_digest as compute_evidence_digest
from .package_inputs import input_arcnames
from .util import (anchor_schema_version, canonical_json, csv_unescape_cell, digest_of,
                   evidence_schema_version, manifest_checksum, sha256_hex)

INPUTS_DIRNAME = "inputs"
MANIFEST_FILE = "manifest.json"
VERIFY_SCRIPT = "verify.py"
VERIFY_REQUIREMENTS = "verify-requirements.txt"
README_FILE = "README.txt"
# 0.4.3 起新包必须有 evidence_digest；更早的包按旧包兼容路径记 NOT CHECKED。
EVIDENCE_DIGEST_MIN_PRODUCER = (0, 4, 3)
REQUIRED_ARTIFACTS = (
    "findings.csv", "input_files.csv", "quality_issues.csv",
    "conclusions_final.csv", "responsibility.json", "not_covered.json", "未覆盖清单.md",
    README_FILE, VERIFY_REQUIREMENTS,
    "policies/RULE-PACK.md", "policies/LAW-REFERENCES.md",
    "policies/口径声明-对外版.md", "policies/字段口径与条文依据-对外版.md",
    "policies/CONFIDENCE.md",
)
# 审计链由独立的链重算与签名链头保护；不放进 artifact_sha256，
# 否则“改一条链事件”会先报工件哈希，掩盖具体断在第几条。
CHAIN_FILE = "audit_chain.jsonl"
TRIPLE_KEYS = ("rule_pack_version", "input_fingerprint", "conclusion_digest")
FINDINGS_COLUMNS = ("rule_id", "rule_version", "emp_id", "work_date", "period_key",
                    "severity", "citations", "metric_json", "explanation")


def _sha256_file(path: Path) -> str:
    h = signing._file_sha256(path)
    return h


def _load_manifest(root: Path) -> dict:
    path = root / MANIFEST_FILE
    if not path.is_file():
        raise ValueError("MANIFEST FAIL 包内缺少 manifest.json")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"MANIFEST FAIL 无法解析 manifest.json：{type(exc).__name__}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("MANIFEST FAIL manifest 不是对象")
    return doc


def _normalize_artifact_path(name: object) -> str:
    text = str(name).replace("\\", "/")
    parts = [p for p in text.split("/") if p]
    if (not parts or text.startswith("/") or ".." in parts
            or (len(parts[0]) >= 2 and parts[0][1] == ":")):
        raise ValueError(f"ARTIFACT FAIL 包内路径非法（必须是包内相对路径）：{name!r}")
    return "/".join(parts)


def check_artifacts(root: Path, manifest: dict, schema_ver: int) -> dict:
    """逐文件哈希 + verify.py 哈希 + 未声明文件检查；v1 旧包跳过。

    每个子检查独立记录 OK/FAIL/NOT CHECKED；早退时未走的检查不能写成 FAIL。
    """
    result = {"ok": True, "reason": "", "checked": 0, "extras": [],
              "files_status": "NOT CHECKED", "verify_script_status": "NOT CHECKED",
              "digest_status": "NOT CHECKED", "extras_status": "NOT CHECKED",
              "artifact_sha256": {}, "artifacts_digest": "", "verify_script_sha256": ""}
    if schema_ver < 2:
        result["reason"] = "LEGACY v1 包未做工件绑定"
        return result
    declared = manifest.get("artifact_sha256")
    declared_digest = manifest.get("artifacts_digest")
    script_digest = manifest.get("verify_script_sha256")
    if not isinstance(declared, dict) or not declared:
        result.update(ok=False, files_status="FAIL",
                      reason="ARTIFACT BINDING FAIL 缺少 manifest.artifact_sha256")
        return result
    if not isinstance(declared_digest, str) or not declared_digest:
        result.update(ok=False, digest_status="FAIL",
                      reason="ARTIFACT BINDING FAIL 缺少 manifest.artifacts_digest")
        return result
    if not isinstance(script_digest, str) or not script_digest:
        result.update(ok=False, verify_script_status="FAIL",
                      reason="VERIFY SCRIPT FAIL 缺少 manifest.verify_script_sha256")
        return result
    try:
        normalized = {_normalize_artifact_path(k): str(v).lower()
                      for k, v in declared.items()}
    except ValueError as exc:
        result.update(ok=False, files_status="FAIL", reason=str(exc))
        return result
    result["artifact_sha256"] = normalized
    result["artifacts_digest"] = declared_digest
    result["verify_script_sha256"] = script_digest
    missing = [name for name in REQUIRED_ARTIFACTS if name not in normalized]
    if missing:
        result.update(ok=False, files_status="FAIL",
                      reason="ARTIFACT BINDING FAIL 缺少必需工件：" + ",".join(missing))
        return result
    for name, expected in normalized.items():
        path = root / name
        if not path.is_file():
            result.update(ok=False, files_status="FAIL",
                          reason=f"ARTIFACT FAIL 工件缺失：{name}")
            return result
        actual = _sha256_file(path)
        result["checked"] += 1
        if actual != expected:
            result.update(ok=False, files_status="FAIL",
                          reason=f"ARTIFACT FAIL 工件哈希不一致：{name}")
            return result
    result["files_status"] = "OK"
    try:
        actual_digest = signing.artifact_digest(normalized)
    except ValueError as exc:
        result.update(ok=False, digest_status="FAIL",
                      reason=f"ARTIFACT BINDING FAIL {exc}")
        return result
    if actual_digest != declared_digest:
        result.update(ok=False, digest_status="FAIL",
                      reason="ARTIFACT BINDING FAIL artifacts_digest 不一致")
        return result
    result["digest_status"] = "OK"
    script_path = root / VERIFY_SCRIPT
    if not script_path.is_file():
        result.update(ok=False, verify_script_status="FAIL",
                      reason="VERIFY SCRIPT FAIL 包内缺少 verify.py")
        return result
    actual_script = _sha256_file(script_path)
    if actual_script != script_digest:
        result.update(ok=False, verify_script_status="FAIL",
                      reason="VERIFY SCRIPT FAIL verify.py 哈希与 manifest 不一致")
        return result
    result["verify_script_status"] = "OK"
    allowed_paths = set(normalized) | {MANIFEST_FILE, VERIFY_SCRIPT, CHAIN_FILE}
    allowed_inputs = {f"{INPUTS_DIRNAME}/manifest.json"}
    inputs_manifest = root / INPUTS_DIRNAME / "manifest.json"
    if inputs_manifest.is_file():
        try:
            doc = json.loads(inputs_manifest.read_text(encoding="utf-8"))
            entries = doc.get("entries")
            if not isinstance(entries, list):
                raise ValueError("inputs/manifest.json entries 不是数组")
            derived_names = input_arcnames(entries)
            for entry, derived in zip(entries, derived_names):
                arc = str(entry.get("arcname") or derived)
                normalized_arc = _normalize_artifact_path(arc)
                allowed_inputs.add(normalized_arc)
        except ValueError as exc:
            result.update(ok=False, files_status="FAIL",
                          reason=f"ARTIFACT FAIL 输入路径非法：{exc}")
            return result
        except Exception as exc:
            result.update(ok=False, extras_status="FAIL",
                          reason="ARTIFACT FAIL 无法读取 inputs/manifest.json："
                                 f"{type(exc).__name__}: {exc}")
            return result
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in allowed_paths:
            continue
        if rel.startswith(INPUTS_DIRNAME + "/") and rel in allowed_inputs:
            continue
        result["extras"].append(rel)
    if result["extras"]:
        result.update(ok=False, extras_status="FAIL",
                      reason="EXTRA FILE FAIL 未声明的包内文件：" + ",".join(result["extras"]))
    else:
        result["extras_status"] = "OK"
    result["ok"] = all(result[k] == "OK" for k in (
        "files_status", "verify_script_status", "digest_status", "extras_status"))
    return result


def _unescape_text(value: object) -> str:
    return str(csv_unescape_cell(value) or "")


def _empty_to_none(value: object) -> str | None:
    text = _unescape_text(value)
    return text if text != "" else None


def conclusion_digest_from_findings(path: Path) -> tuple[str, int, dict[str, int]]:
    """公开规范化算法：findings.csv -> Finding.canonical 列表 -> SHA-256。

    - 只取 `Finding.canonical()` 的字段；`severity_label`/`source_*` 不参与摘要；
    - 文本字段撤销 CSV 公式转义；`citations`/`metric_json` 按 JSON 解析；
    - 空 `work_date`/`period_key` 还原为 `null`；
    - 按 `(emp_id, work_date or "", period_key or "", rule_id, severity)` 排序；
    - 对列表做 canonical JSON（key 排序、UTF-8、无空白）后 SHA-256。
    """
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        missing = [c for c in FINDINGS_COLUMNS if c not in header]
        if missing:
            raise ValueError("findings.csv 缺列：" + ",".join(missing))
        rows = []
        for row in reader:
            try:
                citations = json.loads(_unescape_text(row["citations"]) or "[]")
                metric = json.loads(_unescape_text(row["metric_json"]) or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"findings.csv JSON 列非法：{exc}") from exc
            if not isinstance(citations, list) or not all(isinstance(x, str) for x in citations):
                raise ValueError("findings.csv citations 必须是字符串数组")
            if not isinstance(metric, dict):
                raise ValueError("findings.csv metric_json 必须是对象")
            rows.append({
                "rule_id": _unescape_text(row["rule_id"]),
                "rule_version": _unescape_text(row["rule_version"]),
                "emp_id": _unescape_text(row["emp_id"]),
                "work_date": _empty_to_none(row["work_date"]),
                "period_key": _empty_to_none(row["period_key"]),
                "severity": _unescape_text(row["severity"]),
                "metric": metric,
                "citations": sorted(citations),
                "explanation": _unescape_text(row["explanation"]),
            })
    rows.sort(key=lambda r: (r["emp_id"], r["work_date"] or "", r["period_key"] or "",
                             r["rule_id"], r["severity"]))
    versions: dict[str, int] = {}
    for r in rows:
        versions[r["rule_version"]] = versions.get(r["rule_version"], 0) + 1
    return digest_of(rows), len(rows), versions


def check_inputs_completeness(root: Path, manifest: dict, schema_ver: int) -> dict:
    """对账 `input_files.csv`（input_fingerprint 覆盖的引用集合）与 `inputs/` 实际成员。

    旧包（schema < 3）没有 inputs_digest 契约，记 NOT CHECKED；新包必须逐项齐全，
    否则属于“静默残缺”：verify 不能只看摘要命中就报 OK。
    """
    if schema_ver < 3:
        return {"ok": True, "status": "NOT CHECKED",
                "reason": "INPUTS COMPLETENESS NOT CHECKED 旧包（schema < 3）"}
    manifest_path = root / INPUTS_DIRNAME / "manifest.json"
    if not manifest_path.is_file():
        return {"ok": False, "status": "FAIL",
                "reason": "INPUTS COMPLETENESS FAIL 包内缺少 inputs/manifest.json"}
    try:
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "status": "FAIL",
                "reason": f"INPUTS COMPLETENESS FAIL 无法解析 inputs/manifest.json："
                          f"{type(exc).__name__}: {exc}"}
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return {"ok": False, "status": "FAIL",
                "reason": "INPUTS COMPLETENESS FAIL inputs/manifest.json 缺少 entries"}
    declared = Counter((str(e.get("rel_path")), str(e.get("sha256")), str(e.get("kind")))
                       for e in entries if isinstance(e, dict))
    path = root / "input_files.csv"
    if not path.is_file():
        return {"ok": False, "status": "FAIL",
                "reason": "INPUTS COMPLETENESS FAIL 包内缺少 input_files.csv"}
    expected = Counter()
    total = 0
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            rel = csv_unescape_cell(row.get("rel_path") or "")
            if rel.startswith("inline://"):
                continue
            total += 1
            expected[(rel, str(row.get("sha256") or "").lower(),
                      csv_unescape_cell(row.get("kind") or ""))] += 1
    missing = list((expected - declared).elements())
    extra = list((declared - expected).elements())
    absent_files: list[str] = []
    try:
        arcs = input_arcnames(entries)
    except ValueError as exc:
        return {"ok": False, "status": "FAIL",
                "reason": f"INPUTS COMPLETENESS FAIL 包内输入路径非法：{exc}"}
    for entry, arc in zip(entries, arcs):
        target = root / arc
        if not target.is_file():
            absent_files.append(f"{entry.get('rel_path')}（包内缺少 {arc}）")
            continue
        actual = _sha256_file(target)
        if actual != str(entry.get("sha256") or "").lower():
            absent_files.append(f"{entry.get('rel_path')}（包内字节与声明 sha256 不一致）")
    problems = [f"{rel}:{kind}" for rel, _sha, kind in missing] + \
               [f"{rel}:{kind}（声明多出）" for rel, _sha, kind in extra] + absent_files
    if problems:
        return {"ok": False, "status": "FAIL",
                "expected": total, "missing": len(missing) + len(absent_files),
                "extra": len(extra), "problems": problems,
                "reason": (f"INPUTS COMPLETENESS FAIL 输入清单列了 {total} 个，"
                           f"包内 inputs 缺少 {len(missing) + len(absent_files)} 个："
                           + "；".join(problems[:8]))}
    return {"ok": True, "status": "OK", "expected": total, "missing": 0, "extra": 0,
            "reason": f"INPUTS COMPLETENESS OK 输入清单 {total} 个与包内 inputs/ 一致"}


def check_findings(root: Path, manifest: dict) -> dict:
    """从 findings.csv 反算 conclusion_digest，并核对 counts。"""
    path = root / "findings.csv"
    if not path.is_file():
        return {"ok": False, "reason": "FINDINGS FAIL 包内缺少 findings.csv"}
    try:
        actual, rows, versions = conclusion_digest_from_findings(path)
    except Exception as exc:
        return {"ok": False,
                "reason": f"FINDINGS FAIL 无法反算 conclusion_digest：{type(exc).__name__}: {exc}"}
    triple = manifest.get("triple") if isinstance(manifest.get("triple"), dict) else {}
    counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
    if not isinstance(triple.get("conclusion_digest"), str) or actual != triple["conclusion_digest"]:
        return {"ok": False,
                "reason": "FINDINGS DIGEST FAIL findings.csv 反算的 conclusion_digest 与 manifest 不一致",
                "actual_digest": actual, "rows": rows, "rule_versions": versions}
    if int(counts.get("findings", -1)) != rows:
        return {"ok": False,
                "reason": "COUNTS FAIL manifest.counts.findings 与 findings.csv 行数不一致",
                "actual_digest": actual, "rows": rows, "rule_versions": versions}
    declared_versions = counts.get("rule_versions")
    if not isinstance(declared_versions, dict) or \
            {str(k): int(v) for k, v in declared_versions.items()} != versions:
        return {"ok": False,
                "reason": "COUNTS FAIL manifest.counts.rule_versions 与 findings.csv 不一致",
                "actual_digest": actual, "rows": rows, "rule_versions": versions}
    conclusions = root / "conclusions_final.csv"
    final_rows = 0
    if conclusions.is_file():
        with conclusions.open("r", encoding="utf-8-sig", newline="") as fh:
            final_rows = sum(1 for _ in csv.DictReader(fh))
    if int(counts.get("final_conclusions", -1)) != final_rows:
        return {"ok": False,
                "reason": "COUNTS FAIL manifest.counts.final_conclusions 与 conclusions_final.csv 行数不一致",
                "actual_digest": actual, "rows": rows, "final_rows": final_rows,
                "rule_versions": versions}
    return {"ok": True, "reason": "", "actual_digest": actual, "rows": rows,
            "final_rows": final_rows, "rule_versions": versions}


def evidence_digest_from_findings(path: Path) -> tuple[str, int]:
    """公开规范化算法：findings.csv 的 evidence_json -> evidence_digest。

    `findings.csv` 必须有 `evidence_json` 列；解析失败/未知字段按失败关闭。
    evidence 不进入 conclusion_digest，只用于这里的独立摘要。
    """
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        if "evidence_json" not in header:
            raise ValueError("findings.csv 缺列：evidence_json")
        records = []
        for row in reader:
            try:
                evidence = json.loads(_unescape_text(row["evidence_json"]) or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"findings.csv evidence_json 非法：{exc}") from exc
            if not isinstance(evidence, dict):
                raise ValueError("findings.csv evidence_json 必须是对象")
            records.append({
                "rule_id": _unescape_text(row["rule_id"]),
                "rule_version": _unescape_text(row["rule_version"]),
                "emp_id": _unescape_text(row["emp_id"]),
                "work_date": _empty_to_none(row["work_date"]),
                "period_key": _empty_to_none(row["period_key"]),
                "evidence": evidence,
            })
    return compute_evidence_digest(records), len(records)


def _producer_version(manifest: dict) -> tuple[int, ...] | None:
    block = manifest.get("producer")
    if not isinstance(block, dict):
        return None
    raw = str(block.get("version") or "").strip()
    parts = raw.split(".")
    if len(parts) < 2:
        return None
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def check_evidence(root: Path, manifest: dict) -> dict:
    """核验 manifest.evidence_digest 与 findings.csv 的 evidence 块。

    分档（写死，避免“缺字段也能过”）：
      * manifest 有 evidence_digest：必须能重算且一致；缺列/解析失败/不一致 → FAIL；
      * 缺失且 producer.version >= 0.4.3：新版本包失败关闭 → FAIL；
      * 缺失且无 producer 或 producer.version < 0.4.3：旧包兼容路径 → NOT CHECKED，
        不能给 RESULT OK；这是历史包没有该字段的事实，不是“检查通过”。
    """
    declared = manifest.get("evidence_digest")
    version = _producer_version(manifest)
    if declared is None:
        if version is not None and version >= EVIDENCE_DIGEST_MIN_PRODUCER:
            return {"ok": False, "legacy": False, "actual_digest": "", "rows": 0,
                    "reason": ("EVIDENCE DIGEST FAIL 新版本包（producer.version="
                               + ".".join(str(part) for part in version)
                               + "）缺少 manifest.evidence_digest")}
        return {"ok": True, "legacy": True, "actual_digest": "", "rows": 0,
                "reason": ("旧包（producer.version < 0.4.3 或无 producer）无 "
                           "manifest.evidence_digest；EVIDENCE DIGEST NOT CHECKED，"
                           "不能算完整验收")}
    if not isinstance(declared, str) or not declared.strip():
        return {"ok": False, "legacy": False, "actual_digest": "", "rows": 0,
                "reason": "EVIDENCE DIGEST FAIL manifest.evidence_digest 为空或不是字符串"}
    path = root / "findings.csv"
    if not path.is_file():
        return {"ok": False, "legacy": False, "actual_digest": "", "rows": 0,
                "reason": "EVIDENCE DIGEST FAIL 包内缺少 findings.csv"}
    try:
        actual, rows = evidence_digest_from_findings(path)
    except Exception as exc:
        return {"ok": False, "legacy": False, "actual_digest": "", "rows": 0,
                "reason": f"EVIDENCE DIGEST FAIL 无法重算 evidence_digest："
                          f"{type(exc).__name__}: {exc}"}
    if actual != declared.strip():
        return {"ok": False, "legacy": False, "actual_digest": actual, "rows": rows,
                "reason": "EVIDENCE DIGEST FAIL findings.csv 的 evidence 块与 "
                          "manifest.evidence_digest 不一致"}
    return {"ok": True, "legacy": False, "actual_digest": actual, "rows": rows,
            "reason": ""}


def _parse_expected_anchor(value: object) -> dict | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, (tuple, list)) and len(value) in (4, 5):
        parts = [str(p).strip() for p in value]
    else:
        raise ValueError("需要四段或五段锚点")
    if len(parts) not in (4, 5) or any(not p for p in parts):
        raise ValueError("需要四段/五段非空值：schema_version,rule_pack_version,"
                         "input_fingerprint,conclusion_digest[,projection_fingerprint]")
    version = anchor_schema_version(parts[0])
    if version is None:
        raise ValueError("schema_version 无法识别：" + parts[0])
    result = {"schema_version": version, "rule_pack_version": parts[1],
              "input_fingerprint": parts[2], "conclusion_digest": parts[3]}
    if len(parts) == 5:
        result["projection_fingerprint"] = parts[4]
    return result


def load_anchor_record(path: Path | str) -> dict:
    """读取单包 anchor 文件，作为显式参数的兜底。

    支持扁平格式：`anchor`（四/五段字符串或 `anchor_segments` 数组）、
    `package_sha256`、`artifacts_digest`、`evidence_digest`。组合式 `anchor.json` 含多个包时，
    不能直接用于单包验算，避免把 A 包的哈希套到 B 包。
    """
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"anchor 文件不存在或不可读：{p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"anchor 文件不是合法 JSON：{type(exc).__name__}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("anchor 文件必须是 JSON 对象")
    if "packages" in doc:
        raise ValueError("组合式 anchor.json 含多个包；请使用单包 anchor 文件，"
                         "或显式传 --expect-anchor/--expect-package-sha256/"
                         "--expect-artifacts-digest/--expect-evidence-digest")
    anchor = doc.get("anchor") or doc.get("expect_anchor")
    segments = doc.get("anchor_segments") or doc.get("expected_anchor")
    if not anchor and isinstance(segments, list):
        anchor = ",".join(str(x).strip() for x in segments)
    return {
        "anchor": str(anchor).strip() if anchor else None,
        "package_sha256": str(doc.get("package_sha256")
                              or doc.get("expect_package_sha256") or "").strip() or None,
        "artifacts_digest": str(doc.get("artifacts_digest")
                                or doc.get("expect_artifacts_digest") or "").strip() or None,
        "evidence_digest": str(doc.get("evidence_digest")
                               or doc.get("expect_evidence_digest") or "").strip() or None,
    }


def _parse_expected_triple(value: object) -> dict | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, (tuple, list)) and len(value) == 3:
        parts = [str(p).strip() for p in value]
    else:
        raise ValueError("需要 rule_pack_version,input_fingerprint,conclusion_digest 三段")
    if len(parts) != 3 or any(not p for p in parts):
        raise ValueError("需要三段非空值")
    return dict(zip(TRIPLE_KEYS, parts))


def _anchor_check(manifest: dict, schema_ver: int, expected_anchor: dict | None,
                  expected_triple: dict | None) -> tuple[bool, str, list[str]]:
    triple = manifest.get("triple") if isinstance(manifest.get("triple"), dict) else {}
    if expected_anchor:
        mismatched = []
        if expected_anchor["schema_version"] != schema_ver:
            mismatched.append("schema_version")
        for key in TRIPLE_KEYS:
            if expected_anchor[key] != triple.get(key):
                mismatched.append(key)
        expected_projection = expected_anchor.get("projection_fingerprint")
        package_projection = manifest.get("projection_fingerprint")
        if expected_projection is not None:
            if not isinstance(package_projection, str) or package_projection != expected_projection:
                mismatched.append("projection_fingerprint")
        if mismatched:
            return False, "ANCHOR FAIL 外部锚点与包内不一致：" + ",".join(mismatched), mismatched
        return True, "ANCHOR CHECK OK", []
    if expected_triple:
        mismatched = [k for k in TRIPLE_KEYS if expected_triple[k] != triple.get(k)]
        if mismatched:
            return False, "TRIPLE FAIL 外部三元组与包内不一致：" + ",".join(mismatched), mismatched
        return True, "EXTERNAL TRIPLE CHECK OK（legacy；未约束 schema）", []
    return True, "ANCHOR NOT CHECKED", []


def verify_package(package: Path | str, *, public_keys: list[str] | tuple[str, ...] | None = None,
                   expect_anchor: str | tuple[str, ...] | None = None,
                   expect_triple: str | tuple[str, ...] | None = None,
                   expect_package_sha256: str | None = None,
                   expect_artifacts_digest: str | None = None,
                   expect_evidence_digest: str | None = None,
                   require_signature: bool = False) -> dict:
    """独立验算入口；返回 ok/partial/reason 与各检查状态。不执行包内代码。

    RESULT OK 的门禁：内容检查全通过 + 签名 pin 命中 + 外部锚点通过 +
    外部包 SHA 通过 + 外部 artifacts_digest 通过 + 外部 evidence_digest 通过。
    任一外部项缺失/未通过 → PARTIAL（内容检查失败 → FAIL）。
    """
    p = Path(package)
    check_names = ("manifest", "producer", "artifacts", "verify_script",
                   "artifacts_digest_internal", "extras", "findings", "evidence", "chain",
                   "inputs_completeness", "inputs", "signature", "signature_pinned", "anchor",
                   "package_sha", "artifacts_digest_external", "evidence_digest_external")
    result = {
        "package": str(p), "schema": "", "manifest_schema_version": None, "run_id": "",
        "producer": {}, "producer_ok": True, "producer_reason": "",
        "manifest_checksum": "missing", "chain": {"ok": False, "reason": "未校验", "length": 0,
                                                   "head_hash": "", "checked": False},
        "artifact": {}, "findings": {}, "evidence": {}, "evidence_legacy": False,
        "inputs_digest": "", "inputs_digest_ok": False,
        "signature_present": False, "signature_ok": False, "signature_trust": "none",
        "signature_key_id": "", "signature_reason": "", "signature_checked": False,
        "anchor_checked": False, "anchor_expected": bool(
            expect_anchor or os.environ.get("WCA_EXPECT_ANCHOR")),
        "anchor_reason": "ANCHOR NOT CHECKED",
        "package_sha256": "", "package_sha256_checked": False, "package_sha256_ok": None,
        "package_sha256_expected": "",
        "artifacts_digest": "", "artifacts_digest_checked": False, "artifacts_digest_ok": None,
        "artifacts_digest_expected": "",
        "evidence_digest": "", "evidence_digest_checked": False, "evidence_digest_ok": None,
        "evidence_digest_expected": "",
        "checks": {k: "NOT CHECKED" for k in check_names},
        "partial": False, "ok": False, "reason": "",
    }
    checks = result["checks"]
    if not p.exists():
        result["reason"] = f"包不存在：{p}"
        return result
    package_sha = _sha256_file(p) if p.is_file() else ""
    result["package_sha256"] = package_sha
    if expect_package_sha256:
        result["package_sha256_checked"] = True
        result["package_sha256_expected"] = str(expect_package_sha256).strip().lower()
        if not package_sha:
            checks["package_sha"] = "FAIL"
            result.update(ok=False, partial=False, package_sha256_ok=False,
                          reason="PACKAGE SHA256 FAIL 目录形态无法比较包文件哈希")
            return result
        if result["package_sha256_expected"] != package_sha:
            checks["package_sha"] = "FAIL"
            result.update(ok=False, partial=False, package_sha256_ok=False,
                          reason="PACKAGE SHA256 FAIL 包文件哈希与外部记录不一致")
            return result
        checks["package_sha"] = "OK"
        result["package_sha256_ok"] = True
    try:
        from .replay import unpacked
        with unpacked(p) as root:
            try:
                manifest = _load_manifest(root)
            except ValueError as exc:
                checks["manifest"] = "FAIL"
                result["reason"] = str(exc)
                return result
            schema_ver = evidence_schema_version(manifest.get("schema"))
            result["schema"] = str(manifest.get("schema") or "")
            result["run_id"] = str(manifest.get("run_id") or "")
            if schema_ver is None:
                checks["manifest"] = "FAIL"
                result["reason"] = "MANIFEST FAIL manifest.schema 缺失或无法识别"
                return result
            if schema_ver < 2:
                checks["manifest"] = "FAIL"
                result["reason"] = "LEGACY PACKAGE FAIL 独立验算器只接受 v2+ 包（v1 仅保留历史回放）"
                return result
            result["manifest_schema_version"] = schema_ver
            declared_checksum = manifest.get("manifest_checksum")
            if not isinstance(declared_checksum, str) or not declared_checksum:
                checks["manifest"] = "FAIL"
                result.update(manifest_checksum="missing", reason="MANIFEST FAIL 缺少 manifest_checksum")
                return result
            if declared_checksum != manifest_checksum(manifest):
                checks["manifest"] = "FAIL"
                result.update(manifest_checksum="mismatch", reason="MANIFEST FAIL manifest_checksum 不一致")
                return result
            result["manifest_checksum"] = "ok"
            checks["manifest"] = "OK"
            triple = manifest.get("triple") if isinstance(manifest.get("triple"), dict) else {}
            if any(not isinstance(triple.get(k), str) or not triple.get(k) for k in TRIPLE_KEYS):
                checks["manifest"] = "FAIL"
                result["reason"] = "MANIFEST FAIL manifest.triple 缺字段或为空"
                return result
            producer_ok, producer_reason = producer.check_manifest_producer(manifest)
            result["producer_ok"] = producer_ok
            result["producer_reason"] = producer_reason
            result["producer"] = dict(manifest.get("producer") or {})
            checks["producer"] = "OK" if producer_ok else "FAIL"
            if not producer_ok:
                result["reason"] = producer_reason
                return result
            artifact = check_artifacts(root, manifest, schema_ver)
            result["artifact"] = artifact
            checks["artifacts"] = artifact["files_status"]
            checks["verify_script"] = artifact["verify_script_status"]
            checks["artifacts_digest_internal"] = artifact["digest_status"]
            checks["extras"] = artifact["extras_status"]
            if not artifact["ok"]:
                result["reason"] = artifact["reason"]
                return result
            findings = check_findings(root, manifest)
            result["findings"] = findings
            checks["findings"] = "OK" if findings["ok"] else "FAIL"
            if not findings["ok"]:
                result["reason"] = findings["reason"]
                return result
            evidence = check_evidence(root, manifest)
            result["evidence"] = evidence
            result["evidence_legacy"] = bool(evidence.get("legacy"))
            checks["evidence"] = ("OK" if evidence["ok"] and not evidence.get("legacy")
                                  else ("NOT CHECKED" if evidence.get("legacy") else "FAIL"))
            if not evidence["ok"]:
                result["reason"] = evidence["reason"]
                return result
            result["evidence_digest"] = str(manifest.get("evidence_digest") or "")
            if expect_evidence_digest:
                result["evidence_digest_checked"] = True
                result["evidence_digest_expected"] = str(
                    expect_evidence_digest).strip().lower()
                declared_evidence = result["evidence_digest"]
                if evidence.get("legacy") or not declared_evidence:
                    checks["evidence_digest_external"] = "FAIL"
                    result.update(evidence_digest_ok=False, ok=False, partial=False,
                                  reason="EVIDENCE DIGEST FAIL 包内无 evidence_digest，"
                                         "无法与外部期望值比对")
                    return result
                if result["evidence_digest_expected"] != declared_evidence.lower():
                    checks["evidence_digest_external"] = "FAIL"
                    result.update(evidence_digest_ok=False, ok=False, partial=False,
                                  reason="EVIDENCE DIGEST FAIL "
                                         f"expected={result['evidence_digest_expected']} "
                                         f"actual={declared_evidence}")
                    return result
                checks["evidence_digest_external"] = "OK"
                result["evidence_digest_ok"] = True
            result["artifacts_digest"] = artifact["artifacts_digest"]
            checks["artifacts_digest_internal"] = artifact["digest_status"]
            if expect_artifacts_digest:
                result["artifacts_digest_checked"] = True
                result["artifacts_digest_expected"] = str(expect_artifacts_digest).strip().lower()
                if result["artifacts_digest_expected"] != artifact["artifacts_digest"]:
                    checks["artifacts_digest_external"] = "FAIL"
                    result.update(artifacts_digest_ok=False, ok=False, partial=False,
                                  reason="ARTIFACTS DIGEST external FAIL "
                                         f"expected={result['artifacts_digest_expected']} "
                                         f"actual={artifact['artifacts_digest']} "
                                         "(manifest-internal OK)")
                    return result
                checks["artifacts_digest_external"] = "OK"
                result["artifacts_digest_ok"] = True
            chain_text = (root / "audit_chain.jsonl").read_text(encoding="utf-8")
            from .replay import _chain_from_snapshot
            chain = _chain_from_snapshot(chain_text.splitlines(),
                                         str(manifest.get("engine_version") or ""),
                                         triple["rule_pack_version"],
                                         manifest.get("audit_segment"))
            chain["checked"] = True
            result["chain"] = chain
            checks["chain"] = "OK" if chain["ok"] else "FAIL"
            if not chain["ok"]:
                result["reason"] = f"CHAIN FAIL {chain['reason']}"
                return result
            declared_head = (manifest.get("chain_verification") or {}).get("head_hash")
            if declared_head and str(declared_head) != chain["head_hash"]:
                result["reason"] = "CHAIN FAIL manifest.chain_verification.head_hash 与重算链头不一致"
                return result
            completeness = check_inputs_completeness(root, manifest, schema_ver)
            result["inputs_completeness"] = completeness
            checks["inputs_completeness"] = completeness["status"]
            if not completeness["ok"]:
                result["reason"] = completeness["reason"]
                return result
            try:
                actual_inputs = signing.compute_inputs_digest_from_dir(root)
            except Exception as exc:
                checks["inputs"] = "FAIL"
                result["reason"] = f"INPUTS FAIL 无法计算输入摘要：{type(exc).__name__}: {exc}"
                return result
            declared_inputs = manifest.get("inputs_digest")
            if not isinstance(declared_inputs, str) or not declared_inputs:
                checks["inputs"] = "FAIL"
                result["reason"] = "INPUTS FAIL 缺少 manifest.inputs_digest"
                return result
            result["inputs_digest"] = declared_inputs
            if actual_inputs != declared_inputs:
                checks["inputs"] = "FAIL"
                result["reason"] = "INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致"
                return result
            result["inputs_digest_ok"] = True
            checks["inputs"] = "OK"
            pinned = signing.load_public_keys(public_keys)
            signature = signing.verify_signature(manifest, chain["head_hash"], pinned)
            result["signature_checked"] = True
            result.update(signature_present=signature["present"], signature_ok=signature["ok"],
                          signature_trust=signature["trust"],
                          signature_key_id=signature["key_id"],
                          signature_reason=signature["reason"])
            if signature["present"] and not signature["ok"]:
                checks["signature"] = "FAIL"
                result["reason"] = f"SIGNATURE FAIL {signature['reason']}"
                return result
            if not signature["present"] and (schema_ver >= 3 or require_signature):
                checks["signature"] = "FAIL"
                result["reason"] = "SIGNATURE FAIL 包无签名，且当前要求必须有签名"
                return result
            checks["signature"] = "OK" if signature["present"] else "NOT CHECKED"
            checks["signature_pinned"] = ("OK" if signature["trust"] == "pinned" else "NOT CHECKED")
            try:
                expected_anchor_parsed = _parse_expected_anchor(
                    expect_anchor if expect_anchor is not None else os.environ.get("WCA_EXPECT_ANCHOR"))
                expected_triple_parsed = _parse_expected_triple(
                    expect_triple if expect_triple is not None else os.environ.get("WCA_EXPECT_TRIPLE"))
            except ValueError as exc:
                checks["anchor"] = "FAIL"
                result["reason"] = str(exc)
                return result
            anchor_ok, anchor_reason, mismatched = _anchor_check(
                manifest, schema_ver, expected_anchor_parsed, expected_triple_parsed)
            result["anchor_checked"] = expected_anchor_parsed is not None
            result["anchor_reason"] = anchor_reason
            checks["anchor"] = ("OK" if anchor_ok and result["anchor_checked"]
                                else ("FAIL" if not anchor_ok else "NOT CHECKED"))
            if not anchor_ok:
                result["reason"] = anchor_reason
                return result
            internal_checks = ("manifest", "producer", "artifacts", "verify_script",
                               "artifacts_digest_internal", "extras", "findings", "evidence",
                               "chain", "inputs_completeness", "inputs")
            if schema_ver < 3:
                internal_checks = tuple(name for name in internal_checks
                                        if name != "inputs_completeness")
            if result.get("evidence_legacy"):
                # 旧包没有 evidence_digest：按既有分档保留可验证性，但不把 NOT CHECKED
                # 写成“检查通过”，也不让它参与 RESULT OK 门禁。
                internal_checks = tuple(name for name in internal_checks
                                        if name != "evidence")
            content_ok = all(checks[k] == "OK" for k in internal_checks) and \
                checks["signature"] in ("OK", "NOT CHECKED")
            external_ok = (checks["signature_pinned"] == "OK"
                           and checks["anchor"] == "OK"
                           and checks["package_sha"] == "OK"
                           and checks["artifacts_digest_external"] == "OK"
                           and checks["evidence_digest_external"] == "OK")
            result["partial"] = content_ok and not external_ok
            result["ok"] = content_ok and external_ok
            missing_external = []
            if checks["signature_pinned"] != "OK":
                missing_external.append("外部公钥 pin")
            if checks["anchor"] != "OK":
                missing_external.append("外部锚点")
            if checks["package_sha"] != "OK":
                missing_external.append("外部包 SHA-256")
            if checks["artifacts_digest_external"] != "OK":
                missing_external.append("外部 artifacts_digest")
            if checks["evidence_digest_external"] != "OK":
                missing_external.append("外部 evidence_digest")
            if result["ok"]:
                result["reason"] = ("工件、发现摘要、证据定位摘要、链、输入与签名均一致；"
                                    "外部 pin、锚点、包 SHA、artifacts_digest 与 "
                                    "evidence_digest 均通过")
            elif result["partial"]:
                result["reason"] = ("RESULT PARTIAL：内容检查通过，但缺少/未通过 "
                                    + "、".join(missing_external))
            else:
                result["reason"] = "RESULT FAIL：内容检查未通过"
            return result
    except Exception as exc:
        result["reason"] = f"VERIFY FAIL {type(exc).__name__}: {exc}"
        return result
