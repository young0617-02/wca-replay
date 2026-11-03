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
from pathlib import Path

from . import producer, signing
from .util import (anchor_schema_version, canonical_json, csv_unescape_cell, digest_of,
                   evidence_schema_version, manifest_checksum, sha256_hex)

INPUTS_DIRNAME = "inputs"
MANIFEST_FILE = "manifest.json"
VERIFY_SCRIPT = "verify.py"
VERIFY_REQUIREMENTS = "verify-requirements.txt"
README_FILE = "README.txt"
REQUIRED_ARTIFACTS = (
    "findings.csv", "input_files.csv", "quality_issues.csv",
    "conclusions_final.csv", "responsibility.json", "not_covered.json", "未覆盖清单.md",
    README_FILE, VERIFY_REQUIREMENTS,
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


def _normalize_root_artifact(name: object) -> str:
    text = str(name).replace("\\", "/")
    if not text or "/" in text or text in (".", ".."):
        raise ValueError(f"ARTIFACT FAIL 工件路径非法（必须是包根文件名）：{name!r}")
    return text


def check_artifacts(root: Path, manifest: dict, schema_ver: int) -> dict:
    """逐文件哈希 + verify.py 哈希 + 未声明文件检查；v1 旧包跳过。"""
    result = {"ok": True, "reason": "", "checked": 0, "extras": [],
              "artifact_sha256": {}, "artifacts_digest": "", "verify_script_sha256": ""}
    if schema_ver < 2:
        result["reason"] = "LEGACY v1 包未做工件绑定"
        return result
    declared = manifest.get("artifact_sha256")
    declared_digest = manifest.get("artifacts_digest")
    script_digest = manifest.get("verify_script_sha256")
    if not isinstance(declared, dict) or not declared:
        result.update(ok=False, reason="ARTIFACT BINDING FAIL 缺少 manifest.artifact_sha256")
        return result
    if not isinstance(declared_digest, str) or not declared_digest:
        result.update(ok=False, reason="ARTIFACT BINDING FAIL 缺少 manifest.artifacts_digest")
        return result
    if not isinstance(script_digest, str) or not script_digest:
        result.update(ok=False, reason="VERIFY SCRIPT FAIL 缺少 manifest.verify_script_sha256")
        return result
    try:
        normalized = {_normalize_root_artifact(k): str(v).lower() for k, v in declared.items()}
    except ValueError as exc:
        result.update(ok=False, reason=str(exc))
        return result
    result["artifact_sha256"] = normalized
    result["artifacts_digest"] = declared_digest
    result["verify_script_sha256"] = script_digest
    missing = [name for name in REQUIRED_ARTIFACTS if name not in normalized]
    if missing:
        result.update(ok=False, reason="ARTIFACT BINDING FAIL 缺少必需工件：" + ",".join(missing))
        return result
    for name, expected in normalized.items():
        path = root / name
        if not path.is_file():
            result.update(ok=False, reason=f"ARTIFACT FAIL 工件缺失：{name}")
            return result
        actual = _sha256_file(path)
        result["checked"] += 1
        if actual != expected:
            result.update(ok=False, reason=f"ARTIFACT FAIL 工件哈希不一致：{name}")
            return result
    try:
        actual_digest = signing.artifact_digest(normalized)
    except ValueError as exc:
        result.update(ok=False, reason=f"ARTIFACT BINDING FAIL {exc}")
        return result
    if actual_digest != declared_digest:
        result.update(ok=False, reason="ARTIFACT BINDING FAIL artifacts_digest 不一致")
        return result
    script_path = root / VERIFY_SCRIPT
    if not script_path.is_file():
        result.update(ok=False, reason="VERIFY SCRIPT FAIL 包内缺少 verify.py")
        return result
    actual_script = _sha256_file(script_path)
    if actual_script != script_digest:
        result.update(ok=False, reason="VERIFY SCRIPT FAIL verify.py 哈希与 manifest 不一致")
        return result
    allowed_root = set(normalized) | {MANIFEST_FILE, VERIFY_SCRIPT, CHAIN_FILE}
    allowed_inputs = {f"{INPUTS_DIRNAME}/manifest.json"}
    inputs_manifest = root / INPUTS_DIRNAME / "manifest.json"
    if inputs_manifest.is_file():
        try:
            doc = json.loads(inputs_manifest.read_text(encoding="utf-8"))
            entries = doc.get("entries")
            if not isinstance(entries, list):
                raise ValueError("inputs/manifest.json entries 不是数组")
            for entry in entries:
                arc = str(entry.get("arcname") or "")
                normalized = arc.replace("\\", "/")
                parts = [p for p in normalized.split("/") if p]
                if (not parts or normalized.startswith("/") or ".." in parts
                        or (len(parts[0]) >= 2 and parts[0][1] == ":")):
                    raise ValueError(f"inputs/manifest.json 包内路径非法：{arc!r}")
                allowed_inputs.add(normalized)
        except ValueError:
            raise
        except Exception as exc:
            result.update(ok=False,
                          reason=f"ARTIFACT FAIL 无法读取 inputs/manifest.json：{type(exc).__name__}: {exc}")
            return result
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in allowed_root:
            continue
        if rel.startswith(INPUTS_DIRNAME + "/"):
            if rel in allowed_inputs:
                continue
        result["extras"].append(rel)
    if result["extras"]:
        result.update(ok=False, reason="EXTRA FILE FAIL 未声明的包内文件：" + ",".join(result["extras"]))
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
                   require_signature: bool = False) -> dict:
    """独立验算入口；返回 ok/partial/reason 与各检查结果。不执行包内代码。"""
    p = Path(package)
    result = {
        "package": str(p), "schema": "", "manifest_schema_version": None, "run_id": "",
        "producer": {}, "producer_ok": True, "producer_reason": "",
        "manifest_checksum": "missing", "chain": {"ok": False, "reason": "未校验", "length": 0,
                                                   "head_hash": ""},
        "artifact": {}, "findings": {}, "inputs_digest": "", "inputs_digest_ok": False,
        "signature_present": False, "signature_ok": False, "signature_trust": "none",
        "signature_key_id": "", "signature_reason": "",
        "anchor_checked": False, "anchor_reason": "ANCHOR NOT CHECKED",
        "package_sha256": "", "package_sha256_ok": True,
        "artifacts_digest": "", "artifacts_digest_ok": True,
        "partial": False, "ok": False, "reason": "",
    }
    if not p.exists():
        result["reason"] = f"包不存在：{p}"
        return result
    package_sha = _sha256_file(p) if p.is_file() else ""
    result["package_sha256"] = package_sha
    if expect_package_sha256:
        if not package_sha:
            result.update(ok=False, partial=False, package_sha256_ok=False,
                          reason="PACKAGE SHA256 FAIL 目录形态无法比较包文件哈希")
            return result
        if str(expect_package_sha256).strip().lower() != package_sha:
            result.update(ok=False, partial=False, package_sha256_ok=False,
                          reason="PACKAGE SHA256 FAIL 包文件哈希与外部记录不一致")
            return result
    try:
        from .replay import unpacked
        with unpacked(p) as root:
            try:
                manifest = _load_manifest(root)
            except ValueError as exc:
                result["reason"] = str(exc)
                return result
            schema_ver = evidence_schema_version(manifest.get("schema"))
            result["schema"] = str(manifest.get("schema") or "")
            result["run_id"] = str(manifest.get("run_id") or "")
            if schema_ver is None:
                result["reason"] = "MANIFEST FAIL manifest.schema 缺失或无法识别"
                return result
            if schema_ver < 2:
                result["reason"] = "LEGACY PACKAGE FAIL 独立验算器只接受 v2+ 包（v1 仅保留历史回放）"
                return result
            result["manifest_schema_version"] = schema_ver
            declared_checksum = manifest.get("manifest_checksum")
            if not isinstance(declared_checksum, str) or not declared_checksum:
                result.update(manifest_checksum="missing", reason="MANIFEST FAIL 缺少 manifest_checksum")
                return result
            if declared_checksum != manifest_checksum(manifest):
                result.update(manifest_checksum="mismatch", reason="MANIFEST FAIL manifest_checksum 不一致")
                return result
            result["manifest_checksum"] = "ok"
            triple = manifest.get("triple") if isinstance(manifest.get("triple"), dict) else {}
            if any(not isinstance(triple.get(k), str) or not triple.get(k) for k in TRIPLE_KEYS):
                result["reason"] = "MANIFEST FAIL manifest.triple 缺字段或为空"
                return result
            producer_ok, producer_reason = producer.check_manifest_producer(manifest)
            result["producer_ok"] = producer_ok
            result["producer_reason"] = producer_reason
            result["producer"] = dict(manifest.get("producer") or {})
            if not producer_ok:
                result["reason"] = producer_reason
                return result
            artifact = check_artifacts(root, manifest, schema_ver)
            result["artifact"] = artifact
            if not artifact["ok"]:
                result["reason"] = artifact["reason"]
                return result
            findings = check_findings(root, manifest)
            result["findings"] = findings
            if not findings["ok"]:
                result["reason"] = findings["reason"]
                return result
            if expect_artifacts_digest:
                expected = str(expect_artifacts_digest).strip().lower()
                if expected != artifact["artifacts_digest"]:
                    result.update(artifacts_digest_ok=False, ok=False, partial=False,
                                  reason="ARTIFACTS DIGEST FAIL manifest.artifacts_digest 与外部记录不一致")
                    return result
            result["artifacts_digest"] = artifact["artifacts_digest"]
            chain_text = (root / "audit_chain.jsonl").read_text(encoding="utf-8")
            from .replay import _chain_from_snapshot
            chain = _chain_from_snapshot(chain_text.splitlines(),
                                         str(manifest.get("engine_version") or ""),
                                         triple["rule_pack_version"],
                                         manifest.get("audit_segment"))
            result["chain"] = chain
            if not chain["ok"]:
                result["reason"] = f"CHAIN FAIL {chain['reason']}"
                return result
            declared_head = (manifest.get("chain_verification") or {}).get("head_hash")
            if declared_head and str(declared_head) != chain["head_hash"]:
                result["reason"] = "CHAIN FAIL manifest.chain_verification.head_hash 与重算链头不一致"
                return result
            try:
                actual_inputs = signing.compute_inputs_digest_from_dir(root)
            except Exception as exc:
                result["reason"] = f"INPUTS FAIL 无法计算输入摘要：{type(exc).__name__}: {exc}"
                return result
            declared_inputs = manifest.get("inputs_digest")
            if not isinstance(declared_inputs, str) or not declared_inputs:
                result["reason"] = "INPUTS FAIL 缺少 manifest.inputs_digest"
                return result
            result["inputs_digest"] = declared_inputs
            if actual_inputs != declared_inputs:
                result["reason"] = "INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致"
                return result
            result["inputs_digest_ok"] = True
            pinned = signing.load_public_keys(public_keys)
            signature = signing.verify_signature(manifest, chain["head_hash"], pinned)
            result.update(signature_present=signature["present"], signature_ok=signature["ok"],
                          signature_trust=signature["trust"],
                          signature_key_id=signature["key_id"],
                          signature_reason=signature["reason"])
            if signature["present"] and not signature["ok"]:
                result["reason"] = f"SIGNATURE FAIL {signature['reason']}"
                return result
            if not signature["present"] and (schema_ver >= 3 or require_signature):
                result["reason"] = "SIGNATURE FAIL 包无签名，且当前要求必须有签名"
                return result
            try:
                expected_anchor_parsed = _parse_expected_anchor(
                    expect_anchor if expect_anchor is not None else os.environ.get("WCA_EXPECT_ANCHOR"))
                expected_triple_parsed = _parse_expected_triple(
                    expect_triple if expect_triple is not None else os.environ.get("WCA_EXPECT_TRIPLE"))
            except ValueError as exc:
                result["reason"] = str(exc)
                return result
            anchor_ok, anchor_reason, mismatched = _anchor_check(
                manifest, schema_ver, expected_anchor_parsed, expected_triple_parsed)
            result["anchor_checked"] = expected_anchor_parsed is not None
            result["anchor_reason"] = anchor_reason
            if not anchor_ok:
                result["reason"] = anchor_reason
                return result
            content_ok = True
            result["partial"] = not result["anchor_checked"]
            result["ok"] = content_ok and result["anchor_checked"]
            result["reason"] = ("工件、发现摘要、链、输入与签名均一致" if result["ok"]
                                else "ANCHOR NOT CHECKED：字节层与发现摘要一致，但未做外部锚点校验")
            return result
    except Exception as exc:
        result["reason"] = f"VERIFY FAIL {type(exc).__name__}: {exc}"
        return result
