"""`wca-verify`：发行 wheel 内的独立验算入口。

它**不执行**包内 `verify.py`，只读取包内文件并重算哈希、链、输入摘要、签名、
工件绑定与 findings 摘要。包内脚本只是便利脚本，不是信任依据。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import package_verify, signing


def _public_keys(values: list[str] | None) -> list[str]:
    out = list(values or [])
    env = os.environ.get("WCA_PUBLIC_KEY")
    if env:
        out.extend(p.strip() for p in env.split(",") if p.strip())
    return out


def _note(name: str, status: str, result: dict, checks: dict, early: bool) -> str:
    """给 NOT CHECKED 补足原因；从未走到不能写成 FAIL。"""
    if status != "NOT CHECKED":
        return ""
    if name in ("package_sha", "artifacts_digest_external"):
        return ("（早退，尚未走到外部比对；非缺失）" if early
                else "（未传外部期望值）")
    if name == "anchor":
        if result.get("anchor_expected"):
            return ("（早退，尚未走到锚点校验；非锚点缺失）" if early
                    else "（未完成外部锚点校验）")
        return "（未传外部锚点）"
    if name == "signature":
        if result.get("signature_checked"):
            return "（包内无签名；v2 旧包仅在 --require-signature 时失败）"
        return "（早退，尚未走到验签）" if early else "（未验签）"
    if name == "signature_pinned":
        return "（早退，尚未走到验签）" if early else "（未提供外部公钥或 pin 未命中）"
    if name == "inputs":
        if result.get("inputs_digest_legacy"):
            return "（v2 契约无 inputs_digest；属版本缺失，不是缺失/篡改）"
        return "（早退，尚未走到输入摘要）" if early else "（未走到输入摘要）"
    return "（早退，尚未走到该检查）" if early else "（未走到该检查）"


def _print_result(result: dict) -> None:
    checks = result.get("checks") or {}
    early = any(value == "FAIL" for value in checks.values())

    def st(name: str) -> str:
        return str(checks.get(name, "NOT CHECKED"))

    def line(label: str, status: str, name: str, detail: str = "") -> None:
        print(f"{label} {status}" + (f" {detail}" if detail else "")
              + _note(name, status, result, checks, early))

    if result.get("schema"):
        print(f"MANIFEST SCHEMA v{result.get('manifest_schema_version')}")
    producer = result.get("producer") or {}
    if producer:
        print("PRODUCER", producer.get("version"), producer.get("commit"),
              "python=" + str(producer.get("python")),
              "rule_pack=" + str(producer.get("rule_pack_version")))
    line("MANIFEST CHECKSUM", st("manifest"), "manifest")
    artifact = result.get("artifact") or {}
    artifact_detail = f"checked={artifact.get('checked', 0)}"
    if st("artifacts") == "FAIL":
        reason = str(artifact.get("reason") or "")
        reason = reason.removeprefix("ARTIFACT FAIL ").removeprefix("ARTIFACT BINDING FAIL ")
        artifact_detail += f"（{reason}）"
    line("ARTIFACTS", st("artifacts"), "artifacts", artifact_detail)
    script_detail = (f"sha256={artifact.get('verify_script_sha256')}"
                     if artifact.get("verify_script_sha256") else "")
    line("VERIFY SCRIPT", st("verify_script"), "verify_script", script_detail)

    # 内部清单摘要与外部比对只打一行，且只在外部比对通过时才是 external OK。
    internal = st("artifacts_digest_internal")
    external = st("artifacts_digest_external") if result.get("artifacts_digest_checked") \
        else "NOT CHECKED"
    digest_line = (f"ARTIFACTS DIGEST manifest-internal {internal} / external {external}")
    if external == "FAIL":
        digest_line += (f" expected={result.get('artifacts_digest_expected')} "
                        f"actual={result.get('artifacts_digest')}")
    elif external == "NOT CHECKED":
        digest_line += ("（早退，尚未走到摘要比对；非缺失）" if early
                        else "（未传外部期望值）")
    print(digest_line)

    line("EXTRA FILE", st("extras"), "extras",
         ("：" + ",".join(artifact.get("extras") or [])) if artifact.get("extras") else "")
    findings = result.get("findings") or {}
    findings_detail = str(findings.get("actual_digest", ""))
    if st("findings") == "OK":
        findings_detail += " (9 fields; source_* not covered by digest)"
    line("FINDINGS DIGEST", st("findings"), "findings", findings_detail)
    evidence = result.get("evidence") or {}
    if result.get("evidence_legacy"):
        print("EVIDENCE DIGEST NOT CHECKED（旧包无 evidence_digest；"
              "不能据此给完整通过）")
    else:
        internal = st("evidence")
        external = ("OK" if result.get("evidence_digest_ok") else "FAIL") \
            if result.get("evidence_digest_checked") else "NOT CHECKED"
        detail = str(result.get("evidence_digest") or evidence.get("actual_digest") or "")
        if internal == "OK":
            line_text = f"EVIDENCE DIGEST OK {detail} / external={external}"
        elif internal == "FAIL":
            line_text = f"EVIDENCE DIGEST FAIL {detail} / external={external}"
        else:
            line_text = f"EVIDENCE DIGEST NOT CHECKED / external={external}"
        if external == "FAIL":
            line_text += (f" expected={result.get('evidence_digest_expected')} "
                          f"actual={result.get('evidence_digest')}")
        elif external == "NOT CHECKED":
            line_text += ("（早退，尚未走到摘要比对；非缺失）" if early
                          else "（未传外部期望值；不能算完整验收）")
        print(line_text)
    if findings.get("ok"):
        print(f"COUNTS 发现（未签认） {findings.get('rows', 0)} 条 / "
              f"已确认结论 {findings.get('final_rows', 0)} 条")
        print("RULE VERSIONS " + json.dumps(findings.get("rule_versions") or {},
                                            ensure_ascii=False, sort_keys=True))
    chain = result.get("chain") or {}
    line("CHAIN", st("chain"), "chain",
         f"events={chain.get('length', 0)}" if chain.get("checked") else "")
    completeness = result.get("inputs_completeness") or {}
    line("INPUTS COMPLETENESS", st("inputs_completeness"), "inputs_completeness",
         str(completeness.get("reason") or ""))
    line("INPUTS DIGEST", st("inputs"), "inputs", str(result.get("inputs_digest") or ""))

    sig_status = st("signature")
    if sig_status == "FAIL":
        print(f"SIGNATURE FAIL —— {result.get('signature_reason') or result.get('reason')}")
    elif sig_status == "OK":
        trust = ("pinned (key matches supplied pin; independent key_id verification not done)"
                 if result.get("signature_trust") == "pinned"
                 else "package self-check (NOT source trust)")
        print(f"SIGNATURE OK / {trust} / "
              f"key_id={result.get('signature_key_id') or '?'}")
    elif result.get("signature_checked"):
        print("SIGNATURE NOT CHECKED（包内无签名；v2 旧包仅在 --require-signature 时失败）")
    else:
        print("SIGNATURE NOT CHECKED（早退，尚未走到验签）")
    line("SIGNATURE PINNED", st("signature_pinned"), "signature_pinned")

    computed_sha = result.get("package_sha256") or "NOT AVAILABLE"
    sha_status = st("package_sha")
    print(f"PACKAGE SHA256 computed={computed_sha} / external={sha_status}"
          + (f" expected={result.get('package_sha256_expected')}"
             if sha_status == "FAIL" else "")
          + _note("package_sha", sha_status, result, checks, early))
    anchor_status = st("anchor")
    if anchor_status == "OK":
        print("ANCHOR CHECK OK")
    elif anchor_status == "INCOMPARABLE":
        print(f"ANCHOR INCOMPARABLE —— {result.get('anchor_reason') or result.get('reason')}")
    elif anchor_status == "FAIL":
        print(f"ANCHOR FAIL —— {result.get('anchor_reason') or result.get('reason')}")
    elif result.get("anchor_expected") and early:
        # 已传入锚点但前序失败：与“未提供锚点”彻底分开。
        print("ANCHOR SKIPPED (early exit)")
    else:
        print("ANCHOR NOT CHECKED" + _note(
            "anchor", anchor_status, result, checks, early))
    if result.get("incomparable"):
        print(f"RESULT INCOMPARABLE —— {result.get('reason')}")
    elif result.get("ok"):
        print("RESULT OK")
    elif result.get("partial"):
        print(f"RESULT PARTIAL —— {result.get('reason')}")
    else:
        print(f"RESULT FAIL —— {result.get('reason')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wca-verify",
        description="独立复核举证包；不执行包内 verify.py。")
    parser.add_argument("package", help="包 zip 或已解压目录")
    parser.add_argument("--expect-anchor", default=None,
                        help="外部四/五段锚点；也可用 WCA_EXPECT_ANCHOR")
    parser.add_argument("--expect-triple", default=None,
                        help="外部三元组（legacy，不约束 schema）；也可用 WCA_EXPECT_TRIPLE")
    parser.add_argument("--expect-package-sha256", dest="expect_package_sha256", default=None,
                        help="包外记录的 zip SHA-256（RESULT OK 必需）")
    parser.add_argument("--expect-artifacts-digest", dest="expect_artifacts_digest", default=None,
                        help="包外记录的 manifest.artifacts_digest（RESULT OK 必需）")
    parser.add_argument("--expect-evidence-digest", dest="expect_evidence_digest", default=None,
                        help="包外记录的 manifest.evidence_digest（RESULT OK 必需；"
                             "也可用环境变量 WCA_EXPECT_EVIDENCE_DIGEST）")
    parser.add_argument("--anchor-file", dest="anchor_file", default=None,
                        help="单包 anchor JSON（anchor/package_sha256/artifacts_digest/"
                             "evidence_digest）；显式参数优先，文件兜底")
    parser.add_argument("--public-key", action="append", default=None, dest="public_keys",
                        help="外部固定公钥路径或 Base64，可重复；也可用 WCA_PUBLIC_KEY")
    parser.add_argument("--require-signature", action="store_true",
                        help="包无签名也失败；也可用 WCA_REQUIRE_SIGNATURE=1")
    parser.add_argument("--json", action="store_true", help="输出机器可读结果")
    args = parser.parse_args(argv)
    require_signature = bool(args.require_signature) or str(
        os.environ.get("WCA_REQUIRE_SIGNATURE") or "").strip().lower() in (
            "1", "true", "yes", "on")
    try:
        record = package_verify.load_anchor_record(args.anchor_file) \
            if args.anchor_file else {}
        # 显式参数优先；环境变量次之；anchor 文件兜底。
        anchor = args.expect_anchor or os.environ.get("WCA_EXPECT_ANCHOR") \
            or record.get("anchor")
        package_sha = args.expect_package_sha256 or record.get("package_sha256")
        artifacts_digest = args.expect_artifacts_digest or record.get("artifacts_digest")
        evidence_digest = args.expect_evidence_digest \
            or os.environ.get("WCA_EXPECT_EVIDENCE_DIGEST") \
            or record.get("evidence_digest")
        result = package_verify.verify_package(
            Path(args.package),
            public_keys=_public_keys(args.public_keys),
            expect_anchor=anchor,
            expect_triple=args.expect_triple,
            expect_package_sha256=package_sha,
            expect_artifacts_digest=artifacts_digest,
            expect_evidence_digest=evidence_digest,
            expect_comparability=record.get("comparability_scope"),
            comparability_required=bool(getattr(args, "anchor_file", None)
                                        and record.get("anchor")),
            require_signature=require_signature)
    except ValueError as exc:
        print(f"RESULT FAIL —— {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        _print_result(result)
    if result.get("ok"):
        return 0
    if result.get("incomparable"):
        return 3
    return 2 if result.get("partial") else 1
