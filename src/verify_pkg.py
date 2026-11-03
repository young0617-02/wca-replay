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


def _print_result(result: dict) -> None:
    checks = result.get("checks") or {}

    def st(name: str) -> str:
        return str(checks.get(name, "NOT CHECKED"))

    if result.get("schema"):
        print(f"MANIFEST SCHEMA v{result.get('manifest_schema_version')}")
    producer = result.get("producer") or {}
    if producer:
        print("PRODUCER", producer.get("version"), producer.get("commit"),
              "python=" + str(producer.get("python")),
              "rule_pack=" + str(producer.get("rule_pack_version")))
    print(f"MANIFEST CHECKSUM {st('manifest')}")
    artifact = result.get("artifact") or {}
    print(f"ARTIFACTS {st('artifacts')} checked={artifact.get('checked', 0)}")
    if artifact.get("verify_script_sha256"):
        print(f"VERIFY SCRIPT {st('verify_script')}"
              f" sha256={artifact.get('verify_script_sha256')}")
    else:
        print(f"VERIFY SCRIPT {st('verify_script')}")
    print(f"ARTIFACTS DIGEST manifest-internal {st('artifacts_digest_internal')}"
          f" {result.get('artifacts_digest') or ''}".rstrip())
    print(f"EXTRA FILE {st('extras')}"
          + (f"：{','.join(artifact.get('extras') or [])}" if artifact.get("extras") else ""))
    findings = result.get("findings") or {}
    print(f"FINDINGS DIGEST {st('findings')}"
          f" {str(findings.get('actual_digest', ''))}".rstrip())
    if findings.get("ok"):
        print(f"COUNTS 发现（未签认） {findings.get('rows', 0)} 条 / "
              f"已确认结论 {findings.get('final_rows', 0)} 条")
        print("RULE VERSIONS " + json.dumps(findings.get("rule_versions") or {},
                                            ensure_ascii=False, sort_keys=True))
    chain = result.get("chain") or {}
    print(f"CHAIN {st('chain')}"
          + (f" events={chain.get('length', 0)}" if chain.get("checked") else ""))
    if result.get("inputs_digest"):
        print(f"INPUTS DIGEST {st('inputs')} {result.get('inputs_digest')}")
    else:
        print(f"INPUTS DIGEST {st('inputs')}")
    sig_status = st("signature")
    if sig_status == "FAIL":
        print(f"SIGNATURE FAIL —— {result.get('signature_reason') or result.get('reason')}")
    elif sig_status == "NOT CHECKED":
        print("SIGNATURE NOT CHECKED")
    else:
        trust = ("pinned (key matches supplied pin; independent key_id verification not done)"
                 if result.get("signature_trust") == "pinned"
                 else "package self-check (NOT source trust)")
        print(f"SIGNATURE {sig_status} / {trust} / "
              f"key_id={result.get('signature_key_id') or '?'}")
    print(f"SIGNATURE PINNED {st('signature_pinned')}")
    computed_sha = result.get("package_sha256") or "NOT AVAILABLE"
    sha_status = st("package_sha")
    print(f"PACKAGE SHA256 computed={computed_sha} / external={sha_status}"
          + (f" expected={result.get('package_sha256_expected')}"
             if sha_status == "FAIL" else ""))
    if result.get("artifacts_digest_checked"):
        ext_status = st("artifacts_digest_external")
        line = (f"ARTIFACTS DIGEST manifest-internal {st('artifacts_digest_internal')} / "
                f"external {ext_status}")
        if ext_status == "FAIL":
            line += (f" expected={result.get('artifacts_digest_expected')} "
                     f"actual={result.get('artifacts_digest')}")
        print(line)
    else:
        print(f"ARTIFACTS DIGEST external NOT CHECKED")
    print(f"ANCHOR {st('anchor')}")
    if result.get("ok"):
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
                        help="包外记录的 zip SHA-256")
    parser.add_argument("--expect-artifacts-digest", dest="expect_artifacts_digest", default=None,
                        help="包外记录的 manifest.artifacts_digest")
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
        result = package_verify.verify_package(
            Path(args.package),
            public_keys=_public_keys(args.public_keys),
            expect_anchor=args.expect_anchor,
            expect_triple=args.expect_triple,
            expect_package_sha256=args.expect_package_sha256,
            expect_artifacts_digest=args.expect_artifacts_digest,
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
    return 2 if result.get("partial") else 1
