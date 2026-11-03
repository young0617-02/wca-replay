"""P0-1/P0-2 回归：工件绑定、独立验算器与七种坏包。"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import cli, signing
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay
from src.util import canonical_json, manifest_checksum, sha256_hex

DAY = date(2025, 9, 2)
ROOT = Path(__file__).resolve().parent.parent


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build_signed(conn, cfg, tmp_path: Path):
    cfg.ensure_dirs()
    files = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [schedule(
            "T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
            "2025-09-02T19:00:00+08:00")]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T19:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, rows) in files.items():
        path = cfg.data_dir / name
        _write_csv(path, rows)
        import_csv_file(conn, cfg, path, kind=kind, rel_path=name)
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="binding fixture")
    key = signing.generate_keypair()
    manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    pub = tmp_path / "pub.pub"
    signing.write_public_key(pub, key.verify_key.encode(), force=True)
    return out, Path(manifest["package_zip"]), manifest, key, pub


def _unpack(zip_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    return dest


def _manifest_of(package: Path) -> dict:
    path = package / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _anchor(manifest: dict) -> str:
    schema = str(manifest["schema"]).rsplit("-v", 1)[1]
    triple = manifest["triple"]
    return ",".join([schema, triple["rule_pack_version"], triple["input_fingerprint"],
                     triple["conclusion_digest"]])


def _verify(pkg: Path, *args: str, cwd: Path = ROOT) -> tuple[int, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, "-c",
         "from src.verify_pkg import main; import sys; sys.exit(main(sys.argv[1:]))",
         str(pkg), *args],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
    return proc.returncode, proc.stdout + proc.stderr


def _assert_both_fail(pkg: Path, pub: Path, anchor: str, *,
                      reason: str | None = None) -> tuple[str, str]:
    code, out = _verify(pkg, "--public-key", str(pub), "--expect-anchor", anchor)
    assert code != 0, out
    assert "RESULT FAIL" in out, out
    if reason:
        assert reason in out, out
    res = replay(pkg, expect_anchor=anchor, public_keys=[str(pub)])
    assert not res["ok"], res.get("reason")
    if reason:
        assert reason in str(res.get("reason") or ""), res.get("reason")
    return out, str(res.get("reason") or "")


def _unexpected_fail_lines(text: str, allowed: tuple[str, ...]) -> list[str]:
    """只允许与实际改动对应的 FAIL 标签；其余任何带 FAIL 的行都算误报。"""
    bad: list[str] = []
    for line in text.splitlines():
        if "FAIL" not in line:
            continue
        if any(label in line for label in allowed):
            continue
        bad.append(line.strip())
    return bad


def _lines_starting(text: str, prefix: str) -> list[str]:
    """只统计以标签开头的检查行，避免把 RESULT 原因文本计入。"""
    return [line.strip() for line in text.splitlines() if line.strip().startswith(prefix)]


def test_good_package_passes_independent_verify(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    anchor = _anchor(manifest)
    code, out = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", sha256_hex(zip_path.read_bytes()),
                        "--expect-artifacts-digest", manifest["artifacts_digest"])
    assert code == 0, out
    assert "RESULT OK" in out and "pinned (key matches supplied pin" in out
    assert "来源可信" not in out, out
    assert "independent key_id verification not done" in out, out
    assert len(_lines_starting(out, "ARTIFACTS DIGEST")) == 1, out
    res = replay(zip_path, expect_anchor=anchor, public_keys=[str(pub)],
                 expect_package_sha256=sha256_hex(zip_path.read_bytes()),
                 expect_artifacts_digest=manifest["artifacts_digest"])
    assert res["ok"], res["reason"]
    assert res["partial"] is False, res["reason"]
    assert res["producer_ok"] is True


def test_a_findings_severity_change_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "a")
    path = pkg / "findings.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"), newline="")))
    rows[0]["severity"] = "DEFENSIBLE" if rows[0]["severity"] != "DEFENSIBLE" else "REVIEW"
    rows[0]["severity_label"] = "可申辩" if rows[0]["severity"] == "DEFENSIBLE" else "需复核"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "ARTIFACT" in out or "FINDINGS" in out or "结论" in out
    assert "ARTIFACT" in reason or "FINDINGS" in reason or "结论" in reason
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out
    assert len(_lines_starting(out, "ARTIFACTS DIGEST")) == 1, out


def test_a2_findings_change_with_recomputed_artifacts_fails_digest(conn, cfg, tmp_path):
    """即使攻击者同步更新工件哈希/清单摘要/checksum 并重签，findings 反算摘要仍要戳穿。"""
    _out, zip_path, manifest, key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "a2")
    path = pkg / "findings.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"), newline="")))
    rows[0]["severity"] = "DEFENSIBLE" if rows[0]["severity"] != "DEFENSIBLE" else "REVIEW"
    rows[0]["severity_label"] = "可申辩" if rows[0]["severity"] == "DEFENSIBLE" else "需复核"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    doc = _manifest_of(pkg)
    doc["artifact_sha256"]["findings.csv"] = sha256_hex(path.read_bytes())
    doc["artifacts_digest"] = signing.artifact_digest(doc["artifact_sha256"])
    doc["manifest_checksum"] = manifest_checksum(doc)
    doc["signature"] = signing.create_signature(
        doc, key, str(doc["chain_verification"]["head_hash"]))
    (pkg / "manifest.json").write_text(canonical_json(doc) + "\n", encoding="utf-8")

    code, out = _verify(pkg, "--public-key", str(pub), "--expect-anchor", _anchor(manifest))
    assert code != 0, out
    assert "FINDINGS DIGEST FAIL" in out, out
    assert _unexpected_fail_lines(out, ("FINDINGS DIGEST FAIL", "RESULT FAIL")) == [], out
    res = replay(pkg, expect_anchor=_anchor(manifest), public_keys=[str(pub)])
    assert not res["ok"]
    assert "FINDINGS DIGEST" in str(res.get("reason") or "")


def test_h_source_line_no_change_fails_by_artifact_hash(conn, cfg, tmp_path):
    """H：source_line_no 不在 conclusion_digest 内，但必须被文件级 SHA-256 捕获。"""
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "h")
    path = pkg / "findings.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"), newline="")))
    rows[0]["source_line_no"] = "999999"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "ARTIFACT FAIL" in out, out
    assert "ARTIFACT FAIL" in reason, reason
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out


def test_b_input_timestamp_change_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "b")
    inputs = json.loads((pkg / "inputs" / "manifest.json").read_text(encoding="utf-8"))
    punch_entry = next(e for e in inputs["entries"] if e["kind"] == "punch")
    path = pkg / punch_entry["arcname"]
    path.write_text(path.read_text(encoding="utf-8").replace(
        "2025-09-02T19:00:00+08:00", "2025-09-02T22:00:00+08:00"), encoding="utf-8")
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "INPUTS" in out or "INPUT" in out
    assert "INPUTS" in reason or "INPUT" in reason
    assert _unexpected_fail_lines(out, ("INPUTS DIGEST FAIL", "RESULT FAIL")) == [], out


def test_c_extra_confirmed_conclusion_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "c")
    path = pkg / "conclusions_final.csv"
    path.write_text(path.read_text(encoding="utf-8")
                    + "OT-D01,E001,2025-09-02,,REVIEW,confirm,auditor,2026-01-01,x\n",
                    encoding="utf-8")
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "ARTIFACT" in out or "CONCLUSION" in out
    assert "ARTIFACT" in reason or "CONCLUSION" in reason
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out


def test_d_replaced_verify_script_is_not_executed(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "d")
    marker = pkg / "PWNED"
    (pkg / "verify.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
        "print('RESULT OK')\n",
        encoding="utf-8")
    code, out = _verify(pkg, "--public-key", str(pub), "--expect-anchor", _anchor(manifest),
                        )
    assert code != 0, out
    assert "VERIFY SCRIPT FAIL" in out, out
    assert not marker.exists(), "独立验算器执行了包内 verify.py"
    res = replay(pkg, expect_anchor=_anchor(manifest), public_keys=[str(pub)])
    assert not res["ok"]
    assert "VERIFY SCRIPT" in str(res.get("reason") or "")
    assert _unexpected_fail_lines(out, ("VERIFY SCRIPT FAIL", "RESULT FAIL")) == [], out


def test_e_deleted_findings_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "e")
    (pkg / "findings.csv").unlink()
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "ARTIFACT" in out or "FINDINGS" in out
    assert "ARTIFACT" in reason or "FINDINGS" in reason
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out


def test_f_extra_file_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "f")
    (pkg / "extra.txt").write_text("smuggled", encoding="utf-8")
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "EXTRA" in out or "UNDECLARED" in out or "ARTIFACT" in out
    assert "EXTRA" in reason or "UNDECLARED" in reason or "ARTIFACT" in reason
    assert _unexpected_fail_lines(out, ("EXTRA FILE FAIL", "RESULT FAIL")) == [], out


def test_g_not_covered_markdown_change_fails_both(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "g")
    path = pkg / "未覆盖清单.md"
    path.write_text(path.read_text(encoding="utf-8") + "\n- 伪造说明\n", encoding="utf-8")
    out, reason = _assert_both_fail(pkg, pub, _anchor(manifest))
    assert "ARTIFACT" in out
    assert "ARTIFACT" in reason
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out


def test_missing_anchor_is_partial_not_ok(conn, cfg, tmp_path, capsys):
    _out, zip_path, _manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    code, out = _verify(zip_path, "--public-key", str(pub))
    assert code != 0, out
    assert "ANCHOR NOT CHECKED" in out, out
    assert "RESULT PARTIAL" in out, out
    assert "RESULT OK" not in out, out

    cli_code = cli.main(["replay", str(zip_path), "--public-key", str(pub)])
    cli_out = capsys.readouterr().out
    assert cli_code != 0, cli_out
    assert "ANCHOR NOT CHECKED" in cli_out, cli_out
    assert "RESULT PARTIAL" in cli_out, cli_out
    assert "重放结果：一致" not in cli_out, cli_out


def test_package_sha_and_artifacts_digest_are_enforced(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    anchor = _anchor(manifest)
    package_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    artifacts_digest = manifest["artifacts_digest"]
    code, out = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", package_sha,
                        "--expect-artifacts-digest", artifacts_digest)
    assert code == 0, out
    assert "external=OK" in out
    assert "manifest-internal OK / external OK" in out

    code, out = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", "0" * 64)
    assert code != 0 and "PACKAGE SHA256 FAIL" in out, out
    assert len(_lines_starting(out, "ARTIFACTS DIGEST")) == 1, out

    bad_digest = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                         "--expect-package-sha256", package_sha,
                         "--expect-artifacts-digest", "0" * 64)
    assert bad_digest[0] != 0, bad_digest[1]
    assert "ARTIFACTS DIGEST" in bad_digest[1], bad_digest[1]
    assert len(_lines_starting(bad_digest[1], "ARTIFACTS DIGEST")) == 1, bad_digest[1]
    digest_line = next(line for line in bad_digest[1].splitlines()
                       if "ARTIFACTS DIGEST" in line)
    assert "manifest-internal OK / external FAIL" in digest_line, digest_line
    assert f"expected={'0' * 64}" in digest_line, digest_line
    assert f"actual={artifacts_digest}" in digest_line, digest_line

    res = replay(zip_path, expect_anchor=anchor, public_keys=[str(pub)],
                 expect_package_sha256=package_sha,
                 expect_artifacts_digest=artifacts_digest)
    assert res["ok"], res["reason"]
    bad = replay(zip_path, expect_anchor=anchor, public_keys=[str(pub)],
                 expect_package_sha256="0" * 64)
    assert not bad["ok"] and "PACKAGE SHA256 FAIL" in bad["reason"]


def test_result_ok_requires_four_external_gates(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    anchor = _anchor(manifest)
    package_sha = sha256_hex(zip_path.read_bytes())
    digest = manifest["artifacts_digest"]

    code, out = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", package_sha,
                        "--expect-artifacts-digest", digest)
    assert code == 0 and "RESULT OK" in out, out

    no_key = _verify(zip_path, "--expect-anchor", anchor,
                     "--expect-package-sha256", package_sha,
                     "--expect-artifacts-digest", digest)
    assert no_key[0] != 0, no_key[1]
    assert "RESULT OK" not in no_key[1] and "RESULT PARTIAL" in no_key[1], no_key[1]
    assert "package self-check (NOT source trust)" in no_key[1], no_key[1]
    assert "external=OK" in no_key[1], no_key[1]
    assert "来源可信" not in no_key[1], no_key[1]

    no_sha = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                     "--expect-artifacts-digest", digest)
    assert no_sha[0] != 0, no_sha[1]
    assert "RESULT OK" not in no_sha[1] and "RESULT PARTIAL" in no_sha[1], no_sha[1]
    assert "PACKAGE SHA256" in no_sha[1] and "external=NOT CHECKED" in no_sha[1], no_sha[1]
    assert "PACKAGE SHA256 OK" not in no_sha[1], no_sha[1]

    no_anchor = _verify(zip_path, "--public-key", str(pub),
                        "--expect-package-sha256", package_sha,
                        "--expect-artifacts-digest", digest)
    assert no_anchor[0] != 0, no_anchor[1]
    assert "RESULT OK" not in no_anchor[1] and "RESULT PARTIAL" in no_anchor[1], no_anchor[1]
    anchor_line = next(line for line in no_anchor[1].splitlines() if "ANCHOR" in line)
    assert "NOT CHECKED" in anchor_line and "未传外部锚点" in anchor_line, anchor_line

    no_digest = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", package_sha)
    assert no_digest[0] != 0, no_digest[1]
    assert "RESULT OK" not in no_digest[1] and "RESULT PARTIAL" in no_digest[1], no_digest[1]
    assert "外部 artifacts_digest" in no_digest[1], no_digest[1]


def test_anchor_file_fallback_and_explicit_priority(conn, cfg, tmp_path, capsys):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    record = {
        "anchor": _anchor(manifest),
        "package_sha256": sha256_hex(zip_path.read_bytes()),
        "artifacts_digest": manifest["artifacts_digest"],
    }
    anchor_file = tmp_path / "anchor-single.json"
    anchor_file.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")

    code, out = _verify(zip_path, "--public-key", str(pub),
                        "--anchor-file", str(anchor_file))
    assert code == 0 and "RESULT OK" in out, out

    # 显式参数优先：文件里故意放错包 SHA，显式值正确时仍应通过。
    bad_record = dict(record, package_sha256="0" * 64)
    bad_file = tmp_path / "anchor-bad-sha.json"
    bad_file.write_text(json.dumps(bad_record, ensure_ascii=False), encoding="utf-8")
    code, out = _verify(zip_path, "--public-key", str(pub),
                        "--anchor-file", str(bad_file),
                        "--expect-package-sha256", record["package_sha256"])
    assert code == 0 and "RESULT OK" in out, out

    # 组合式 anchor.json 含多个包时必须拒绝，避免套错哈希。
    combo = tmp_path / "anchor-combined.json"
    combo.write_text(json.dumps({"packages": {"a": record}}, ensure_ascii=False),
                     encoding="utf-8")
    code, out = _verify(zip_path, "--public-key", str(pub),
                        "--anchor-file", str(combo))
    assert code != 0 and "组合式 anchor.json" in out, out

    cli_code = cli.main(["replay", str(zip_path), "--public-key", str(pub),
                         "--anchor-file", str(anchor_file)])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert cli_code == 0, text
    assert "RESULT OK" in text, text


def test_early_failure_has_only_relevant_fail_labels(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "early-a")
    path = pkg / "findings.csv"
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"), newline="")))
    rows[0]["severity"] = "DEFENSIBLE" if rows[0]["severity"] != "DEFENSIBLE" else "REVIEW"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    code, out = _verify(pkg, "--public-key", str(pub), "--expect-anchor", _anchor(manifest))
    assert code != 0 and "RESULT FAIL" in out, out
    assert "ARTIFACT" in out and "findings.csv" in out, out
    assert _unexpected_fail_lines(out, ("ARTIFACTS FAIL", "RESULT FAIL")) == [], out
    assert len(_lines_starting(out, "ARTIFACTS DIGEST")) == 1, out
    for label in ("VERIFY SCRIPT NOT CHECKED", "ARTIFACTS DIGEST", "SIGNATURE NOT CHECKED",
                  "ANCHOR NOT CHECKED"):
        line = next(line for line in out.splitlines() if label in line)
        assert "早退" in line, line
    anchor_line = next(line for line in out.splitlines() if "ANCHOR NOT CHECKED" in line)
    assert "非锚点缺失" in anchor_line, anchor_line


def test_external_artifacts_digest_failure_shows_internal_ok(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    anchor = _anchor(manifest)
    code, out = _verify(zip_path, "--public-key", str(pub), "--expect-anchor", anchor,
                        "--expect-package-sha256", sha256_hex(zip_path.read_bytes()),
                        "--expect-artifacts-digest", "0" * 64)
    assert code != 0, out
    assert len(_lines_starting(out, "ARTIFACTS DIGEST")) == 1, out
    line = next(line for line in out.splitlines() if "ARTIFACTS DIGEST" in line)
    assert "manifest-internal OK / external FAIL" in line, line
    assert "expected=0000000000000000000000000000000000000000000000000000000000000000" in line, line
    assert f"actual={manifest['artifacts_digest']}" in line, line


def test_replay_early_failure_does_not_report_chain_break_or_no_signature(conn, cfg, tmp_path, capsys):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    pkg = _unpack(zip_path, tmp_path / "replay-early")
    (pkg / "findings.csv").unlink()
    code = cli.main(["replay", str(pkg), "--public-key", str(pub),
                     "--expect-anchor", _anchor(manifest)])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert code != 0, text
    assert "CHAIN NOT CHECKED" in text, text
    assert "SIGNATURE NOT CHECKED" in text, text
    assert "断裂" not in text, text
    assert "签名：无" not in text, text
    assert "ANCHOR NOT CHECKED" in text and "早退" in text, text
    assert len(_lines_starting(text, "ARTIFACTS DIGEST")) == 1, text


def test_replay_wrong_anchor_reports_anchor_fail_not_not_checked(conn, cfg, tmp_path, capsys):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    anchor = _anchor(manifest)
    wrong = anchor[:-1] + ("0" if anchor[-1] != "0" else "1")
    code = cli.main(["replay", str(zip_path), "--public-key", str(pub),
                     "--expect-anchor", wrong])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert code != 0, text
    assert "ANCHOR FAIL" in text, text
    assert "ANCHOR NOT CHECKED" not in text, text
    assert "SIGNATURE FAIL" not in text, text
    assert "CHAIN NOT CHECKED" not in text, text


def test_replay_external_artifacts_digest_failure_shows_expected_actual(conn, cfg, tmp_path, capsys):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    code = cli.main(["replay", str(zip_path), "--public-key", str(pub),
                     "--expect-anchor", _anchor(manifest),
                     "--expect-package-sha256", sha256_hex(zip_path.read_bytes()),
                     "--expect-artifacts-digest", "0" * 64])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert code != 0, text
    assert len(_lines_starting(text, "ARTIFACTS DIGEST")) == 1, text
    line = next(line for line in text.splitlines() if "ARTIFACTS DIGEST" in line)
    assert "manifest-internal OK" in line and "external=FAIL" in line, line
    assert "expected=" + "0" * 64 in line, line
    assert f"actual={manifest['artifacts_digest']}" in line, line
    assert "ANCHOR NOT CHECKED" in text and "早退" in text, text


def test_missing_relative_public_key_reports_path_not_base64(conn, cfg, tmp_path):
    _out, zip_path, _manifest, _key, _pub = _build_signed(conn, cfg, tmp_path)
    code, out = _verify(zip_path, "--public-key", "missing-key.pub")
    assert code != 0
    assert "公钥文件不存在" in out, out
    assert "不是合法 Base64" not in out, out


def test_relative_public_key_resolves_from_caller_cwd(conn, cfg, tmp_path, monkeypatch):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    monkeypatch.chdir(tmp_path)
    code, out = _verify(zip_path, "--public-key", "pub.pub", "--expect-anchor",
                        _anchor(manifest), "--expect-package-sha256",
                        sha256_hex(zip_path.read_bytes()),
                        "--expect-artifacts-digest", manifest["artifacts_digest"],
                        cwd=tmp_path)
    assert code == 0, out
    assert "pinned (key matches supplied pin" in out, out


def test_row_count_is_data_rows_not_header_columns(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, _pub = _build_signed(conn, cfg, tmp_path)
    row = conn.execute("SELECT row_count FROM raw_file WHERE rel_path = ?",
                       ("employee.csv",)).fetchone()
    assert int(row["row_count"]) == len(EMPLOYEES), "row_count 必须是数据行数，不是表头列数"
    with zipfile.ZipFile(zip_path) as zf:
        rows = list(csv.DictReader(io.StringIO(
            zf.read("input_files.csv").decode("utf-8"), newline="")))
    employee_row = next(r for r in rows if r["rel_path"] == "employee.csv")
    assert int(employee_row["row_count"]) == len(EMPLOYEES)


def test_policies_are_in_package_and_hashed(conn, cfg, tmp_path):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    policy_names = {
        "policies/RULE-PACK.md", "policies/LAW-REFERENCES.md",
        "policies/口径声明-对外版.md", "policies/字段口径与条文依据-对外版.md",
        "policies/CONFIDENCE.md",
    }
    hashes = manifest.get("artifact_sha256") or {}
    assert policy_names <= set(hashes), sorted(hashes)
    assert len(hashes) == 14, len(hashes)
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert policy_names <= names, names
    code, out = _verify(zip_path, "--public-key", str(pub),
                        "--expect-anchor", _anchor(manifest),
                        "--expect-package-sha256", sha256_hex(zip_path.read_bytes()),
                        "--expect-artifacts-digest", manifest["artifacts_digest"])
    assert code == 0, out
    assert "ARTIFACTS OK checked=14" in out, out


def test_not_covered_has_no_stale_101_and_rule_versions_are_explained(conn, cfg, tmp_path):
    out, _zip_path, manifest, _key, _pub = _build_signed(conn, cfg, tmp_path)
    with zipfile.ZipFile(manifest["package_zip"]) as zf:
        md = zf.read("未覆盖清单.md").decode("utf-8")
    assert "101 条结论" not in md, "未覆盖清单仍保留历史 101 条口径"
    assert "发现（未签认）" in md
    expected_versions: dict[str, int] = {}
    for f in out.findings:
        expected_versions[f.rule_version] = expected_versions.get(f.rule_version, 0) + 1
    assert manifest["counts"]["rule_versions"] == expected_versions


def test_terminology_separates_findings_from_final_conclusions(conn, cfg, tmp_path, capsys):
    _out, zip_path, manifest, _key, pub = _build_signed(conn, cfg, tmp_path)
    cli_code = cli.main(["replay", str(zip_path), "--public-key", str(pub),
                         "--expect-anchor", _anchor(manifest),
                         "--expect-package-sha256", sha256_hex(zip_path.read_bytes()),
                         "--expect-artifacts-digest", manifest["artifacts_digest"]])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert cli_code == 0, text
    assert "发现（未签认）" in text
    assert "已确认结论" in text
    assert "结论条数" not in text
