"""Ed25519 签名/验签回归测试（先写测试，再实现）。

覆盖：
- 正常 v3 包 + 包内自洽验签 / replay；
- 改 manifest 字段（重算 checksum）仍被签名戳穿；
- 改结论 CSV（签名包内哈希）；
- 删审计事件；
- 攻击者自签未 pin / pin 后失败；
- v3 缺 signature；
- 轮换后旧包仍可验；
- --require-signature；
- keygen 不覆盖。
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import cli, signing
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay

DAY = date(2025, 9, 2)
SIGNATURE_FIELD = "signature"


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build_package(conn, cfg, key=None):
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
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="signature fixture")
    manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    return out, Path(manifest["package_zip"]), manifest


@pytest.fixture
def unsigned_packed(conn, cfg):
    return _build_package(conn, cfg)


@pytest.fixture
def signed_packed(conn, cfg):
    key = signing.generate_keypair()
    out, zip_path, manifest = _build_package(conn, cfg, key)
    return conn, cfg, out, zip_path, manifest, key


def _zip_manifest(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("manifest.json"))


def _unpack(zip_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    return dest


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


def _checksum(doc: dict) -> str:
    """独立实现：排除 checksum 与 signature 后重算。"""
    payload = {k: v for k, v in doc.items()
               if k not in ("manifest_checksum", SIGNATURE_FIELD)}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _mutate_manifest(pkg: Path, mutate, *, recompute: bool = False) -> dict:
    path = pkg / "manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    mutate(doc)
    if recompute:
        doc["manifest_checksum"] = _checksum(doc)
    path.write_text(json.dumps(doc, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return doc


def _run_verify(pkg: Path, *args: str):
    env = os.environ.copy()
    for name in ("WCA_PUBLIC_KEY", "WCA_REQUIRE_SIGNATURE"):
        env.pop(name, None)
    return subprocess.run([sys.executable, "verify.py", *args], cwd=pkg,
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=120, env=env)


def _public_file(tmp_path: Path, key, name: str = "pub") -> Path:
    path = tmp_path / name
    signing.write_public_key(path, key.verify_key.encode(), force=True)
    return path


def test_signed_package_v3_and_package_self_check(signed_packed, tmp_path):
    _, _, _, zip_path, manifest, key = signed_packed
    doc = _zip_manifest(zip_path)
    assert doc["schema"] == "wca-evidence-package-v3"
    assert doc["signature"]["alg"] == "Ed25519"
    assert doc["signature"]["key_id"] == signing.key_id_for_public_key(
        key.verify_key.encode())
    assert doc["signature"]["public_key_b64"] == signing.public_key_b64(
        key.verify_key.encode())
    assert manifest["signature"]["signature_b64"]

    pkg = _unpack(zip_path, tmp_path / "signed")
    proc = _run_verify(pkg)
    assert proc.returncode == 0
    assert "SIGNATURE OK" in proc.stdout
    assert "package self-check" in proc.stdout and "NOT source trust" in proc.stdout
    assert "RESULT OK" in proc.stdout

    res = replay(zip_path)
    assert res["ok"], res["reason"]
    assert res["signature_ok"] is True
    assert res["signature_trust"] == "package-self-check"


def test_manifest_tamper_with_recomputed_checksum_is_caught_by_signature(
        signed_packed, tmp_path):
    _, _, _, zip_path, _, _ = signed_packed
    pkg = _unpack(zip_path, tmp_path / "tamper-manifest")
    _mutate_manifest(pkg, lambda d: d["counts"].update(findings=d["counts"]["findings"] + 1),
                     recompute=True)
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "SIGNATURE FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    forged_zip = _rezip(zip_path, tmp_path / "forged-manifest.zip", lambda files: {
        **files,
        "manifest.json": (pkg / "manifest.json").read_bytes(),
    })
    res = replay(forged_zip)
    assert not res["ok"]
    assert res["signature_ok"] is False


def test_conclusion_csv_tamper_is_caught_by_artifact_hash(signed_packed, tmp_path):
    _, _, _, zip_path, _, _ = signed_packed

    def mutate(files):
        files["conclusions_final.csv"] = (
            files["conclusions_final.csv"].rstrip(b"\n") + b"\n"
            + b"T-STD,2025-09-02,forged,0,0,0,0,0,forged\n")
        return files

    forged = _rezip(zip_path, tmp_path / "forged-conclusions.zip", mutate)
    pkg = _unpack(forged, tmp_path / "forged-conclusions")
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "ARTIFACT FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(forged)
    assert not res["ok"]
    assert "ARTIFACT FAIL" in res["reason"]


def test_delete_audit_event_fails_chain_and_signature(signed_packed, tmp_path):
    _, _, _, zip_path, _, _ = signed_packed

    def mutate(files):
        lines = files["audit_chain.jsonl"].decode("utf-8").splitlines()
        files["audit_chain.jsonl"] = ("\n".join(lines[1:]) + "\n").encode("utf-8")
        return files

    forged = _rezip(zip_path, tmp_path / "forged-chain.zip", mutate)
    pkg = _unpack(forged, tmp_path / "forged-chain")
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "CHAIN FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout
    res = replay(forged)
    assert not res["ok"]


def test_attacker_self_signed_package_fails_with_external_pin(signed_packed, tmp_path):
    _, _, _, zip_path, _, original_key = signed_packed
    attacker = signing.generate_keypair()
    head = _zip_manifest(zip_path)["chain_verification"]["head_hash"]

    def mutate(files):
        doc = json.loads(files["manifest.json"])
        doc[SIGNATURE_FIELD] = signing.create_signature(doc, attacker, head)
        files["manifest.json"] = json.dumps(doc, ensure_ascii=False,
                                            sort_keys=True).encode("utf-8")
        return files

    forged = _rezip(zip_path, tmp_path / "attacker.zip", mutate)
    pkg = _unpack(forged, tmp_path / "attacker")
    no_pin = _run_verify(pkg)
    assert no_pin.returncode == 0, "无 pin 时包内自洽验签会通过，但必须提示非来源可信"
    assert "package self-check" in no_pin.stdout and "NOT source trust" in no_pin.stdout

    original_pub = _public_file(tmp_path, original_key, "original.pub")
    pinned = _run_verify(pkg, "--public-key", str(original_pub))
    assert pinned.returncode != 0
    assert "SIGNATURE FAIL" in pinned.stdout
    res = replay(forged, public_keys=[str(original_pub)])
    assert not res["ok"]
    assert res["signature_ok"] is False


def test_v3_without_signature_fails_even_without_require(signed_packed, tmp_path):
    _, _, _, zip_path, _, _ = signed_packed

    def mutate(files):
        doc = json.loads(files["manifest.json"])
        doc.pop(SIGNATURE_FIELD, None)
        files["manifest.json"] = json.dumps(doc, ensure_ascii=False,
                                            sort_keys=True).encode("utf-8")
        return files

    forged = _rezip(zip_path, tmp_path / "v3-no-sig.zip", mutate)
    pkg = _unpack(forged, tmp_path / "v3-no-sig")
    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "SIGNATURE FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout
    res = replay(forged)
    assert not res["ok"]
    assert res["signature_present"] is False


def test_rotation_old_and_new_packages_verify_with_their_own_pin(
        signed_packed, tmp_path):
    conn, cfg, out, old_zip, old_manifest, old_key = signed_packed
    old_copy = tmp_path / "old.zip"
    old_copy.write_bytes(old_zip.read_bytes())
    new_key = signing.generate_keypair()
    new_manifest = export_package(conn, cfg, out.run_id, signing_key=new_key)
    new_zip = Path(new_manifest["package_zip"])

    old_pub = _public_file(tmp_path, old_key, "old.pub")
    new_pub = _public_file(tmp_path, new_key, "new.pub")
    for zip_path, pub, key in ((old_copy, old_pub, old_key),
                               (new_zip, new_pub, new_key)):
        suffix = signing.key_id_for_public_key(key.verify_key.encode())[-8:]
        pkg = _unpack(zip_path, tmp_path / f"rot-{suffix}")
        proc = _run_verify(pkg, "--public-key", str(pub))
        assert proc.returncode == 0, proc.stdout
        assert "pinned" in proc.stdout
        res = replay(zip_path, public_keys=[str(pub)])
        assert res["ok"], res["reason"]
        assert res["signature_trust"] == "pinned"


def test_require_signature_fails_on_legacy_unsigned(unsigned_packed, tmp_path):
    _, zip_path, _ = unsigned_packed
    pkg = _unpack(zip_path, tmp_path / "unsigned")
    proc = _run_verify(pkg, "--require-signature")
    assert proc.returncode != 0
    assert "SIGNATURE FAIL" in proc.stdout
    res = replay(zip_path, require_signature=True)
    assert not res["ok"]
    assert res["signature_present"] is False


def test_keygen_refuses_overwrite_then_force(tmp_path):
    key_path = tmp_path / "ed25519.key"
    pub_path = tmp_path / "ed25519.pub"
    assert cli.main(["keygen", "--out", str(key_path), "--public-out", str(pub_path)]) == 0
    assert key_path.is_file() and pub_path.is_file()
    assert cli.main(["keygen", "--out", str(key_path), "--public-out", str(pub_path)]) == 1
    assert cli.main(["keygen", "--out", str(key_path), "--public-out", str(pub_path),
                     "--force"]) == 0


def _inputs_manifest(pkg: Path) -> dict:
    return json.loads((pkg / "inputs" / "manifest.json").read_text(encoding="utf-8"))


def _write_inputs_manifest(pkg: Path, doc: dict) -> None:
    (pkg / "inputs" / "manifest.json").write_text(
        json.dumps(doc, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def test_swap_input_csv_with_synced_manifest_fails_inputs_digest(signed_packed, tmp_path):
    """换掉 inputs CSV 并同步改登记表哈希：现有 INPUTS 逐文件检查会放过，输入摘要必须拦住。"""
    _, _, _, zip_path, _, _ = signed_packed
    pkg = _unpack(zip_path, tmp_path / "swap-input")
    im = _inputs_manifest(pkg)
    entry = next(e for e in im["entries"] if e["kind"] == "punch")
    target = pkg / entry["arcname"]
    original = target.read_bytes()
    forged = original.replace(b"T-STD", b"X-STD", 1)
    assert forged != original and len(forged) == len(original)
    target.write_bytes(forged)
    entry["sha256"] = hashlib.sha256(forged).hexdigest()
    _write_inputs_manifest(pkg, im)

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "INPUTS FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout

    res = replay(pkg)
    assert not res["ok"]
    assert "INPUTS FAIL" in res["reason"]


def test_tamper_inputs_manifest_only_fails_inputs_digest(signed_packed, tmp_path):
    """只改 inputs/manifest.json（不动 CSV/条目哈希）：登记表本身也必须被签名覆盖。"""
    _, _, _, zip_path, _, _ = signed_packed
    pkg = _unpack(zip_path, tmp_path / "tamper-inputs-manifest")
    im = _inputs_manifest(pkg)
    im["forged_note"] = "只改登记表"
    _write_inputs_manifest(pkg, im)

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "INPUTS FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout


@pytest.mark.parametrize("action", ["add", "remove"])
def test_add_or_remove_input_file_fails_inputs_digest(signed_packed, tmp_path, action):
    """inputs/ 多一个或少一个文件，输入摘要必须变化；不能只按登记表条目校验。"""
    _, _, _, zip_path, _, _ = signed_packed
    pkg = _unpack(zip_path, tmp_path / f"inputs-{action}")
    if action == "add":
        (pkg / "inputs" / "999-extra.csv").write_text("extra\n", encoding="utf-8")
    else:
        im = _inputs_manifest(pkg)
        (pkg / im["entries"][0]["arcname"]).unlink()

    proc = _run_verify(pkg)
    assert proc.returncode != 0
    assert "INPUTS FAIL" in proc.stdout
    assert "RESULT FAIL" in proc.stdout


def test_inputs_digest_normalizes_separators_and_preserves_case():
    """规范化只统一 `/`，不折叠大小写；排序按路径字节序。"""
    from src.signing import compute_inputs_digest, normalize_input_path

    assert normalize_input_path("inputs\\Foo.CSV") == "inputs/Foo.CSV"
    assert normalize_input_path("./inputs//a.csv") == "inputs/a.csv"
    sha_a, sha_b = "a" * 64, "b" * 64
    entries = [["inputs\\b.csv", sha_b], ["inputs/a.csv", sha_a]]
    assert compute_inputs_digest(entries) == compute_inputs_digest(
        [["inputs/a.csv", sha_a], ["inputs/b.csv", sha_b]])
    assert compute_inputs_digest([["inputs/foo.csv", sha_a]]) != \
        compute_inputs_digest([["inputs/Foo.csv", sha_a]])


def test_signed_package_with_external_pin_binds_inputs(signed_packed, tmp_path):
    """正常 v3 包 + 正确 pin：输入摘要与签名同时通过。"""
    _, _, _, zip_path, _, key = signed_packed
    pkg = _unpack(zip_path, tmp_path / "pinned-inputs")
    pub = _public_file(tmp_path, key, "pinned.pub")
    proc = _run_verify(pkg, "--public-key", str(pub))
    assert proc.returncode == 0, proc.stdout
    assert "INPUTS SIGNED OK" in proc.stdout
    assert "SIGNATURE OK (pinned" in proc.stdout
    assert "RESULT OK" in proc.stdout
