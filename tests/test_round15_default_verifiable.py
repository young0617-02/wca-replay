"""0.4.13：默认流程产物必须能被自家验算器正确判定（先红后绿）。

实测缺陷（0.4.12）：默认 `wca all` 导出 v2 无签名包，`wca-verify` 因
"缺少 manifest.inputs_digest" 判 `INPUTS FAIL`、exit 1。v2 契约从未包含该字段，
属于“字段因版本缺失”，只能是 NOT CHECKED / PARTIAL（exit 2）；
schema v3 缺字段才是真违约，必须继续 FAIL（exit 1）。
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import load_full_facts
from src import signing, verify_pkg
from src.engine import run_check
from src.evidence import export_package
from src.package_verify import verify_package
from src.util import canonical_json, manifest_checksum

ROOT = Path(__file__).resolve().parent.parent
HANDOFF = ROOT / "handoff" / "20261104-第十五轮整改"


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


@pytest.fixture
def unsigned_package(conn, cfg):
    """默认流程等价物：不传签名钥导出的 v2 包。"""
    load_full_facts(conn, cfg)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30),
                    notes="round15 default flow")
    manifest = export_package(conn, cfg, out.run_id, signing_key=None)
    return Path(manifest["package_zip"]), manifest


@pytest.fixture
def signed_package(conn, cfg):
    load_full_facts(conn, cfg)
    key = signing.generate_keypair()
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2026, 4, 30),
                    notes="round15 signed")
    manifest = export_package(conn, cfg, out.run_id, signing_key=key)
    return Path(manifest["package_zip"]), manifest, key


def test_default_unsigned_export_is_partial_not_fail(unsigned_package):
    """默认产物（v2 无签名）应可得 PARTIAL，而不是因版本缺字段 FAIL。"""
    path, manifest = unsigned_package
    assert str(manifest["schema"]).endswith("-v2")
    assert "inputs_digest" not in manifest, "v2 包按契约不写 inputs_digest"

    result = verify_package(path)
    assert result["checks"]["manifest"] == "OK", result
    assert result["checks"]["inputs"] == "NOT CHECKED", result
    assert result["inputs_digest_legacy"] is True, result
    assert result["ok"] is False, result
    assert result["partial"] is True, result
    assert "PARTIAL" in result["reason"], result["reason"]
    assert "INPUTS FAIL" not in result["reason"], result["reason"]


def test_v2_missing_inputs_digest_not_checked(unsigned_package):
    """旧版本缺字段必须明确标 NOT CHECKED，且不得进入 RESULT OK 门禁。"""
    path, _manifest = unsigned_package
    result = verify_package(path)
    assert result["checks"]["inputs"] == "NOT CHECKED", result
    assert result["inputs_digest_legacy"] is True, result
    assert result["ok"] is False, result
    assert result["partial"] is True, result


def test_unsigned_package_exit_code_is_2(unsigned_package):
    """无签名 v2 包的默认验算退出码必须是 2（PARTIAL），不是 1（FAIL）。"""
    path, _manifest = unsigned_package
    assert verify_pkg.main([str(path)]) == 2


def test_v3_missing_inputs_digest_still_fail(signed_package, tmp_path):
    """新版本（schema v3）缺 inputs_digest 仍是真违约，必须 FAIL exit 1。"""
    src, _manifest, _key = signed_package

    def mutate(files):
        manifest = json.loads(files["manifest.json"])
        assert manifest["schema"] == "wca-evidence-package-v3"
        manifest.pop("inputs_digest", None)
        # 去掉签名并重算 checksum，隔离出“字段缺失”这一项，避免先被验签拦截。
        manifest.pop("signature", None)
        manifest["schema"] = "wca-evidence-package-v3"
        manifest["manifest_checksum"] = manifest_checksum(manifest)
        files["manifest.json"] = canonical_json(manifest).encode("utf-8")
        return files

    mutated = _rezip(src, tmp_path / "v3-missing-inputs-digest.zip", mutate)
    result = verify_package(mutated)
    assert result["checks"]["inputs"] == "FAIL", result
    assert "缺少 manifest.inputs_digest" in result["reason"], result["reason"]
    assert result["ok"] is False, result
    assert result["partial"] is False, result


# ---------------------------------------------------------------------------
# 文档与实物口径必须与实测退出码一致
# ---------------------------------------------------------------------------

def test_docs_and_verifier_agree_on_unsigned_package():
    signing_doc = (ROOT / "docs" / "签名方案.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    template = (ROOT / "scripts" / "build_release.py").read_text(encoding="utf-8")

    assert "无签名仍通过" not in signing_doc
    assert "RESULT PARTIAL" in signing_doc
    assert "exit 2" in signing_doc
    assert "未配置私钥时仍导出 v2 无签名包" in readme
    assert "不能作为完整验收" in readme
    # 签名文件口径：只覆盖 5 个顶层文件，旧 wheel/旧包目录不在保护范围。
    assert "5 个顶层文件" in template or "5 个顶层文件" in readme
    assert "old-wheels/" in template and "old-packages/" in template
    assert "全部发行文件" not in template
    assert "文档写“无签名仍通过”" not in template


def test_handoff_docs_round15():
    if not HANDOFF.is_dir():
        pytest.skip("第十五轮交接目录尚未生成")
    unshipped = (HANDOFF / "未随交付清单.md").read_text(encoding="utf-8")
    old_wheels = (HANDOFF / "OLD-WHEELS.md").read_text(encoding="utf-8")
    freeze = (ROOT / "docs" / "冻结版本说明.md").read_text(encoding="utf-8")

    assert "源码随 wheel 提供" in unshipped
    assert "0.4.6" in old_wheels and "误用" in old_wheels
    assert "不可验证" in old_wheels
    assert "0.4.13" in freeze
    assert "0.4.12" in freeze and "未对外" in freeze
