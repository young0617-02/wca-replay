"""附带缺陷 1 回归：从 wheel 内容跑通默认流程，证明打包没有漏模块。

这里不创建新 venv（会依赖网络），而是把 `uv build` 产出的 wheel 解压到临时目录，
让子进程只从该目录导入 `src`（PYTHONPATH 指向解压目录），从而验证：
  1) wheel 里确实有 `data/generator/make_synthetic.py`；
  2) 不指定数据目录，`gen → ingest → check → export → verify → replay` 全链路可跑通。
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)


def test_wheel_runs_default_flow_without_data_dir(tmp_path: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("需要 uv 构建 wheel")
    out_dir = tmp_path / "dist"
    built = _run(["uv", "build", "--wheel", "--out-dir", str(out_dir)],
                 cwd=ROOT, env=os.environ.copy())
    assert built.returncode == 0, built.stderr[-2000:]
    wheel = next(out_dir.glob("*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert "data/generator/make_synthetic.py" in names, "wheel 漏打包 make_synthetic"
    assert any(n.endswith("policies/RULE-PACK.md") for n in names)

    site = tmp_path / "site"
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(site)

    work = tmp_path / "work"
    work.mkdir()
    keyfile = tmp_path / "keys" / "ed25519.key"
    keyfile.parent.mkdir()
    from src import signing

    key = signing.generate_keypair()
    signing.write_private_key(keyfile, key)
    pubfile = keyfile.with_suffix(".pub")
    signing.write_public_key(pubfile, bytes(key.verify_key))

    env = os.environ.copy()
    env.pop("WCA_DATA_DIR", None)
    env["PYTHONPATH"] = str(site)
    env.update({
        "WCA_DB_BACKEND": "sqlite",
        "WCA_DB_PATH": str(tmp_path / "db" / "wca.sqlite3"),
        "WCA_DB_IDENTITY_PATH": str(tmp_path / "db" / "db_target.json"),
        "WCA_PACKAGES_DIR": str(tmp_path / "packages"),
        "WCA_REPORTS_DIR": str(tmp_path / "reports"),
        "WCA_UPLOAD_DIR": str(tmp_path / "uploads"),
        "WCA_USERS_PATH": str(tmp_path / "users.json"),
        "WCA_SIGNING_KEY_FILE": str(keyfile),
        "WCA_LLM_PROVIDER": "stub",
        "WCA_EMBEDDING_BACKEND": "bm25",
    })

    def wca(*argv: str) -> subprocess.CompletedProcess:
        return _run([sys.executable, "-c",
                     "import sys;from src.cli import main;sys.exit(main())", *argv],
                    cwd=work, env=env)

    assert wca("gen").returncode == 0
    assert (work / "data" / "raw").glob("*.csv")
    assert wca("ingest").returncode == 0
    assert wca("check").returncode == 0

    with sqlite3.connect(tmp_path / "db" / "wca.sqlite3") as conn:
        run_id = conn.execute(
            "SELECT run_id FROM run ORDER BY rowid DESC LIMIT 1").fetchone()[0]

    exported = wca("export", "--run", run_id)
    assert exported.returncode == 0, exported.stderr[-2000:]
    package = next((tmp_path / "packages").glob("*.zip"))
    with zipfile.ZipFile(package) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    triple = manifest["triple"]
    anchor = ",".join([str(manifest["schema"]).rsplit("-v", 1)[1],
                       triple["rule_pack_version"], triple["input_fingerprint"],
                       triple["conclusion_digest"]])
    sha = __import__("hashlib").sha256(package.read_bytes()).hexdigest()
    gates = ["--expect-anchor", anchor, "--expect-package-sha256", sha,
             "--expect-artifacts-digest", manifest["artifacts_digest"],
             "--expect-evidence-digest", manifest["evidence_digest"],
             "--public-key", str(pubfile)]

    verified = _run([sys.executable, "-c",
                     "import sys;from src.verify_pkg import main;sys.exit(main())",
                     str(package), *gates], cwd=work, env=env)
    assert verified.returncode == 0, (verified.stdout + verified.stderr)[-3000:]
    assert "RESULT OK" in verified.stdout + verified.stderr

    replayed = wca("replay", str(package), *gates)
    assert replayed.returncode == 0, (replayed.stdout + replayed.stderr)[-3000:]
    assert "RESULT OK" in replayed.stdout + replayed.stderr
