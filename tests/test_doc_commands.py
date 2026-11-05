"""机制 2：文档里的每条示例命令都必须被真跑，退出码与结论标签必须与文档一致。

红线（本测试会失败的情形）：

- 命令缺必需门禁参数（如 `--expect-evidence-digest`），但文档写 `RESULT OK` / `rc=0`；
- 实测退出码或 `RESULT ...` 标签与注释里的期望不一致；
- 示例命令没有写期望（无从比对）。

用环境变量 `WCA_DOC_COMMANDS_DIR=<交接目录>` 可把同一套断言指到旧交付，用于“先红”取证。
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CURRENT_HANDOFF = ROOT / "handoff" / "20261104-第十九轮整改"
BLOCK_RE = re.compile(r"```powershell\s*\n(.*?)```", re.S)
LABEL_RE = re.compile(r"RESULT (OK|PARTIAL|FAIL|INCOMPARABLE)")
RC_RE = re.compile(r"(?:rc=|exit(?: code)?\s*)(\d)")
REQUIRED_GATES = ("--public-key", "--expect-anchor", "--expect-package-sha256",
                  "--expect-artifacts-digest", "--expect-evidence-digest")


def handoff_dir() -> Path:
    return Path(os.environ.get("WCA_DOC_COMMANDS_DIR", CURRENT_HANDOFF))


def _doc_paths() -> list[Path]:
    base = handoff_dir()
    paths = [base / "README-验收.md", base / "release" / "README-验收.md",
             base / "docs" / "安全与证据链现状.md"]
    dist_readme = ROOT / "dist" / "wca-replay-0.4.17" / "README-验收.md"
    if dist_readme.is_file():
        paths.append(dist_readme)
    return [p for p in paths if p.is_file()]


def _facts(base: Path, role: str) -> dict:
    """事实全部从实物读取：包字节取自包内 manifest，锚点取自同角色 anchor 文件。"""
    package = base / "package" / f"{role}.zip"
    if not package.is_file():
        pytest.skip(f"交接目录缺少 {package}，无法逐条真跑示例命令")
    with zipfile.ZipFile(package) as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    anchor_files = sorted(base.glob(f"anchor-0.4.*-{role}.json"))
    if not anchor_files:
        pytest.skip(f"交接目录缺少 {role} 的锚点文件")
    anchor = json.loads(anchor_files[-1].read_text(encoding="utf-8"))
    return {
        "package": package,
        "public_key": base / "trusted-public-key.pub",
        "anchor": anchor["anchor"],
        "package_sha256": anchor["package_sha256"],
        "artifacts_digest": manifest["artifacts_digest"],
        "evidence_digest": manifest["evidence_digest"],
        "anchor_file": anchor_files[-1],
    }


def _role_of(command: str, base: Path) -> str:
    stems = {p.stem for p in (base / "package").glob("*.zip")}
    for stem in sorted(stems, key=len, reverse=True):
        if f"{stem}.zip" in command or f"<包" in command and stem == "confirmed":
            return stem
    return "confirmed"


def _commands(text: str) -> list[dict]:
    """把 powershell 块拆成逻辑命令，并收集其后的期望（注释优先，其次紧随的散文）。"""
    out: list[dict] = []
    for match in BLOCK_RE.finditer(text):
        block = match.group(1)
        logical: list[str] = []
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                logical.append("")
                continue
            if stripped.startswith("#"):
                logical.append(stripped)  # 注释保留，用于收集期望
                continue
            if logical and logical[-1] and logical[-1].rstrip().endswith("`"):
                logical[-1] = logical[-1].rstrip()[:-1].rstrip() + " " + stripped
            else:
                logical.append(stripped)
        for index, command in enumerate(logical):
            head = command.split()[0] if command.split() else ""
            is_verify = bool(re.match(r".*wca-verify(\.exe)?$", head))
            is_replay = bool(re.match(r".*wca(-replay)?(\.exe)?$", head)) and " replay " in \
                f" {command} "
            if not (is_verify or is_replay):
                continue
            expectation: list[str] = []
            for following in logical[index + 1:]:
                if not following:
                    break
                if following.startswith("#"):
                    expectation.append(following.lstrip("# ").strip())
                else:
                    break
            out.append({"command": command, "expected": " ".join(expectation),
                        "kind": "verify" if is_verify else "replay", "block_end": match.end()})
    # 代码块后紧跟的“期望：……”散文（发行 README 用这种写法）
    for match in BLOCK_RE.finditer(text):
        tail = text[match.end():]
        prose = re.search(r"期望[：:]([^。]*)", tail.split("```")[0].split("\n##")[0])
        if not prose:
            continue
        for item in out:
            if item["block_end"] == match.end() and not item["expected"]:
                item["expected"] = prose.group(1).strip()
    return out


def _map_token(token: str, base: Path, facts: dict) -> str:
    if token.startswith("-"):
        return token
    placeholders = {
        "<四/五段>": facts["anchor"],
        "<包SHA256>": facts["package_sha256"],
        "<artifacts_digest>": facts["artifacts_digest"],
        "<evidence_digest>": facts["evidence_digest"],
        "<固定公钥文件>": facts["public_key"].as_posix(),
        "<包外固定公钥>": facts["public_key"].as_posix(),
        "<包.zip>": facts["package"].as_posix(),
        "<包>.zip": facts["package"].as_posix(),
        "<包>": facts["package"].as_posix(),
    }
    if token in placeholders:
        return placeholders[token]
    for candidate in (base / token, base / Path(token).name):
        if candidate.is_file():
            return candidate.as_posix()
    return token


def _argv(command: str, base: Path) -> list[str]:
    facts = _facts(base, _role_of(command, base))
    tokens = shlex.split(command.replace("\\", "/"), posix=True)
    head, rest = tokens[0], tokens[1:]
    # 文档命令通常写 `wca replay <包> ...`；子命令名不是参数，避免重复传入。
    if rest and rest[0] == "replay":
        rest = rest[1:]
    rest = [_map_token(tok, base, facts) for tok in rest]
    # `python -m src.verify_pkg` 不执行 main()；按 console entry point 的方式调用。
    if "wca-verify" in head:
        return [sys.executable, "-c",
                "import sys; from src.verify_pkg import main; sys.exit(main(sys.argv[1:]))",
                *rest]
    return [sys.executable, "-m", "src.cli", "replay", *rest]


def _run(doc: Path) -> list[dict]:
    base = handoff_dir()
    results = []
    for item in _commands(doc.read_text(encoding="utf-8")):
        argv = _argv(item["command"], base)
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        results.append({**item, "rc": proc.returncode,
                        "output": (proc.stdout or "") + (proc.stderr or ""),
                        "doc": doc, "argv": argv})
    return results


def _assert_matches(result: dict) -> None:
    expected_text = result["expected"]
    assert expected_text, (
        f"{result['doc'].name}: 示例命令未写期望，无法比对：\n{result['command']}")
    rc_match = RC_RE.search(expected_text)
    expected_rc = int(rc_match.group(1)) if rc_match else None
    expected_labels = LABEL_RE.findall(expected_text)
    if expected_rc is None and expected_labels:
        # 散文期望只声明结论标签；退出码按标签的标准映射核对，避免把“变体说明”里的
        # exit 1/2/3 误当成本命令的期望。
        expected_rc = {"OK": 0, "PARTIAL": 2, "FAIL": 1, "INCOMPARABLE": 3}[expected_labels[0]]
    if expected_rc is not None:
        assert result["rc"] == expected_rc, (
            f"{result['doc'].name}: 退出码与文档不符\n命令：{result['command']}\n"
            f"文档期望 rc={expected_rc}，实测 rc={result['rc']}\n输出：\n{result['output']}")
    for label in expected_labels:
        assert f"RESULT {label}" in result["output"], (
            f"{result['doc'].name}: 结论标签与文档不符\n命令：{result['command']}\n"
            f"文档期望 RESULT {label}\n输出：\n{result['output']}")


@pytest.mark.parametrize("doc_index", range(4))
def test_documented_commands_execute_as_written(doc_index: int) -> None:
    docs = _doc_paths()
    if doc_index >= len(docs):
        pytest.skip("该文档在本交付中不存在")
    doc = docs[doc_index]
    results = _run(doc)
    assert results, f"{doc} 中未抽到任何 wca-verify/wca replay 示例命令（机制 2 失去覆盖）"
    for result in results:
        _assert_matches(result)


def test_missing_evidence_gate_yields_partial_exit_2() -> None:
    """A1 的运行时红线：声称 `RESULT OK` 的命令若缺 `--expect-evidence-digest`，
    真实结果只能是 `RESULT PARTIAL` exit 2。这条测试证明“文档写 OK 却不给该参数”必错。"""
    base = handoff_dir()
    facts = _facts(base, "engine-only")
    argv = [sys.executable, "-c",
            "import sys; from src.verify_pkg import main; sys.exit(main(sys.argv[1:]))",
            facts["package"].as_posix(),
            "--public-key", facts["public_key"].as_posix(),
            "--expect-anchor", facts["anchor"],
            "--expect-package-sha256", facts["package_sha256"],
            "--expect-artifacts-digest", facts["artifacts_digest"]]
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert proc.returncode == 2, (
        f"缺 --expect-evidence-digest 竟未降级为 PARTIAL：rc={proc.returncode}\n"
        f"{(proc.stdout or '') + (proc.stderr or '')}")
    assert "RESULT PARTIAL" in (proc.stdout or ""), (
        "缺 --expect-evidence-digest 时必须输出 RESULT PARTIAL：\n" + (proc.stdout or ""))


def test_commands_claiming_ok_carry_all_five_gates() -> None:
    """静态红线：写 `RESULT OK`/rc=0 的命令必须给全五项外部门禁（或完整 anchor 文件）。"""
    missing: list[str] = []
    for doc in _doc_paths():
        for item in _commands(doc.read_text(encoding="utf-8")):
            if "OK" not in item["expected"] and "rc=0" not in item["expected"]:
                continue
            if "--anchor-file" in item["command"]:
                continue
            absent = [gate for gate in REQUIRED_GATES if gate not in item["command"]]
            if absent:
                missing.append(f"{doc}: 缺 {absent}\n  {item['command']}")
    assert not missing, "文档示例命令声称通过但缺门禁参数：\n" + "\n".join(missing)


def test_five_gate_count_is_consistent() -> None:
    """A2：文档只能写“五项”，历史四项必须写明是 0.4.1–0.4.2 时代口径。"""
    status = (ROOT / "docs" / "安全与证据链现状.md").read_text(encoding="utf-8")
    signing = (ROOT / "docs" / "签名方案.md").read_text(encoding="utf-8")
    assert "五项" in status and "第五项" in status
    assert "0.4.1–0.4.2" in status or "0.4.1-0.4.2" in status
    assert "五项外部门禁" in signing
    for text in (status, signing):
        for bad in ("0.4.1 起四项", "0.4.1 起 四项", "共四项门禁"):
            assert bad not in text
