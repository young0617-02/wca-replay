"""外部重放（US-EX-01 / A8）：包必须自带输入，且重放能把三元组比回来。

这些测试的方向和别处相反：**先证明重放能过，再证明它会被真改动打破**。
后者才是"自含输入"的意义——如果换个输入它照样报一致，那这条命令就是摆设。
"""

from __future__ import annotations

import csv
import json
import zipfile
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src.evidence import export_package
from src.engine import run_check
from src.ingest import import_csv_file as ingest_csv
from src.replay import replay

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


@pytest.fixture
def packed(conn, cfg):
    """真落盘的 4 个输入文件 -> 导入 -> 校验 -> 导出一个自含输入的举证包。

    `rel_path` 用裸文件名，导出时才会解析到 `cfg.data_dir` 下的这份文件本身
    （不是仓库里那批演示数据），重放才有意义。
    """
    cfg.ensure_dirs()
    rows = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [schedule("T-STD", "2025-09-02",
                                               "2025-09-02T09:00:00+08:00",
                                               "2025-09-02T19:00:00+08:00")]),
        "punch.csv": ("punch", [punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
                                 punch("T-STD", "2025-09-02T19:00:00+08:00", "out")]),
    }
    for name, (kind, data) in rows.items():
        _write_csv(cfg.data_dir / name, data)
        ingest_csv(conn, cfg, cfg.data_dir / name, kind=kind, rel_path=name)
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="replay fixture")
    manifest = export_package(conn, cfg, out.run_id)
    return out, Path(manifest["package_zip"]), manifest


def _unpack(zip_path: Path, into: Path) -> Path:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(into)
    return into


def test_package_carries_the_inputs_it_actually_used(packed):
    out, zip_path, manifest = packed
    inputs = manifest["inputs"]
    assert inputs["packed"] == 4, "主数据 + 排班 + 打卡都要进包，少一个就重放不回来"
    assert inputs["missing"] == [] and inputs["reason"] == ""
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        for n in ("org.csv", "employee.csv", "schedule.csv", "punch.csv"):
            assert any(x.startswith("inputs/") and x.endswith(n) for x in names), n
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        assert im["selection_rule"].startswith("主数据")
        assert all(e["sha256"] for e in im["entries"])


def test_replay_reproduces_the_triple_from_the_package_alone(packed, tmp_path):
    out, zip_path, manifest = packed
    res = replay(zip_path)
    assert res["ok"], res["reason"]
    assert res["chain"]["ok"] and res["chain"]["length"] >= 3
    assert res["actual_triple"] == res["expected_triple"]
    assert res["findings_actual"] == res["findings_expected"] == len(out.findings)
    assert res["inputs_packed"] == 4
    assert res["pinned_params"]["cross_day_cut_hour"] == 7, "口径参数必须从包里钉回来"
    # 重放是在临时库里重建事实，不是复用原库
    assert {i["kind"] for i in res["imports"]} == {"org", "employee", "schedule", "punch"}


def test_replay_survives_a_directory_package(packed, tmp_path):
    _, zip_path, _ = packed
    d = _unpack(zip_path, tmp_path / "unpacked")
    assert replay(d)["ok"] is True, "复核方常常已经解压过，目录形式也必须能重放"


def test_replay_catches_a_swapped_input_file(packed, tmp_path):
    """把打卡收工从 19:00 改成 22:00（多 180 分钟）——重放必须算出不同的结论摘要。"""
    _, zip_path, manifest = packed
    d = _unpack(zip_path, tmp_path / "tamper")
    target = next(e for e in json.loads((d / "inputs" / "manifest.json")
                                        .read_text(encoding="utf-8"))["entries"]
                  if e["kind"] == "punch")
    path = d / target["arcname"]
    text = path.read_text(encoding="utf-8").replace("2025-09-02T19:00:00+08:00",
                                                    "2025-09-02T22:00:00+08:00")
    path.write_text(text, encoding="utf-8")

    res = replay(d)
    assert not res["ok"], "换了输入还报一致，这条命令就是摆设"
    assert "conclusion_digest" in res["mismatched_fields"] or \
        "input_fingerprint" in res["mismatched_fields"]
    assert res["actual_triple"]["conclusion_digest"] != \
        manifest["triple"]["conclusion_digest"]


def test_replay_catches_a_broken_audit_chain(packed, tmp_path):
    _, zip_path, _ = packed
    d = _unpack(zip_path, tmp_path / "chain")
    lines = (d / "audit_chain.jsonl").read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["actor"] = "system:没这号人"
    lines[1] = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    (d / "audit_chain.jsonl").write_text(chr(10).join(lines) + chr(10), encoding="utf-8")

    res = replay(d)
    assert not res["ok"] and not res["chain"]["ok"]
    assert res["chain"]["broken_at_seq"] == event["seq"], "必须指出断在第几条"


def test_no_inputs_package_reports_why_it_cannot_be_replayed(conn, cfg):
    cfg.ensure_dirs()
    _write_csv(cfg.data_dir / "org.csv", ORGS)
    _write_csv(cfg.data_dir / "employee.csv", EMPLOYEES)
    ingest_csv(conn, cfg, cfg.data_dir / "org.csv", kind="org", rel_path="org.csv")
    ingest_csv(conn, cfg, cfg.data_dir / "employee.csv", kind="employee",
               rel_path="employee.csv")
    out = run_check(conn, cfg, start=DAY, end=DAY, notes="no-inputs")
    manifest = export_package(conn, cfg, out.run_id, include_inputs=False)
    assert manifest["inputs"]["packed"] == 0
    assert "无法离线重放" in manifest["inputs"]["reason"]
    res = replay(Path(manifest["package_zip"]))
    assert not res["ok"]
    assert "没有可重放的原始输入" in res["reason"], "不能假装重放通过"


def test_replay_refuses_a_different_rule_pack(packed, monkeypatch):
    """版本守卫：包是 v4 算的就用 v4 的代码比；换版本的差异必须走 REV 对账，不能靠重放掩盖。"""
    _, zip_path, _ = packed
    monkeypatch.setattr("src.replay._current_rule_pack", lambda: "rp-someother.v9")
    res = replay(zip_path)
    assert not res["ok"] and "规则包版本不一致" in res["reason"]
    assert res["chain"]["ok"], "链本身还是完整的，拒的是版本而不是数据"
