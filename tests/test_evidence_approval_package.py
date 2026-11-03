"""Phase 3A：非空审批台账进入 v5 举证包，并可离线重放出同一三元组。"""

from __future__ import annotations

import csv
import json
import logging
import shutil
import zipfile
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conftest import EMPLOYEES, ORGS, punch, schedule
from src import cli, evidence
from src.config import Config
from src.engine import run_check
from src.evidence import export_package
from src.ingest import import_csv_file
from src.replay import replay
from src.rules.approvals import upsert_approval
from src.rules.rulepack import RULE_PACK_V5

DAY = date(2025, 9, 2)


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _approval() -> dict:
    return {
        "emp_id": "T-CMP", "doc_no": "深人社函〔2025〕001号",
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "a" * 64,
        "recorded_at": "2025-01-02T00:00:00+08:00",
    }


def _v5_cfg(cfg: Config) -> Config:
    return replace(cfg, rule_pack_id=RULE_PACK_V5)


def _seed(conn, cfg5: Config) -> None:
    cfg5.ensure_dirs()
    rows = {
        "org.csv": ("org", ORGS),
        "employee.csv": ("employee", EMPLOYEES),
        "schedule.csv": ("schedule", [
            schedule("T-STD", "2025-09-02", "2025-09-02T09:00:00+08:00",
                     "2025-09-02T19:00:00+08:00")]),
        "punch.csv": ("punch", [
            punch("T-STD", "2025-09-02T09:00:00+08:00", "in"),
            punch("T-STD", "2025-09-02T19:00:00+08:00", "out"),
        ]),
    }
    for name, (kind, data) in rows.items():
        path = cfg5.data_dir / name
        _write_csv(path, data)
        import_csv_file(conn, cfg5, path, kind=kind, rel_path=name)


def _rezip(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    files = mutate(files)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return dst


@pytest.fixture
def packed_with_approval(conn, cfg, tmp_path):
    cfg5 = _v5_cfg(cfg)
    _seed(conn, cfg5)
    upsert_approval(conn, _approval())
    out = run_check(conn, cfg5, start=DAY, end=DAY, notes="approval package")
    manifest = export_package(conn, cfg5, out.run_id)
    return conn, out, Path(manifest["package_zip"]), manifest, cfg5


def test_v5_package_contains_approval_ledger(packed_with_approval):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    assert manifest["inputs"]["approval_rows"] == 1
    assert manifest["inputs"]["approval_sha256"]
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        assert "inputs/000-approval.csv" in names
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
        approval_entries = [e for e in im["entries"] if e["kind"] == "approval"]
        assert len(approval_entries) == 1
        assert approval_entries[0]["arcname"] == "inputs/000-approval.csv"
        rows = list(csv.DictReader(zf.read("inputs/000-approval.csv").decode("utf-8")
                                   .splitlines()))
        assert rows and rows[0]["doc_no"] == "深人社函〔2025〕001号"
        assert rows[0]["job_codes"] == '["warehouse_shift"]'
        input_files = zf.read("input_files.csv").decode("utf-8")
        assert "approval_ledger.csv" in input_files


def test_export_near_cap_warns_but_still_succeeds(packed_with_approval, monkeypatch,
                                                   caplog):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_WARN_BYTES", 1)
    with caplog.at_level(logging.WARNING, logger="src.evidence"):
        warned = export_package(conn, cfg5, out.run_id)
    assert warned["inputs"]["warning"] is True
    assert warned["inputs"]["critical"] is False
    assert warned["inputs"]["warn_bytes"] == 1
    assert "接近上限" in warned["inputs"]["warning_message"]
    assert "接近输入上限" in caplog.text
    with zipfile.ZipFile(Path(warned["package_zip"])) as zf:
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
    assert im["warning"] is True
    assert im["critical"] is False
    assert im["warn_bytes"] == 1
    assert "接近上限" in im["warning_message"]


def test_export_below_warning_line_has_no_warning(packed_with_approval, monkeypatch):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_WARN_BYTES", 10_000_000)
    quiet = export_package(conn, cfg5, out.run_id)
    assert quiet["inputs"]["warning"] is False
    assert quiet["inputs"]["critical"] is False
    assert quiet["inputs"]["warning_message"] == ""


def test_export_over_critical_line_is_critical_but_still_succeeds(packed_with_approval,
                                                                  monkeypatch, caplog):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_WARN_BYTES", 1)
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_CRITICAL_BYTES", 1)
    with caplog.at_level(logging.ERROR, logger="src.evidence"):
        critical = export_package(conn, cfg5, out.run_id)
    assert critical["inputs"]["warning"] is True
    assert critical["inputs"]["critical"] is True
    assert critical["inputs"]["critical_bytes"] == 1
    assert "需人工确认" in critical["inputs"]["critical_message"]
    assert "接近硬上限" in caplog.text
    with zipfile.ZipFile(Path(critical["package_zip"])) as zf:
        im = json.loads(zf.read("inputs/manifest.json").decode("utf-8"))
    assert im["critical"] is True
    assert im["critical_bytes"] == 1
    assert "需人工确认" in im["critical_message"]


def test_cli_export_records_delivery_event_with_new_flag(packed_with_approval,
                                                        monkeypatch, capsys):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg5)
    ns = cli.build_parser().parse_args([
        "export", "--run", out.run_id, "--record-delivery-as", "rv1", "--no-inputs"])
    assert cli.cmd_export(ns) == 0
    printed = capsys.readouterr().out
    assert "登记交付事件" in printed and "非密码学签名" in printed

    row = conn.execute(
        "SELECT actor, action, run_id FROM audit_event WHERE action = 'evidence.sign' "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    assert (row["actor"], row["action"], row["run_id"]) == (
        "human:rv1", "evidence.sign", out.run_id)
    assert evidence.verify_chain(conn, cfg5).ok


def test_cli_export_prints_warning_but_returns_zero(packed_with_approval, monkeypatch, capsys):
    import argparse

    from src import cli
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg5)
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_WARN_BYTES", 1)
    args = argparse.Namespace(run=out.run_id, sign_as="", no_inputs=False)
    assert cli.cmd_export(args) == 0
    printed = capsys.readouterr().out
    assert "接近上限" in printed


def test_cli_export_prints_critical_but_returns_zero(packed_with_approval, monkeypatch, capsys):
    import argparse

    from src import cli
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    monkeypatch.setattr(cli, "_cfg", lambda args: cfg5)
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_WARN_BYTES", 1)
    monkeypatch.setattr(evidence, "EXPORT_INPUTS_CRITICAL_BYTES", 1)
    args = argparse.Namespace(run=out.run_id, sign_as="", no_inputs=False)
    assert cli.cmd_export(args) == 0
    printed = capsys.readouterr().out
    assert "需人工确认" in printed


def test_v5_package_with_approval_replays_same_triple(packed_with_approval):
    conn, out, zip_path, manifest, cfg5 = packed_with_approval
    res = replay(zip_path)
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]
    assert res["inputs_packed"] >= 5
    assert any(i["kind"] == "approval" for i in res["imports"])
    assert res["findings_actual"] == res["findings_expected"] == len(out.findings)


def test_tampered_approval_csv_breaks_replay(packed_with_approval, tmp_path):
    _, _, zip_path, _, _ = packed_with_approval

    def mutate(files):
        text = files["inputs/000-approval.csv"].decode("utf-8")
        files["inputs/000-approval.csv"] = text.replace("深人社函〔2025〕001号",
                                                        "深人社函〔2099〕999号").encode("utf-8")
        return files

    tampered = _rezip(zip_path, tmp_path / "tampered-approval.zip", mutate)
    res = replay(tampered)
    assert not res["ok"]
    assert "input_fingerprint" in res["mismatched_fields"]
    assert res["actual_triple"]["input_fingerprint"] != \
        res["expected_triple"]["input_fingerprint"]


def test_export_refuses_when_ledger_changed_after_run(conn, cfg, tmp_path):
    cfg5 = _v5_cfg(cfg)
    _seed(conn, cfg5)
    upsert_approval(conn, _approval())
    out = run_check(conn, cfg5, start=DAY, end=DAY)
    upsert_approval(conn, dict(_approval(), valid_to="2025-06-30"))
    with pytest.raises(ValueError, match="审批台账在 run 之后发生变化"):
        export_package(conn, cfg5, out.run_id)


def test_empty_ledger_package_still_replays_old_v5_shape(conn, cfg, tmp_path):
    """模拟 phase 2 的 v5 包：inputs/manifest 里没有 approval 条目。"""
    cfg5 = _v5_cfg(cfg)
    _seed(conn, cfg5)
    out = run_check(conn, cfg5, start=DAY, end=DAY)
    manifest = export_package(conn, cfg5, out.run_id)
    src = Path(manifest["package_zip"])

    def strip(files):
        im = json.loads(files["inputs/manifest.json"].decode("utf-8"))
        im["entries"] = [e for e in im["entries"] if e["kind"] != "approval"]
        files["inputs/manifest.json"] = json.dumps(im, ensure_ascii=False,
                                                   sort_keys=True).encode("utf-8")
        files.pop("inputs/000-approval.csv", None)
        return files

    legacy_shape = _rezip(src, tmp_path / "legacy-v5.zip", strip)
    res = replay(legacy_shape)
    assert res["ok"], res["reason"]
    assert res["actual_triple"] == res["expected_triple"]
