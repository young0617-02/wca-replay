"""Phase 3A：审批台账最小受控入口（校验 + CSV + CLI）。"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import load_base
from src import cli
from src.rules.approvals import (import_approval_csv, upsert_approval,
                                 validate_approval_record)
from src.rules.rulepack import RULE_PACK_V5


def _record() -> dict:
    return {
        "emp_id": "T-CMP", "doc_no": "深人社函〔2025〕003号",
        "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
        "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
        "region_code": "440300", "attachment_sha256": "c" * 64,
        "recorded_at": "2025-01-02T00:00:00+08:00",
    }


def test_valid_approval_record_passes_validation():
    assert validate_approval_record(_record()) == []


@pytest.mark.parametrize("field,value,keyword", [
    ("doc_no", "", "文号"),
    ("valid_from", "2026-01-01", "期限"),
    ("valid_to", "2024-12-31", "期限"),
    ("job_codes", "[]", "岗位"),
    ("region_code", "", "城市"),
    ("attachment_sha256", "not-a-sha256", "附件哈希"),
    ("regime", "standard", "工时制"),
])
def test_invalid_approval_fields_report_clear_errors(field, value, keyword):
    record = dict(_record(), **{field: value})
    errors = validate_approval_record(record)
    assert errors and keyword in "；".join(errors)


def test_upsert_rejects_invalid_record(conn, cfg):
    with pytest.raises(ValueError, match="附件哈希"):
        upsert_approval(conn, dict(_record(), attachment_sha256="bad"))


def test_csv_import_is_all_or_nothing(conn, cfg):
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    load_base(conn, cfg5)
    path = Path(cfg.data_dir) / "bad_approval.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "emp_id,doc_no,regime,valid_from,valid_to,job_codes,region_code,"
        "attachment_sha256,recorded_at\n"
        f"T-CMP,,comprehensive_monthly,2025-01-01,2025-12-31,"
        f'["warehouse_shift"],440300,{"c" * 64},2025-01-02T00:00:00+08:00\n',
        encoding="utf-8")
    with pytest.raises(ValueError, match="文号"):
        import_approval_csv(conn, path)
    assert conn.execute("SELECT COUNT(*) AS n FROM worktime_approval").fetchone()["n"] == 0


def _write_env(tmp_path: Path, conn, cfg) -> Path:
    path = tmp_path / "approval.env"
    path.write_text("\n".join([
        "WCA_DB_BACKEND=sqlite", f"WCA_DB_PATH={cfg.db_path}",
        f"WCA_DB_IDENTITY_PATH={tmp_path / 'db_target.json'}",
        f"WCA_DATA_DIR={cfg.data_dir}", f"WCA_REPORTS_DIR={cfg.reports_dir}",
        f"WCA_PACKAGES_DIR={cfg.packages_dir}", f"WCA_USERS_PATH={cfg.users_path}",
        f"WCA_UPLOAD_DIR={cfg.upload_dir}", "WCA_REGION_CODE=440300",
        f"WCA_RULE_PACK={RULE_PACK_V5}", "WCA_LLM_PROVIDER=stub",
        "WCA_EMBEDDING_BACKEND=bm25",
    ]) + "\n", encoding="utf-8")
    return path


def test_cli_approval_writes_valid_row_and_rejects_bad_hash(conn, cfg, tmp_path, capsys):
    cfg5 = replace(cfg, rule_pack_id=RULE_PACK_V5)
    load_base(conn, cfg5)
    env = _write_env(tmp_path, conn, cfg5)
    argv = ["--env", str(env), "approval", "--emp", "T-CMP", "--doc-no", "深人社函〔2025〕004号",
            "--regime", "comprehensive_monthly", "--valid-from", "2025-01-01",
            "--valid-to", "2025-12-31", "--job-codes", "warehouse_shift",
            "--region", "440300", "--attachment-sha256", "d" * 64]
    assert cli.main(argv) == 0
    row = conn.execute("SELECT * FROM worktime_approval WHERE doc_no = ?",
                       ("深人社函〔2025〕004号",)).fetchone()
    assert row is not None and row["region_code"] == "440300"
    assert json.loads(row["job_codes"]) == ["warehouse_shift"]

    bad = list(argv)
    bad[bad.index("d" * 64)] = "bad-hash"
    assert cli.main(bad) == 2
    assert "附件哈希" in capsys.readouterr().err
