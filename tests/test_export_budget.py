"""导出输入预算的边界：低于/等于上限放行，超过 1 字节即拒绝。"""

from __future__ import annotations

import csv

import pytest

from src.evidence import (EXPORT_INPUTS_CRITICAL_BYTES, EXPORT_INPUTS_MAX_BYTES,
                          EXPORT_INPUTS_WARN_BYTES, check_input_budget,
                          input_budget_status)
from src.rules.approvals import APPROVAL_FIELDS
from tools.perf_probe import _build_scale_rows, _write_csv


def test_export_input_budget_is_12_mib_for_the_controlled_experiment():
    assert EXPORT_INPUTS_MAX_BYTES == 12 * 1024 * 1024 == 12_582_912
    assert EXPORT_INPUTS_WARN_BYTES == 10_485_760 + 524_288 == 11_010_048
    assert EXPORT_INPUTS_CRITICAL_BYTES == 11 * 1024 * 1024 + 524_288 == 12_058_624


def test_input_budget_below_warning_line_is_ok():
    assert input_budget_status(EXPORT_INPUTS_WARN_BYTES - 1) == "ok"
    assert input_budget_status(0) == "ok"


def test_input_budget_at_warning_line_and_between_warn_critical_is_warning():
    assert input_budget_status(EXPORT_INPUTS_WARN_BYTES) == "warning"
    assert input_budget_status(EXPORT_INPUTS_WARN_BYTES + 1) == "warning"
    assert input_budget_status(EXPORT_INPUTS_CRITICAL_BYTES - 1) == "warning"


def test_input_budget_at_critical_and_between_critical_cap_is_critical():
    assert input_budget_status(EXPORT_INPUTS_CRITICAL_BYTES) == "critical"
    assert input_budget_status(EXPORT_INPUTS_CRITICAL_BYTES + 1) == "critical"
    assert input_budget_status(EXPORT_INPUTS_MAX_BYTES) == "critical"


def test_input_budget_below_cap_is_allowed():
    check_input_budget(EXPORT_INPUTS_MAX_BYTES - 1)


def test_input_budget_equal_to_cap_is_allowed():
    check_input_budget(EXPORT_INPUTS_MAX_BYTES)


def test_measured_3000_approval_rows_input_is_warning_but_under_critical():
    """3,000 行实测 11,493,475 字节：落在 10.5–11.5 MiB 的 warning 档，仍可导出。"""
    total = 11_493_475
    assert input_budget_status(total) == "warning"
    assert EXPORT_INPUTS_CRITICAL_BYTES - total == 565_149
    assert EXPORT_INPUTS_MAX_BYTES - total == 1_089_437
    check_input_budget(total)


def test_input_budget_one_byte_over_cap_is_rejected():
    with pytest.raises(ValueError) as exc:
        check_input_budget(EXPORT_INPUTS_MAX_BYTES + 1)
    message = str(exc.value)
    assert f"{EXPORT_INPUTS_MAX_BYTES + 1:,}" in message
    assert f"{EXPORT_INPUTS_MAX_BYTES:,}" in message
    assert "超过预算" in message


def test_3000_scale_input_bytes_with_nonempty_ledger_stay_under_12_mib(tmp_path):
    """3,000 员工月 + 450 行审批台账的输入体积仍应低于 12 MiB。

    这是输入字节边界的纯计算测试；包内 approval 条目与 manifest 的装配由
    `tests/test_evidence_approval_package.py` 的非空台账用例守住。
    """
    files, _ = _build_scale_rows(3000, "2025-09", dense=True)
    for name, (_kind, rows) in files.items():
        _write_csv(tmp_path / name, rows)
    total = sum((tmp_path / name).stat().st_size for name in files)

    ledger = tmp_path / "000-approval.csv"
    with ledger.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(APPROVAL_FIELDS), lineterminator="\n")
        writer.writeheader()
        for i in range(450):
            writer.writerow({
                "emp_id": f"P{i + 1:04d}", "doc_no": f"PERF-AP-2025-{i + 1:04d}",
                "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
                "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
                "region_code": "440300", "attachment_sha256": "a" * 64,
                "recorded_at": "2025-01-02T00:00:00+08:00",
            })
    total += ledger.stat().st_size

    assert total > 10_881_370                  # 台账非空，确实增加了字节
    assert total == 10_966_963                 # 450 行样本的实测输入总量
    assert EXPORT_INPUTS_WARN_BYTES - total == 43_085
    assert total < EXPORT_INPUTS_MAX_BYTES
    assert EXPORT_INPUTS_MAX_BYTES - total > 1_000_000
    check_input_budget(total)


def test_600_person_full_ledger_does_not_cross_warning_line(tmp_path):
    """600 人全量台账实测输入 10,995,463 字节，距 10.5 MiB 告警线 14,585 字节。"""
    files, _ = _build_scale_rows(3000, "2025-09", dense=True)
    for name, (_kind, rows) in files.items():
        _write_csv(tmp_path / name, rows)
    total = sum((tmp_path / name).stat().st_size for name in files)

    ledger = tmp_path / "000-approval.csv"
    with ledger.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(APPROVAL_FIELDS), lineterminator="\n")
        writer.writeheader()
        for i in range(600):
            writer.writerow({
                "emp_id": f"P{i + 1:04d}", "doc_no": f"PERF-AP-2025-{i + 1:04d}",
                "regime": "comprehensive_monthly", "valid_from": "2025-01-01",
                "valid_to": "2025-12-31", "job_codes": '["warehouse_shift"]',
                "region_code": "440300", "attachment_sha256": "a" * 64,
                "recorded_at": "2025-01-02T00:00:00+08:00",
            })
    total += ledger.stat().st_size

    assert total == 10_995_463
    assert EXPORT_INPUTS_WARN_BYTES - total == 14_585
    assert total < EXPORT_INPUTS_WARN_BYTES
    check_input_budget(total)

