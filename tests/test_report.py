"""异常报表：SQLite 下 rc=0、内容与既有行格式一致、失败不留下半截文件。

PG 真实 rc=0 的用例在 test_postgres_integration.py（由 WCA_TEST_POSTGRES_URL 显式开启）。
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

import src.anomaly as anomaly
from src import cli
from src.anomaly import HEADER, build_anomalies, write_anomaly_report
from src.util import csv_safe_row


def _env_file(cfg, tmp_path: Path) -> Path:
    path = tmp_path / "report.env"
    path.write_text("\n".join([
        f"WCA_DB_BACKEND={cfg.db_backend}",
        f"WCA_DB_PATH={cfg.db_path}",
        f"WCA_DB_IDENTITY_PATH={cfg.db_identity_path}",
        f"WCA_DATA_DIR={cfg.data_dir}",
        f"WCA_REPORTS_DIR={cfg.reports_dir}",
        f"WCA_PACKAGES_DIR={cfg.packages_dir}",
        f"WCA_USERS_PATH={cfg.users_path}",
        f"WCA_UPLOAD_DIR={cfg.upload_dir}",
        "WCA_REGION_CODE=440300",
        f"WCA_RULE_PACK={cfg.rule_pack_id}",
        "WCA_LLM_PROVIDER=stub",
        "WCA_EMBEDDING_BACKEND=bm25",
        "WCA_SQLITE_SYNCHRONOUS=OFF",
    ]) + "\n", encoding="utf-8")
    return path


def _read_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def test_report_cli_rc0_on_sqlite_and_rows_match_anomalies(checked, tmp_path):
    conn, cfg, out = checked
    env = _env_file(cfg, tmp_path)
    rc = cli.main(["--env", str(env), "report"])
    assert rc == 0
    path = Path(cfg.reports_dir) / f"异常报表-{out.run_id}.csv"
    assert path.is_file()
    rows = _read_rows(path)
    expected = [HEADER] + [csv_safe_row(a.as_row()) for a in build_anomalies(conn, out.run_id)]
    assert rows == expected, "报表行必须与既有 AnomalyItem 行格式逐行一致"
    assert len(rows) == len(build_anomalies(conn, out.run_id)) + 1


def test_report_write_failure_keeps_old_file_and_leaves_no_partial(
        checked, tmp_path, monkeypatch):
    conn, cfg, out = checked
    target_dir = tmp_path / "report-out"
    target_dir.mkdir()
    target = target_dir / "report.csv"
    target.write_text("OLD-CONTENT", encoding="utf-8")

    class Boom:
        def writerow(self, _row):
            raise RuntimeError("simulated csv failure")

    monkeypatch.setattr(anomaly.csv, "writer", lambda _fh, **_kwargs: Boom())

    with pytest.raises(RuntimeError, match="simulated csv failure"):
        write_anomaly_report(conn, cfg, out.run_id, path=target)

    assert target.read_text(encoding="utf-8") == "OLD-CONTENT", "失败不得覆盖旧报表"
    assert set(p.name for p in target_dir.iterdir()) == {"report.csv"}, \
        "失败不得留下临时文件"
