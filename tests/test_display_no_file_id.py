"""0.4.6：客户可见展示不得出现数据库自增 file_id。"""
from __future__ import annotations

import json
from pathlib import Path

from src.anomaly import _with_rel_path
from src.ingest import import_rows
import src.api  # noqa: F401  先初始化 api，避免 web.routes 循环导入
from src.web.routes import _decorate_review_row

ROOT = Path(__file__).resolve().parent.parent


def test_index_template_uses_relative_paths_only():
    text = (ROOT / "src" / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "ref.file_id" not in text
    assert "i.file_id" not in text
    assert "ref.rel_path" in text
    assert "i.rel_path" in text


def test_review_line_refs_use_relative_paths():
    row = {"source_refs": json.dumps([
        {"file_id": 12, "rel_path": "2025-09/punch.csv", "line_no": 7},
        {"file_id": 13, "rel_path": "2025-09/schedule.csv", "line_no": 3},
    ])}
    out = _decorate_review_row(row)
    assert out["line_refs"] == "2025-09/punch.csv:7 · 2025-09/schedule.csv:3"


def test_anomaly_source_refs_drop_db_ids(conn, cfg):
    rows = import_rows(conn, cfg, "schedule", [{
        "emp_id": "T-STD", "work_date": "2025-09-02",
        "planned_start": "2025-09-02T09:00:00+08:00",
        "planned_end": "2025-09-02T18:00:00+08:00", "rest_minutes": 60,
    }], rel_path="inline://display")
    assert rows.file_id
    refs = _with_rel_path(conn, [{"file_id": rows.file_id, "line_no": 2}])
    assert refs == [{"rel_path": "inline://display", "line_no": 2}]
    assert all("file_id" not in ref for ref in refs)
