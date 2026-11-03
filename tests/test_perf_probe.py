"""性能探针的纯计算部分：分组、注入行数与百分位口径。

不启动 PG、不导入数据：规模实测在工具命令里跑，这里只守住“注入了什么”
和“P50/P95 用哪个口径”，避免探针自身变成不可复核的黑盒。
"""

from __future__ import annotations

import pytest

import tools.perf_probe as perf_probe
from tools.perf_probe import _build_scale_rows, _dense_groups, _timing

ACTIVE_PG_URL = "postgresql://probe@127.0.0.1:5927/wca_worktime"
TEMP_PG_URL = "postgresql://probe@127.0.0.1:5927/wca_perf_guard_order"


def test_dense_groups_cover_all_employees_without_gaps():
    groups = _dense_groups(1000)
    assert [g["group"] for g in groups] == [
        "comp_no_approval", "missing_punch", "overtime_cap",
        "multi_shift_no_plan", "device_conflict", "no_weekly_rest", "normal_baseline",
    ]
    assert [g["count"] for g in groups] == [200, 150, 100, 100, 50, 50, 350]
    assert groups[0]["from"] == 1 and groups[-1]["to"] == 1000
    for left, right in zip(groups, groups[1:]):
        assert left["to"] + 1 == right["from"]


def test_dense_rows_keep_the_declared_injection_shapes():
    files, meta = _build_scale_rows(1000, "2025-09", dense=True)
    assert meta["rows"] == {
        "org.csv": 2, "employee.csv": 1000,
        "schedule.csv": 22000, "punch.csv": 44300,
    }
    punches = files["punch.csv"][1]
    by_emp: dict[str, list[dict]] = {}
    for row in punches:
        by_emp.setdefault(row["emp_id"], []).append(row)

    assert len(by_emp["P0201"]) == 43       # 22 个工作日共 44 次，缺一条下班卡
    assert any(r["event_ts"].endswith("T23:00:00+08:00") for r in by_emp["P0351"])
    assert len(by_emp["P0451"]) == 46       # 21 个正常工作日 + 异常日 4 段打卡
    assert len(by_emp["P0551"]) == 45       # 正常 44 次 + 1 条设备冲突
    assert len(by_emp["P0601"]) == 48       # 正常 44 次 + 周末 4 次
    assert len(by_emp["P0651"]) == 44       # 对照：正常基线 22 个工作日 × 2


def test_percentiles_use_nearest_rank_and_report_sample_count():
    timing = _timing([float(i) for i in range(1, 11)])
    assert timing["n"] == 10
    assert timing["median_ms"] == 5.5
    assert timing["p50_ms"] == 5.0
    assert timing["p95_ms"] == 10.0
    assert timing["p99_ms"] == 10.0
    assert timing["min_ms"] == 1.0 and timing["max_ms"] == 10.0


def test_probe_refuses_active_database_before_connect_init_or_seed(monkeypatch):
    """H-02：配置指向活动库时，任何连接/建表/播种都不允许发生。"""
    calls: list[str] = []

    def forbidden(*_args, **_kwargs):
        calls.append("connect")
        raise AssertionError("活动库守卫失败前不应建立连接")

    monkeypatch.setattr(perf_probe, "connect", forbidden)
    monkeypatch.setattr(perf_probe, "init_db", lambda *_a, **_k: calls.append("init_db"))
    monkeypatch.setattr(perf_probe, "_seed_scale", lambda *_a, **_k: calls.append("seed"))

    with pytest.raises(SystemExit) as exc:
        perf_probe.main(["--pg-url", ACTIVE_PG_URL, "--employees", "5"])

    assert "拒绝执行" in str(exc.value.code)
    assert calls == []


def test_probe_guards_temp_database_before_connecting_and_initialising(monkeypatch):
    """先做配置层预检，再连接；连接后、init_db/播种前做实际库身份复核。"""
    events: list[str] = []

    real_precheck = perf_probe.assert_temporary_database

    def precheck(cfg):
        events.append("precheck")
        return real_precheck(cfg)

    class FakeConn:
        dialect = "postgres"

        def close(self):
            events.append("close")

    def fake_connect(cfg, *args, **kwargs):
        events.append(f"connect:provision={kwargs.get('provision')}")
        return FakeConn()

    def fake_postcheck(conn, cfg):
        events.append("postcheck")
        return "wca_perf_guard_order"

    def fake_match(cfg, actual):
        events.append("match")

    monkeypatch.setattr(perf_probe, "assert_temporary_database", precheck)
    monkeypatch.setattr(perf_probe, "connect", fake_connect)
    monkeypatch.setattr(perf_probe, "assert_connection_is_temporary", fake_postcheck)
    monkeypatch.setattr(perf_probe, "ensure_config_matches_actual", fake_match)
    monkeypatch.setattr(perf_probe, "init_db", lambda _conn: events.append("init_db"))
    monkeypatch.setattr(perf_probe, "_seed_scale",
                        lambda *_a, **_k: events.append("seed") or {})
    monkeypatch.setattr(perf_probe, "measure_batch",
                        lambda *_a, **_k: events.append("measure") or {"sql_statements": 0})

    assert perf_probe.main(["--pg-url", TEMP_PG_URL, "--employees", "2"]) == 0

    assert events == ["precheck", "connect:provision=False", "postcheck", "match",
                      "init_db", "seed", "measure", "close"]
