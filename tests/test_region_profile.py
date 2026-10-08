"""三市分档（GAP-03）：广州 / 深圳 / 佛山 各按自己的条文集合出结论，代码里不留市名。

守四条：
  1. 地方倍数条文按**员工所属城市**挂，不同城市挂不同条文（需求 §7.3-3 禁止一套规则强盖多城）；
  2. 城市清单与市名只在 `config/region_profile.json`，`src/` 里不得出现市名或城市代码字面量（US-AD-06）；
  3. 未建档城市不猜适用法规，只出国家层面结论并记 SCOPE-04；
  4. 主体永远能看见自己那一城的本人条目——地域层级不能反过来把本人条目挡在门外。
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

from conftest import find, punch, schedule
from src.config import Config
from src.engine import run_check
from src.ingest import import_rows
from src.kb import build_kb
from src.kb.acl import Principal
from src.region_profile import RegionProfile, RegionProfileError
from src.retrieve import retrieve

ROOT = Path(__file__).resolve().parent.parent
PROFILE_PATH = ROOT / "config" / "region_profile.json"
SZ_CITE = "local.sz.wage-reg.18"
GD_CITE = "local.gd.wage-reg.20"


def _ensure_org(conn, cfg) -> None:
    import_rows(conn, cfg, "org", [{"org_id": "ORG-A", "org_name": "A组", "parent_id": ""}],
                rel_path="inline://org-A")


def _load_employee(conn, cfg, emp_id: str, region: str, regime: str = "standard") -> None:
    import_rows(conn, cfg, "employee", [{
        "emp_id": emp_id, "pseudonym": f"{emp_id}化名", "job_code": "assembly_line",
        "org_id": "ORG-A", "region_code": region, "worktime_regime": regime,
        "contract_approved_flex": "0", "normal_hourly_cents": "3000",
    }], rel_path=f"inline://emp-{emp_id}")


def _one_overtime_day(conn, cfg, emp_id: str, day: str = "2025-09-02") -> None:
    import_rows(conn, cfg, "schedule", [
        schedule(emp_id, day, f"{day}T09:00:00+08:00", f"{day}T20:00:00+08:00", rest=60)],
        rel_path=f"inline://sch-{emp_id}")
    import_rows(conn, cfg, "punch", [
        punch(emp_id, f"{day}T09:00:00+08:00", "in"),
        punch(emp_id, f"{day}T20:00:00+08:00", "out")], rel_path=f"inline://pun-{emp_id}")


@pytest.fixture
def three_city(conn, cfg):
    """三个城市各一名员工，同一天加班事实——差异只应来自城市档。"""
    _ensure_org(conn, cfg)
    for emp, region in (("C-SZ", "440300"), ("C-GZ", "440100"), ("C-FS", "440600")):
        _load_employee(conn, cfg, emp, region)
        _one_overtime_day(conn, cfg, emp)
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5))
    return conn, cfg, out


def test_city_tier_attaches_different_local_article(three_city):
    conn, cfg, out = three_city
    per = {emp: [f for f in out.findings if f.emp_id == emp and f.rule_id == "OT-D01"]
           for emp in ("C-SZ", "C-GZ", "C-FS")}
    assert all(len(v) == 1 for v in per.values()), "三档都该各出一条工作日延长结论"

    sz, gz, fs = (per[e][0] for e in ("C-SZ", "C-GZ", "C-FS"))
    assert SZ_CITE in sz.citations, "深圳档结论必须挂《深圳市员工工资支付条例》第 18 条"
    assert GD_CITE in gz.citations and GD_CITE in fs.citations, "广佛档挂《广东省工资支付条例》第 20 条"
    assert GD_CITE not in sz.citations and SZ_CITE not in gz.citations, "两档条文不得互窜"
    # 国家层面依据三档共有，差异只在地方这一层
    for f in (sz, gz, fs):
        assert "law.labor.44" in f.citations or "rule.mohrss.1994-489.13" in f.citations


def test_run_header_records_city_and_rule_version(three_city):
    """US-OP-03：结论头部要能看出是哪个城市档、哪个规则版本跑出来的。"""
    conn, cfg, out = three_city
    row = conn.execute("SELECT scope_json, rule_pack_version FROM run WHERE run_id=?",
                       (out.run_id,)).fetchone()
    scope = json.loads(row["scope_json"])
    assert scope["region_code"] == cfg.region_code
    assert scope["region_label"] == cfg.region_label, "头部记录市名来自档位表，不是代码字面量"
    assert scope["cities_configured"] == ["440100", "440300", "440600"]
    assert row["rule_pack_version"] == scope["rule_pack_id"]


def test_unlisted_city_is_declared_not_guessed(conn, cfg):
    """上海（310100）没建档：只出国家层面结论，并记 SCOPE-04，不许默认套深圳档。"""
    _ensure_org(conn, cfg)
    _load_employee(conn, cfg, "C-SH", "310100")
    _one_overtime_day(conn, cfg, "C-SH")
    out = run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5))
    scope = find(out.findings, "SCOPE-04", emp="C-SH")
    assert len(scope) == 1, "未建档城市必须显式标未覆盖"
    assert json.loads(scope[0].metric)["unlisted"] == 1 if isinstance(scope[0].metric, str) \
        else scope[0].metric["unlisted"] == 1
    for f in find(out.findings, "OT-D01", emp="C-SH"):
        assert SZ_CITE not in f.citations and GD_CITE not in f.citations, \
            "未建档城市不得挂任何地方条文——猜一个更严或更宽的档位就是伪造依据"


def test_own_city_entry_is_visible_regardless_of_tier(conn, cfg):
    """地域层级不能把本人条目挡在门外：广州员工问自己的薪酬，自己的条目必须在候选里。

    这条是本轮改检索谓词时踩到的真实回归：按「本次校验档」过滤时，
    广州员工跑深圳档会把自己那条 region_code=440100 的条目一起滤掉，
    表现为「本人也问不到本人」——那不是隔离，是权限实现错误。
    """
    _ensure_org(conn, cfg)
    _load_employee(conn, cfg, "C-GZ", "440100")
    _one_overtime_day(conn, cfg, "C-GZ")
    run_check(conn, cfg, start=date(2025, 9, 1), end=date(2025, 9, 5))
    build_kb(conn, include_personnel=True)
    res = retrieve(conn, cfg, Principal(emp_id="C-GZ", org_id="ORG-A", is_manager=False,
                                        region_code="440100"),
                   "薪酬明细 基数", top_k=20)
    assert "personnel.payroll.C-GZ" in res.candidates, "本人条目被地域过滤误伤＝权限实现错误"


def test_no_hardcoded_city_names_in_source():
    """US-AD-06：市名与城市代码只在配置文件里，src/ 出现即失败。"""
    banned_names = ("广州市", "深圳市", "佛山市", "上海市")
    banned_codes = ("440100", "440300", "440600")
    offenders = []
    for f in sorted((ROOT / "src").rglob("*.py")):
        text = f.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "#" in line and any(b in line.split("#", 1)[1] for b in banned_names + banned_codes):
                continue          # 注释里说明来源允许出现，判定逻辑不允许
            code_part = line.split("#", 1)[0]
            for token in banned_names + banned_codes:
                if token in code_part:
                    offenders.append(f"{f.relative_to(ROOT)}:{line_no} 出现 {token}")
    assert not offenders, "城市名/城市代码写进了代码：" + "\n".join(offenders[:10])


def test_profile_missing_or_bad_is_fatal(tmp_path):
    """档位表缺失/引用了不存在的条文集合/默认城市不在表内，一律启动期报错，不退回硬编码。"""
    with pytest.raises(RegionProfileError, match="不存在"):
        RegionProfile.load(tmp_path / "nope.json")

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "schema": "wca-region-profile-v1",
        "citation_sets": {"national-only": {"multiplier": ["law.labor.44"]}},
        "cities": {"999999": {"label": "某市", "tier": ["CN"], "sets": ["ghost"]}},
        "default_city": "999999",
    }, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(RegionProfileError, match="不存在的条文集合"):
        RegionProfile.load(bad)

    nodefault = tmp_path / "nd.json"
    nodefault.write_text(json.dumps({
        "schema": "wca-region-profile-v1",
        "citation_sets": {"national-only": {"multiplier": ["law.labor.44"]}},
        "cities": {"440100": {"label": "某市", "tier": ["CN"], "sets": ["national-only"]}},
        "default_city": "440300",
    }, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(RegionProfileError, match="不在 cities"):
        RegionProfile.load(nodefault)


def test_shipped_profile_covers_three_cities():
    profile = RegionProfile.load(PROFILE_PATH)
    assert profile.codes() == ["440100", "440300", "440600"]
    assert profile.multiplier_citations("440100") == profile.multiplier_citations("440600"), \
        "广佛经核实同属省级档（字段口径文档 2.1），若日后出现市级差异必须拆成两个条文集合"
    assert SZ_CITE in profile.multiplier_citations("440300")
    for code in profile.codes():
        assert profile.city(code).tier, "每档必须写明地域层级，供举证包标注"


def test_cfg_rejects_region_outside_profile(cfg):
    """WCA_REGION_CODE 填了档位表外的城市：启动期报错，不静默退回默认档（否则三市分档会假生效）。"""
    from dataclasses import replace  # noqa: F401  仅确认可用

    with pytest.raises(ValueError, match="不在城市档位表"):
        Config.load(env_path="nonexistent.env", WCA_REGION_CODE="310100")
