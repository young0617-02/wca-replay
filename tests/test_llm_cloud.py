"""云后端 / Ollama 通道的可测性（US-AD-05 / NFR-08 / NFR-18 / NFR-19）。

基线里 `HttpProvider` 一行代码都没被测过：`pytest -m "not llm"` 收集到的是全部 118 条，
等于没有隔离。这里补三件事：
  1) 不可达（401 / 超时 / 空返回）时**明确降级**，不静默成功、不编造带出处的答案；
  2) 外发内容走最小视图（无姓名、无金额、无原始打卡行、无证件号）；
  3) 需要真凭证的用例打 `llm` 标记，`-m "not llm"` 能把它筛掉。
"""

from __future__ import annotations

import json
import os
import urllib.error
from dataclasses import replace

import pytest

from conftest import load_base
from src.agent import ComplianceAgent
from src.kb import build_kb
from src.llm import (PROVIDER_CLOUD, HttpProvider, LlmUnavailable, outbound_facts)

# 注意：**不要**在本文件加模块级 pytestmark。
# 打桩的降级用例是确定性测试，必须留在 `-m "not llm"` 里（它们正是"无凭证也能证明降级"的部分）；
# 只有真出网的那一条用 @pytest.mark.llm 单独标记。


# ------------------------------------------------------------------ 打桩用的假 provider
class _RaisingProvider:
    """把 provider 变成可控故障源：真实网络不可依赖，测试要的只是降级行为。"""

    name = PROVIDER_CLOUD

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls = 0

    def plan(self, question: str, *, subject_emp_id: str):
        from src.llm import StubProvider
        self.calls += 1
        return StubProvider().plan(question, subject_emp_id=subject_emp_id)

    def compose(self, question, plan, facts, allowed_numbers):
        self.calls += 1
        raise self.exc


def _cloud_cfg(cfg, **over):
    base = replace(cfg, llm_provider=PROVIDER_CLOUD,
                   cloud_base_url="https://api.invalid.example/v1",
                   cloud_api_key="sk-test-do-not-leak", llm_timeout_s=1)
    return replace(base, **over) if over else base


# ------------------------------------------------------------------ 配置与错误处理
def test_cloud_provider_requires_base_url(cfg):
    """没填 base_url 时在**构造阶段**就报错，而不是退到 stub 后看起来像配置生效了。"""
    from src.llm import build_provider
    empty = replace(cfg, llm_provider=PROVIDER_CLOUD, cloud_base_url="", cloud_api_key="")
    with pytest.raises(LlmUnavailable, match="base_url"):
        build_provider(empty)


def test_http_error_surfaces_status_code(cfg, monkeypatch):
    """401（无凭证/密钥失效）要带上状态码，降级提示才有区分度。"""
    def fake_urlopen(*_a, **_k):
        raise urllib.error.HTTPError("https://x", 401, "Unauthorized", {}, None)

    monkeypatch.setattr("src.llm.urllib.request.urlopen", fake_urlopen)
    p = HttpProvider(base_url="https://api.invalid.example/v1", model="m",
                     api_key="sk", name=PROVIDER_CLOUD)
    with pytest.raises(LlmUnavailable, match="HTTP 401"):
        p.compose("q", None, [], set())


def test_timeout_is_not_silent(cfg, monkeypatch):
    def fake_urlopen(*_a, **_k):
        raise TimeoutError("read timed out")

    monkeypatch.setattr("src.llm.urllib.request.urlopen", fake_urlopen)
    p = HttpProvider(base_url="https://api.invalid.example/v1", model="m",
                     api_key="sk", name=PROVIDER_CLOUD, timeout_s=1)
    with pytest.raises(LlmUnavailable, match="TimeoutError"):
        p.compose("q", None, [], set())


def test_empty_completion_is_treated_as_unavailable(cfg, monkeypatch):
    """返回 200 但内容为空：以前会被当成功，答案就成了"没有出处的空话"。"""
    class Resp:
        def read(self):
            return json.dumps({"choices": [{"message": {"content": "   "}}]}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr("src.llm.urllib.request.urlopen", lambda *a, **k: Resp())
    p = HttpProvider(base_url="https://api.invalid.example/v1", model="m",
                    api_key="sk", name=PROVIDER_CLOUD)
    with pytest.raises(LlmUnavailable, match="空内容"):
        p.compose("q", None, [], set())


# ------------------------------------------------------------------ 问答链的降级行为
@pytest.mark.parametrize("exc", [
    LlmUnavailable("cloud HTTP 401"),
    LlmUnavailable("cloud 调用失败：TimeoutError: read timed out"),
], ids=["llm_unavailable_401", "llm_unavailable_timeout"])
def test_llm_unavailable_degrades_without_fabricating(conn, cfg, exc):
    """US-AD-05：云不可达 → 回退离线模板 + 明确标 degraded，且答案仍由检索条文支撑。"""
    load_base(conn, cfg)
    build_kb(conn, include_personnel=True)
    provider = _RaisingProvider(exc)
    agent = ComplianceAgent(conn, _cloud_cfg(cfg), provider=provider)

    ans = agent.ask("法定节假日上班按几倍算", actor_emp_id="T-STD")

    assert provider.calls >= 1, "根本没有走云通道，测不到降级路径"
    assert ans.degraded is True, "降级必须显式标记，不能看起来像模型正常回答"
    assert ans.provider != PROVIDER_CLOUD
    assert ans.answer.strip(), "降级后仍要有可用的模板答案，不能返回空"
    # 关键：降级不等于放行。没有条文支撑就不许给出带出处的结论
    if ans.gate_decision.startswith("REFUSED"):
        assert not ans.citations, "拒答时不该还挂着出处"
    else:
        assert ans.citations, f"决策 {ans.gate_decision} 属于已作答，必须带出处"


# ------------------------------------------------------------------ 外发最小化
def test_outbound_facts_drop_identity_and_money():
    """NFR-18：姓名、金额（分）、原始打卡行、证件号、行级来源都不许进出发的上下文。"""
    facts = [
        {"kind": "citation", "doc_id": "law.labor.44", "citation": "《劳动法》第四十四条",
         "text": "休息日安排工作又不能补休的，支付不低于工资的 200% 的工资报酬",
         "region_code": "CN", "effective_from": "1995-01-01", "version": "v1"},
        {"kind": "numeric", "label": "员工 E001（员工一）考勤汇总",
         "value_text": "本月累计工作 1,740 分钟，其中认定加班 300 分钟",
         "minutes_worked": 1740, "estimate_cents": 999999, "authorized_final": 0,
         "source_line_no": 42, "source_rel_path": "data/raw/punch.csv",
         "device_id": "DEV-A1", "pseudonym": "员工一"},
        {"kind": "numeric", "label": "薪酬", "value_text": "正常工作时间小时工资 3200 分",
         "normal_hourly_cents": 3200},
        {"kind": "note", "text": "打卡 2026-01-15T09:05:00+08:00；证件号 440301199001011234"},
    ]

    blob = json.dumps(outbound_facts(facts), ensure_ascii=False)

    assert "999999" not in blob and "estimate_cents" not in blob, "金额测算字段外发了"
    assert "3200 分" not in blob, "薪酬基数（分）外发了"
    assert "normal_hourly_cents" not in blob
    assert "员工一" not in blob, "化名外发了"
    assert "DEV-A1" not in blob and "source_line_no" not in blob, "原始打卡行定位信息外发了"
    assert "440301199001011234" not in blob, "证件号形态外发了"
    assert "2026-01-15T09:05:00" not in blob, "行踪时间戳外发了"
    assert "第四十四条" in blob, "条文正文应当保留，否则问答没有依据"


def test_outbound_facts_reject_unknown_kinds():
    """未登记的 kind 默认不外发（白名单而非黑名单）。"""
    out = outbound_facts([{"kind": "payroll_raw_rows", "body": "一整行原始数据"}])
    assert out == []


@pytest.mark.llm
@pytest.mark.skipif(not os.environ.get("WCA_CLOUD_API_KEY"),
                    reason="未配置 WCA_CLOUD_API_KEY，真实云后端用例跳过（NFR-19：无凭证可跑）")
def test_real_cloud_roundtrip_requires_credentials(cfg):
    """真模型轨：只有用户填了凭证才跑。跳过而不是失败，是评审者复跑的前提。"""
    from src.llm import build_provider
    provider = build_provider(cfg)
    plan = provider.plan("我上个月加了多少小时班", subject_emp_id="T-STD")
    assert plan.intent in {"overtime_calc", "policy_question", "anomaly_lookup", "unknown"}
