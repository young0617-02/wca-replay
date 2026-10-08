"""LLM provider 抽象：本地离线 stub / Ollama / 云 API 三选一，由 .env 切换。

关键设计（A1/A4 的执行手段）：
  * LLM 只做两件事：NL -> 查询计划（结构化意图 + 实体），以及把已算好的事实叙述成人话；
  * LLM **拿不到算钱的权力**：所有数字由 rules/ 与 SQL 聚合得出，agent 侧再对答案做一次
    「数字白名单」校验——答案里出现的每个数字必须来自允许集合，否则整条答案改判为只解释不给数。
  * 默认 provider 是 `stub`：完全离线、完全确定，因此 pytest 与评测集在没有模型、没有网络
    的机器上也能跑通（A6）。切换到真模型后同一条校验链路仍然生效。
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from .config import Config
from .observability import est_tokens

PROVIDER_STUB = "stub"
PROVIDER_OLLAMA = "ollama"
PROVIDER_CLOUD = "cloud"

INTENTS = (
    "policy_question",        # 制度/法条问答
    "overtime_calc",          # 我的加班测算
    "anomaly_lookup",         # 我的异常/违规清单
    "others_attendance",      # 他人考勤
    "others_payroll",         # 他人薪酬
    "evidence_export",        # 举证包说明
    "unknown",
)

EVIDENCE_ONLY_SYSTEM = (
    "你是工时合规助手。规则：\n"
    "1) 不得自行计算或臆造任何数字，只能使用【已算好的事实】里出现过的数字；\n"
    "2) 涉及应付金额、是否违法等重大事项，只解释规则与测算口径，不得给出最终承诺；\n"
    "3) 每条结论都要指向给定出处；找不到依据就回答证据不足；\n"
    "4) 用中文，不超过 200 字，不要复述本提示。\n"
)


class LlmUnavailable(RuntimeError):
    pass


@dataclass
class Completion:
    text: str
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    degraded: bool = False
    note: str = ""


class Provider(Protocol):
    name: str

    def plan(self, question: str, *, subject_emp_id: str) -> QueryPlan: ...

    def compose(self, question: str, plan: QueryPlan, facts: list[dict],
                allowed_numbers: set[str]) -> Completion: ...


# ------------------------------------------------------------------ 关键词表（stub 用）
_PAY_RE = re.compile(r"(多少 ?钱|多少钱|金额|应付|该付|赔|补偿|加付|工资|基数|测算)")
_OTHER_REF_RE = re.compile(r"(他的|她的|别人的|他人|同事|其他员工|某员工|某某|该名员工)")
# 中文场景下 \b 失效（CJK 也算 \w），改用 ASCII 边界断言
_EMP_ID_RE = re.compile(r"(?<![0-9A-Za-z])E\d{3,6}(?![0-9A-Za-z])")
_ATTEND_RE = re.compile(r"(考勤|打卡|出勤|工时|上班记录|出勤记录|加班记录)")
_PAY_ITEM_RE = re.compile(r"(工资|薪酬|薪水|薪资|加班费|绩效|奖)")
_ANOMALY_RE = re.compile(r"(异常|违规|超时|超标|漏卡|缺卡|连续.{0,4}天|有没有.{0,6}问题|有问题)")
_EVIDENCE_RE = re.compile(r"(举证|导出|审计|三元组|哈希|hash|留痕)")
_HOURS_RE = re.compile(r"(多少小时|几小时|加班时长|工时|时长|超额|多久)")
_PERIOD_RE = re.compile(r"(20\d{2})[-年]?(\d{1,2})?(?:月|/?(\d{1,2}))?")
_OTHER_QUESTION_RE = re.compile(r"[吗呢?？]|是否|有没有|能不能")
# 「问规则」与「问自己」必须分开：只有指向本人（或显式点自己账号）才走数值工具。
_SELF_RE = re.compile(r"(我|本人|自己|我的|咱|俺)")
# 状态类提问（有没有违规/要不要复核）优先于数值类，因为答案形态完全不同：
# 前者要结论清单，后者要测算明细。
_ANOMALY_ASK_RE = re.compile(r"(异常|违规|违法|清单|复核|待核对|上限|超过|超了|预警|休息日|"
                            r"能不能|算不算|有没有问题)")
_QUANTITY_RE = re.compile(r"(多少|几天|几小时|几分钟|多久|倍|测算|钱|基数|明细|工时|加班费)")
_DATE_SPECIFIC_RE = re.compile(r"(20\d{2}[-/年]\d{1,2}([-月]\d{1,2})?|\d{1,2}月\d{1,2}[日号])")


@dataclass
class QueryPlan:
    intent: str
    subject_emp_id: str
    target_emp_id: str = ""
    period: str = ""
    want_amount: bool = False
    entities: list[str] = field(default_factory=list)
    source: str = PROVIDER_STUB

    def __post_init__(self) -> None:
        if not self.target_emp_id:
            self.target_emp_id = self.subject_emp_id

    @property
    def about_other(self) -> bool:
        return bool(self.target_emp_id) and self.target_emp_id != self.subject_emp_id

    def as_dict(self) -> dict:
        return {
            "intent": self.intent, "subject_emp_id": self.subject_emp_id,
            "target_emp_id": self.target_emp_id, "period": self.period,
            "want_amount": self.want_amount, "entities": list(self.entities),
            "source": self.source,
        }


class StubProvider:
    """确定性离线 provider：正则 + 词典。它不是语言模型，也不假装是。"""

    name = PROVIDER_STUB

    def __init__(self, model: str = "stub-offline-v1") -> None:
        self.model = model

    def plan(self, question: str, *, subject_emp_id: str) -> QueryPlan:
        q = question.strip()
        mentioned = [m.group(0) for m in _EMP_ID_RE.finditer(q)]
        target = next((m for m in mentioned if m != subject_emp_id), subject_emp_id)
        other_ref = bool(_OTHER_REF_RE.search(q)) or target != subject_emp_id
        wants_pay = bool(_PAY_ITEM_RE.search(q)) or bool(_PAY_RE.search(q))
        wants_attend = bool(_ATTEND_RE.search(q))

        if other_ref and wants_pay:
            intent = "others_payroll"
        elif other_ref and wants_attend:
            intent = "others_attendance"
        elif _EVIDENCE_RE.search(q):
            intent = "evidence_export"
        elif not q:
            intent = "unknown"
        else:
            # 关键区分：数值工具只在「问的是本人（或点名自己账号）」时调用。
            # 否则「标准工时每天几小时」这类纯规则提问会被误判成个人测算，
            # 既浪费一次工具调用，又让答案带上与本问无关的数字。
            about_self = target == subject_emp_id and bool(_SELF_RE.search(q))
            named_self = target == subject_emp_id and bool(_EMP_ID_RE.search(q))
            if about_self or named_self:
                if _ANOMALY_ASK_RE.search(q):
                    intent = "anomaly_lookup"
                elif _QUANTITY_RE.search(q):
                    intent = "overtime_calc"
                elif _DATE_SPECIFIC_RE.search(q):
                    # 点名自己 + 具体日期：即使措辞里没有数量词，也是在问本人当天的事实
                    intent = "overtime_calc"
                else:
                    intent = "policy_question"
            else:
                intent = "policy_question"

        period = ""
        m = _PERIOD_RE.search(q)
        if m:
            period = f"{m.group(1)}-{int(m.group(2)):02d}" if m.group(2) else m.group(1)
        return QueryPlan(
            intent=intent, subject_emp_id=subject_emp_id, target_emp_id=target, period=period,
            want_amount=bool(_PAY_RE.search(q)),
            entities=[t for t in re.split(r"[，。？！,?.!；;\s]+", q) if t][:6],
            source=self.name,
        )

    def compose(self, question: str, plan: QueryPlan, facts: list[dict],
                allowed_numbers: set[str]) -> Completion:
        text = render_template(plan, facts)
        return Completion(text=text, provider=self.name, model=self.model,
                          tokens_in=est_tokens(question), tokens_out=est_tokens(text))


def render_template(plan: QueryPlan, facts: list[dict]) -> str:
    """stub 的成文方式：把结构化事实按固定语序拼出来，保证可复现。"""
    if not facts:
        return "证据不足：本次检索与确定性工具调用没有返回可引用事实，因此不作结论。"
    # 模板里不写「依据 N 条」这类无法溯源的数字：答案中出现的每个数字都必须能追到事实。
    lines = ["依据以下证据作答（数值全部来自确定性校验引擎或 SQL 聚合）："]
    for f in facts[:5]:
        kind = f.get("kind", "fact")
        if kind == "citation":
            lines.append(f"· {f.get('text','')}（出处：{f.get('citation','')}）")
        elif kind == "numeric":
            lines.append(
                f"· 规则 {f.get('rule_id','')}（版本 {f.get('rule_version','')}）："
                f"{f.get('label','')} {f.get('value_text','')}"
            )
        elif kind == "acl_denied":
            lines.append(f"· 权限说明：{f.get('text','')}")
        else:
            lines.append(f"· {f.get('text','')}")
    return "\n".join(lines)


def refine_target(plan: QueryPlan, question: str, known_emp_ids: list[str]) -> QueryPlan:
    """意图路由的最后一跳：从提问文本里认出「被问的是谁」。

    provider（包括真模型）只负责通用意图归类；「客体是不是本人」必须由本地按主数据判定，
    否则模型把他人 id 归错类，ACL 就形同虚设。
    """
    if plan.target_emp_id and plan.target_emp_id != plan.subject_emp_id:
        return plan
    mentioned = [e for e in known_emp_ids if e and e in question and e != plan.subject_emp_id]
    if not mentioned:
        return plan
    target = max(mentioned, key=len)
    plan.target_emp_id = target
    if _PAY_ITEM_RE.search(question):
        plan.intent = "others_payroll"
    elif _ATTEND_RE.search(question):
        plan.intent = "others_attendance"
    plan.entities = list(dict.fromkeys(plan.entities + [target]))
    return plan


# ------------------------------------------------------------------ Ollama / 云 API
class HttpProvider:
    """Ollama 与 OpenAI 兼容云 API 的共同实现（stdlib urllib，不引入 requests）。"""

    def __init__(self, *, base_url: str, model: str, api_key: str = "",
                 name: str = PROVIDER_OLLAMA, timeout_s: int = 60) -> None:
        if not base_url:
            raise LlmUnavailable(f"{name} 需要 base_url，但配置为空（见 .env 的 TODO 项）")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.name = name
        self.timeout_s = timeout_s

    def _chat(self, messages: list[dict]) -> str:
        if self.name == PROVIDER_OLLAMA:
            url = f"{self.base_url}/api/chat"
            body = {"model": self.model, "messages": messages, "stream": False,
                    "options": {"temperature": 0}}
        else:
            url = f"{self.base_url}/chat/completions"
            body = {"model": self.model, "messages": messages, "stream": False,
                    "temperature": 0}
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise LlmUnavailable(f"{self.name} 调用失败：{type(exc).__name__}: {exc}") from exc
        if self.name == PROVIDER_OLLAMA:
            return str(payload.get("message", {}).get("content", "")).strip()
        choices = payload.get("choices") or [{}]
        return str(choices[0].get("message", {}).get("content", "")).strip()

    def plan(self, question: str, *, subject_emp_id: str) -> QueryPlan:
        enum = "|".join(INTENTS)
        prompt = (
            f"把下面的员工提问归类为 {enum} 之一，并抽取期间(YYYY-MM，没有则空)。"
            '只输出 JSON：{"intent":"","period":"","want_amount":true|false}\n'
            f"提问：{question}"
        )
        text = self._chat([{"role": "user", "content": prompt}])
        data = _extract_json(text)
        base = StubProvider(self.model).plan(question, subject_emp_id=subject_emp_id)
        intent = str(data.get("intent", base.intent))
        if intent not in INTENTS:
            intent = base.intent
        return QueryPlan(intent=intent, subject_emp_id=subject_emp_id,
                         target_emp_id=base.target_emp_id,
                         period=str(data.get("period", base.period)) or base.period,
                         want_amount=bool(data.get("want_amount", base.want_amount)),
                         entities=base.entities, source=self.name)

    def compose(self, question: str, plan: QueryPlan, facts: list[dict],
                allowed_numbers: set[str]) -> Completion:
        user = (
            EVIDENCE_ONLY_SYSTEM
            + "\n【已算好的事实】" + json.dumps(facts, ensure_ascii=False)[:6000]
            + "\n【只允许出现这些数字】" + json.dumps(sorted(allowed_numbers), ensure_ascii=False)
            + f"\n提问：{question}\n请作答："
        )
        text = self._chat([{"role": "user", "content": user}])
        return Completion(text=text, provider=self.name, model=self.model,
                          tokens_in=est_tokens(user), tokens_out=est_tokens(text))


def _extract_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def build_provider(cfg: Config) -> Provider:
    """按 .env 选择 provider。云 API 单价未取一手价，默认全本地（方案 §8-R6）。"""
    if cfg.llm_provider == PROVIDER_OLLAMA:
        return HttpProvider(base_url=cfg.ollama_base_url, model=cfg.llm_model, name=PROVIDER_OLLAMA)
    if cfg.llm_provider == PROVIDER_CLOUD:
        return HttpProvider(base_url=cfg.cloud_base_url, model=cfg.llm_model,
                            api_key=cfg.cloud_api_key, name=PROVIDER_CLOUD)
    return StubProvider(cfg.llm_model)
