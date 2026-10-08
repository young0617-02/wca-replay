"""答案守卫：数字白名单 + 重大事项只解释不给数。

这是 A1（数值 100% 出自 rules/）与 A4（错承诺条数 = 0）的**执行机制**，不是一句口头承诺：
答案里出现的每个数字都必须落在允许集合内，否则整条答案改写为「只解释规则、不给数」，
并强制转人工复核。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .util import round_half_up

# 重大事项：涉及钱、赔偿、违法定性的提问，一律不得由系统单方给最终结论
MAJOR_MATTER_RE = re.compile(
    r"(该付多少|应付多少|该拿多少|拿多少|给多少|发多少|赔多少|赔偿|补偿|加付|最终|多少钱|多少加班费|"
    r"加班费多少|加班费怎么算|是否违法|算不算违法|能不能只给|要不要发|要不要赔|该不该赔|能不能拒|"
    r"合法吗|违规吗)"
)
# 与 src/util.py 同口径：字母数字紧邻的数字串（如员工号 E012 里的 012）不算数值 token
NUM_RE = re.compile(r"(?<![0-9A-Za-z.])\d[\d,]*(?:\.\d+)?(?![0-9A-Za-z])")
_DATEISH_RE = re.compile(r"^\d{1,4}(?:[-/年]\d{1,2}(?:[-/月]\d{1,2})?)?$")


@dataclass
class GuardResult:
    ok: bool
    answer: str
    gate_decision: str
    violations: list[str] = field(default_factory=list)
    numbers_found: list[str] = field(default_factory=list)
    allowed_sample: list[str] = field(default_factory=list)
    major_matter: bool = False

    @property
    def failed(self) -> bool:
        return not self.ok


def allowed_surface(facts: list[dict]) -> set[str]:
    """把结构化事实展开成「答案里允许出现的字面数字」。

    展开口径（写死，便于复述）：
      * 整数分钟 v -> 允许 v、"v分钟"；v 能被 60 整除时再允许 h、"h小时"
      * 整数分 c   -> 允许 c；c 能被 100 整除时再允许元值
      * 条文号、日期串等事实文本里的数字，随事实一起进入允许集合
      * 法定倍数固定档位：150% / 200% / 300% / 100% 及对应倍数写法
    """
    allowed: set[str] = set()

    def add_int(v: int) -> None:
        allowed.add(str(v))
        allowed.add(f"{v}分钟")
        if v % 60 == 0:
            allowed.add(str(v // 60))
            allowed.add(f"{v // 60}小时")
        if v % 100 == 0:
            allowed.add(str(v // 100))
            allowed.add(f"{v // 100}元")

    def walk(obj: object) -> None:
        if isinstance(obj, bool):
            return
        if isinstance(obj, int):
            add_int(obj)
        elif isinstance(obj, str):
            allowed.add(obj)
            for m in NUM_RE.finditer(obj):
                allowed.add(m.group(0))
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)
        elif isinstance(obj, float):
            raise TypeError("守卫不接受浮点事实：请在 rules/ 里换成整数分/分钟")

    for f in facts:
        walk(f)

    for permille, label in ((1500, "150%"), (2000, "200%"), (3000, "300%"), (1000, "100%")):
        # "150%" 这个写法的字面数字是 150，所以百分比数值本身也要进白名单
        allowed.update({label, _mult_text(permille), str(permille), str(permille // 10)})
    return allowed


def _mult_text(permille: int) -> str:
    whole, frac = divmod(permille, 1000)
    if frac == 0:
        return f"{whole}倍"
    if frac % 100 == 0:
        return f"{whole}.{frac // 100}倍"
    return f"{permille}千分位"


def numbers_in(text: str) -> list[str]:
    return [m.group(0) for m in NUM_RE.finditer(text)]


def offenders(text: str, allowed: set[str]) -> list[str]:
    """答案里出现、但不在允许集合中的数字。日期串各段都在允许集合里才算合法。"""
    bad: list[str] = []
    for token in numbers_in(text):
        if token in allowed:
            continue
        parts = [p for p in re.split(r"[-/年月日]", token) if p]
        if _DATEISH_RE.match(token) and parts and all(p in allowed for p in parts):
            continue
        bad.append(token)
    return bad


def coverage(claims_total: int, claims_with_citation: int) -> int:
    if claims_total <= 0:
        return 0
    return round_half_up(1000 * claims_with_citation, claims_total)


EXPLAIN_ONLY_TEMPLATE = (
    "规则解释（系统不给出最终数额）：\n"
    "{rule_lines}\n"
    "为什么不给最终数：应付金额取决于加班工资基数口径、是否已安排补休、是否足额支付与地方裁口径，"
    "这些事实不在本系统的数据边界内；且 AI 结论在劳动争议里不构成安全证据。"
    "本条已转入人工复核队列，复核通过后才会出具可对外的数额或结论。"
)


def enforce(answer: str, *, facts: list[dict], major_matter: bool,
            citations_ok: bool, confidence_permille: int, threshold_permille: int,
            coverage_permille: int, min_coverage_permille: int) -> GuardResult:
    """最终门禁：先查数字白名单，再查重大事项与证据覆盖率。"""
    allowed = allowed_surface(facts)
    found = numbers_in(answer)
    bad = offenders(answer, allowed)
    violations: list[str] = []
    decision = "ANSWERED"
    text = answer

    if bad:
        violations.append(f"数字白名单违规：{sorted(set(bad))} 不在确定性事实集合中")
        decision = "ESCALATED"
        text = EXPLAIN_ONLY_TEMPLATE.format(rule_lines=_rule_lines(facts))
    elif major_matter:
        violations.append("重大事项：不允许由系统单方给出最终数额或违法定性")
        decision = "EXPLAIN_ONLY"
        text = EXPLAIN_ONLY_TEMPLATE.format(rule_lines=_rule_lines(facts))
    elif not citations_ok:
        violations.append("无可用出处，拒绝作答（不允许无引用生成）")
        decision = "REFUSED_NO_EVIDENCE"
        text = "证据不足：知识库中没有可引用的条文或制度条目，因此不作结论。"
    elif coverage_permille < min_coverage_permille or confidence_permille < threshold_permille:
        violations.append(
            f"置信度 {confidence_permille}‰ 或证据覆盖率 {coverage_permille}‰ 低于阈值"
            f"（{threshold_permille}‰ / {min_coverage_permille}‰），只解释规则并转人工复核"
        )
        decision = "EXPLAIN_ONLY"
        text = EXPLAIN_ONLY_TEMPLATE.format(rule_lines=_rule_lines(facts))

    return GuardResult(
        ok=not violations and decision == "ANSWERED", answer=text, gate_decision=decision,
        violations=violations, numbers_found=found,
        allowed_sample=sorted(allowed)[:40], major_matter=major_matter,
    )


def _rule_lines(facts: list[dict]) -> str:
    lines: list[str] = []
    for f in facts[:6]:
        if f.get("kind") == "citation":
            lines.append(f"· {f.get('text', '')}（出处：{f.get('citation', '')}）")
        elif f.get("kind") == "numeric":
            lines.append(
                f"· 规则 {f.get('rule_id', '')}：{f.get('label', '')} {f.get('value_text', '')}，"
                f"法定倍数 {f.get('rate_text', '')}；本系统不产出金额，"
                "须复核后才可对外"
            )
        elif f.get("kind") == "acl_denied":
            lines.append(f"· 权限说明：{f.get('text', '')}")
    return "\n".join(lines) or "· 本次没有可用事实"
