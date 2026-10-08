"""自带中文分词（零依赖）：CJK 单字 + 相邻二元组，ASCII/数字整词小写。

索引侧与查询侧必须调用同一个函数，否则 BM25 打分无意义。
"""

from __future__ import annotations

import re

_ASCII_RE = re.compile(r"[A-Za-z0-9]+(?:\.[0-9]+)?")
_CJK_RE = re.compile(r"[㐀-䶿一-鿿豈-﫿]")


def tokenize(text: object) -> list[str]:
    if text is None:
        return []
    if not isinstance(text, str):
        text = str(text)
    tokens: list[str] = [m.group(0).lower() for m in _ASCII_RE.finditer(text)]
    run: list[str] = []
    for ch in text:
        if _CJK_RE.match(ch):
            run.append(ch)
        else:
            tokens.extend(_flush(run))
            run = []
    tokens.extend(_flush(run))
    return tokens


def _flush(run: list[str]) -> list[str]:
    if not run:
        return []
    out = list(run)
    out.extend(run[i] + run[i + 1] for i in range(len(run) - 1))
    return out


# 查询侧同义扩展（只做召回增强，不改写原文，也不参与打分权重以外的任何判断）：
# 法条正文用词是「延长工作时间/法定休假日」，员工提问用词是「加班/国庆」，不对齐就会漏召。
SYNONYMS: dict[str, tuple[str, ...]] = {
    "加班": ("延长工作时间", "加班费", "工资报酬"),
    "加班费": ("工资报酬", "加班", "倍数"),
    "国庆": ("国庆节", "法定休假日", "节假日"),
    "春节": ("春节", "法定休假日", "节假日"),
    "节假日": ("法定休假日", "节假日", "放假"),
    "休息日": ("周休息日", "补休", "休息日"),
    "调休": ("补休", "调休", "周休息日"),
    "倍数": ("百分之一百五十", "百分之二百", "百分之三百", "倍数"),
    "综合工时": ("综合计算工时", "周期", "平均周工作时间"),
    "不定时": ("不定时工作制", "审批", "岗位"),
    "审批": ("批准", "审批", "劳动行政部门"),
    "提前": ("事前", "提前", "申请", "提交"),
    "基数": ("正常工作时间工资", "小时工资标准", "基数"),
    "36小时": ("三十六小时", "每月", "上限"),
    "补卡": ("漏打卡", "补卡", "出勤"),
    "薪酬": ("工资", "报酬", "工资报酬"),
}


def expand_query(text: str) -> str:
    """把提问里的口语词映射到法条用词，返回扩展后的查询串（原串保留在前）。"""
    extra: list[str] = []
    for key, subs in SYNONYMS.items():
        if key in text:
            extra.extend(subs)
    return text + " " + " ".join(dict.fromkeys(extra))


def cjk_only(text: str) -> list[str]:
    return [t for t in tokenize(text) if _CJK_RE.match(t[0])]
