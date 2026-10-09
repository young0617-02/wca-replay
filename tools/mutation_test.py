"""F-012 变异测试：往源码里注入真实缺陷，证明测试套件抓得住（A5 一票否决项）。

做法（把 auscult 的回归纪律迁过来）：
  1. 先记录被测文件的基线 MD5；
  2. 逐个注入**语义上真实会犯的错**（倍数写错、边界 > 写成 >=、ACL 改成先召回再过滤、
     hash 链 prev 写死、四舍五入改成截断、报酬类允许下违规结论等）；
  3. 每次注入后只跑对应断言的测试，要求必须失败——失败即「被捕获」；
  4. 还原并复核 MD5 与基线一致；
  5. 结果写 reports/变异测试.md。

用法：python tools/mutation_test.py [--keep-failing]
退出码：捕获数 < 注入数 时为 1。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def read_source(path: Path) -> bytes:
    """按字节读，还原时原样写回：Windows 上 CRLF/LF 混用会让文本模式往返改变文件指纹。"""
    return path.read_bytes()


def normalize(text_bytes: bytes) -> str:
    """注入匹配用 LF 规范化文本；还原永远用原始字节，保证 MD5 回到基线。"""
    return text_bytes.decode("utf-8").replace("\r\n", "\n")


@dataclass
class Mutant:
    mid: str
    title_zh: str
    target: str                     # 相对 ROOT 的源文件
    old: str                        # 被替换的原文（必须唯一）
    new: str                        # 注入的缺陷
    probe: str                      # 用来验证捕获的 pytest 目标
    why: str                        # 这个缺陷在真实项目里为什么会发生


MUTANTS: list[Mutant] = [
    Mutant(
        "M1", "休息日加班倍数 200% 写成 150%", "src/rules/quantities.py",
        "RATE_RESTDAY_OT_PERMILLE = 2000", "RATE_RESTDAY_OT_PERMILLE = 1500",
        "tests/test_rules_engine.py::test_rest_day_work_is_200_percent_and_needs_review",
        "倍数抄错是考勤引擎最常见的事故，且金额会静默偏低"),
    Mutant(
        "M2", "法定节假日倍数 300% 写成 200%", "src/rules/quantities.py",
        "RATE_HOLIDAY_OT_PERMILLE = 3000", "RATE_HOLIDAY_OT_PERMILLE = 2000",
        "tests/test_rules_engine.py::test_statutory_holiday_work_is_300_percent",
        "节假日与休息日混淆，直接对应「错承诺一条多少钱」"),
    Mutant(
        "M3", "日上限边界 > 写成 >=", "src/rules/rulepack.py",
        "if extension > cfg.ot_cap_daily_special_minutes:",
        "if extension >= cfg.ot_cap_daily_special_minutes:",
        "tests/test_rules_engine.py::test_extension_180min_at_cap_does_not_trigger_daily_violation",
        "边界符号写反会把合法的 3 小时判成违规"),
    Mutant(
        "M4", "月 36 小时上限改成 40 小时", "src/config.py",
        'ot_cap_monthly_minutes=_as_int(values, "WCA_OT_CAP_MONTHLY_MIN", 2160),',
        'ot_cap_monthly_minutes=_as_int(values, "WCA_OT_CAP_MONTHLY_MIN", 2400),',
        "tests/test_rules_engine.py::test_monthly_overtime_over_36h_is_violation",
        "配置默认值漂移：条文是 36 小时，默认值被顺手改大"),
    Mutant(
        "M5", "ACL 改成先召回再过滤（红线）", "src/retrieve.py",
        '    base = (\n        "SELECT d.doc_id AS doc_id,',
        '    pred = "1=1"  # 变异：权限不再下推，改由下方 Python 过滤\n'
        '    pred_params: list = []\n'
        '    base = (\n        "SELECT d.doc_id AS doc_id,',
        "tests/test_acl_retrieval.py::test_other_payroll_doc_never_enters_candidates",
        "「先全量召回再过滤」看起来结果一样，但无权文档已进入候选与上下文"),
    Mutant(
        "M6", "本人可见条目从 ACL 里删掉", "src/kb/acl.py",
        '    parts.append(f"({alias}.acl_scope = ? AND {alias}.acl_emp_id = ?)")\n'
        '    params += [ACL_SELF, principal.emp_id]',
        '    pass  # 变异：不再承认 self 归属，本人条目也查不到',
        "tests/test_acl_retrieval.py::test_other_payroll_doc_never_enters_candidates",
        "权限实现过度收紧同样要被抓到：本人查不到自己 = 功能失效"),
    Mutant(
        "M7", "审计链 prev 写死为常量", "src/evidence.py",
        '        prev = str(last["entry_hash"])',
        '        prev = "0" * 64  # 变异：链不衔接前一条',
        "tests/test_evidence_chain.py::test_chain_verifies_after_run",
        "链式哈希若不用上一条的哈希，事后根本无法定位哪条被改过"),
    Mutant(
        "M8", "半进位取整改成截断", "src/util.py",
        "    if 2 * r >= denominator:", "    if 2 * r > denominator:",
        "tests/test_rules_engine.py::test_money_math_uses_integers_only",
        "分钱级舍入口径变化会静默改变所有测算结果"),
    Mutant(
        "M9", "允许报酬类规则下违规结论", "src/rules/rulepack.py",
        '    if meta.severity_kind == "pay" and severity == SEV_VIOLATION:',
        '    if False and meta.severity_kind == "pay" and severity == SEV_VIOLATION:',
        "tests/test_rules_engine.py::test_pay_rule_violation_is_structurally_demoted",
        "越权下判决是本项目最不能接受的行为形态"),
    Mutant(
        "M10", "数字白名单校验被跳过", "src/guard.py",
        "    bad = offenders(answer, allowed)", "    bad = []",
        "tests/test_agent_guard.py::test_enforce_blocks_unauthorized_number",
        "去掉出口校验，模型擅自算钱就再也拦不住"),
    Mutant(
        "M11", "重大事项改为直接给金额", "src/guard.py",
        '    elif major_matter:\n        violations.append("重大事项：不允许由系统单方给出最终数额或违法定性")\n'
        '        decision = "EXPLAIN_ONLY"',
        '    elif major_matter and False:\n'
        '        violations.append("重大事项：不允许由系统单方给出最终数额或违法定性")\n'
        '        decision = "EXPLAIN_ONLY"',
        "tests/test_agent_guard.py::test_major_matter_never_gets_final_amount",
        "A4 红线的直接对应缺陷"),
    Mutant(
        "M12", "跨零点班次不再判定", "src/rules/dayfacts.py",
        "    if facts.out_ts is not None and facts.out_ts.date() > facts.work_date:",
        "    if False:",
        "tests/test_rules_engine.py::test_cross_midnight_without_schedule_needs_review",
        "夜班切分失效会让工时归错日，进而影响所有倍数判据"),
    Mutant(
        "M13", "输入指纹退回「全库登记文件」口径", "src/engine.py",
        "    fingerprint = input_fingerprint(conn, scope, file_ids=referenced_files)",
        "    fingerprint = input_fingerprint(conn, scope)  # 变异：忽略引用集合",
        "tests/test_optimization_regressions.py::test_o11a_unrelated_input_does_not_move_the_fingerprint",
        "指纹口径一松，任何无关导入都会让「同一输入可复现」难以解释"),
    Mutant(
        "M14", "被拒收的行不再形成结论", "src/rules/rulepack.py",
        '        if str(issue.get("severity")) == "REJECT":',
        "        if False:",
        "tests/test_optimization_regressions.py::test_o2_rejected_row_becomes_a_conclusion_and_a_review_item",
        "最该补录的数据最容易被漏掉：缺口只留在 CSV 里就没人跟进"),
    Mutant(
        "M15", "未归属质量问题不再汇成结论", "src/engine.py",
        "        \"WHERE (emp_id = '' OR emp_id NOT IN (SELECT emp_id FROM employee)) \"",
        '        "WHERE 0 = 1 "',
        "tests/test_optimization_regressions.py::test_o2_unattributable_issues_are_not_invisible_anymore",
        "主数据缺失时若不出结论，举证包会显示「一切正常」——恰好是最危险的时候"),
    Mutant(
        "M16", "异常报表退回 INNER JOIN 丢掉未归属结论", "src/anomaly.py",
        '        "LEFT JOIN employee e ON e.emp_id = f.emp_id "',
        '        "INNER JOIN employee e ON e.emp_id = f.emp_id "',
        "tests/test_optimization_regressions.py::test_o2_unattributable_issues_are_not_invisible_anymore",
        "结论写进了库但报表查不到，等于对复核人员不可见"),
    Mutant(
        "M17", "打卡内容唯一索引退化为普通索引", "src/schema.sql",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_punch_dedup ON punch(emp_id, event_ts, punch_type,",
        "CREATE INDEX IF NOT EXISTS idx_punch_dedup ON punch(emp_id, event_ts, punch_type,",
        "tests/test_optimization_regressions.py::test_o3_same_content_reimported_under_new_name_is_not_double_counted",
        "改名重传即重复入账，工时与打卡次数虚增——看起来像「数据变多了」的好事"),
    Mutant(
        "M18", "无人工结论的异常也进对外结论集（US-RV-01★）", "src/evidence.py",
        '        if x["status"] and x["status"] != "OPEN":',
        '        if True:  # 变异：不再区分是否有人登记过结论',
        "tests/test_evidence_chain.py::test_unsigned_findings_never_reach_the_conclusion_set",
        "举证包最容易在这里造假：把「机器发现的可疑」写成「人已确认的结论」，接收方完全看不出差别"),
    Mutant(
        "M19", "签发人不再带 human: 前缀（责任无法归到具体的人）", "src/evidence.py",
        '        conn, run_id=run_id, actor=f"human:{signed_by}", action="evidence.sign",',
        '        conn, run_id=run_id, actor=signed_by, action="evidence.sign",',
        "tests/test_evidence_chain.py::test_signing_puts_a_named_actor_in_the_chain",
        "审计链里机器动作与人的动作必须一眼可分；去掉前缀后签发看起来像系统自己签的"),
    Mutant(
        "M20", "举证包漏掉主数据（org/employee）", "src/evidence.py",
        '    for r in conn.execute("SELECT file_id FROM raw_file WHERE kind IN (\'org\',\'employee\')"\n'
        '                          " ORDER BY file_id").fetchall():',
        '    for r in conn.execute("SELECT file_id FROM raw_file WHERE kind IN (\'__none__\')"\n'
        '                          " ORDER BY file_id").fetchall():',
        "tests/test_replay.py::test_replay_reproduces_the_triple_from_the_package_alone",
        "主数据不出现在 source_refs 里，最容易被当成「不属于本次结论」漏打包——"
        "接收方重放时一个员工都查不到，结论全空却看不出问题出在包上"),
]


@dataclass
class MutationResult:
    mid: str
    title: str
    target: str
    probe: str
    captured: bool
    note: str
    restored_md5_ok: bool


def run_probe(probe: str, timeout_s: int) -> tuple[bool, str]:
    """返回 (测试是否失败, 摘要)。测试失败 = 变异被捕获。"""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-x", probe],
        cwd=str(ROOT), capture_output=True, text=True, timeout=timeout_s, env=env,
    )
    tail = "\n".join(proc.stdout.strip().splitlines()[-3:])
    return proc.returncode != 0, tail


def purge_bytecode() -> None:
    """注入前后都要清 `__pycache__`。

    踩过的坑：pyc 的复用校验是「秒级 mtime + 文件字节数」，而像
    `RATE_HOLIDAY_OT_PERMILLE = 3000` → `= 2000` 这种注入**字节数不变**，
    同一秒内 Python 会直接加载上一个版本的字节码，注入根本没生效，
    测试于是"通过"——报出来的是一条不存在的漏网（M2 复跑时就是这样翻车的）。
    """
    for pkg in ("src", "tests", "evals", "tools", "config", "data"):
        for cache in (ROOT / pkg).rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="变异测试：注入缺陷证明套件有鉴别力")
    ap.add_argument("--only", default="", help="逗号分隔的 mutant id，默认全部")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--no-report", action="store_true")
    args = ap.parse_args(argv)

    selected = [m for m in MUTANTS if not args.only or m.mid in args.only.split(",")]
    targets = sorted({ROOT / m.target for m in selected})
    baseline = {p: md5(p) for p in targets}
    print(f"基线 MD5（{len(targets)} 个文件）：")
    for p, h in baseline.items():
        print(f"  {p.relative_to(ROOT).as_posix()}  {h}")

    results: list[MutationResult] = []
    for m in selected:
        path = ROOT / m.target
        original = read_source(path)
        text = normalize(original)
        if text.count(m.old) != 1:
            results.append(MutationResult(m.mid, m.title_zh, m.target, m.probe, False,
                                          f"注入锚点在文件中出现 {text.count(m.old)} 次，无法唯一定位",
                                          False))
            print(f"[{m.mid}] {m.title_zh}: 注入失败（锚点不唯一）")
            continue
        try:
            path.write_bytes(text.replace(m.old, m.new, 1).encode("utf-8"))
            purge_bytecode()                    # 不让陈旧字节码把注入吞掉
            captured, tail = run_probe(m.probe, args.timeout)
        finally:
            path.write_bytes(original)
            purge_bytecode()                    # 还原后也要清，否则污染下一条
            shutil.rmtree(ROOT / ".pytest_cache", ignore_errors=True)
        ok = md5(path) == baseline[path]
        results.append(MutationResult(m.mid, m.title_zh, m.target, m.probe, captured,
                                      tail.replace("\n", " / "), ok))
        print(f"[{m.mid}] {m.title_zh}: {'已捕获' if captured else '漏网（套件无鉴别力）'}"
              f"{'，还原 MD5 一致' if ok else '，还原 MD5 不一致！'}")

    captured = sum(1 for r in results if r.captured)
    total = len(results)
    all_restored = all(r.restored_md5_ok for r in results)
    print(f"\n注入 {total} 个缺陷，捕获 {captured} 个，还原 MD5 全部一致：{all_restored}")

    if not args.no_report:
        cfg_reports = ROOT / "reports"
        cfg_reports.mkdir(exist_ok=True)
        rows = "\n".join(
            f"| {r.mid} | {r.title} | `{r.target}` | `{r.probe.split('::')[-1]}` | "
            f"{'捕获' if r.captured else '**漏网**'} | {'一致' if r.restored_md5_ok else '**不一致**'} |"
            for r in results
        )
        (cfg_reports / "变异测试.md").write_text(
            f"""# 变异测试结果（F-012 / A5）

> 实测命令：`python tools/mutation_test.py`
> 实测环境：{json.dumps({'python': sys.version.split()[0], 'root': str(ROOT)}, ensure_ascii=False)}
> 基线 MD5 与还原 MD5 逐文件比对，全部一致 = {all_restored}

## 一、结果

注入缺陷 **{total}** 个，被测试套件捕获 **{captured}** 个，漏网 **{total - captured}** 个。

| id | 注入的缺陷 | 目标文件 | 用于捕获的测试 | 结果 | 还原 MD5 |
|---|---|---|---|---|---|
{rows}

## 二、为什么这些变异是「真缺陷」

{chr(10).join(f"- **{m.mid} {m.title_zh}**：{m.why}" for m in selected)}

## 三、读法说明

- 每次注入只跑对应断言的测试（`-x -q`），失败即视为捕获；跑完立刻按内存中的原文还原。
- 变异体互不叠加，一次只改一处，避免「多个缺陷互相抵消」的假阴性。
- 本文件由工具生成，不要手工改数字；要复跑请按 README 的一条命令执行。
""", encoding="utf-8")
        print(f"报告：{cfg_reports / '变异测试.md'}")

    return 0 if (captured == total and all_restored) else 1


if __name__ == "__main__":
    raise SystemExit(main())
