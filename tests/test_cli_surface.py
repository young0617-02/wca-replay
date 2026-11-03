"""CLI 表面一致性：子命令清单、参数注册与处理函数读取的字段必须互相对得上。

为什么单独测这个：`python -m src.cli all` 是 README 的复跑入口，它把各子命令的处理函数串起来跑。
基线里 `all` 自己手工拼了一个 Namespace，新加 `--sign-as` 之后它直接 `AttributeError` 挂在最后一步——
**测试全绿但演示命令跑不通**。这类缺陷只有把"注册了什么参数"和"函数读了什么参数"做机械对账才拦得住。
"""

from __future__ import annotations

import argparse
import inspect
import re

import pytest

from src import cli

READS_RES = (re.compile(r"args\.([a-z_][a-z0-9_]*)"),
             re.compile(r"""getattr\(\s*args\s*,\s*["']([a-z_][a-z0-9_]*)["']"""))
# 只有位置参数是"必须给"的：给它一个占位值，其余一律走默认值
MIN_ARGV = {"ask": ["加班怎么算"], "replay": ["var/packages/dummy.zip"]}


def _module_funcs() -> dict[str, object]:
    return {name: obj for name, obj in inspect.getmembers(cli, inspect.isfunction)
            if obj.__module__ == cli.__name__}


def _reads(text: str) -> set[str]:
    out: set[str] = set()
    for rx in READS_RES:
        out |= set(rx.findall(text))
    return out


def _reads_of(fn) -> set[str]:
    """处理函数自己读的字段，加上它调用的同模块辅助函数读的字段（一层就够）。"""
    text = inspect.getsource(fn)
    names = _reads(text)
    for other, other_fn in _module_funcs().items():
        if other != fn.__name__ and re.search(rf"\b{other}\(", text):
            names |= _reads(inspect.getsource(other_fn))
    return names


def _registered(action_holder) -> set[str]:
    out = set()
    for action in action_holder._actions:
        if action.dest in ("help", "cmd", "subparsers"):
            continue
        out.add(action.dest)
    return out


def test_subcommand_names_match_the_parser():
    """A12 的另一半：SUBCOMMAND_NAMES 必须与解析器注册的一字不差。"""
    ap = cli.build_parser()
    choices = {a.dest: a for a in ap._actions if getattr(a, "choices", None)}
    registered = set(next(a for d, a in choices.items() if d == "cmd").choices)
    assert registered == set(cli.SUBCOMMAND_NAMES), (
        f"只在解析器：{sorted(registered - set(cli.SUBCOMMAND_NAMES))}；"
        f"只在清单：{sorted(set(cli.SUBCOMMAND_NAMES) - registered)}")


@pytest.mark.parametrize("name", sorted(set(cli.SUBCOMMAND_NAMES) - {"all"}))
def test_handler_only_reads_registered_arguments(name):
    ap = cli.build_parser()
    ns = ap.parse_args([name, *MIN_ARGV.get(name, [])])
    missing = sorted(_reads_of(ns.fn) - set(vars(ns)))
    assert not missing, f"{name} 的处理函数读了未注册的参数：{missing}（已注册 {sorted(vars(ns))}）"


def test_all_step_namespaces_cover_their_handlers():
    """`all` 逐步复用子命令自己的解析结果，所以每一步的对账也必须成立。"""
    ap = cli.build_parser()
    all_ns = ap.parse_args(["all"])
    for step in cli.ALL_STEPS:
        ns = ap.parse_args([step] + cli._step_argv(step, all_ns))
        ns.env = all_ns.env
        missing = sorted(_reads_of(ns.fn) - set(vars(ns)))
        assert not missing, f"all -> {step} 会读不到字段：{missing}"


def test_all_step_argv_pins_only_reproducible_inputs():
    """`all` 只钉种子/导入时刻/校验区间，别的一律用默认值——多钉一个就多一处漂移。"""
    ap = cli.build_parser()
    all_ns = ap.parse_args(["all", "--seed", "7", "--start", "2025-09-01", "--end", "2025-09-30"])
    assert cli._step_argv("gen", all_ns) == ["--seed", "7"]
    assert cli._step_argv("ingest", all_ns) == ["--imported-at", "2026-10-06T09:00:00+08:00"]
    assert cli._step_argv("check", all_ns) == ["--start", "2025-09-01", "--end", "2025-09-30",
                                               "--notes", "cli all"]
    assert cli._step_argv("kb", all_ns) == []


def test_all_does_not_hand_build_step_namespaces():
    """结构性拦住本轮真实发生的缺陷：`all` 手工拼 Namespace 导致新开关读不到。"""
    text = inspect.getsource(cli.cmd_all)
    assert "argparse.Namespace(" not in text, "all 必须复用子命令自己的解析结果"


def test_export_delivery_flag_and_legacy_alias_registered():
    ap = cli.build_parser()
    new = ap.parse_args(["export", "--record-delivery-as", "rv1"])
    old = ap.parse_args(["export", "--sign-as", "rv1"])
    assert new.record_delivery_as == "rv1" and new.sign_as is None
    assert old.sign_as == "rv1" and old.record_delivery_as is None

    sub = next(action for action in ap._actions
               if isinstance(action, argparse._SubParsersAction))
    help_text = sub.choices["export"].format_help()
    assert "--record-delivery-as" in help_text
    assert "--sign-as" in help_text
    assert "非密码学签名" in help_text


def test_export_sign_as_defaults_to_unsigned():
    """不签发必须是默认行为：签发是人的动作，不能由复跑命令替人做。"""
    ns = cli.build_parser().parse_args(["export"])
    assert ns.sign_as is None


def test_registered_arguments_are_consumed():
    """注册了却没人读的参数 = 文档会宣传一个不起作用的开关。"""
    ap = cli.build_parser()
    holder = next(a for a in ap._actions if getattr(a, "choices", None) and a.dest == "cmd")
    all_reads: set[str] = set()
    for name in cli.SUBCOMMAND_NAMES:
        fn = cli.cmd_all if name == "all" else ap.parse_args([name] + MIN_ARGV.get(name, [])).fn
        all_reads |= _reads_of(fn)
    for name in cli.SUBCOMMAND_NAMES:
        unread = sorted(_registered(holder.choices[name]) - all_reads)
        assert not unread, f"{name} 注册了没人读的参数：{unread}"
