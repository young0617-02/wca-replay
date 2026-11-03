"""命令行入口：一条命令跑通「生成 -> 导入 -> 建库 -> 校验 -> 举证包 -> 问答 -> 评测」。

README 的复跑路径就是这里的 `python -m src.cli all`。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

from . import ENGINE_VERSION, signing
from .agent import ComplianceAgent
from .anomaly import review_backlog, rule_hit_counts, severity_rollup, write_anomaly_report
from .config import Config
from .db import (DatabaseIdentityMismatch, DatabaseUnavailable, connect, count, get_meta,
                 init_db, set_meta)
from .evidence import export_package, input_fingerprint, verify_chain
from .ingest import import_csv_file
from .kb import build_kb, citation_ids_missing
from .rules.citations import ALL_CITATIONS
from .rules.holidays import HolidayCalendar
from .rules.rulepack import RULE_CATALOG
from .util import CN_TZ

INGEST_ORDER = ("org", "employee", "schedule", "punch", "leave", "trip", "correction")
# 供演示脚本自洽性检查（A12）使用：命令名必须与 build_parser 中的注册保持一致
SUBCOMMAND_NAMES = ("init", "db-target", "gen", "ingest", "kb", "check", "report", "export",
                    "replay", "ask", "verify", "covers", "start", "stop", "status", "users",
                    "approval", "approval-doc", "approval-migrate", "keygen", "all")
KIND_BY_FILE = {
    "org.csv": "org",
    "employee.csv": "employee", "schedule.csv": "schedule", "punch.csv": "punch",
    "leave.csv": "leave", "trip.csv": "trip", "correction.csv": "correction",
}


def _cfg(args: argparse.Namespace) -> Config:
    return Config.load(getattr(args, "env", None))


def cmd_init(args) -> int:
    cfg = _cfg(args)
    cfg.ensure_dirs()
    conn = connect(cfg)
    init_db(conn)
    from .evidence import ensure_audit_epoch
    epoch = ensure_audit_epoch(conn, cfg)
    print(f"已初始化 {cfg.db_backend}：{cfg.safe_database_target}"
          f"（schema v{get_meta(conn, 'schema_version')}）")
    if epoch:
        print(f"审计纪元已建立：{epoch['epoch_id']} "
              f"{epoch['prev_rule_pack_version']} → {epoch['rule_pack_version']}，"
              f"旧链头 {epoch['prev_head_hash'][:16]}…，新段起点 "
              f"seq={epoch['segment_start_seq']} prev={epoch['segment_start_prev_hash'][:16]}…")
    conn.close()
    return 0


def cmd_db_target(args) -> int:
    """显式查看/重置 PostgreSQL identity。重置是唯一允许切换目标库的用户动作。"""
    from .db import describe_identity, reset_database_identity

    cfg = _cfg(args)
    if args.show:
        info = describe_identity(cfg)
        if not info["applicable"]:
            print(f"db-target 仅适用于 PostgreSQL；当前后端 {info['backend']}，"
                  f"SQLite 回退不需要 identity（{info['path']}）")
            return 0
        print(f"配置库：{info['configured']}")
        if info["identity_database"]:
            print(f"identity：{info['identity_database']}（{info['path']}）")
        else:
            print(f"identity：不存在（{info['path']}）")
        print(f"匹配：{'是' if info['match'] else '否'}")
        if info.get("error"):
            print(f"错误：{info['error']}")
        return 0
    if args.reset:
        if not args.confirm:
            print("用法：python -m src.cli db-target --reset --confirm <配置库名>",
                  file=sys.stderr)
            return 2
        try:
            res = reset_database_identity(cfg, confirm=args.confirm)
        except ValueError as exc:
            print(f"拒绝执行：{exc}", file=sys.stderr)
            return 2
        print(f"已重置数据库 identity：{res['path']}（配置库 {res['configured']}；"
              f"{'已删除' if res['removed'] else '原本不存在'}）")
        return 0
    print("用法：python -m src.cli db-target --show | --reset --confirm <配置库名>",
          file=sys.stderr)
    return 2


def cmd_gen(args) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "data" / "generator"))
    from make_synthetic import write  # type: ignore

    manifest = write(args.seed)
    total = sum(v["rows"] for v in manifest["files"].values())
    print(f"合成数据生成完成：seed={args.seed}，{len(manifest['files'])} 个文件 / {total} 行 -> data/raw")
    return 0


def cmd_ingest(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    init_db(conn)
    root = Path(args.dir)
    if not root.is_dir():
        print(f"目录不存在：{root}（先跑 python -m src.cli gen）", file=sys.stderr)
        return 2
    files = {f.name: f for f in sorted(root.glob("*.csv"))}
    unknown = set(files) - set(KIND_BY_FILE)
    if unknown:
        print(f"跳过未识别文件：{sorted(unknown)}", file=sys.stderr)
    for kind in INGEST_ORDER:
        for name, path in files.items():
            if KIND_BY_FILE.get(name) != kind:
                continue
            res = import_csv_file(conn, cfg, path, kind=kind, created_at=args.imported_at)
            mode_note = res.write_mode
            if res.degraded_from:
                mode_note += f"(请求 {res.degraded_from}，已降级)"
            print(f"[{kind:10s}] {name:16s} 行 {res.rows_seen:5d} 入库 {res.rows_accepted:5d} "
                  f"拒收 {res.rows_rejected:3d} 质量问题 {len(res.issues):3d} "
                  f"写入 {mode_note} 分块 {res.chunk_rows:5d} "
                  f"sha256={res.sha256[:12]}…")
    print(f"员工 {count(conn, 'employee')} / 打卡 {count(conn, 'punch')} / "
          f"请假 {count(conn, 'leave_record')} / 出差 {count(conn, 'trip_record')} / "
          f"补卡 {count(conn, 'punch_correction')} / 排班 {count(conn, 'shift_plan')} / "
          f"质量记录 {count(conn, 'ingest_issue')}")
    return 0


def cmd_kb(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    init_db(conn)
    res = build_kb(conn)
    missing = citation_ids_missing(conn, ALL_CITATIONS)
    print(f"知识库构建完成：条目 {res.docs}（其中个人数据 {res.personnel_docs}）、"
          f"term 索引 {res.terms}、语料 sha256={res.corpus_sha256[:12]}…")
    if missing:
        print(f"规则引用但库中缺失的条文 id：{missing}", file=sys.stderr)
        return 3
    print("规则引用的全部条文 id 均可在知识库中定位（A2 前置检查通过）")
    return 0


def cmd_check(args) -> int:
    from .engine import run_check

    cfg = _cfg(args)
    conn = connect(cfg)
    init_db(conn)
    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end)
    emp_ids = args.emp.split(",") if args.emp else None
    out = run_check(conn, cfg, start=start, end=end, emp_ids=emp_ids,
                    notes=args.notes or "cli check")
    print(f"run_id={out.run_id}")
    print(f"  规则版本 {cfg.rule_pack_id} / 引擎 {ENGINE_VERSION}")
    print(f"  员工 {out.employees} 人 / 工作日事实 {out.days} 条 / 结论 {len(out.findings)} 条")
    counts = out.counts_by_severity()
    print(f"  分级：明显违规 {counts['VIOLATION']}，需复核 {counts['REVIEW']}，可申辩 {counts['DEFENSIBLE']}")
    print(f"  输入指纹 {out.input_fingerprint[:20]}…")
    print(f"  结论摘要 {out.conclusion_digest[:20]}…")
    for warning in out.warnings:
        print(f"  ⚠ {warning}", file=sys.stderr)
    print(f"  耗时 {out.elapsed_us / 1000:.1f} ms")
    return 0


def cmd_report(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    run_id = args.run or get_meta(conn, "last_run_id")
    if not run_id:
        print("尚无校验运行，请先 `python -m src.cli check`", file=sys.stderr)
        return 2
    from .anomaly import build_anomalies

    # 先完成所有查询，再落盘：查询/方言失败时不会留下已写出的半截报表。
    items = build_anomalies(conn, run_id)
    hits = rule_hit_counts(conn, run_id)
    path = write_anomaly_report(conn, cfg, run_id)
    print(f"异常报表：{path}（{len(items)} 条异常，分级汇总 {severity_rollup(items)}）")
    for row in hits[:12]:
        print(f"  {row['rule_id']:10s} {row['severity']:10s} x{row['count']}")
    print(f"待复核队列：{review_backlog(conn)}")
    return 0


def cmd_export(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    run_id = args.run or get_meta(conn, "last_run_id")
    if not run_id:
        print("尚无校验运行，请先 `python -m src.cli check`", file=sys.stderr)
        return 2
    recorded_by = (getattr(args, "record_delivery_as", None)
                   or getattr(args, "sign_as", None))
    if recorded_by:
        from .evidence import record_delivery_event
        rec = record_delivery_event(conn, cfg, run_id, recorded_by=recorded_by)
        print(f"登记交付事件（非密码学签名；--sign-as 为迁移期旧别名）：{recorded_by} "
              f"审计序号 {rec['audit_seq']} 链哈希 {rec['entry_hash'][:16]}…")
    signing_key = signing.load_signing_key(getattr(args, "signing_key", None))
    manifest = export_package(conn, cfg, run_id, include_inputs=not args.no_inputs,
                              signing_key=signing_key)
    inputs = manifest["inputs"]
    print(f"举证包：{manifest['package_zip']}")
    print(f"  对外结论 {manifest['counts']['final_conclusions']} 条 / 未人工确认 {manifest['counts']['unsigned_pending']} 条"
          f"（无人工结论的异常不进结论集）")
    print(f"  自含输入 {inputs['packed']} 个 / {inputs['total_bytes']:,} 字节"
          + (f"；缺项 {len(inputs['missing'])}：{inputs['missing']}" if inputs["missing"] else "")
          + (f"；{inputs['reason']}" if inputs["reason"] else ""))
    if inputs.get("critical"):
        print(f"  ⚠ {inputs.get('critical_message') or '自含输入已超过临界线，需人工确认'}")
    elif inputs.get("warning"):
        print(f"  ⚠ {inputs.get('warning_message') or '自含输入已接近上限'}")
    print(f"  三元组 {json.dumps(manifest['triple'], ensure_ascii=False, sort_keys=True)}")
    print(f"  审计链 {manifest['chain_verification']}")
    print(f"  manifest sha256={manifest['manifest_sha256'][:20]}… 结论 {manifest['counts']['findings']} 条")
    signature = manifest.get("signature") or {}
    if signature:
        print(f"  Ed25519 签名 key_id={signature.get('key_id', '')}（包内公钥只证明自洽；"
              "来源可信需复核方用 --public-key 固定公钥）")
    else:
        print("  未签名（v2）；如需签名：--signing-key <私钥文件> 或 WCA_SIGNING_KEY_FILE")
    print("  复核方重放：unzip 后 python verify.py（链+输入+结论集哈希+验签），"
          "或 python -m src.cli replay <包>（把输入喂回引擎比三元组）")
    return 0


def cmd_keygen(args) -> int:
    """生成本机 Ed25519 私钥与公钥；私钥不覆盖、不进包、不打印内容。"""
    out = Path(args.out)
    public_out = Path(args.public_out) if args.public_out else None
    if not args.force:
        existing = [str(p) for p in (out, public_out)
                    if p is not None and p.exists()]
        if existing:
            print("密钥文件已存在，拒绝覆盖：" + "、".join(existing)
                  + "（确认要覆盖请加 --force）", file=sys.stderr)
            return 1
    key = signing.generate_keypair()
    signing.write_private_key(out, key, force=args.force)
    public = key.verify_key.encode()
    if public_out is not None:
        signing.write_public_key(public_out, public, force=args.force)
    print(f"私钥：{out}（权限已收紧；不要提交、不要外发）")
    if public_out is not None:
        print(f"公钥：{public_out}")
    print(f"key_id：{signing.key_id_for_public_key(public)}")
    print(f"公钥 Base64：{signing.public_key_b64(public)}")
    return 0


def cmd_replay(args) -> int:
    from .replay import replay

    res = replay(args.package, expect_triple=getattr(args, "expect_triple", None),
                 expect_anchor=getattr(args, "expect_anchor", None),
                 public_keys=getattr(args, "public_key", None),
                 require_signature=bool(getattr(args, "require_signature", False)))
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if res["ok"] else 1
    print(f"重放举证包 {res['package']}（run {res['run_id']}）")
    if (res.get("manifest_checksum") == "missing"
            and not str(res.get("reason") or "").startswith("MANIFEST FAIL")):
        print("  MANIFEST CHECKSUM MISSING（旧包，继续按既有规则比对）")
    if res.get("external_mismatched_fields"):
        print("  外部锚点差异：" + ", ".join(res["external_mismatched_fields"]))
    print(f"  审计链：{'完整' if res['chain']['ok'] else '断裂'}，{res['chain']['length']} 条"
          + (f"（seq={res['chain']['broken_at_seq']} {res['chain']['reason']}）"
             if not res["chain"]["ok"] else ""))
    print(f"  包内输入 {res['inputs_packed']} 个"
          + (f"，导出时缺项 {res['inputs_missing']}" if res["inputs_missing"] else ""))
    if res.get("inputs_digest"):
        print(f"  输入摘要：{'与 manifest/签名一致' if res['inputs_digest_ok'] else '不一致'}"
              f"（{str(res['inputs_digest'])[:16]}…）")
    print(f"  钉回口径参数 {json.dumps(res['pinned_params'], ensure_ascii=False, sort_keys=True)}")
    print(f"  {res['inherited_params_note']}")
    if res.get("signature_present"):
        trust = ("pinned（来源可信）" if res["signature_trust"] == "pinned"
                 else "package self-check（NOT source trust，仅包内自洽）")
        print(f"  签名：{'有效' if res['signature_ok'] else '无效'} / {trust}"
              f" / key_id={res.get('signature_key_id') or '?'}"
              + (f" —— {res['signature_reason']}" if not res["signature_ok"] else ""))
    else:
        print("  签名：无（旧包；来源不可证明）"
              + (" —— 已要求 --require-signature" if getattr(args, "require_signature", False)
                 else ""))
    if "actual_triple" not in res:
        print(f"  结论：{'通过' if res['ok'] else '无法重放'} —— {res['reason']}")
        return 0 if res["ok"] else 1
    for key in ("rule_pack_version", "input_fingerprint", "conclusion_digest"):
        same = res["expected_triple"][key] == res["actual_triple"][key]
        print(f"  {'=' if same else '≠'} {key}: 期望 {str(res['expected_triple'][key])[:20]}… "
              f"实得 {str(res['actual_triple'][key])[:20]}…")
    print(f"  结论条数 期望 {res['findings_expected']} / 实得 {res['findings_actual']} "
          f"分级 {res['counts_actual']}")
    print(f"  重放结果：{'一致' if res['ok'] else '不一致'} —— {res['reason']}")
    return 0 if res["ok"] else 1


def cmd_users(args) -> int:
    """配置界面账号：口令只在本机换成 scrypt 哈希写进 users.json，仓库里不留明文。"""
    from .auth import ROLES, AuthError, hash_password, sync_users
    from .db import connect, init_db

    cfg = _cfg(args)
    path = Path(cfg.users_path)
    if args.password is None:
        print("用法：python -m src.cli users --username op1 --emp E001 --roles OP --password '<口令>'",
              file=sys.stderr)
        print(f"当前账号文件：{path}"
              f"{'（不存在，登录会被拒绝）' if not path.is_file() else ''}")
        return 2
    if not args.emp:
        print("--emp 必须是员工主数据里已有的 emp_id", file=sys.stderr)
        return 2
    conn = connect(cfg)
    init_db(conn)
    if conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (args.emp,)).fetchone() is None:
        # 先挡住"账号绑定不存在的员工"：否则它会在校验时被 sync_users 静默跳过，
        # 表现为"配了账号却登不进去"，排查成本高
        print(f"员工主数据里没有 {args.emp}：先跑 python -m src.cli all 或 ingest", file=sys.stderr)
        return 2
    if not set(args.roles.split(",")) <= set(ROLES):
        print(f"--roles 只能是 {list(ROLES)} 的组合", file=sys.stderr)
        return 2
    try:
        entry = {"username": args.username, "emp_id": args.emp,
                 "roles": [x for x in args.roles.split(",") if x],
                 "pw_hash": hash_password(args.password)}
    except AuthError as exc:
        print(f"口令不合要求：{exc}", file=sys.stderr)
        return 2
    data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"users": []}
    users = [u for u in data.get("users", []) if u.get("username") != entry["username"]]
    users.append(entry)
    data["users"] = sorted(users, key=lambda u: u["username"])
    data["note"] = ("界面账号来源。pw_hash 是 scrypt 摘要、不是口令；演示口令只写在 docs/演示脚本-30分钟.md，"
                    "对应的人与数据都是合成的。")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")
    res = sync_users(conn, cfg)
    print(f"已写入 {path}：账号 {entry['username']} → {entry['emp_id']} "
          f"角色 {entry['roles']}；入库 added={res['added']} updated={res['updated']} "
          f"skipped={res['skipped']}")
    return 0


def cmd_approval(args) -> int:
    """最小受控录入：文号、期限、岗位范围、城市、附件哈希；界面入口留到后续。"""
    from .rules.approvals import upsert_approval, validate_approval_record

    cfg = _cfg(args)
    if not (args.emp and args.doc_no and args.regime and args.valid_from and args.valid_to
            and args.job_codes and args.region and args.attachment_sha256):
        print("用法：python -m src.cli approval --emp E006 --doc-no <文号> "
              "--regime comprehensive_monthly --valid-from 2025-01-01 --valid-to 2025-12-31 "
              "--job-codes warehouse_shift --region <城市码> --attachment-sha256 <64位hex> "
              "[--recorded-at ISO8601]", file=sys.stderr)
        return 2
    jobs = [x.strip() for x in args.job_codes.split(",") if x.strip()]
    record = {
        "emp_id": args.emp, "doc_no": args.doc_no, "regime": args.regime,
        "valid_from": args.valid_from, "valid_to": args.valid_to,
        "job_codes": json.dumps(jobs, ensure_ascii=False), "region_code": args.region,
        "attachment_sha256": args.attachment_sha256,
        "recorded_at": args.recorded_at or datetime.now(CN_TZ).isoformat(),
    }
    errors = validate_approval_record(record)
    if errors:
        print("审批台账校验失败：" + "；".join(errors), file=sys.stderr)
        return 2
    conn = connect(cfg)
    init_db(conn)
    if conn.execute("SELECT 1 FROM employee WHERE emp_id = ?", (args.emp,)).fetchone() is None:
        print(f"员工主数据里没有 {args.emp}：先导入 employee.csv 再登记审批台账",
              file=sys.stderr)
        return 2
    try:
        upsert_approval(conn, record)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"审批台账已写入：{args.emp} / {args.doc_no} / {args.regime} "
          f"{args.valid_from}~{args.valid_to} / 岗位 {jobs} / 城市 {args.region}")
    return 0


def cmd_approval_doc(args) -> int:
    """审批台账 P0 只读入口：列批文 / 看员工覆盖 / 看版本链。

    CLI 是本机工具，没有网页会话；`--role` 只用于演示/测试角色边界，
    真正的写操作仍只由 service 层的 AD 校验放行，AU 或非读角色越权会明确报错。
    """
    from .auth import ROLES, User
    from .rules.approval_docs import coverage_for, list_docs, version_chain

    cfg = _cfg(args)
    role = str(args.role or "AU").upper()
    if role not in ROLES:
        print(f"未知角色 {role}；可用：{list(ROLES)}", file=sys.stderr)
        return 2
    user = User(username=f"cli-{role.lower()}", emp_id="", roles=(role,),
                org_id="", region_code="", pseudonym="CLI")
    conn = connect(cfg)
    init_db(conn)
    try:
        if args.docs:
            rows = list_docs(conn, user)
            if not rows:
                print("（无批文）")
            for row in rows:
                print(f"{row['doc_no']}\t{row['status']}\tv{row['current_version'] or '-'}\t"
                      f"{row['regime']}\t{row['title']}")
            return 0
        if args.coverage:
            rows = coverage_for(conn, user, args.coverage)
            if not rows:
                print(f"{args.coverage} 无已发布审批覆盖")
            for row in rows:
                print(f"{row['emp_id']}\t{row['doc_no']}\tv{row['version_no']}\t"
                      f"{row['regime']}\t{row['valid_from']}~{row['valid_to']}\t"
                      f"{row['attachment_sha256'][:16]}…")
            return 0
        if args.versions:
            data = version_chain(conn, user, args.versions)
            doc = data["doc"]
            print(f"{doc['doc_no']}\t{doc['status']}\tcurrent=v{doc['current_version'] or '-'}\t"
                  f"{doc['regime']}\t{doc['title']}")
            for version in data["versions"]:
                scopes = ",".join(f"{s['scope_type']}:{s['scope_value']}"
                                  for s in version["scopes"])
                print(f"  v{version['version_no']}\t{version['status']}\t"
                      f"{version['valid_from']}~{version['valid_to']}\t"
                      f"scopes={scopes}\t附件={version['attachment_sha256'][:16]}…")
            return 0
        print("用法：approval-doc --docs | --coverage <emp_id> | --versions <doc_no> "
              "[--role AU|AD]", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"越权：{exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        conn.close()


def cmd_approval_migrate(args) -> int:
    """旧台账迁移/对照：默认 dry-run 只读；--apply 才写临时库；活动库一律拒绝。"""
    from .rules.approval_migration import (MigrationSafetyError, apply_migration,
                                           assert_no_widening, assert_temporary_database,
                                           build_report, latest_run_window, plan_migration,
                                           write_report)
    from .db_guard import (assert_connection_is_temporary, ensure_config_matches_actual,
                           validate_active_cutover, validate_backup_file)

    cfg = _cfg(args)
    allow_active = bool(getattr(args, "allow_active", False))
    if allow_active and not args.apply:
        print("拒绝执行：--allow-active 只允许与 --apply 一起使用；活动库 dry-run 仍禁止。",
              file=sys.stderr)
        return 2
    if allow_active:
        # 连接前先做备份文件存在/非空/哈希校验；连接后再按实际库名复核。
        try:
            validate_backup_file(args.backup_path, args.backup_sha256)
        except MigrationSafetyError as exc:
            print(f"拒绝执行：{exc}", file=sys.stderr)
            return 2
    else:
        try:
            assert_temporary_database(cfg)
        except MigrationSafetyError as exc:
            print(f"拒绝执行：{exc}", file=sys.stderr)
            return 2

    # provision=False：不让 ensure_database 按本地 identity 改写目标库。
    try:
        conn = connect(cfg, provision=False)
    except DatabaseUnavailable as exc:
        print(f"无法连接目标库：{exc}", file=sys.stderr)
        return 2
    # 连接后按实际库身份复核：不认配置自述，也不认 caller 传入的库名。
    try:
        if allow_active:
            from .db_guard import actual_database_identity
            actual = actual_database_identity(conn)
            validate_active_cutover(
                actual=actual, confirm_active=args.confirm_active,
                backup_path=args.backup_path, backup_sha256=args.backup_sha256)
            ensure_config_matches_actual(cfg, actual)
        else:
            actual = assert_connection_is_temporary(conn, cfg)
            ensure_config_matches_actual(cfg, actual)
    except MigrationSafetyError as exc:
        conn.close()
        print(f"拒绝执行：{exc}", file=sys.stderr)
        return 2
    if args.apply:
        confirm = str(getattr(args, "confirm_apply", "") or "").strip()
        if not confirm:
            conn.close()
            print("拒绝执行：--apply 必须同时给 --confirm-apply <实际库名/实际路径>，"
                  "防止误把临时库迁移写到未确认的目标。", file=sys.stderr)
            return 2
        if confirm != actual:
            conn.close()
            print(f"拒绝执行：--confirm-apply={confirm!r} 与实际连接 {actual!r} 不一致。",
                  file=sys.stderr)
            return 2
    init_db(conn)
    try:
        start = date.fromisoformat(args.start) if args.start else None
        end = date.fromisoformat(args.end) if args.end else None
        if start is None or end is None:
            window = latest_run_window(conn)
            if window is None:
                print("库里没有可用的最近 run；请显式给 --start/--end", file=sys.stderr)
                return 2
            start, end = window
        if start > end:
            print(f"区间非法：{start} > {end}", file=sys.stderr)
            return 2

        plan = plan_migration(conn)
        mode = "apply-active" if allow_active else ("apply" if args.apply else "dry-run")
        report = build_report(conn, cfg, plan, start, end, mode=mode)
        reg01 = report["reg01"]
        report_path = Path(args.report) if args.report else (
            cfg.reports_dir / f"迁移对照-{mode}-{datetime.now(CN_TZ).strftime('%Y%m%dT%H%M%S')}.json")
        written_path = write_report(report, report_path)

        print(f"审批台账迁移对照（{mode}，{'已写库' if args.apply else '未写库'}）")
        print(f"  数据库 {cfg.safe_database_target}")
        print(f"  连接后实际库 {actual}")
        print(f"  校验区间 {start} ~ {end}")
        print(f"  旧台账 {plan.legacy_rows} 行 / {plan.legacy_docs} 个文号 / "
              f"{len(plan.legacy_employee_ids)} 名员工")
        print(f"  计划：批文 {len(plan.docs)} / 版本 {len(plan.versions)} / "
              f"覆盖 {len(plan.coverage)} 行（{len(plan.coverage_employee_ids)} 名员工）；"
              f"丢弃 {len(plan.skipped)} 行；合并 {len(plan.merged)} 组")
        print(f"  REG-01：v5 命中 {reg01['v5_hits_count']} / v6 预测命中 "
              f"{reg01['v6_hits_count']}；仅 v5 {len(reg01['only_v5'])}（危险） / "
              f"仅 v6 {len(reg01['only_v6'])}")
        for item in plan.skipped[:5]:
            print(f"    丢弃 {item['emp_id']} / {item['doc_no']}：{item['reason']}")
        if len(plan.skipped) > 5:
            print(f"    ……其余 {len(plan.skipped) - 5} 条见报告")
        print(f"  报告 {written_path}")

        if args.apply:
            assert_no_widening(reg01)
            result = apply_migration(conn, cfg, plan, actor=args.actor,
                                     allow_active=allow_active)
            print(f"  已写库：批文 {result['docs']} / 版本 {result['versions']} / "
                  f"范围 {result['scopes']} / 覆盖 {result['coverage']}；"
                  f"跳过已存在文号 {result['skipped_existing_docs']} 个版本")
            print(f"  审计事件 approval_doc.migrate 已写入；旧表 worktime_approval 保留未动")
        else:
            print("  下一步：确认报告后加 --apply 才会落库（仅临时库）")
        return 0
    except MigrationSafetyError as exc:
        print(f"迁移拒绝：{exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        conn.close()


def cmd_ask(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    init_db(conn)
    agent = ComplianceAgent(conn, cfg)
    ans = agent.ask(args.question, actor_emp_id=args.actor)
    print(f"[{ans.intent}/{ans.tier}] gate={ans.gate_decision} "
          f"置信 {ans.confidence_permille}‰ 证据覆盖 {ans.evidence_coverage_permille}‰ "
          f"耗时 {ans.elapsed_us / 1000:.1f}ms provider={ans.provider}"
          f"{'（离线降级）' if ans.degraded else ''}")
    print(ans.answer)
    print("--- 引用 ---")
    print(ans.citation_markdown)
    if ans.violations:
        print("--- 门禁记录 ---")
        for v in ans.violations:
            print(f"  · {v}")
    print(f"--- 检索候选 {len(ans.retrieval['candidates'])} 条，命中 {ans.retrieval['hit_doc_ids']}")
    return 0


def cmd_verify(args) -> int:
    cfg = _cfg(args)
    conn = connect(cfg)
    chain = verify_chain(conn, cfg)
    print(f"审计链：{chain.length} 条，{'完整' if chain.ok else f'在 seq={chain.broken_at_seq} 断裂：{chain.reason}'}")
    return 0 if chain.ok else 4


def cmd_covers(args) -> int:
    """打印判据分支覆盖情况，供 reports/ 直接引用。"""
    cfg = _cfg(args)
    conn = connect(cfg)
    hit = {r["rule_id"]: int(r["c"]) for r in conn.execute(
        "SELECT rule_id, COUNT(*) AS c FROM finding GROUP BY rule_id").fetchall()}
    cal = HolidayCalendar.load()
    print(f"规则包 {cfg.rule_pack_id}：{len(RULE_CATALOG)} 条规则，覆盖年度 {cal.covered_years}")
    for m in RULE_CATALOG:
        mark = "命中" if hit.get(m.rule_id) else "未命中"
        print(f"  {m.rule_id:10s} [{mark}] {m.name_zh}（{m.tier}/{m.severity_kind}）")
    untouched = [m.rule_id for m in RULE_CATALOG if not hit.get(m.rule_id)]
    print(f"未命中规则 {len(untouched)} 条：{untouched}")
    return 0


def cmd_start(args) -> int:
    from .service_cli import main_start

    return main_start(_service_argv(args, restart=args.no_restart))


def cmd_stop(args) -> int:
    from .service_cli import main_stop

    return main_stop(_service_argv(args, force=args.force))


def cmd_status(args) -> int:
    from .service_cli import main_stop

    return main_stop(_service_argv(args) + ["--status"])


def _service_argv(args, *, restart: bool = False, force: bool = False) -> list[str]:
    """把 CLI 参数翻成 service_cli 的 argv：只有真值才传，缺省一律交还给 service_cli 的默认。"""
    argv: list[str] = []
    if args.config:
        argv += ["--config", str(args.config)]
    if args.only:
        argv += ["--only", str(args.only)]
    if args.json:
        argv.append("--json")
    if restart:
        argv.append("--no-restart")
    if force:
        argv.append("--force")
    return argv


ALL_STEPS = ("init", "gen", "ingest", "kb", "check", "report", "export")


def cmd_all(args) -> int:
    ap = build_parser()
    for name in ALL_STEPS:
        # 用子命令自己的解析结果当参数包：新增开关不会再把 all 炸成 AttributeError
        ns = ap.parse_args([name] + _step_argv(name, args))
        ns.env = args.env          # --env 挂在根解析器上，子命令 argv 不接受它
        print(f"\n=== {name} ===")
        if ns.fn(ns) != 0:
            return 1
    print("\n=== 下一步 ===")
    print("  python -m src.cli ask \"国庆当天上班加班费怎么算\" --as E004")
    print("  python -m pytest tests/ -q")
    print("  python evals/judge.py --write-report")
    return 0


def _step_argv(name: str, args) -> list[str]:
    """`all` 只钉死三件可复现输入：数据种子、导入时刻、校验区间与备注。"""
    if name == "gen":
        return ["--seed", str(args.seed)]
    if name == "ingest":
        return ["--imported-at", "2026-10-06T09:00:00+08:00"]
    if name == "check":
        return ["--start", args.start, "--end", args.end, "--notes", "cli all"]
    return []


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m src.cli",
                                 description="工时合规校验与制度问答 Agent（合成数据 + 公开法条基准）")
    ap.add_argument("--env", default=None, help=".env 路径，默认项目根 .env")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="建库"); p.set_defaults(fn=cmd_init)
    p = sub.add_parser("db-target", help="查看/显式重置 PostgreSQL identity（切库唯一入口）")
    p.add_argument("--show", action="store_true", help="只查看配置库与 identity 是否匹配")
    p.add_argument("--reset", action="store_true", help="显式删除 identity 文件，允许下次按配置库重建")
    p.add_argument("--confirm", default="", help="--reset 必须精确给出配置 URL 里的库名")
    p.set_defaults(fn=cmd_db_target)
    p = sub.add_parser("gen", help="生成合成数据"); p.add_argument("--seed", type=int, default=20260106)
    p.set_defaults(fn=cmd_gen)
    p = sub.add_parser("ingest", help="导入 CSV（含质量门禁）")
    p.add_argument("--dir", default="data/raw"); p.add_argument("--imported-at", default=None,
                                                                dest="imported_at")
    p.set_defaults(fn=cmd_ingest)
    p = sub.add_parser("kb", help="构建知识库与检索索引"); p.set_defaults(fn=cmd_kb)
    p = sub.add_parser("check", help="运行确定性合规校验")
    p.add_argument("--start", default="2025-09-01"); p.add_argument("--end", default="2026-04-30")
    p.add_argument("--emp", default="", help="逗号分隔员工 id，默认全部")
    p.add_argument("--notes", default=""); p.set_defaults(fn=cmd_check)
    p = sub.add_parser("report", help="导出异常报表 CSV")
    p.add_argument("--run", default=""); p.set_defaults(fn=cmd_report)
    p = sub.add_parser("export", help="导出举证包（三元组 + 审计链 + 责任区块 + 未覆盖清单 + 自含输入）")
    p.add_argument("--run", default="")
    p.add_argument("--record-delivery-as", dest="record_delivery_as", default=None,
                   help="登记交付事件（非密码学签名），写入 evidence.sign 审计链后再导出")
    p.add_argument("--sign-as", dest="sign_as", default=None,
                   help="迁移期旧别名，等价于 --record-delivery-as（非密码学签名）")
    p.add_argument("--no-inputs", dest="no_inputs", action="store_true",
                   help="不打包原始输入 CSV（包会因此无法离线重放）")
    p.add_argument("--signing-key", dest="signing_key", default=None,
                   help="Ed25519 私钥文件（单行 Base64 seed）；不传则读 "
                        "WCA_SIGNING_KEY_FILE / WCA_SIGNING_KEY_B64，仍无则导出 v2 无签名包")
    p.set_defaults(fn=cmd_export)
    p = sub.add_parser("replay", help="拿举证包自己重放：解包 -> 重导输入 -> 重跑引擎 -> 比三元组")
    p.add_argument("package", help="包 zip 或已解压的目录")
    p.add_argument("--json", action="store_true", help="输出机器可比的完整结果")
    p.add_argument("--expect-triple", default=None,
                   help="包外记录的外部三元组：rule_pack_version,input_fingerprint,"
                        "conclusion_digest（不约束 schema）；也可用环境变量 WCA_EXPECT_TRIPLE")
    p.add_argument("--expect-anchor", default=None,
                   help="包外记录的外部四元组：schema_version,rule_pack_version,"
                        "input_fingerprint,conclusion_digest；也可用环境变量 WCA_EXPECT_ANCHOR")
    p.add_argument("--public-key", action="append", default=None, dest="public_key",
                   help="外部固定公钥（文件路径或 Base64），可重复传入以支持轮换；"
                        "不传时验签只证明包内自洽，不能证明来源")
    p.add_argument("--require-signature", action="store_true",
                   help="旧 v1/v2 包无签名也判失败；v3 缺签名始终失败")
    p.set_defaults(fn=cmd_replay)
    p = sub.add_parser("keygen", help="生成 Ed25519 签名密钥（私钥不覆盖，公钥可公开）")
    p.add_argument("--out", default="var/keys/ed25519.key", help="私钥输出路径")
    p.add_argument("--public-out", dest="public_out", default=None,
                   help="公钥输出路径（可选；不给则只打印 Base64）")
    p.add_argument("--force", action="store_true", help="允许覆盖已存在的密钥文件")
    p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("ask", help="问一答（走同一条 API 链路）")
    p.add_argument("question"); p.add_argument("--as", dest="actor", default="E001")
    p.set_defaults(fn=cmd_ask)
    p = sub.add_parser("verify", help="校验审计 hash 链"); p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("covers", help="规则命中覆盖表"); p.set_defaults(fn=cmd_covers)
    p = sub.add_parser("users", help="配置界面账号（只写 scrypt 口令哈希，不存明文）")
    p.add_argument("--username", default="op1")
    p.add_argument("--emp", default="E001")
    p.add_argument("--roles", default="OP")
    p.add_argument("--password", default=None)
    p.set_defaults(fn=cmd_users)
    p = sub.add_parser("approval", help="登记特殊工时审批台账（最小 CLI，界面入口留到后续）")
    p.add_argument("--emp", default="")
    p.add_argument("--doc-no", dest="doc_no", default="")
    p.add_argument("--regime", default="comprehensive_monthly")
    p.add_argument("--valid-from", dest="valid_from", default="")
    p.add_argument("--valid-to", dest="valid_to", default="")
    p.add_argument("--job-codes", dest="job_codes", default="")
    p.add_argument("--region", default="")
    p.add_argument("--attachment-sha256", dest="attachment_sha256", default="")
    p.add_argument("--recorded-at", dest="recorded_at", default=None)
    p.set_defaults(fn=cmd_approval)
    p = sub.add_parser("approval-doc", help="审批台账 P0 只读入口（列批文/员工覆盖/版本链）")
    p.add_argument("--docs", action="store_true", help="列出批文")
    p.add_argument("--coverage", default="", help="查看某员工的已发布覆盖")
    p.add_argument("--versions", default="", help="查看某批文的版本链")
    p.add_argument("--role", default="AU", help="本机只读演示角色，默认 AU")
    p.set_defaults(fn=cmd_approval_doc)
    p = sub.add_parser("approval-migrate",
                       help="旧 worktime_approval 迁移/对照（默认 dry-run；--apply 仅临时库）")
    p.add_argument("--start", default="", help="REG-01 对照区间起；默认取最近一次 run")
    p.add_argument("--end", default="", help="REG-01 对照区间止；默认取最近一次 run")
    p.add_argument("--report", default="", help="差异报告 JSON 路径")
    p.add_argument("--apply", action="store_true",
                   help="真正写入 P0 四表（仅临时库；默认只读 dry-run）")
    p.add_argument("--confirm-apply", dest="confirm_apply", default="",
                   help="--apply 的显式确认：必须等于连接后读到的实际库名（PG）或实际路径（SQLite）")
    p.add_argument("--allow-active", dest="allow_active", action="store_true",
                   help="一次性活动库切换：必须同时给备份、备份 sha256 与 --confirm-active；只允许与 --apply")
    p.add_argument("--backup-path", dest="backup_path", default="",
                   help="allow-active 的活动库备份文件（pg_dump 自定义格式）")
    p.add_argument("--backup-sha256", dest="backup_sha256", default="",
                   help="allow-active 备份文件的期望 SHA-256")
    p.add_argument("--confirm-active", dest="confirm_active", default="",
                   help="allow-active 的显式确认：必须等于连接后实际库名 wca_worktime")
    p.add_argument("--actor", default="system:migration", help="审计事件里的迁移执行者")
    p.set_defaults(fn=cmd_approval_migrate)
    for name, fn, needs in (("start", cmd_start, "restart"), ("stop", cmd_stop, "force"),
                            ("status", cmd_status, "")):
        q = sub.add_parser(name, help={
            "start": "一键启动服务（检测到在跑则先停后起）",
            "stop": "一键优雅停止服务",
            "status": "只看服务状态，不动任何东西",
        }[name])
        q.add_argument("--config", default=None, help="服务清单，默认 config/services.json")
        q.add_argument("--only", default="", help="逗号分隔服务名")
        q.add_argument("--json", action="store_true")
        if needs == "restart":
            q.add_argument("--no-restart", action="store_true")
        if needs == "force":
            q.add_argument("--force", action="store_true")
        q.set_defaults(fn=fn)
    p = sub.add_parser("all", help="一键复跑：init->gen->ingest->kb->check->report->export")
    p.add_argument("--seed", type=int, default=20260106)
    p.add_argument("--start", default="2025-09-01"); p.add_argument("--end", default="2026-04-30")
    p.set_defaults(fn=cmd_all)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except DatabaseIdentityMismatch as exc:
        print(f"拒绝执行：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
