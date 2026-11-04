"""外部重放：拿着举证包自己把引擎跑一遍，比对三元组（需求 US-EX-01 / 一票否决项 A8）。

为什么要有这个命令：`verify.py` 只能证明**包没被改写**（链与文件哈希），
证明不了"这些结论是这批数据算出来的"。需求原文写的是「只给包内三元组 + 原始 CSV，重放逐条一致」，
所以包必须自带输入，且必须有一条命令能把输入喂回引擎再比一次摘要。

口径边界要说清（不做无法兑现的承诺）：
  * 重放用的是**当前代码**，规则包版本与包内不一致时直接拒绝，不假装能跨版本复现；
  * 包内 scope 记了哪些参数，重放就强制钉回哪些参数；**没记的**（夜间窗口、月度上限等）
    沿用代码默认值——本机 `.env` 不参与，所以结果只依赖"包 + 仓库默认口径"。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath

from . import ENGINE_VERSION, package_verify, producer, projection, signing
from .config import Config
from .db import DB_BACKEND_SQLITE, connect, init_db
from .engine import run_check
from .ingest import import_csv_file
from .package_inputs import input_arcnames
from .rules.approvals import import_approval_csv, import_coverage_csv
from .util import (CSV_FORMULA_ESCAPE, MANIFEST_CHECKSUM_FIELD, anchor_schema_version,
                   evidence_schema_version, manifest_checksum, sha256_hex)

GENESES = "wca-audit-chain-v1"
TRIPLE_KEYS = ("rule_pack_version", "input_fingerprint", "conclusion_digest")
# 导入顺序决定"同一份主数据被谁最后覆盖"，所以重放必须按与 CLI 相同的顺序来；
# 审批台账依赖 employee 主数据，必须排在 employee 之后。
INGEST_ORDER = ("org", "employee", "approval", "schedule", "punch", "leave", "trip", "correction")
# scope 里记了哪些口径参数，重放就钉回哪些；其余沿用代码默认值并如实列出
PINNED_SCOPE_PARAMS = {
    "ot_cap_scope": "WCA_OT_CAP_SCOPE",
    "cross_day_cut_hour": "WCA_CROSS_DAY_CUT_HOUR",
    "daily_std_minutes": "WCA_DAILY_STD_MINUTES",
    "weekly_std_minutes": "WCA_WEEKLY_STD_MINUTES",
    "pay_base_source": "WCA_PAY_BASE_SOURCE",
}


_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# zip 资源上限默认值。依据是既有真实包 var/v6-3000/packages/
# run-20261102T225122-b335a25d.zip：17 个条目、解压合计 17,368,524 字节、
# 单条目最大 5,914,237 字节、最大压缩比 32.31:1。默认值留约 3-5 倍余量：
#   * 条目数 256：真实包 17 的 15 倍，足够覆盖输入文件 + 报告 + verify.py；
#   * 总解压 64 MiB：真实包约 16.56 MiB 的 3.8 倍，也高于 12 MiB 输入预算；
#   * 单条目 32 MiB：真实包最大成员的 5.7 倍，避免单文件先撑爆总预算；
#   * 压缩比 100:1：真实包最大 32.31:1 的 3 倍；正常 CSV 重复度高也很难长期超过。
# 需要放宽/收紧时用 `ZipLimits(...)` 显式传入 `replay`/`unpacked`，不改全局常量。
ZIP_MAX_ENTRIES = 256
ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
ZIP_MAX_MEMBER_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
ZIP_MAX_COMPRESSION_RATIO = 100.0
# 目录/zip 路径的最大嵌套深度。当前包布局只有 `inputs/<file>`（深度 2），
# 8 层留出 6 层余量，足以覆盖未来受控子目录，同时阻止“构造 100 层目录”拖死遍历。
MAX_PACKAGE_DEPTH = 8
EXTRACT_CHUNK_SIZE = 64 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class ZipLimits:
    """zip/目录解包资源上限；默认值见上方常量与依据说明。"""

    max_entries: int = ZIP_MAX_ENTRIES
    max_total_uncompressed_bytes: int = ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES
    max_member_uncompressed_bytes: int = ZIP_MAX_MEMBER_UNCOMPRESSED_BYTES
    max_compression_ratio: float = ZIP_MAX_COMPRESSION_RATIO
    max_depth: int = MAX_PACKAGE_DEPTH


class _LimitState:
    """zip 与目录两种来源共用的限额执行器（条目/深度/单文件/总量）。"""

    def __init__(self, limits: ZipLimits):
        self.limits = limits
        self.entries = 0
        self.total = 0

    def entry(self, rel_path: str) -> None:
        parts = PurePosixPath(str(rel_path).replace(chr(92), "/")).parts
        if len(parts) > self.limits.max_depth:
            raise ValueError(
                f"[DEPTH_TOO_DEEP] 路径深度 {len(parts)} 超过上限 "
                f"{self.limits.max_depth}：{rel_path}")
        self.entries += 1
        if self.entries > self.limits.max_entries:
            raise ValueError(
                f"[TOO_MANY_ENTRIES] 条目数 {self.entries} 超过上限 "
                f"{self.limits.max_entries}：{rel_path}")

    def check_declared_member(self, rel_path: str, size: int) -> None:
        if size > self.limits.max_member_uncompressed_bytes:
            raise ValueError(
                f"[MEMBER_TOO_LARGE] {rel_path} 解压后 {size:,} 字节超过单条目上限 "
                f"{self.limits.max_member_uncompressed_bytes:,} 字节")

    def add_declared_total(self, size: int) -> None:
        self.total += size
        if self.total > self.limits.max_total_uncompressed_bytes:
            raise ValueError(
                f"[TOTAL_TOO_LARGE] 解压总大小已超过上限 "
                f"{self.limits.max_total_uncompressed_bytes:,} 字节")

    def consume(self, rel_path: str, written_before: int, chunk_len: int) -> None:
        """按实际读到的字节计数；不信任 stat/中央目录声称的 size。"""
        if written_before + chunk_len > self.limits.max_member_uncompressed_bytes:
            raise ValueError(
                f"[MEMBER_TOO_LARGE] {rel_path} 实际解压超过单条目上限 "
                f"{self.limits.max_member_uncompressed_bytes:,} 字节")
        self.total += chunk_len
        if self.total > self.limits.max_total_uncompressed_bytes:
            raise ValueError(
                f"[TOTAL_TOO_LARGE] 解压总大小已超过上限 "
                f"{self.limits.max_total_uncompressed_bytes:,} 字节")


def _check_zip_limits(zf: zipfile.ZipFile, limits: ZipLimits) -> list[zipfile.ZipInfo]:
    """解包前按中央目录元数据预检；任何一项超限都不开始写盘。"""
    infos = zf.infolist()
    state = _LimitState(limits)
    for info in infos:
        _relative_parts(info.filename, "zip 内")
        state.entry(info.filename)
        size = int(info.file_size)
        state.check_declared_member(info.filename, size)
        if size > 0:
            if info.compress_size <= 0:
                raise ValueError(
                    f"[RATIO_TOO_HIGH] zip 成员 {info.filename} 压缩比异常"
                    "（压缩大小为 0），拒绝解压")
            ratio = size / info.compress_size
            if ratio > limits.max_compression_ratio:
                raise ValueError(
                    f"[RATIO_TOO_HIGH] zip 成员 {info.filename} 压缩比 {ratio:.1f}:1 "
                    f"超过上限 {limits.max_compression_ratio:g}:1，拒绝解压")
        state.add_declared_total(size)
    return infos


def _extract_zip(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], dest: Path,
                 limits: ZipLimits) -> None:
    """逐条流式解压并再次计数；实际字节超限立即失败，不把半成品交给调用方。"""
    actual = _LimitState(limits)
    for info in infos:
        target = _package_member(dest, info.filename)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with zf.open(info) as src, target.open("wb") as dst:
            while True:
                chunk = src.read(EXTRACT_CHUNK_SIZE)
                if not chunk:
                    break
                actual.consume(info.filename, written, len(chunk))
                written += len(chunk)
                dst.write(chunk)
        if written != int(info.file_size):
            raise ValueError(
                f"zip 成员 {info.filename} 实际解压 {written:,} 字节与声明 "
                f"{int(info.file_size):,} 字节不一致，拒绝使用")


def _check_dir_limits(root: Path, limits: ZipLimits) -> None:
    """目录包限额适配：复用 _LimitState，并在真正打开文件时按实际字节计数。

    拒绝符号链接、Windows 重解析点、硬链接与非普通文件；不跟随链接到包外。
    """
    state = _LimitState(limits)

    def walk(current: Path, rel_prefix: str) -> None:
        with os.scandir(current) as entries:
            for entry in entries:
                rel = rel_prefix + entry.name
                state.entry(rel)
                if entry.is_symlink():
                    raise ValueError(f"[SYMLINK_REJECTED] 目录包含符号链接：{rel}")
                # Windows 上 scandir 缓存的 stat 可能把 st_nlink 报成 0；
                # 用 os.stat(..., follow_symlinks=False) 取真实链接计数/属性。
                st = os.stat(entry.path, follow_symlinks=False)
                attrs = int(getattr(st, "st_file_attributes", 0))
                if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError(f"[REPARSE_POINT_REJECTED] 目录包含重解析点：{rel}")
                if entry.is_dir(follow_symlinks=False):
                    walk(Path(entry.path), rel + "/")
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"[NOT_REGULAR_FILE] 目录包含非普通文件：{rel}")
                if int(getattr(st, "st_nlink", 1)) > 1:
                    raise ValueError(f"[HARDLINK_REJECTED] 目录包含硬链接：{rel}")
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"[NOT_REGULAR_FILE] 目录包含非普通文件：{rel}")
                target = _package_member(root, rel)
                written = 0
                with target.open("rb") as fh:
                    while True:
                        chunk = fh.read(EXTRACT_CHUNK_SIZE)
                        if not chunk:
                            break
                        state.consume(rel, written, len(chunk))
                        written += len(chunk)

    walk(Path(root), "")


def _relative_parts(name: object, label: str) -> tuple[str, ...]:
    """校验包内相对路径：拒绝空值、绝对路径/UNC、驱动器号与任何 `..`。

    同时把 `\\` 归一成 `/`：zip 规范用 `/`，但恶意包可能混用；在 Windows 上
    反斜杠会被当成目录分隔符，必须先归一再看 parts，不能只信 `Path.resolve()`。
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{label}路径非法：arcname 为空")
    normalized = name.replace(chr(92), "/")
    if normalized.startswith("/"):
        raise ValueError(f"{label}路径非法（绝对路径/UNC）：{name}")
    if _DRIVE_RE.match(normalized):
        raise ValueError(f"{label}路径非法（含驱动器号）：{name}")
    parts = PurePosixPath(normalized).parts
    if not parts or ".." in parts:
        raise ValueError(f"{label}路径非法（包含上级目录 ..）：{name}")
    return parts


def _package_member(root: Path, arcname: object) -> Path:
    """把包内 arcname 解析成包根目录下的真实路径；越界立即报错。"""
    parts = _relative_parts(arcname, "包内")
    root_resolved = root.resolve()
    target = root_resolved.joinpath(*parts).resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"包内路径越界（不在包根目录内）：{arcname}")
    return target


def _chain_from_snapshot(lines: list[str], engine_version: str, rule_pack: str,
                        audit_segment: dict | None = None) -> dict:
    """不依赖本项目写入逻辑，独立按同一公式重算链（与包内 verify.py 同口径）。

    v5 纪元包从 `audit_segment.segment_start_prev_hash` 起算；旧 v4/v5 包没有该字段，
    继续从规则包 genesis 起算（legacy 兼容）。
    """
    prev = (str(audit_segment["segment_start_prev_hash"])
            if audit_segment else sha256_hex(f"{GENESES}|{engine_version}|{rule_pack}"))
    if audit_segment:
        activation = audit_segment.get("activation_event") or {}
        if activation:
            expect_act = sha256_hex(
                f"{activation['prev_hash']}|{activation['seq']}|{activation['actor']}"
                f"|{activation['action']}|{activation['ts']}|{activation['payload_sha256']}")
            if (activation["entry_hash"] != expect_act
                    or activation["entry_hash"] != audit_segment["segment_start_prev_hash"]
                    or activation["prev_hash"] != audit_segment["prev_head_hash"]):
                return {"ok": False, "broken_at_seq": int(activation["seq"]),
                        "reason": "规则包纪元切换事件哈希/旧链头不匹配", "length": 0}
    n = 0
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        expect = sha256_hex(f"{prev}|{e['seq']}|{e['actor']}|{e['action']}"
                            f"|{e['ts']}|{e['payload_sha256']}")
        if e["prev_hash"] != prev:
            return {"ok": False, "broken_at_seq": int(e["seq"]),
                    "reason": "prev_hash 与前一条 entry_hash 不衔接", "length": n}
        if e["entry_hash"] != expect:
            return {"ok": False, "broken_at_seq": int(e["seq"]),
                    "reason": "entry_hash 与内容重算不一致（疑似改写）", "length": n}
        prev = str(e["entry_hash"])
        n += 1
    return {"ok": True, "broken_at_seq": None, "reason": "", "length": n, "head_hash": prev}


@contextmanager
def unpacked(package: Path | str, *, limits: ZipLimits | None = None):
    """zip 解到临时目录，目录就用原目录；两条路径都支持，因为复核方可能已经解压了。

    zip 路径会先做路径/资源上限预检，再逐条流式解压；超限立即抛 ValueError，
    临时目录在 finally 中清理，调用方拿不到部分解压结果。
    """
    lim = limits or ZipLimits()
    p = Path(package)
    if p.is_dir():
        if not (p / "manifest.json").is_file():
            raise ValueError(f"目录里没有 manifest.json：{p}")
        # 目录形态与 zip 复用同一套条目/深度/单文件/总量上限；
        # 扫描在真正读取每个文件时计数，失败前不会 yield 给调用方。
        _check_dir_limits(p, lim)
        yield p
        return
    if not p.is_file():
        raise FileNotFoundError(f"举证包不存在：{p}")
    tmp = Path(tempfile.mkdtemp(prefix="wca-replay-"))
    try:
        with zipfile.ZipFile(p) as zf:
            # 先校验全部成员与资源上限，再逐条流式解压：`..`、绝对路径、驱动器号、
            # zip bomb（条目数/总量/单条/压缩比）一律拒绝，避免写到包根目录之外。
            infos = _check_zip_limits(zf, lim)
            _extract_zip(zf, infos, tmp, lim)
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _replay_cfg(work: Path, scope: dict, rule_pack: str) -> Config:
    if not scope.get("region_code"):
        raise ValueError("包内 scope 没有 region_code，无法确定重放的城市档")
    overrides = {
        "WCA_DB_BACKEND": DB_BACKEND_SQLITE,
        "WCA_DB_PATH": str(work / "replay.sqlite3"),
        "WCA_DB_IDENTITY_PATH": str(work / "db_target.json"),
        "WCA_DATA_DIR": str(work / "data"),
        "WCA_REPORTS_DIR": str(work / "reports"),
        "WCA_PACKAGES_DIR": str(work / "packages"),
        "WCA_UPLOAD_DIR": str(work / "uploads"),
        "WCA_USERS_PATH": str(work / "users.json"),
        "WCA_RULE_PACK": rule_pack,
        "WCA_REGION_CODE": scope["region_code"],
        "WCA_LLM_PROVIDER": "stub",
        "WCA_EMBEDDING_BACKEND": "bm25",
    }
    for scope_key, env_key in PINNED_SCOPE_PARAMS.items():
        if scope.get(scope_key) not in (None, ""):
            overrides[env_key] = str(scope[scope_key])
    # env_path 指向一个不存在的路径：重放只依赖「包 + 仓库默认口径」，不吃本机 .env；
    # 城市标签由档位表解析（代码里没有市名，见 config/region_profile.json）
    return Config.load(env_path=work / "absent.env", **overrides)


def _checksum_status(manifest: dict) -> str:
    """返回 ok / missing / mismatch；旧包无字段不判失败。"""
    if MANIFEST_CHECKSUM_FIELD not in manifest:
        return "missing"
    stored = manifest.get(MANIFEST_CHECKSUM_FIELD)
    try:
        return "ok" if isinstance(stored, str) and stored == manifest_checksum(manifest) \
            else "mismatch"
    except Exception:
        return "mismatch"


def _parse_expected_triple(value: object) -> dict | None:
    """解析外部三元组：逗号分隔字符串、三元组列表/元组；空值返回 None。"""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, (tuple, list)) and len(value) == 3:
        parts = [str(p).strip() for p in value]
    else:
        raise ValueError("需要 rule_pack_version,input_fingerprint,conclusion_digest 三段")
    if len(parts) != 3 or any(not p for p in parts):
        raise ValueError("需要 rule_pack_version,input_fingerprint,conclusion_digest 三段非空值")
    return dict(zip(TRIPLE_KEYS, parts))


def _parse_expected_anchor(value: object) -> dict | None:
    """解析外部四元组/五元组；第五段可选 projection_fingerprint。"""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
    elif isinstance(value, (tuple, list)) and len(value) in (4, 5):
        parts = [str(p).strip() for p in value]
    else:
        raise ValueError("期望四元组或五元组格式非法（需要四段或五段：schema_version,"
                         "rule_pack_version,input_fingerprint,conclusion_digest"
                         "[,projection_fingerprint]）")
    if len(parts) not in (4, 5) or any(not p for p in parts):
        raise ValueError("期望四元组或五元组格式非法（需要四段/五段非空值：schema_version,"
                         "rule_pack_version,input_fingerprint,conclusion_digest"
                         "[,projection_fingerprint]）")
    version = anchor_schema_version(parts[0])
    if version is None:
        raise ValueError("schema_version 无法识别：" + parts[0])
    result = {"schema_version": version, "rule_pack_version": parts[1],
              "input_fingerprint": parts[2], "conclusion_digest": parts[3]}
    if len(parts) == 5:
        result["projection_fingerprint"] = parts[4]
    return result


def _base_result(package: Path | str, manifest: dict, *,
                 anchor_expected: bool = False) -> dict:
    triple = manifest.get("triple") if isinstance(manifest.get("triple"), dict) else {}
    scope = manifest.get("scope_json") if isinstance(manifest.get("scope_json"), dict) else {}
    return {
        "package": str(package), "run_id": manifest.get("run_id", ""),
        "expected_triple": triple,
        "inputs_packed": 0, "inputs_missing": [],
        "engine_expected": manifest.get("engine_version", ""),
        "engine_actual": ENGINE_VERSION,
        "pinned_params": {k: scope[k] for k in PINNED_SCOPE_PARAMS if k in scope},
        "inherited_params_note": "包内 scope 未记录的判据参数沿用代码默认值（不读本机 .env）",
        "manifest_checksum": "missing",
        "chain": {"ok": False, "reason": "未校验", "length": 0, "head_hash": "",
                  "checked": False},
        "signature_present": False, "signature_ok": False, "signature_trust": "none",
        "signature_key_id": "", "signature_reason": "", "signature_checked": False,
        "inputs_digest": "", "inputs_digest_ok": False,
        "projection_fingerprint": "", "actual_projection_fingerprint": "",
        "projection_ok": False, "omitted_fields": [],
        "producer": dict(manifest["producer"]) if isinstance(
            manifest.get("producer"), dict) else {},
        "producer_ok": True, "producer_reason": "",
        "artifact": {}, "findings_binding": {},
        "evidence_binding": {}, "evidence_legacy": False,
        "evidence_digest": "", "evidence_actual_digest": "", "evidence_replay_ok": None,
        "anchor_expected": anchor_expected, "anchor_checked": False, "anchor_ok": None,
        "incomparable": False,
        "partial": False,
        "package_sha256": "", "package_sha256_checked": False, "package_sha256_ok": None,
        "artifacts_digest": "", "artifacts_digest_checked": False, "artifacts_digest_ok": None,
        "artifacts_digest_expected": "",
        "evidence_digest": "", "evidence_digest_checked": False, "evidence_digest_ok": None,
        "evidence_digest_expected": "",
        "final_conclusions_expected": 0, "final_conclusions_packaged": 0,
        "input_fingerprint_recomputed": False,
        "ok": False, "reason": "",
    }


def replay(package: Path | str, *, limits: ZipLimits | None = None,
           expect_triple: str | tuple[str, str, str] | None = None,
           expect_anchor: str | tuple[str, ...] | None = None,
           public_keys: list[str] | tuple[str, ...] | None = None,
           require_signature: bool = False,
           expect_package_sha256: str | None = None,
           expect_artifacts_digest: str | None = None,
           expect_evidence_digest: str | None = None) -> dict:
    """重放一个举证包，返回可比对的字典（不抛异常即代表流程跑通，结论看 ok 字段）。

    `expect_anchor`（或 `WCA_EXPECT_ANCHOR`）是包外记录的四元组锚点，优先使用；
    它先比对 schema 版本与三元组，不一致直接返回 ok=false。`expect_triple`
    （或 `WCA_EXPECT_TRIPLE`）保留兼容，但**不约束 schema**。
    `public_keys` 是包外固定公钥（文件路径或 Base64），可传多把支持轮换；不传时
    验签只能证明“包内自洽”，返回值 `signature_trust=package-self-check`。
    `require_signature=True` 时旧 v1/v2 包无签名也失败；v3 缺签名始终失败。
    """
    pkg_path = Path(package)
    package_sha = package_verify._sha256_file(pkg_path) if pkg_path.is_file() else ""
    anchor_expected = bool(expect_anchor if expect_anchor is not None
                           else os.environ.get("WCA_EXPECT_ANCHOR"))
    result = _base_result(package, {}, anchor_expected=anchor_expected)
    result["package_sha256"] = package_sha
    if expect_package_sha256:
        result["package_sha256_checked"] = True
        if not package_sha or str(expect_package_sha256).strip().lower() != package_sha:
            result["package_sha256_ok"] = False
            result["reason"] = ("PACKAGE SHA256 FAIL 目录形态无法比较包文件哈希"
                                if not package_sha else
                                "PACKAGE SHA256 FAIL 包文件哈希与外部记录不一致")
            return result
        result["package_sha256_ok"] = True
    else:
        result["package_sha256_ok"] = None
    with unpacked(package, limits=limits) as d:
        manifest = json.loads(
            _package_member(d, "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            result = _base_result(package, {}, anchor_expected=anchor_expected)
            result["reason"] = "MANIFEST FAIL manifest 不是对象"
            return result
        result = _base_result(package, manifest, anchor_expected=anchor_expected)
        result["package_sha256"] = package_sha
        result["package_sha256_checked"] = bool(expect_package_sha256)
        result["package_sha256_ok"] = (
            str(expect_package_sha256).strip().lower() == package_sha
            if expect_package_sha256 and package_sha else None)
        schema_ver = evidence_schema_version(manifest.get("schema"))
        if schema_ver is None:
            result["manifest_checksum"] = "unknown"
            result["reason"] = ("MANIFEST FAIL manifest.schema 缺失或无法识别："
                                + repr(manifest.get("schema")))
            return result
        result["manifest_schema_version"] = schema_ver
        result["manifest_checksum"] = _checksum_status(manifest)
        if schema_ver >= 2 and result["manifest_checksum"] == "missing":
            result["reason"] = (f"MANIFEST FAIL 新 schema v{schema_ver} 包缺少 "
                                "manifest_checksum")
            return result
        if result["manifest_checksum"] == "mismatch":
            result["reason"] = "MANIFEST FAIL manifest_checksum 不一致"
            return result
        triple = manifest.get("triple")
        if not isinstance(triple, dict) or any(
                not isinstance(triple.get(k), str) or not triple.get(k) for k in TRIPLE_KEYS):
            result["reason"] = "MANIFEST FAIL manifest.triple 缺字段或为空"
            return result
        result["expected_triple"] = triple
        scope = manifest.get("scope_json") if isinstance(manifest.get("scope_json"), dict) else {}
        producer_ok, producer_reason = producer.check_manifest_producer(manifest)
        result["producer_ok"] = producer_ok
        result["producer_reason"] = producer_reason
        if not producer_ok:
            result["reason"] = producer_reason
            return result
        result["package_sha256"] = package_sha
        if schema_ver >= 2:
            artifact = package_verify.check_artifacts(d, manifest, schema_ver)
            result["artifact"] = artifact
            result["artifacts_digest"] = artifact.get("artifacts_digest", "")
            if not artifact["ok"]:
                result["reason"] = artifact["reason"]
                return result
            findings_binding = package_verify.check_findings(d, manifest)
            result["findings_binding"] = findings_binding
            result["final_conclusions_expected"] = int(
                (manifest.get("counts") or {}).get("final_conclusions") or 0)
            result["final_conclusions_packaged"] = int(findings_binding.get("final_rows", 0))
            if not findings_binding["ok"]:
                result["reason"] = findings_binding["reason"]
                return result
            evidence_binding = package_verify.check_evidence(d, manifest)
            result["evidence_binding"] = evidence_binding
            result["evidence_legacy"] = bool(evidence_binding.get("legacy"))
            result["evidence_digest"] = str(manifest.get("evidence_digest") or "")
            if not evidence_binding["ok"]:
                result["reason"] = evidence_binding["reason"]
                return result
            if expect_evidence_digest:
                result["evidence_digest_checked"] = True
                result["evidence_digest_expected"] = str(
                    expect_evidence_digest).strip().lower()
                if evidence_binding.get("legacy") or not result["evidence_digest"]:
                    result["evidence_digest_ok"] = False
                    result["reason"] = ("EVIDENCE DIGEST FAIL 包内无 evidence_digest，"
                                        "无法与外部期望值比对")
                    return result
                if result["evidence_digest_expected"] != result["evidence_digest"].lower():
                    result["evidence_digest_ok"] = False
                    result["reason"] = ("EVIDENCE DIGEST FAIL "
                                        f"expected={result['evidence_digest_expected']} "
                                        f"actual={result['evidence_digest']}")
                    return result
                result["evidence_digest_ok"] = True
        if expect_artifacts_digest:
            result["artifacts_digest_checked"] = True
            expected_artifacts = str(expect_artifacts_digest).strip().lower()
            result["artifacts_digest_expected"] = expected_artifacts
            if expected_artifacts != result["artifacts_digest"]:
                result["artifacts_digest_ok"] = False
                result["reason"] = (
                    "ARTIFACTS DIGEST external FAIL "
                    f"expected={expected_artifacts} actual={result['artifacts_digest']} "
                    "(manifest-internal OK)")
                return result
            result["artifacts_digest_ok"] = True

        raw_anchor = expect_anchor if expect_anchor is not None \
            else os.environ.get("WCA_EXPECT_ANCHOR")
        raw_expected = None if raw_anchor else (
            expect_triple if expect_triple is not None
            else os.environ.get("WCA_EXPECT_TRIPLE"))
        try:
            expected_anchor = _parse_expected_anchor(raw_anchor)
            expected = _parse_expected_triple(raw_expected)
        except ValueError as exc:
            prefix = "ANCHOR FAIL " if raw_anchor else "TRIPLE FAIL "
            result["reason"] = prefix + str(exc)
            return result
        chain = _chain_from_snapshot(
            _package_member(d, "audit_chain.jsonl").read_text(encoding="utf-8").splitlines(),
            str(manifest.get("engine_version") or ""), triple["rule_pack_version"],
            manifest.get("audit_segment"))
        chain["checked"] = True
        inputs_manifest = _package_member(d, "inputs/manifest.json")
        inputs = json.loads(inputs_manifest.read_text(encoding="utf-8")) \
            if inputs_manifest.is_file() else {"entries": [], "missing": [],
                                               "reason": "包内没有 inputs/manifest.json"}
        result.update({"chain": chain, "inputs_packed": len(inputs["entries"]),
                       "inputs_missing": inputs["missing"],
                       "engine_expected": manifest.get("engine_version", ""),
                       "pinned_params": {k: scope[k] for k in PINNED_SCOPE_PARAMS
                                         if k in scope}})
        if expected_anchor:
            result["anchor_checked"] = True
            mismatched = []
            if expected_anchor["schema_version"] != schema_ver:
                mismatched.append("schema_version")
            for key in TRIPLE_KEYS:
                if expected_anchor[key] != triple.get(key):
                    mismatched.append(key)
            expected_projection = expected_anchor.get("projection_fingerprint")
            package_projection = manifest.get("projection_fingerprint")
            if expected_projection is not None:
                if not isinstance(package_projection, str) or not package_projection \
                        or package_projection != expected_projection:
                    mismatched.append("projection_fingerprint")
            result["expected_external_anchor"] = expected_anchor
            result["external_mismatched_fields"] = mismatched
            if mismatched:
                def _actual(key: str) -> str:
                    if key == "schema_version":
                        return str(schema_ver)
                    if key == "projection_fingerprint":
                        return str(package_projection or "（包内无）")
                    return str(triple.get(key))

                # 0.4.9：跨 schema / 跨 rule_pack_version 是“不可比”，不是“失败”。
                if "schema_version" in mismatched or "rule_pack_version" in mismatched:
                    result["incomparable"] = True
                    result["anchor_ok"] = False
                    result["reason"] = ("ANCHOR INCOMPARABLE 外部锚点与包不可比（schema/"
                                        "rule_pack_version 不同）：" + ",".join(mismatched))
                    return result
                result["anchor_ok"] = False
                result["reason"] = ("ANCHOR FAIL 外部锚点与包内不一致：" + ",".join(
                    f"{k}（期望 {expected_anchor.get(k)} / 包内 {_actual(k)}）"
                    for k in mismatched))
                return result
            result["anchor_ok"] = True
        elif expected:
            mismatched = [k for k in TRIPLE_KEYS if expected[k] != triple.get(k)]
            result["expected_external_triple"] = expected
            result["external_mismatched_fields"] = mismatched
            if mismatched:
                if "rule_pack_version" in mismatched:
                    result["incomparable"] = True
                    result["reason"] = ("ANCHOR INCOMPARABLE 外部三元组与包不可比"
                                        "（rule_pack_version 不同）：" + ",".join(mismatched))
                    return result
                result["reason"] = ("外部三元组不一致：" + ",".join(
                    f"{k}（期望 {expected[k]} / 包内 {triple.get(k)}）" for k in mismatched))
                return result
        if not chain["ok"]:
            result["reason"] = f"审计链断裂：seq={chain['broken_at_seq']} {chain['reason']}"
            return result
        # 输入摘要：v3 必须覆盖 inputs/ 下实际每个文件（含 inputs/manifest.json）。
        declared_inputs_digest = manifest.get("inputs_digest")
        if declared_inputs_digest is None:
            if schema_ver >= 3:
                result["reason"] = "INPUTS FAIL v3 包缺少 manifest.inputs_digest"
                return result
        else:
            try:
                actual_inputs_digest = signing.compute_inputs_digest_from_dir(d)
            except Exception as exc:
                result["reason"] = (f"INPUTS FAIL 无法计算输入摘要："
                                    f"{type(exc).__name__}: {exc}")
                return result
            result["inputs_digest"] = declared_inputs_digest
            if not isinstance(declared_inputs_digest, str) \
                    or actual_inputs_digest != declared_inputs_digest:
                result["reason"] = "INPUTS FAIL 输入摘要与 manifest.inputs_digest 不一致"
                return result
            result["inputs_digest_ok"] = True
        # 结论集字节哈希：只有声明了才校验；v3 必须声明，否则无法证明结论文件未被改。
        declared_artifact = manifest.get("conclusions_sha256")
        if declared_artifact is None:
            if schema_ver >= 3:
                result["reason"] = "ARTIFACT FAIL v3 包缺少 manifest.conclusions_sha256"
                return result
        else:
            try:
                actual_artifact = sha256_hex(
                    _package_member(d, "conclusions_final.csv").read_bytes())
            except Exception as exc:
                result["reason"] = ("ARTIFACT FAIL 无法读取 conclusions_final.csv："
                                    f"{type(exc).__name__}: {exc}")
                return result
            if not isinstance(declared_artifact, str) or actual_artifact != declared_artifact:
                result["reason"] = (
                    "ARTIFACT FAIL conclusions_final.csv 与 manifest.conclusions_sha256 不一致")
                return result
        try:
            pinned = signing.load_public_keys(public_keys)
        except ValueError as exc:
            result["reason"] = f"PIN FAIL {exc}"
            return result
        signature = signing.verify_signature(manifest, chain["head_hash"], pinned)
        result.update({"signature_checked": True,
                       "signature_present": signature["present"],
                       "signature_ok": signature["ok"],
                       "signature_trust": signature["trust"],
                       "signature_key_id": signature["key_id"],
                       "signature_reason": signature["reason"]})
        if signature["present"]:
            if not signature["ok"]:
                result["reason"] = f"SIGNATURE FAIL {signature['reason']}"
                return result
        elif schema_ver >= 3:
            result["reason"] = "SIGNATURE FAIL v3 包缺少 manifest.signature"
            return result
        elif require_signature:
            result["reason"] = "SIGNATURE FAIL 本包无签名，且 require_signature=True"
            return result
        if triple["rule_pack_version"] not in _supported_rule_packs():
            result["reason"] = (
                f"不支持的规则包版本：包内 {triple['rule_pack_version']}，"
                f"当前代码可用 {sorted(_supported_rule_packs())}。"
                "重放只能证明同版本代码的行为，不能靠重放掩盖跨版本差异")
            return result
        if (triple["rule_pack_version"] != _current_rule_pack()
                and triple["rule_pack_version"] not in _legacy_rule_packs()):
            result["reason"] = (f"规则包版本不一致：包内 {triple['rule_pack_version']}，"
                                f"当前代码 {_current_rule_pack()}。重放只能证明同版本代码的行为，"
                                "跨版本差异要走 reports/判据修订.md 的 REV 对账，不能靠重放掩盖")
            return result
        if not inputs["entries"]:
            result["reason"] = f"包内没有可重放的原始输入：{inputs.get('reason') or inputs['missing']}"
            return result

        work = Path(tempfile.mkdtemp(prefix="wca-replay-db-"))
        try:
            cfg = _replay_cfg(work, scope, triple["rule_pack_version"])
            cfg.ensure_dirs()
            conn = connect(cfg)
            init_db(conn)
            by_kind: dict[str, list[tuple[dict, str]]] = {}
            derived_arcnames = input_arcnames(inputs["entries"])
            for entry, derived in zip(inputs["entries"], derived_arcnames):
                arc = str(entry.get("arcname") or derived)
                by_kind.setdefault(entry["kind"], []).append((entry, arc))
            # 只有包内明确声明了 `'` 前缀转义时才撤销；旧包没有该字段，按原值导入。
            unescape_formula = str(
                inputs.get("csv_formula_escape") or "") == CSV_FORMULA_ESCAPE
            imported = []
            for kind in INGEST_ORDER:
                for e, arc in sorted(by_kind.pop(kind, []), key=lambda pair: pair[1]):
                    # arcname 是包内相对路径（inputs/<rel_path>）；解析后必须仍在包根目录内。
                    src = _package_member(d, arc)
                    if not src.is_file():
                        raise FileNotFoundError(f"包内缺少输入文件：{arc}")
                    if kind == "approval":
                        if str(inputs.get("approval_source") or "") == "v6-coverage":
                            rows = import_coverage_csv(conn, src,
                                                       unescape_formula=unescape_formula)
                        else:
                            rows = import_approval_csv(conn, src,
                                                       unescape_formula=unescape_formula)
                        imported.append({"rel_path": e["rel_path"], "kind": kind,
                                         "sha256": e.get("sha256", "")[:12], "rows_seen": rows,
                                         "accepted": rows, "rejected": 0,
                                         "source": inputs.get("approval_source") or "v5-ledger"})
                        continue
                    res = import_csv_file(conn, cfg, src, kind=kind, rel_path=e["rel_path"])
                    imported.append({"rel_path": e["rel_path"], "kind": kind,
                                     "sha256": res.sha256[:12], "rows_seen": res.rows_seen,
                                     "accepted": res.rows_accepted, "rejected": res.rows_rejected})
            for kind, rest in by_kind.items():
                raise ValueError(f"包内出现未知数据种类 {kind}（无法确定导入顺序）")
            out = run_check(conn, cfg, start=date.fromisoformat(scope["start"]),
                            end=date.fromisoformat(scope["end"]),
                            emp_ids=scope.get("emp_ids"), notes=f"replay {manifest['run_id']}")
            actual = {"rule_pack_version": cfg.rule_pack_id,
                      "input_fingerprint": out.input_fingerprint,
                      "conclusion_digest": out.conclusion_digest}
            expected_projection = manifest.get("projection_fingerprint")
            omitted_fields = manifest.get("omitted_fields") or []
            result.update({"actual_triple": actual, "imports": imported,
                           "findings_expected": manifest["counts"]["findings"],
                           "findings_actual": len(out.findings),
                           "counts_actual": out.counts_by_severity(),
                           "omitted_fields": omitted_fields,
                           "projection_fingerprint": expected_projection or "",
                           "mismatched_fields": [k for k in actual
                                                 if actual[k] != triple.get(k)]})
            if omitted_fields and not expected_projection:
                result["reason"] = "PROJECTION FAIL 包声明了 omitted_fields 但缺少 projection_fingerprint"
                return result
            if expected_projection:
                try:
                    actual_projection = projection.projection_fingerprint(
                        conn, scope, triple["rule_pack_version"],
                        rel_paths={str(e["rel_path"]) for e in inputs["entries"]
                                   if str(e.get("kind")) != "approval"},
                        emp_ids=scope.get("emp_ids"))
                except Exception as exc:
                    result["reason"] = (f"PROJECTION FAIL 无法重算投影指纹："
                                        f"{type(exc).__name__}: {exc}")
                    return result
                result["actual_projection_fingerprint"] = actual_projection
                if not isinstance(expected_projection, str) \
                        or actual_projection != expected_projection:
                    result["reason"] = "PROJECTION FAIL 投影指纹与 manifest 不一致"
                    return result
                result["projection_ok"] = True

            if expected_projection and omitted_fields:
                # 原始字节被主动裁剪，旧 input_fingerprint 必然不同；
                # 用投影指纹 + 结论摘要决定是否一致，并明确标记“重新计算过”。
                mismatched = [k for k in actual
                              if k != "input_fingerprint" and actual[k] != triple.get(k)]
                result["input_fingerprint_recomputed"] = (
                    actual["input_fingerprint"] != triple.get("input_fingerprint"))
            else:
                mismatched = [k for k in actual if actual[k] != triple.get(k)]
            result["mismatched_fields"] = mismatched
            declared_evidence = str(manifest.get("evidence_digest") or "")
            if declared_evidence:
                result["evidence_actual_digest"] = out.evidence_digest
                result["evidence_replay_ok"] = out.evidence_digest == declared_evidence
                if not result["evidence_replay_ok"]:
                    result["ok"] = False
                    result["reason"] = (
                        "EVIDENCE DIGEST FAIL 重放实得 "
                        f"{out.evidence_digest[:16]}… 与 manifest.evidence_digest "
                        f"{declared_evidence[:16]}… 不一致")
                    return result
            if (not mismatched and result["findings_expected"] == result["findings_actual"]
                    and result.get("evidence_replay_ok") is not False):
                result["ok"] = True
                result["reason"] = ("投影指纹、结论摘要、证据定位摘要与发现（未签认）条数逐项一致"
                                    if expected_projection and omitted_fields
                                    else "三元组、证据定位摘要与发现（未签认）条数逐项一致")
            else:
                result["reason"] = (f"重放结果与包内三元组不一致：{mismatched or '发现（未签认）条数不同'}"
                                    f"（期望 {result['findings_expected']} 条 / 实得 "
                                    f"{result['findings_actual']} 条）")
            conn.close()
        finally:
            shutil.rmtree(work, ignore_errors=True)
        pinned_ok = result.get("signature_trust") == "pinned"
        external_ok = (pinned_ok and result.get("anchor_ok") is True
                       and result.get("package_sha256_ok") is True
                       and result.get("artifacts_digest_ok") is True
                       and result.get("evidence_digest_ok") is True)
        result["partial"] = bool(result["ok"] and not external_ok)
        if result["partial"]:
            missing = []
            if not pinned_ok:
                missing.append("外部公钥 pin")
            if not result.get("anchor_ok"):
                missing.append("外部锚点")
            if not result.get("package_sha256_ok"):
                missing.append("外部包 SHA-256")
            if not result.get("artifacts_digest_ok"):
                missing.append("外部 artifacts_digest")
            if not result.get("evidence_digest_ok"):
                missing.append("外部 evidence_digest")
            result["reason"] += ("；RESULT PARTIAL（缺少/未通过 " + "、".join(missing)
                                 + "，不能算完整验收）")
        return result


def _current_rule_pack() -> str:
    from .rules.rulepack import RULE_PACK_VERSION

    return RULE_PACK_VERSION


def _supported_rule_packs() -> set[str]:
    from .rules.rulepack import RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6

    return {RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6}


def _legacy_rule_packs() -> set[str]:
    """仍保留回放能力的旧规则包；只收已明确冻结的版本。"""
    from .rules.rulepack import RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6

    return {RULE_PACK_V4, RULE_PACK_V5, RULE_PACK_V6}
