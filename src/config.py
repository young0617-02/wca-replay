"""Single-file .env configuration loader (stdlib only).

`.env` holds every value a human must supply; `.env.example` is the template with TODO
markers. PostgreSQL 18 is the default backend and requires `WCA_DATABASE_URL`; SQLite is
only an explicitly selected offline fallback (`WCA_DB_BACKEND=sqlite`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Web 端口只在这里定义一次：uvicorn 默认、服务清单与测试都以它为准。
DEFAULT_WEB_PORT = 9763
DEFAULT_WEB_HOST = "127.0.0.1"

DB_BACKEND_SQLITE = "sqlite"
DB_BACKEND_POSTGRES = "postgres"
_DB_SECRET_KEYS = ("WCA_DATABASE_URL", "WCA_TEST_POSTGRES_URL")

_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n", ""}


def parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        out[key] = value
    return out


def load_env_file(path: Path | str | None = None, *, override_environ: bool = False) -> dict[str, str]:
    """Load `.env`; process environment wins unless override_environ is set."""
    if path is None:
        path = PROJECT_ROOT / ".env"
    p = Path(path)
    values = parse_env_text(p.read_text(encoding="utf-8")) if p.is_file() else {}
    for k, v in os.environ.items():
        if k.startswith("WCA_") or k.startswith("WCA"):
            values[k] = v
    if override_environ:
        file_values = parse_env_text(p.read_text(encoding="utf-8")) if p.is_file() else {}
        values.update(file_values)
    return values


def _as_int(values: dict[str, str], key: str, default: int) -> int:
    raw = values.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:  # 配置错误要炸在启动期，不要静默降级
        raise ValueError(f"配置项 {key} 需要整数，实际为 {raw!r}") from exc


def _as_bool(values: dict[str, str], key: str, default: bool) -> bool:
    raw = values.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    low = str(raw).strip().lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    raise ValueError(f"配置项 {key} 需要布尔值，实际为 {raw!r}")


def _as_str(values: dict[str, str], key: str, default: str) -> str:
    raw = values.get(key)
    return default if raw is None or str(raw).strip() == "" else str(raw).strip()


def redact_database_url(url: str) -> str:
    """连接串脱敏：保留 scheme/用户名/host/port/库名，绝不回显口令。

    query 与 fragment 一律丢弃：口令只应出现在 userinfo，但这里不赌调用方怎么写连接串。
    非法连接串也走同一条“不回显原文”的路径，避免异常文本把口令带进日志。
    """
    try:
        parts = urlsplit(str(url).strip())
        user = parts.username or ""
        netloc = (f"{user}@" if user else "") + (parts.hostname or "")
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme or "postgresql", netloc, parts.path, "", ""))
    except ValueError:
        return "postgresql://<连接串格式错误，已隐藏>"


def _backend_of(values: dict[str, str]) -> str:
    explicit = (_as_str(values, "WCA_DB_BACKEND", "") or "").lower()
    if explicit:
        if explicit not in (DB_BACKEND_SQLITE, DB_BACKEND_POSTGRES):
            raise ValueError(
                f"WCA_DB_BACKEND 只能是 {DB_BACKEND_SQLITE!r} 或 {DB_BACKEND_POSTGRES!r}，"
                f"收到 {explicit!r}")
        return explicit
    # 默认后端是 PostgreSQL 18；没有 URL 时启动期明确报错，不再静默回落 SQLite。
    # SQLite 只在显式设置 WCA_DB_BACKEND=sqlite 时启用。
    return DB_BACKEND_POSTGRES


@dataclass
class Config:
    """Runtime configuration. Anything marked TODO must be filled by the operator."""

    db_path: Path
    db_backend: str
    database_url: str = field(repr=False)  # 含口令，只允许从本地 .env/进程环境读取
    db_identity_path: Path                 # PostgreSQL 选中库的本地标记（不含口令）
    data_dir: Path
    reports_dir: Path
    packages_dir: Path

    region_code: str
    region_label: str
    locked_worktime_regime: str
    rule_pack_id: str

    llm_provider: str
    llm_model: str
    llm_timeout_s: int
    ollama_base_url: str
    cloud_base_url: str
    cloud_api_key: str
    embedding_backend: str
    embedding_model: str

    retrieval_top_k: int
    min_evidence_coverage: int  # 千分位
    confidence_threshold: int  # 千分位
    allow_generation_without_retrieval: bool

    ot_cap_daily_general_minutes: int
    ot_cap_daily_special_minutes: int
    ot_cap_monthly_minutes: int
    daily_std_minutes: int
    weekly_std_minutes: int
    weekly_rest_min_days: int
    cross_day_cut_hour: int
    night_window_start_hour: int
    night_window_end_hour: int
    pay_base_source: str
    ot_cap_scope: str  # weekday_only | weekday_plus_rest：36 小时月上限的统计口径

    users_path: Path          # 界面账号来源（config/users.json），口令哈希不放仓库
    upload_dir: Path          # 界面上传的 CSV 落盘处（var/uploads，产物不入库）
    export_row_budget: int
    # 导入写入方式：single（默认，逐行 INSERT）| executemany（PG 批量）| copy（PG COPY 到暂存表）
    # SQLite 上 executemany/copy 自动降级为 single；批量行数即导入分块行数。
    import_write_mode: str
    import_batch_size: int
    # 单员工/文件 QUAL-DUP 超过该阈值时汇总存一条（引擎仍按天展开，结论不变）。
    qual_dup_aggregate_threshold: int
    sqlite_synchronous: str  # FULL（默认，审计写入落盘）| NORMAL | OFF（仅测试）

    raw: dict[str, str] = field(default_factory=dict, repr=False)
    region_profile: object | None = None   # src.region_profile.RegionProfile；None 表示未启用

    @classmethod
    def load(cls, env_path: Path | str | None = None, **overrides: Any) -> "Config":
        values = load_env_file(env_path)
        values.update({k: str(v) for k, v in overrides.items() if v is not None})

        def path_of(key: str, default: str) -> Path:
            raw = _as_str(values, key, default)
            p = Path(raw)
            return p if p.is_absolute() else (PROJECT_ROOT / p)

        backend = _backend_of(values)
        database_url = _as_str(values, "WCA_DATABASE_URL", "")
        if backend == DB_BACKEND_POSTGRES and not database_url:
            raise ValueError(
                "WCA_DB_BACKEND=postgres 时必须提供 WCA_DATABASE_URL"
                "（只放本地 .env 或进程环境，不要提交到仓库）。"
                "默认后端是 PostgreSQL 18；无 PG 的离线环境请显式设置 "
                "WCA_DB_BACKEND=sqlite 走回退")
        # raw 会传给服务管理器做依赖预检；含口令的 URL 不进入快照，避免被状态/日志带走。
        raw_values = {k: v for k, v in values.items() if k not in _DB_SECRET_KEYS}

        cfg = cls(
            db_path=path_of("WCA_DB_PATH", "var/worktime.sqlite3"),
            db_backend=backend,
            database_url=database_url,
            db_identity_path=path_of("WCA_DB_IDENTITY_PATH", "var/db_target.json"),
            data_dir=path_of("WCA_DATA_DIR", "data"),
            reports_dir=path_of("WCA_REPORTS_DIR", "reports"),
            packages_dir=path_of("WCA_PACKAGES_DIR", "var/packages"),
            region_code=_as_str(values, "WCA_REGION_CODE", ""),
            region_label="",   # 由城市档位表解析，代码里不写市名（需求 US-AD-06）
            locked_worktime_regime=_as_str(values, "WCA_WORKTIME_REGIME", "standard"),
            rule_pack_id=_as_str(values, "WCA_RULE_PACK", "rp-2026.11.gd-pilot-standard.v5"),
            llm_provider=_as_str(values, "WCA_LLM_PROVIDER", "stub"),
            llm_model=_as_str(values, "WCA_LLM_MODEL", "stub-offline-v1"),
            llm_timeout_s=_as_int(values, "WCA_LLM_TIMEOUT_S", 25),
            ollama_base_url=_as_str(values, "WCA_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            cloud_base_url=_as_str(values, "WCA_CLOUD_BASE_URL", ""),
            cloud_api_key=_as_str(values, "WCA_CLOUD_API_KEY", ""),
            embedding_backend=_as_str(values, "WCA_EMBEDDING_BACKEND", "bm25"),
            embedding_model=_as_str(values, "WCA_EMBEDDING_MODEL", ""),
            retrieval_top_k=_as_int(values, "WCA_RETRIEVAL_TOP_K", 5),
            min_evidence_coverage=_as_int(values, "WCA_MIN_EVIDENCE_COVERAGE_PERMILLE", 800),
            confidence_threshold=_as_int(values, "WCA_CONFIDENCE_THRESHOLD_PERMILLE", 700),
            allow_generation_without_retrieval=_as_bool(
                values, "WCA_ALLOW_GENERATION_WITHOUT_RETRIEVAL", False
            ),
            ot_cap_daily_general_minutes=_as_int(values, "WCA_OT_CAP_DAILY_GENERAL_MIN", 60),
            ot_cap_daily_special_minutes=_as_int(values, "WCA_OT_CAP_DAILY_SPECIAL_MIN", 180),
            ot_cap_monthly_minutes=_as_int(values, "WCA_OT_CAP_MONTHLY_MIN", 2160),
            daily_std_minutes=_as_int(values, "WCA_DAILY_STD_MINUTES", 480),
            weekly_std_minutes=_as_int(values, "WCA_WEEKLY_STD_MINUTES", 40 * 60),
            weekly_rest_min_days=_as_int(values, "WCA_WEEKLY_REST_MIN_DAYS", 1),
            cross_day_cut_hour=_as_int(values, "WCA_CROSS_DAY_CUT_HOUR", 7),
            night_window_start_hour=_as_int(values, "WCA_NIGHT_WINDOW_START_HOUR", 0),
            night_window_end_hour=_as_int(values, "WCA_NIGHT_WINDOW_END_HOUR", 6),
            pay_base_source=_as_str(values, "WCA_PAY_BASE_SOURCE", "contract_normal_wage"),
            ot_cap_scope=_as_str(values, "WCA_OT_CAP_SCOPE", "weekday_only"),
            users_path=path_of("WCA_USERS_PATH", "config/users.json"),
            upload_dir=path_of("WCA_UPLOAD_DIR", "var/uploads"),
            export_row_budget=_as_int(values, "WCA_EXPORT_ROW_BUDGET", 1000),
            import_write_mode=_as_str(values, "WCA_IMPORT_WRITE_MODE", "single"),
            import_batch_size=_as_int(values, "WCA_IMPORT_BATCH_SIZE", 5_000),
            qual_dup_aggregate_threshold=_as_int(
                values, "WCA_QUAL_DUP_AGGREGATE_THRESHOLD", 20),
            sqlite_synchronous=_as_str(values, "WCA_SQLITE_SYNCHRONOUS", "FULL"),
            raw=raw_values,
        )
        cfg = _attach_region_profile(cfg, values, path_of)
        return cfg

    @property
    def safe_database_target(self) -> str:
        """可写进日志/错误信息的数据源标识：不含口令。"""
        if self.db_backend == DB_BACKEND_POSTGRES:
            return redact_database_url(self.database_url)
        return f"sqlite:{self.db_path}"

    def with_region(self, region_code: str) -> "Config":
        """换城市档：只接受档位表里有的代码，标签与条文集合随之变（不允许代码里猜市名）。"""
        from dataclasses import replace

        code = (region_code or "").strip()
        profile = self.region_profile
        if profile is None or not profile.known(code):
            raise ValueError(
                f"城市 {code!r} 不在档位表内（已建档：{profile.codes() if profile else '未加载档位表'}）。"
                "扩城市请改 config/region_profile.json。")
        return replace(self, region_code=code, region_label=profile.label(code))

    def ensure_dirs(self) -> None:
        if self.db_backend == DB_BACKEND_SQLITE:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.db_identity_path.parent.mkdir(parents=True, exist_ok=True)
        self.packages_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)


def _attach_region_profile(cfg: "Config", values: dict[str, str], path_of) -> "Config":
    """加载城市档位表；市名、地域层级、适用条文全部来自配置。

    缺表或城市不在表内时**直接报错**，不退回硬编码默认市名——否则三市分档会悄悄退化。
    """
    from .region_profile import RegionProfile

    profile = RegionProfile.load(path_of("WCA_REGION_PROFILE", "config/region_profile.json"))
    code = cfg.region_code or profile.default_city
    if not profile.known(code):
        raise ValueError(
            f"WCA_REGION_CODE={cfg.region_code!r} 不在城市档位表内（已建档：{profile.codes()}）。"
            "要扩城市请改 config/region_profile.json，不要在代码里加市名。")
    cfg.region_code = code
    cfg.region_label = profile.label(code)
    cfg.region_profile = profile
    return cfg
