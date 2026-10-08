"""Single-file .env configuration loader (stdlib only).

`.env` holds every value a human must supply; `.env.example` is the template with TODO
markers. Missing values keep documented defaults so the deterministic core runs offline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

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


@dataclass
class Config:
    """Runtime configuration. Anything marked TODO must be filled by the operator."""

    db_path: Path
    data_dir: Path
    reports_dir: Path
    packages_dir: Path

    region_code: str
    region_label: str
    locked_worktime_regime: str
    rule_pack_id: str

    llm_provider: str
    llm_model: str
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

    export_row_budget: int
    sqlite_synchronous: str  # FULL（默认，审计写入落盘）| NORMAL | OFF（仅测试）

    raw: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, env_path: Path | str | None = None, **overrides: Any) -> "Config":
        values = load_env_file(env_path)
        values.update({k: str(v) for k, v in overrides.items() if v is not None})

        def path_of(key: str, default: str) -> Path:
            raw = _as_str(values, key, default)
            p = Path(raw)
            return p if p.is_absolute() else (PROJECT_ROOT / p)

        cfg = cls(
            db_path=path_of("WCA_DB_PATH", "var/worktime.sqlite3"),
            data_dir=path_of("WCA_DATA_DIR", "data"),
            reports_dir=path_of("WCA_REPORTS_DIR", "reports"),
            packages_dir=path_of("WCA_PACKAGES_DIR", "var/packages"),
            region_code=_as_str(values, "WCA_REGION_CODE", "440300"),
            region_label=_as_str(values, "WCA_REGION_LABEL", "深圳市"),
            locked_worktime_regime=_as_str(values, "WCA_WORKTIME_REGIME", "standard"),
            rule_pack_id=_as_str(values, "WCA_RULE_PACK", "rp-2026.10.shenzhen-standard.v2"),
            llm_provider=_as_str(values, "WCA_LLM_PROVIDER", "stub"),
            llm_model=_as_str(values, "WCA_LLM_MODEL", "stub-offline-v1"),
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
            export_row_budget=_as_int(values, "WCA_EXPORT_ROW_BUDGET", 1000),
            sqlite_synchronous=_as_str(values, "WCA_SQLITE_SYNCHRONOUS", "FULL"),
            raw=values,
        )
        return cfg

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.packages_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
