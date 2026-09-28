"""Configuration: defaults, overridden by a TOML file, overridden by CLI flags."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def default_home() -> Path:
    if env := os.environ.get("SYSSCAN_HOME"):
        return Path(env).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "sysscan"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "sysscan"


@dataclass
class AIConfig:
    enabled: bool = False
    model: str = "claude-haiku-4-5"
    max_items_per_run: int = 150
    batch_size: int = 25
    #: Second pass with web search for items the first pass couldn't identify (costs ~$0.01 per search).
    web: bool = False
    web_max_items: int = 15


@dataclass
class Config:
    home: Path = field(default_factory=default_home)
    report_dir: Path | None = None
    formats: list[str] = field(default_factory=lambda: ["html", "md", "json"])
    open_report: bool = True
    first_run_days: int = 30
    disabled_collectors: list[str] = field(default_factory=list)
    python_interpreters: list[str] = field(default_factory=list)
    extra_routine_patterns: list[str] = field(default_factory=list)
    ai: AIConfig = field(default_factory=AIConfig)
    known_software_file: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.home / "sysscan.db"

    @property
    def reports_path(self) -> Path:
        return self.report_dir or (self.home / "reports")

    @property
    def known_software_path(self) -> Path:
        return self.known_software_file or (self.home / "known_software.toml")

    @property
    def config_file(self) -> Path:
        return self.home / "config.toml"


_TRUE = {"1", "true", "yes", "on", "enabled"}
_FALSE = {"0", "false", "no", "off", "disabled"}


def env_flag(name: str) -> bool | None:
    """True/False for a recognised boolean env var, None when unset or unrecognised."""
    v = os.environ.get(name, "").strip().lower()
    return True if v in _TRUE else False if v in _FALSE else None


def apply_env_overrides(cfg: Config) -> Config:
    """Environment variables (including ones loaded from .env) override config.toml.
    The --ai / --no-ai command-line flags override both."""
    if (flag := env_flag("SYSSCAN_AI")) is not None:
        cfg.ai.enabled = flag
    if model := os.environ.get("SYSSCAN_AI_MODEL", "").strip():
        cfg.ai.model = model
    if (n := os.environ.get("SYSSCAN_AI_MAX_ITEMS", "").strip()).isdigit():
        cfg.ai.max_items_per_run = int(n)
    if (flag := env_flag("SYSSCAN_AI_WEB")) is not None:
        cfg.ai.web = flag
    if (n := os.environ.get("SYSSCAN_AI_WEB_MAX_ITEMS", "").strip()).isdigit():
        cfg.ai.web_max_items = int(n)
    return cfg


def load_config(path: Path | None = None) -> Config:
    cfg = Config()
    file = path or cfg.config_file
    if not file.exists():
        return apply_env_overrides(cfg)
    with file.open("rb") as fh:
        data = tomllib.load(fh)

    general = data.get("general", {})
    if "home" in general:
        cfg.home = Path(general["home"]).expanduser()
    if "report_dir" in general:
        cfg.report_dir = Path(general["report_dir"]).expanduser()
    cfg.formats = list(general.get("formats", cfg.formats))
    cfg.open_report = bool(general.get("open_report", cfg.open_report))
    cfg.first_run_days = int(general.get("first_run_days", cfg.first_run_days))
    if "known_software" in general:
        cfg.known_software_file = Path(general["known_software"]).expanduser()

    collectors = data.get("collectors", {})
    cfg.disabled_collectors = list(collectors.get("disabled", []))
    cfg.python_interpreters = list(collectors.get("python_interpreters", []))

    cfg.extra_routine_patterns = list(data.get("routine", {}).get("extra_patterns", []))

    ai = data.get("ai", {})
    cfg.ai = AIConfig(
        enabled=bool(ai.get("enabled", False)),
        model=str(ai.get("model", AIConfig.model)),
        max_items_per_run=int(ai.get("max_items_per_run", AIConfig.max_items_per_run)),
        batch_size=int(ai.get("batch_size", AIConfig.batch_size)),
        web=bool(ai.get("web", False)),
        web_max_items=int(ai.get("web_max_items", AIConfig.web_max_items)),
    )
    return apply_env_overrides(cfg)
