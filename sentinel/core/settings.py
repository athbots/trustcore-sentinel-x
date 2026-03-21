"""
TrustCore Sentinel X — Runtime Configuration System

Loads settings from a YAML/JSON file and merges with defaults.
Supports runtime reload via API call or file-watch.

Config file location: %LOCALAPPDATA%/TrustCoreSentinel/config.yaml (or ~/.sentinel/config.yaml)
"""
import json
from typing import Any

from sentinel.config import APP_DATA_DIR
from sentinel.utils.logger import get_logger, audit

logger = get_logger("core.settings")

CONFIG_FILE = APP_DATA_DIR / "config.json"

# ── Default settings ─────────────────────────────────────────────────────────
_DEFAULTS: dict[str, Any] = {
    # Response
    "safe_mode": True,
    "enable_blocking": False,
    "enable_process_kill": False,

    # Thresholds (0–100)
    "risk_low": 25,
    "risk_medium": 50,
    "risk_high": 70,
    "risk_critical": 85,

    # Weights
    "weight_phishing": 0.30,
    "weight_network": 0.30,
    "weight_process": 0.20,
    "weight_context": 0.20,

    # Collector intervals (seconds)
    "network_poll_interval": 5.0,
    "process_poll_interval": 3.0,
    "login_poll_interval": 10.0,

    # Feature flags
    "enable_network_collector": True,
    "enable_process_collector": True,
    "enable_login_collector": True,
    "enable_websocket": True,

    # Performance
    "event_queue_max": 1000,
    "max_events_stored": 50000,
    "log_retention_days": 30,

    # UI
    "dashboard_refresh_ms": 1000,
}

# In-memory current settings
_settings: dict[str, Any] = dict(_DEFAULTS)


def load() -> dict[str, Any]:
    """Load settings from config file, merge with defaults."""
    global _settings
    _settings = dict(_DEFAULTS)

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            _settings.update(user_cfg)
            logger.info(f"Loaded config from {CONFIG_FILE}")
        except Exception as e:
            logger.warning(f"Config file error, using defaults: {e}")
    else:
        save()  # Create default config file
        logger.info(f"Created default config at {CONFIG_FILE}")

    return _settings


def save() -> None:
    """Persist current settings to disk."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(_settings, f, indent=2)


def get(key: str, default: Any = None) -> Any:
    return _settings.get(key, default)


def get_all() -> dict[str, Any]:
    return dict(_settings)


def update(changes: dict[str, Any]) -> dict[str, Any]:
    """Update specific settings and persist. Returns updated settings."""
    for k, v in changes.items():
        if k in _DEFAULTS:
            old_val = _settings.get(k)
            _settings[k] = v
            audit("CONFIG_CHANGE", f"{k}: {old_val} → {v}", key=k, old=str(old_val), new=str(v))
        else:
            logger.warning(f"Ignoring unknown config key: {k}")

    save()

    # Apply runtime effects
    _apply_runtime()

    logger.info(f"Config updated: {list(changes.keys())}")
    return _settings


def _apply_runtime() -> None:
    """Push config changes to running modules."""
    try:
        from sentinel.core.response_engine import set_safe_mode
        set_safe_mode(_settings["safe_mode"])
    except Exception:
        pass


def reset() -> dict[str, Any]:
    """Reset to defaults."""
    global _settings
    _settings = dict(_DEFAULTS)
    save()
    _apply_runtime()
    audit("CONFIG_RESET", "All settings reset to defaults")
    return _settings
