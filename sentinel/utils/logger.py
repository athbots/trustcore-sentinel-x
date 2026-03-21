"""
TrustCore Sentinel X — Structured Logger (Production)

JSON-formatted structured logging with:
  - file rotation (max 10MB x 5 files)
  - audit trail (separate audit.log for all security actions)
  - export support (returns recent log entries as list)
"""
import logging
import logging.handlers
import json
import time
from datetime import datetime, timezone

from sentinel.config import LOG_DIR

_loggers: dict[str, logging.Logger] = {}

# ── JSON Formatter ───────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[90m", "INFO": "\033[36m",
        "WARNING": "\033[33m", "ERROR": "\033[31m",
        "CRITICAL": "\033[41m\033[97m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        c = self.COLORS.get(record.levelname, "")
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        return f"{c}{ts} [{record.levelname[0]}] {record.name}: {record.getMessage()}{self.RESET}"


# ── Logger Factory ───────────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"sentinel.{name}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(ConsoleFormatter())
        logger.addHandler(ch)

        # JSON file handler (rotating)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            LOG_DIR / "sentinel.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)

    _loggers[name] = logger
    return logger


# ── Audit Logger ─────────────────────────────────────────────────────────────
_audit_logger: logging.Logger | None = None

def _get_audit_logger() -> logging.Logger:
    global _audit_logger
    if _audit_logger:
        return _audit_logger

    _audit_logger = logging.getLogger("sentinel.audit")
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        LOG_DIR / "audit.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    fh.setFormatter(JSONFormatter())
    _audit_logger.addHandler(fh)
    return _audit_logger


def audit(action: str, detail: str, **extra) -> None:
    """Write an immutable audit record."""
    al = _get_audit_logger()
    record = {
        "action": action,
        "detail": detail,
        "epoch": time.time(),
        **extra,
    }
    al.info(json.dumps(record, ensure_ascii=False))


# ── Export ────────────────────────────────────────────────────────────────────

def export_logs(max_lines: int = 500) -> list[dict]:
    """Read and return recent structured log entries."""
    log_file = LOG_DIR / "sentinel.log"
    if not log_file.exists():
        return []

    entries = []
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"raw": line})

    return entries[-max_lines:]


def export_audit(max_lines: int = 500) -> list[dict]:
    """Read and return recent audit trail entries."""
    audit_file = LOG_DIR / "audit.log"
    if not audit_file.exists():
        return []

    entries = []
    with open(audit_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"raw": line})

    return entries[-max_lines:]
