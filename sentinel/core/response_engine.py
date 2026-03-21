"""
TrustCore Sentinel X — Production Response Engine

Real enforcement actions with safe-mode toggle:
  - BLOCK: netsh advfirewall (Windows) / iptables (Linux)
  - ISOLATE: kill process + block net
  - All real actions require admin + SAFE_MODE=False

Safe mode (default ON) simulates all destructive actions.
"""
import os
import sys
import time
import subprocess
from datetime import datetime, timezone

from sentinel.utils.logger import get_logger

logger = get_logger("core.response_engine")

# ── Settings ─────────────────────────────────────────────────────────────────
# Loaded from config at startup; can be toggled at runtime via API
SAFE_MODE = True          # True = simulate, False = real firewall/kill
_blocked_ips: set = set()  # track IPs we've blocked (for undo)
_killed_pids: set = set()  # track PIDs we've killed

# Action history (ring buffer)
_action_log: list[dict] = []
_MAX_LOG_SIZE = 2000

_ACTION_ICONS = {
    "LOG": "📋", "ALERT": "🔔", "BLOCK": "🚫", "ISOLATE": "☢️",
}
_IS_WIN = sys.platform == "win32"
_IS_ADMIN = False

try:
    if _IS_WIN:
        import ctypes
        _IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        _IS_ADMIN = os.geteuid() == 0
except Exception:
    pass


# ─── Core API ────────────────────────────────────────────────────────────────

def execute_response(
    threat_level: str,
    risk_score: int,
    action: str,
    description: str,
    event: dict | None = None,
) -> dict:
    """Execute an automated security response. Real or simulated based on SAFE_MODE."""
    event = event or {}
    source_ip = event.get("source_ip", "UNKNOWN")
    target = event.get("target", "UNKNOWN")
    event_type = event.get("event_type", "UNKNOWN")
    pid = event.get("pid")

    icon = _ACTION_ICONS.get(action, "⚡")
    ts = datetime.now(timezone.utc).isoformat()
    mode = "SIMULATED" if SAFE_MODE else "ENFORCED"

    # Execute action
    if action == "LOG":
        outcome = f"Event recorded. Risk {risk_score}/100 — monitoring."
    elif action == "ALERT":
        outcome = f"Alert dispatched. {source_ip} flagged for review."
    elif action == "BLOCK":
        outcome = _do_block(source_ip)
    elif action == "ISOLATE":
        outcome = _do_isolate(source_ip, pid, target)
    else:
        outcome = "Unknown action."

    record = {
        "timestamp": ts,
        "action": action,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "event_type": event_type,
        "source_ip": source_ip,
        "target": target,
        "description": description,
        "outcome": outcome,
        "icon": icon,
        "mode": mode,
    }

    _action_log.append(record)
    if len(_action_log) > _MAX_LOG_SIZE:
        _action_log.pop(0)

    logger.info(
        f"{icon} [{mode}] ACTION={action} | THREAT={threat_level} | "
        f"RISK={risk_score}/100 | SRC={source_ip} | {outcome}"
    )
    return record


# ─── Blocking ────────────────────────────────────────────────────────────────

def _do_block(ip: str) -> str:
    """Block an IP address at the host firewall."""
    if ip in ("UNKNOWN", "127.0.0.1", "::1", "localhost") or ip.startswith("0."):
        return f"Skipped blocking {ip} (local/invalid address)."

    if ip in _blocked_ips:
        return f"{ip} already blocked."

    if SAFE_MODE:
        return f"[SIMULATED] Firewall rule to block {ip}. (Enable enforcement in settings)"

    if not _IS_ADMIN:
        return f"[DENIED] Cannot block {ip} — no admin privileges."

    try:
        if _IS_WIN:
            rule_name = f"SentinelX_Block_{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=in", "action=block",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=10, check=True,
            )
            # Also block outbound
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}_out", "dir=out", "action=block",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=10, check=True,
            )
        else:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10, check=True,
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=10, check=True,
            )

        _blocked_ips.add(ip)
        logger.warning(f"🔒 ENFORCED: Blocked IP {ip}")
        return f"[ENFORCED] Firewall rule applied — {ip} blocked in+out."

    except subprocess.TimeoutExpired:
        return f"[ERROR] Firewall command timed out for {ip}."
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Firewall command failed for {ip}: {e.stderr.decode()[:100]}"
    except Exception as e:
        return f"[ERROR] Block failed for {ip}: {e}"


def unblock_ip(ip: str) -> str:
    """Remove a previously applied firewall block."""
    if ip not in _blocked_ips:
        return f"{ip} is not currently blocked."

    try:
        if _IS_WIN:
            rule_name = f"SentinelX_Block_{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_out"],
                capture_output=True, timeout=10,
            )
        else:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, timeout=10)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                           capture_output=True, timeout=10)

        _blocked_ips.discard(ip)
        logger.info(f"🔓 Unblocked IP {ip}")
        return f"Unblocked {ip}."
    except Exception as e:
        return f"Unblock failed: {e}"


# ─── Isolation ───────────────────────────────────────────────────────────────

def _do_isolate(ip: str, pid: int | None, target: str) -> str:
    """Isolate a threat: kill the process + block network."""
    parts = []

    # 1) Block the IP
    parts.append(_do_block(ip))

    # 2) Kill the process
    if pid:
        parts.append(_kill_process(pid))

    ticket = f"INC-{int(time.time()) % 100000}"
    parts.append(f"Incident ticket #{ticket} created.")

    return " ".join(parts)


def _kill_process(pid: int) -> str:
    """Terminate a process by PID."""
    if pid in _killed_pids:
        return f"PID {pid} already terminated."

    if SAFE_MODE:
        return f"[SIMULATED] Would terminate PID {pid}."

    if not _IS_ADMIN:
        return f"[DENIED] Cannot kill PID {pid} — no admin."

    try:
        import psutil
        proc = psutil.Process(pid)
        proc_name = proc.name()

        # Safety: never kill critical system processes
        PROTECTED = {"system", "csrss.exe", "services.exe", "lsass.exe",
                      "smss.exe", "wininit.exe", "svchost.exe", "explorer.exe",
                      "init", "systemd", "kernel"}
        if proc_name.lower() in PROTECTED:
            return f"[PROTECTED] Refusing to kill {proc_name} (PID {pid})."

        proc.terminate()
        proc.wait(timeout=5)
        _killed_pids.add(pid)
        logger.warning(f"💀 ENFORCED: Terminated {proc_name} (PID {pid})")
        return f"[ENFORCED] Terminated {proc_name} (PID {pid})."

    except Exception as e:
        return f"[ERROR] Kill PID {pid} failed: {e}"


# ─── Settings ────────────────────────────────────────────────────────────────

def set_safe_mode(enabled: bool) -> str:
    global SAFE_MODE
    SAFE_MODE = enabled
    mode = "ON (simulated)" if enabled else "OFF (real enforcement)"
    logger.info(f"Safe mode set to {mode}")
    return f"Safe mode: {mode}"


def get_status() -> dict:
    return {
        "safe_mode": SAFE_MODE,
        "is_admin": _IS_ADMIN,
        "blocked_ips": list(_blocked_ips),
        "killed_pids": list(_killed_pids),
    }


# ─── Stats ───────────────────────────────────────────────────────────────────

def get_recent_actions(limit: int = 20) -> list[dict]:
    return list(reversed(_action_log[-limit:]))


def get_action_stats() -> dict:
    counts = {"LOG": 0, "ALERT": 0, "BLOCK": 0, "ISOLATE": 0}
    for r in _action_log:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
    threat_counts: dict[str, int] = {}
    for r in _action_log:
        threat_counts[r["threat_level"]] = threat_counts.get(r["threat_level"], 0) + 1
    return {
        "total_actions": len(_action_log),
        "by_action": counts,
        "by_threat_level": threat_counts,
    }
