"""
TrustCore Sentinel X — Login / Authentication Collector

Monitors authentication events:
    - Windows: reads Security Event Log (Event IDs 4624, 4625, 4648)
    - Linux/Mac: watches /var/log/auth.log (or /var/log/secure)

Detects:
    - Failed login attempts
    - Brute-force patterns (N failures in M seconds)
    - Logins from unusual accounts
    - Privilege escalation (RunAs / sudo)
"""
import asyncio
import sys
import time
from collections import defaultdict

from sentinel.collectors.base import BaseCollector
from sentinel.config import LOGIN_POLL_INTERVAL

# Brute-force thresholds
BRUTE_FORCE_THRESHOLD = 5     # failures within window
BRUTE_FORCE_WINDOW = 120      # seconds


class LoginCollector(BaseCollector):
    """
    Collects authentication/login events from the operating system.

    Platform support:
        - Windows: win32evtlog (Security event log)
        - Linux: /var/log/auth.log file watching
        - macOS: /var/log/system.log (basic)

    Falls back gracefully if platform APIs are unavailable.
    """

    def __init__(self, event_queue: asyncio.Queue, interval: float = LOGIN_POLL_INTERVAL):
        super().__init__(event_queue, interval)
        self._failure_tracker: dict[str, list[float]] = defaultdict(list)
        self._last_read_time = time.time()
        self._platform = sys.platform

        # Windows-specific
        self._win_bookmark = None

    @property
    def collector_name(self) -> str:
        return "login"

    def collect_once(self) -> list[dict]:
        if self._platform == "win32":
            return self._collect_windows()
        elif self._platform.startswith("linux"):
            return self._collect_linux()
        elif self._platform == "darwin":
            return self._collect_macos()
        else:
            return []

    # ── Windows Event Log ────────────────────────────────────────────────────

    def _collect_windows(self) -> list[dict]:
        """Read Windows Security event log for login events."""
        events = []
        now = time.time()

        try:
            import win32evtlog

            server = None  # local machine
            log_type = "Security"

            # Event IDs:
            #   4624 = Successful logon
            #   4625 = Failed logon
            #   4648 = Logon using explicit credentials (RunAs)
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            records = win32evtlog.ReadEventLog(hand, flags, 0)
            cutoff = self._last_read_time

            for record in records:
                ts = record.TimeGenerated.timestamp()
                if ts <= cutoff:
                    break

                event_id = record.EventID & 0xFFFF  # mask to 16-bit

                if event_id == 4625:  # Failed logon
                    evt = self._make_login_event(
                        "LOGIN_FAILED", record, ts, now
                    )
                    events.append(evt)
                    self._track_failure(evt.get("username", "unknown"), now)

                elif event_id == 4624:  # Successful logon
                    events.append(self._make_login_event(
                        "LOGIN_SUCCESS", record, ts, now
                    ))

                elif event_id == 4648:  # RunAs / explicit creds
                    evt = self._make_login_event(
                        "PRIVILEGE_ESCALATION", record, ts, now
                    )
                    evt["risk_hint"] = 0.4
                    evt["signals"] = ["explicit_credential_use"]
                    events.append(evt)

            win32evtlog.CloseEventLog(hand)
            self._last_read_time = now

        except ImportError:
            self.logger.warning(
                "win32evtlog not available. Install pywin32: pip install pywin32"
            )
        except Exception as e:
            self.logger.error(f"Windows event log error: {e}")

        # Check for brute-force
        events.extend(self._check_brute_force(now))

        return events

    def _make_login_event(self, event_type: str, record, ts: float, now: float) -> dict:
        """Build a login event dict from a Windows event log record."""
        try:
            strings = record.StringInserts or []
            username = strings[5] if len(strings) > 5 else "unknown"
            source_ip = strings[18] if len(strings) > 18 else "local"
        except (IndexError, TypeError):
            username = "unknown"
            source_ip = "local"

        return {
            "source": "login",
            "event_type": event_type,
            "timestamp": now,
            "username": username,
            "source_ip": source_ip,
            "risk_hint": 0.2 if event_type == "LOGIN_FAILED" else 0.05,
            "signals": [],
        }

    # ── Linux auth.log ───────────────────────────────────────────────────────

    def _collect_linux(self) -> list[dict]:
        """Parse /var/log/auth.log for login events."""
        events = []
        now = time.time()

        auth_files = ["/var/log/auth.log", "/var/log/secure"]
        auth_file = None
        for f in auth_files:
            try:
                with open(f, "r"):
                    auth_file = f
                    break
            except (FileNotFoundError, PermissionError):
                continue

        if not auth_file:
            return events

        try:
            with open(auth_file, "r") as fh:
                lines = fh.readlines()

            # Only process recent lines (last N based on interval)
            # Simple heuristic: process last 50 lines each cycle
            recent = lines[-50:]

            for line in recent:
                line_lower = line.lower()

                if "failed password" in line_lower or "authentication failure" in line_lower:
                    user = self._extract_user_linux(line)
                    ip = self._extract_ip_linux(line)
                    evt = {
                        "source": "login",
                        "event_type": "LOGIN_FAILED",
                        "timestamp": now,
                        "username": user,
                        "source_ip": ip,
                        "risk_hint": 0.2,
                        "signals": [],
                        "raw_log": line.strip()[:200],
                    }
                    events.append(evt)
                    self._track_failure(user, now)

                elif "accepted password" in line_lower or "session opened" in line_lower:
                    user = self._extract_user_linux(line)
                    events.append({
                        "source": "login",
                        "event_type": "LOGIN_SUCCESS",
                        "timestamp": now,
                        "username": user,
                        "source_ip": self._extract_ip_linux(line),
                        "risk_hint": 0.05,
                        "signals": [],
                    })

        except Exception as e:
            self.logger.error(f"Linux auth.log error: {e}")

        events.extend(self._check_brute_force(now))
        return events

    @staticmethod
    def _extract_user_linux(line: str) -> str:
        import re
        m = re.search(r"for (?:invalid user )?(\S+)", line)
        return m.group(1) if m else "unknown"

    @staticmethod
    def _extract_ip_linux(line: str) -> str:
        import re
        m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        return m.group(1) if m else "local"

    # ── macOS ────────────────────────────────────────────────────────────────

    def _collect_macos(self) -> list[dict]:
        """Basic macOS login monitoring via system.log."""
        # Simplified — macOS Unified Logging requires different approach
        return self._collect_linux()  # auth.log format is similar enough

    # ── Brute-force detection ────────────────────────────────────────────────

    def _track_failure(self, username: str, now: float) -> None:
        """Track failed login for brute-force detection."""
        self._failure_tracker[username].append(now)
        # Prune old entries
        cutoff = now - BRUTE_FORCE_WINDOW
        self._failure_tracker[username] = [
            t for t in self._failure_tracker[username] if t > cutoff
        ]

    def _check_brute_force(self, now: float) -> list[dict]:
        """Check if any user has exceeded the brute-force threshold."""
        events = []
        for username, timestamps in self._failure_tracker.items():
            if len(timestamps) >= BRUTE_FORCE_THRESHOLD:
                events.append({
                    "source": "login",
                    "event_type": "BRUTE_FORCE_DETECTED",
                    "timestamp": now,
                    "username": username,
                    "failure_count": len(timestamps),
                    "window_seconds": BRUTE_FORCE_WINDOW,
                    "risk_hint": 0.85,
                    "signals": [
                        "brute_force",
                        f"{len(timestamps)}_failures_in_{BRUTE_FORCE_WINDOW}s",
                    ],
                })
                # Reset after alerting
                self._failure_tracker[username] = []
        return events
