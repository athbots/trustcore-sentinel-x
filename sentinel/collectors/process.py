"""
TrustCore Sentinel X — Process Activity Collector

Uses psutil to monitor running processes in real-time.
Detects:
    - New process spawning
    - Suspicious command-line patterns (LOLBins, reverse shells, encoded cmds)
    - Crypto-miner behavior (sustained high CPU)
    - Unusual parent→child relationships
"""
import asyncio
import re
import time
from pathlib import Path
from typing import Optional

import psutil

from sentinel.collectors.base import BaseCollector
from sentinel.config import (
    PROCESS_POLL_INTERVAL,
    LOLBINS,
    SUSPICIOUS_CMD_PATTERNS,
    CRYPTO_MINER_CPU_THRESHOLD,
    CRYPTO_MINER_DURATION,
)

# Pre-compile suspicious patterns for speed
_SUSPICIOUS_RE = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_CMD_PATTERNS]


class ProcessCollector(BaseCollector):
    """
    Monitors process creation and behavior using psutil.

    Each polling cycle:
        1. Detect new processes (PIDs not seen before)
        2. Check command lines against LOLBins and suspicious patterns
        3. Check for sustained high CPU usage (crypto-miner heuristic)

    Events emitted:
        - NEW_PROCESS: a new process was spawned
        - SUSPICIOUS_PROCESS: command line matches a threat pattern
        - HIGH_CPU_PROCESS: sustained CPU > threshold (possible miner)
    """

    def __init__(self, event_queue: asyncio.Queue, interval: float = PROCESS_POLL_INTERVAL):
        super().__init__(event_queue, interval)
        self._known_pids: set[int] = set()
        self._high_cpu_tracker: dict[int, float] = {}  # pid → first_seen_high_cpu
        self._initialized = False

    @property
    def collector_name(self) -> str:
        return "process"

    def collect_once(self) -> list[dict]:
        events = []
        now = time.time()
        current_pids = set()

        for proc in psutil.process_iter(
            attrs=["pid", "name", "cmdline", "ppid", "username", "cpu_percent", "create_time"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                name = (info.get("name") or "").lower()
                cmdline_parts = info.get("cmdline") or []
                cmdline = " ".join(cmdline_parts)
                ppid = info.get("ppid", 0)
                cpu = info.get("cpu_percent", 0.0) or 0.0

                # ── New process detection ────────────────────────────────
                if self._initialized and pid not in self._known_pids:
                    event = self._build_process_event(
                        "NEW_PROCESS", info, cmdline, now
                    )

                    # Check for suspicious indicators
                    signals = self._check_suspicious(name, cmdline, ppid)
                    if signals:
                        event["event_type"] = "SUSPICIOUS_PROCESS"
                        event["signals"] = signals
                        event["risk_hint"] = min(0.3 + len(signals) * 0.15, 1.0)

                    events.append(event)

                # ── Crypto-miner heuristic (sustained high CPU) ──────────
                if cpu > CRYPTO_MINER_CPU_THRESHOLD:
                    if pid not in self._high_cpu_tracker:
                        self._high_cpu_tracker[pid] = now
                    elif (now - self._high_cpu_tracker[pid]) > CRYPTO_MINER_DURATION:
                        events.append({
                            "source": "process",
                            "event_type": "HIGH_CPU_PROCESS",
                            "timestamp": now,
                            "pid": pid,
                            "name": info.get("name", "unknown"),
                            "cmdline": cmdline[:500],
                            "cpu_percent": cpu,
                            "sustained_seconds": round(now - self._high_cpu_tracker[pid], 1),
                            "risk_hint": 0.6,
                            "signals": ["sustained_high_cpu", "possible_cryptominer"],
                        })
                        # Reset tracker so we don't spam
                        self._high_cpu_tracker[pid] = now
                else:
                    self._high_cpu_tracker.pop(pid, None)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Update known PIDs (after first cycle, track new ones)
        if not self._initialized:
            self._known_pids = current_pids
            self._initialized = True
            self.logger.info(f"Baseline: {len(current_pids)} processes tracked")
        else:
            # Clean up dead PIDs
            dead = self._known_pids - current_pids
            self._known_pids = current_pids
            for pid in dead:
                self._high_cpu_tracker.pop(pid, None)

        if events:
            self.logger.debug(f"Detected {len(events)} process events")
        return events

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _build_process_event(self, event_type: str, info: dict, cmdline: str, ts: float) -> dict:
        parent_name = self._get_parent_name(info.get("ppid", 0))
        return {
            "source": "process",
            "event_type": event_type,
            "timestamp": ts,
            "pid": info["pid"],
            "name": info.get("name", "unknown"),
            "cmdline": cmdline[:500],  # truncate long commands
            "ppid": info.get("ppid", 0),
            "parent_name": parent_name,
            "username": info.get("username", "unknown"),
            "risk_hint": 0.1,  # baseline risk for any new process
            "signals": [],
        }

    def _check_suspicious(self, name: str, cmdline: str, ppid: int) -> list[str]:
        """Check process against threat indicators. Returns list of signal names."""
        signals = []

        # LOLBin check
        exe_name = Path(name).name.lower() if name else ""
        if exe_name in LOLBINS:
            signals.append(f"lolbin:{exe_name}")

        # Command-line pattern matching
        for i, pattern in enumerate(_SUSPICIOUS_RE):
            if pattern.search(cmdline):
                signals.append(f"cmd_pattern:{SUSPICIOUS_CMD_PATTERNS[i][:30]}")

        # Suspicious parent→child (e.g. excel.exe spawning cmd.exe)
        parent_name = self._get_parent_name(ppid)
        office_parents = {"excel.exe", "winword.exe", "outlook.exe", "powerpnt.exe"}
        shell_children = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}
        if parent_name in office_parents and exe_name in shell_children:
            signals.append(f"suspicious_spawn:{parent_name}→{exe_name}")

        return signals

    @staticmethod
    def _get_parent_name(ppid: int) -> str:
        try:
            return psutil.Process(ppid).name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"
