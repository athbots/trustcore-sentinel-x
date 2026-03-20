"""
TrustCore Sentinel X — Watchdog & Stability Module

Monitors collectors and the pipeline for crashes:
  - Restart crashed collector threads
  - Circuit breaker for pipeline errors
  - Health check endpoint support
"""
import asyncio
import threading
import time

from sentinel.utils.logger import get_logger, audit

logger = get_logger("watchdog")


class CollectorWatchdog:
    """
    Monitors collector threads and restarts them on failure.
    Runs as a daemon thread checking every `check_interval` seconds.
    """

    def __init__(self, check_interval: float = 15.0, max_restarts: int = 5):
        self._collectors: list = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._check_interval = check_interval
        self._max_restarts = max_restarts
        self._restart_counts: dict[str, int] = {}
        self._thread: threading.Thread | None = None
        self._running = False

    def register(self, collector, loop: asyncio.AbstractEventLoop) -> None:
        self._collectors.append(collector)
        self._loop = loop
        self._restart_counts[collector.__class__.__name__] = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._monitor, daemon=True, name="watchdog")
        self._thread.start()
        logger.info(f"Watchdog started — monitoring {len(self._collectors)} collector(s)")

    def stop(self) -> None:
        self._running = False

    def _monitor(self) -> None:
        while self._running:
            time.sleep(self._check_interval)
            for c in self._collectors:
                name = c.__class__.__name__
                if not c._running:
                    continue
                if c._thread and not c._thread.is_alive():
                    count = self._restart_counts.get(name, 0)
                    if count < self._max_restarts:
                        logger.warning(f"🔄 Watchdog: {name} crashed — restarting ({count+1}/{self._max_restarts})")
                        audit("WATCHDOG_RESTART", f"Restarted {name}", restart_count=str(count+1))
                        try:
                            c.start(self._loop)
                            self._restart_counts[name] = count + 1
                        except Exception as e:
                            logger.error(f"Watchdog: failed to restart {name}: {e}")
                    else:
                        logger.error(f"❌ Watchdog: {name} exceeded max restarts ({self._max_restarts}) — disabled")
                        audit("WATCHDOG_DISABLED", f"{name} disabled after {self._max_restarts} restarts")
                        c._running = False

    def health(self) -> dict:
        """Return health status of all collectors."""
        statuses = {}
        for c in self._collectors:
            name = c.__class__.__name__
            alive = c._thread.is_alive() if c._thread else False
            statuses[name] = {
                "running": c._running,
                "alive": alive,
                "restarts": self._restart_counts.get(name, 0),
            }
        return statuses


class CircuitBreaker:
    """
    Prevents cascading failures in the event pipeline.
    Opens after `threshold` consecutive errors, waits `reset_timeout` before retrying.
    """

    def __init__(self, threshold: int = 10, reset_timeout: float = 30.0):
        self._threshold = threshold
        self._reset_timeout = reset_timeout
        self._failure_count = 0
        self._state = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
        self._last_failure_time = 0.0

    @property
    def state(self) -> str:
        if self._state == "OPEN":
            if time.time() - self._last_failure_time > self._reset_timeout:
                self._state = "HALF_OPEN"
        return self._state

    def allow(self) -> bool:
        """Can we process the next event?"""
        s = self.state
        return s in ("CLOSED", "HALF_OPEN")

    def record_success(self) -> None:
        self._failure_count = 0
        if self._state == "HALF_OPEN":
            self._state = "CLOSED"
            logger.info("Circuit breaker closed — pipeline recovered")

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self._threshold and self._state == "CLOSED":
            self._state = "OPEN"
            logger.error(f"⚡ Circuit breaker OPEN — {self._failure_count} consecutive errors")
            audit("CIRCUIT_BREAKER_OPEN", f"Pipeline halted after {self._failure_count} errors")

    def status(self) -> dict:
        return {
            "state": self.state,
            "failure_count": self._failure_count,
            "threshold": self._threshold,
        }


# Global instances
watchdog = CollectorWatchdog()
breaker = CircuitBreaker()
