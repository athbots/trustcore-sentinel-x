"""
TrustCore Sentinel X — Abstract Base Collector

All collectors (network, process, login) inherit from this.
Each runs in its own daemon thread and pushes events into a shared asyncio.Queue.
"""
import abc
import asyncio
import threading
import time
from typing import Optional

from sentinel.utils.logger import get_logger


class BaseCollector(abc.ABC):
    """
    Abstract base for real-time data collectors.

    Subclasses must implement:
        - collect_once() → list[dict]   (one polling cycle)
        - collector_name (property)

    The base class handles:
        - Threading (daemon thread)
        - Start / stop lifecycle
        - Pushing events into the shared asyncio event queue
        - Error resilience (catches exceptions per cycle)
    """

    def __init__(self, event_queue: asyncio.Queue, interval: float = 5.0):
        self._queue = event_queue
        self._interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.logger = get_logger(self.collector_name)

    @property
    @abc.abstractmethod
    def collector_name(self) -> str:
        """Unique name for this collector (used in logs and events)."""
        ...

    @abc.abstractmethod
    def collect_once(self) -> list[dict]:
        """
        Run one collection cycle.

        Returns a list of event dicts.  Each dict MUST contain at minimum:
            - "source": str   (collector name)
            - "event_type": str
            - "timestamp": float  (time.time())
        Additional fields are collector-specific.
        """
        ...

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the collector in a background daemon thread."""
        if self._running:
            return
        self._loop = loop
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"collector-{self.collector_name}",
            daemon=True,
        )
        self._thread.start()
        self.logger.info(f"Started (interval={self._interval}s)")

    def stop(self) -> None:
        """Signal the collector to stop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval + 1)
        self.logger.info("Stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internal loop ────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Main loop — runs in a daemon thread."""
        while self._running:
            try:
                events = self.collect_once()
                for event in events:
                    # Enrich with standard fields
                    event.setdefault("source", self.collector_name)
                    event.setdefault("timestamp", time.time())
                    # Thread-safe push into the asyncio queue
                    if self._loop and not self._loop.is_closed():
                        self._loop.call_soon_threadsafe(self._enqueue, event)
            except Exception as exc:
                self.logger.error(f"Collection cycle error: {exc}", exc_info=True)

            time.sleep(self._interval)

    def _enqueue(self, event: dict) -> None:
        """Put event into the asyncio queue (called from event loop thread)."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.logger.warning("Event queue full — dropping oldest event")
            try:
                self._queue.get_nowait()   # drop oldest
                self._queue.put_nowait(event)
            except asyncio.QueueEmpty:
                pass
