"""
TrustCore Sentinel X — Entity Tracker

Maintains per-entity (IP, user, process) risk profiles over time.
Enables adaptive scoring: entities with repeated violations get
escalating risk multipliers.

Thread-safe — called from both async pipeline and sync collectors.
"""
import time
import threading
from sentinel.utils.logger import get_logger

logger = get_logger("intelligence.entity_tracker")

_lock = threading.Lock()

# ── Per-entity state ─────────────────────────────────────────────────────────
# Key = entity_id (IP, username, or "proc:<name>")
# Value = EntityProfile dict

_entities: dict[str, dict] = {}
_MAX_ENTITIES = 5000
_HISTORY_WINDOW = 3600  # 1 hour look-back for scoring


class EntityProfile:
    __slots__ = ("entity_id", "entity_type", "first_seen", "last_seen",
                 "event_count", "high_risk_count", "total_risk",
                 "actions_taken", "events")

    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.event_count = 0
        self.high_risk_count = 0
        self.total_risk = 0.0
        self.actions_taken: list[str] = []
        self.events: list[dict] = []  # last N events (ring)

    def record(self, risk_score: float, action: str, event_type: str) -> None:
        self.last_seen = time.time()
        self.event_count += 1
        self.total_risk += risk_score
        if risk_score >= 70:
            self.high_risk_count += 1
        self.actions_taken.append(action)
        self.events.append({
            "ts": self.last_seen,
            "risk": risk_score,
            "action": action,
            "type": event_type,
        })
        # Keep last 50 events
        if len(self.events) > 50:
            self.events = self.events[-50:]
        if len(self.actions_taken) > 50:
            self.actions_taken = self.actions_taken[-50:]

    @property
    def avg_risk(self) -> float:
        return self.total_risk / max(self.event_count, 1)

    @property
    def is_repeat_offender(self) -> bool:
        return self.high_risk_count >= 3

    @property
    def risk_multiplier(self) -> float:
        """Adaptive multiplier: escalates with repeated violations."""
        if self.high_risk_count >= 5:
            return 1.5
        if self.high_risk_count >= 3:
            return 1.3
        if self.high_risk_count >= 2:
            return 1.15
        return 1.0

    @property
    def recent_event_rate(self) -> float:
        """Events per minute in the last 5 minutes."""
        cutoff = time.time() - 300
        recent = sum(1 for e in self.events if e["ts"] > cutoff)
        return recent / 5.0

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "type": self.entity_type,
            "event_count": self.event_count,
            "high_risk_count": self.high_risk_count,
            "avg_risk": round(self.avg_risk, 1),
            "risk_multiplier": self.risk_multiplier,
            "is_repeat_offender": self.is_repeat_offender,
            "recent_rate": round(self.recent_event_rate, 2),
            "last_seen": self.last_seen,
        }


# ── Public API ───────────────────────────────────────────────────────────────

def track(entity_id: str, entity_type: str, risk_score: float,
          action: str, event_type: str) -> EntityProfile:
    """Record an event for an entity. Creates profile if new."""
    with _lock:
        if entity_id not in _entities:
            if len(_entities) >= _MAX_ENTITIES:
                _evict_oldest()
            _entities[entity_id] = EntityProfile(entity_id, entity_type)

        profile = _entities[entity_id]
        profile.record(risk_score, action, event_type)
        return profile


def get_profile(entity_id: str) -> EntityProfile | None:
    return _entities.get(entity_id)


def get_multiplier(entity_id: str) -> float:
    """Get risk multiplier for an entity (1.0 if unknown)."""
    p = _entities.get(entity_id)
    return p.risk_multiplier if p else 1.0


def is_repeat_offender(entity_id: str) -> bool:
    p = _entities.get(entity_id)
    return p.is_repeat_offender if p else False


def get_all_profiles() -> list[dict]:
    with _lock:
        return [p.to_dict() for p in _entities.values()]


def get_top_threats(n: int = 10) -> list[dict]:
    with _lock:
        sorted_e = sorted(_entities.values(), key=lambda p: p.avg_risk, reverse=True)
        return [p.to_dict() for p in sorted_e[:n]]


def _evict_oldest() -> None:
    """Remove the entity with oldest last_seen to make room."""
    if not _entities:
        return
    oldest_key = min(_entities, key=lambda k: _entities[k].last_seen)
    del _entities[oldest_key]
