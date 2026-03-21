"""
TrustCore Sentinel X — Behavior Profiling & Temporal Analysis

Builds entity baselines and detects deviations:
  - Time-of-day anomaly (off-hours activity)
  - Frequency spike detection
  - Behavioral shift scoring
"""
import time
from sentinel.utils.logger import get_logger

logger = get_logger("intelligence.behavior")

# ── Baseline State ───────────────────────────────────────────────────────────
_baselines: dict[str, dict] = {}

# Business hours (configurable)
BUSINESS_START = 8   # 08:00
BUSINESS_END = 18    # 18:00


def analyze_behavior(entity_id: str, event: dict) -> dict:
    """
    Analyze event against the entity's behavioral baseline.

    Returns:
        {
            "score": 0.0–1.0 (behavioral anomaly score),
            "signals": list[str],
            "off_hours": bool,
            "frequency_spike": bool,
        }
    """
    now = time.time()
    signals = []
    score = 0.0

    # Initialize baseline
    if entity_id not in _baselines:
        _baselines[entity_id] = {
            "event_times": [],
            "avg_interval": None,
            "event_types_seen": set(),
            "total_events": 0,
        }

    bl = _baselines[entity_id]
    bl["event_times"].append(now)
    bl["total_events"] += 1
    bl["event_types_seen"].add(event.get("event_type", "UNKNOWN"))

    # Keep last 200 timestamps
    if len(bl["event_times"]) > 200:
        bl["event_times"] = bl["event_times"][-200:]

    # ── Off-hours detection ──────────────────────────────────────────────
    hour = time.localtime(now).tm_hour
    off_hours = hour < BUSINESS_START or hour >= BUSINESS_END
    weekend = time.localtime(now).tm_wday >= 5

    if off_hours:
        signals.append(f"Activity at {hour:02d}:00 (off-hours)")
        score += 0.2
    if weekend:
        signals.append("Weekend activity detected")
        score += 0.15

    # ── Frequency spike ──────────────────────────────────────────────────
    times = bl["event_times"]
    if len(times) >= 5:
        recent_5min = sum(1 for t in times if now - t <= 300)
        recent_1min = sum(1 for t in times if now - t <= 60)

        if recent_1min >= 10:
            signals.append(f"High frequency: {recent_1min} events/min")
            score += 0.4
        elif recent_5min >= 20:
            signals.append(f"Elevated frequency: {recent_5min} events/5min")
            score += 0.25

        # Compare to baseline average
        if len(times) >= 20:
            total_span = times[-1] - times[0]
            if total_span > 0:
                avg_rate = len(times) / (total_span / 60)  # per minute
                current_rate = recent_1min
                if avg_rate > 0 and current_rate > avg_rate * 3:
                    signals.append(f"3x baseline rate ({current_rate:.0f} vs {avg_rate:.1f}/min)")
                    score += 0.3

    # ── New event type (behavioral shift) ────────────────────────────────
    event_type = event.get("event_type", "UNKNOWN")
    if bl["total_events"] > 10 and event_type not in bl["event_types_seen"]:
        signals.append(f"New behavior: {event_type} (never seen from this entity)")
        score += 0.15

    score = min(score, 1.0)

    return {
        "score": round(score, 2),
        "signals": signals,
        "off_hours": off_hours,
        "frequency_spike": score >= 0.4,
    }
