"""
TrustCore Sentinel X — Event Pipeline v2

Collectors → Detectors → Intelligence → Risk Scorer → Response → Storage → WS

Integrates:
  - Entity tracking (adaptive risk)
  - Event correlation (multi-step attack detection)
  - Threat intelligence (blacklist matching)
  - Behavior profiling (temporal analysis)
"""
import asyncio
import time
import json

from sentinel.config import EVENT_QUEUE_MAX_SIZE
from sentinel.detectors.phishing import analyze_phishing
from sentinel.detectors.network_anomaly import analyze_anomaly
from sentinel.detectors.process_anomaly import analyze_process
from sentinel.core.risk_scorer import compute_risk
from sentinel.core.response_engine import execute_response
from sentinel.core.explainer import explain
from sentinel.storage.database import db
from sentinel.utils.logger import get_logger

# Intelligence imports
from sentinel.intelligence.entity_tracker import track, get_multiplier, is_repeat_offender
from sentinel.intelligence.correlation import record_event as corr_record, correlate
from sentinel.intelligence.threat_intel import analyze as threat_analyze
from sentinel.intelligence.behavior import analyze_behavior

logger = get_logger("pipeline")

# ── Shared state ─────────────────────────────────────────────────────────────
event_queue: asyncio.Queue = asyncio.Queue(maxsize=EVENT_QUEUE_MAX_SIZE)
last_result: dict = {}
system_status: str = "SECURE"   # SECURE | UNDER ATTACK
_ws_clients: set = set()


def register_ws(ws) -> None:
    _ws_clients.add(ws)

def unregister_ws(ws) -> None:
    _ws_clients.discard(ws)

async def _broadcast(data: dict) -> None:
    dead = set()
    message = json.dumps(data)
    for ws in _ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ── Pipeline ─────────────────────────────────────────────────────────────────

async def process_event(event: dict) -> dict:
    """
    Full detection + intelligence pipeline.

    Steps:
        1. Phishing detection
        2. Network anomaly detection
        3. Process anomaly detection
        4. Threat intelligence lookup
        5. Behavior profiling
        6. Event correlation
        7. Entity tracking + adaptive risk
        8. Multi-signal risk scoring
        9. Explanation generation
        10. Response execution
        11. Storage + broadcast
    """
    global last_result, system_status

    source = event.get("source", "unknown")
    event_type = event.get("event_type", "UNKNOWN")
    source_ip = event.get("source_ip", "")
    entity_id = source_ip or event.get("process_name", "") or source

    # ── 1. Phishing ──────────────────────────────────────────────────────
    text = event.get("text", "")
    phishing_result = analyze_phishing(text) if text else {
        "score": 0.0, "verdict": "LEGITIMATE", "confidence": "HIGH", "signals": []
    }

    # ── 2. Network anomaly ───────────────────────────────────────────────
    features = event.get("features", [])
    network_result = analyze_anomaly(features) if features else {
        "score": 0.0, "verdict": "NORMAL", "anomalous_features": [], "raw_if_score": 0.0
    }

    # ── 3. Process anomaly ───────────────────────────────────────────────
    process_result = {"score": 0.0, "verdict": "NORMAL", "signals": [], "explanation": ""}
    if source == "process" or event_type in (
        "NEW_PROCESS", "SUSPICIOUS_PROCESS", "HIGH_CPU_PROCESS"
    ):
        process_result = analyze_process(event)

    if "risk_hint" in event and process_result["score"] < event["risk_hint"]:
        process_result["score"] = event["risk_hint"]

    # ── 4. Threat intelligence ───────────────────────────────────────────
    ti_result = threat_analyze(event)

    # ── 5. Behavior profiling ────────────────────────────────────────────
    behav_result = analyze_behavior(entity_id, event)

    # ── 6. Correlation ───────────────────────────────────────────────────
    corr_record(entity_id, event_type)
    corr_result = correlate(entity_id)

    # ── 7. Entity tracking ───────────────────────────────────────────────
    # Mark as repeat offender in event (for context scoring)
    if is_repeat_offender(entity_id):
        event["repeat_offender"] = True

    entity_mult = get_multiplier(entity_id)

    # ── 8. Multi-signal risk scoring ─────────────────────────────────────
    risk_result = compute_risk(
        phishing_score=phishing_result["score"],
        network_anomaly_score=network_result["score"],
        process_anomaly_score=process_result["score"],
        event=event,
        threat_intel_score=ti_result["score"],
        behavior_score=behav_result["score"],
        entity_multiplier=entity_mult,
        correlation_boost=corr_result["risk_boost"],
        correlation_info=corr_result,
        behavior_signals=behav_result.get("signals", []),
        threat_indicators=ti_result.get("indicators", []),
    )

    # ── 9. Explanation ───────────────────────────────────────────────────
    explanation = explain(
        risk_result=risk_result,
        phishing_result=phishing_result,
        network_result=network_result,
        process_result=process_result,
        event=event,
    )

    # ── 10. Response ─────────────────────────────────────────────────────
    response_cfg = risk_result["response"]
    response_record = execute_response(
        threat_level=risk_result["threat_level"],
        risk_score=risk_result["risk_score"],
        action=response_cfg["action"],
        description=response_cfg["description"],
        event=event,
    )

    # ── 11. Track entity post-response ───────────────────────────────────
    track(entity_id, "ip", risk_result["risk_score"], response_cfg["action"], event_type)

    # ── Update system status ─────────────────────────────────────────────
    if risk_result["risk_score"] >= 70:
        system_status = "UNDER ATTACK"
    else:
        system_status = "SECURE"

    # ── Assemble result ──────────────────────────────────────────────────
    from datetime import datetime, timezone

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phishing": phishing_result,
        "anomaly": network_result,
        "process": process_result,
        "risk": risk_result,
        "response": response_record,
        "explanation": explanation,
        "intelligence": {
            "threat_intel": ti_result,
            "behavior": behav_result,
            "correlation": corr_result,
            "entity_multiplier": entity_mult,
        },
        "system_status": system_status,
    }

    last_result = result

    # ── Persist ──────────────────────────────────────────────────────────
    try:
        db.store_event(
            timestamp=event.get("timestamp", time.time()),
            source=source,
            event_type=event_type,
            risk_score=risk_result["risk_score"],
            threat_level=risk_result["threat_level"],
            action_taken=response_cfg["action"],
            raw_event=event,
            analysis_result=result,
            explanation=explanation,
        )
    except Exception as e:
        logger.error(f"Failed to persist event: {e}")

    # ── Broadcast ────────────────────────────────────────────────────────
    try:
        await _broadcast(result)
    except Exception as e:
        logger.error(f"WebSocket broadcast error: {e}")

    return result


async def pipeline_consumer() -> None:
    """Background consumer with circuit breaker."""
    from sentinel.utils.watchdog import breaker

    logger.info("Pipeline consumer started — waiting for events...")
    while True:
        try:
            event = await event_queue.get()
            try:
                if not breaker.allow():
                    logger.warning("Circuit breaker OPEN — dropping event")
                    continue
                await process_event(event)
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
                logger.error(f"Pipeline error: {e}", exc_info=True)
            finally:
                event_queue.task_done()
        except asyncio.CancelledError:
            logger.info("Pipeline consumer shutting down")
            break
        except Exception as e:
            logger.error(f"Pipeline consumer error: {e}", exc_info=True)
            await asyncio.sleep(1)
