"""
TrustCore Sentinel X — Event Pipeline

The central event bus that connects collectors → detectors → risk scorer
→ response engine → storage → WebSocket broadcast.

This module owns the asyncio.Queue and the consumer loop.
"""
import asyncio
import time
import json
from typing import Optional

from sentinel.config import EVENT_QUEUE_MAX_SIZE
from sentinel.detectors.phishing import analyze_phishing
from sentinel.detectors.network_anomaly import analyze_anomaly
from sentinel.detectors.process_anomaly import analyze_process
from sentinel.core.risk_scorer import compute_risk
from sentinel.core.response_engine import execute_response
from sentinel.core.explainer import explain
from sentinel.storage.database import db
from sentinel.utils.logger import get_logger

logger = get_logger("pipeline")

# ── Shared state ─────────────────────────────────────────────────────────────
event_queue: asyncio.Queue = asyncio.Queue(maxsize=EVENT_QUEUE_MAX_SIZE)
last_result: dict = {}
_ws_clients: set = set()  # WebSocket connections to broadcast to


def register_ws(ws) -> None:
    _ws_clients.add(ws)


def unregister_ws(ws) -> None:
    _ws_clients.discard(ws)


async def _broadcast(data: dict) -> None:
    """Send event to all connected WebSocket clients."""
    dead = set()
    message = json.dumps(data)
    for ws in _ws_clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ── Pipeline consumer ────────────────────────────────────────────────────────

async def process_event(event: dict) -> dict:
    """
    Run a single event through the full detection pipeline.

    Steps:
        1. Phishing detection (if text present)
        2. Network anomaly detection (if features present)
        3. Process anomaly detection (if process event)
        4. Risk scoring
        5. Explanation generation
        6. Response execution
        7. Storage persistence
        8. WebSocket broadcast

    Returns the full analysis result dict.
    """
    global last_result

    source = event.get("source", "unknown")
    event_type = event.get("event_type", "UNKNOWN")

    # ── 1. Phishing detection ────────────────────────────────────────────
    text = event.get("text", "")
    phishing_result = analyze_phishing(text) if text else {
        "score": 0.0, "verdict": "LEGITIMATE", "confidence": "HIGH", "signals": []
    }

    # ── 2. Network anomaly detection ─────────────────────────────────────
    features = event.get("features", [])
    network_result = analyze_anomaly(features) if features else {
        "score": 0.0, "verdict": "NORMAL", "anomalous_features": [], "raw_if_score": 0.0
    }

    # ── 3. Process anomaly detection ─────────────────────────────────────
    process_result = {"score": 0.0, "verdict": "NORMAL", "signals": [], "explanation": ""}
    if source == "process" or event_type in (
        "NEW_PROCESS", "SUSPICIOUS_PROCESS", "HIGH_CPU_PROCESS"
    ):
        process_result = analyze_process(event)

    # Use risk_hint from collector if available
    if "risk_hint" in event and process_result["score"] < event["risk_hint"]:
        process_result["score"] = event["risk_hint"]

    # ── 4. Risk scoring ──────────────────────────────────────────────────
    risk_result = compute_risk(
        phishing_score=phishing_result["score"],
        network_anomaly_score=network_result["score"],
        process_anomaly_score=process_result["score"],
        event=event,
    )

    # ── 5. Explanation ───────────────────────────────────────────────────
    explanation = explain(
        risk_result=risk_result,
        phishing_result=phishing_result,
        network_result=network_result,
        process_result=process_result,
        event=event,
    )

    # ── 6. Response execution ────────────────────────────────────────────
    response_cfg = risk_result["response"]
    response_record = execute_response(
        threat_level=risk_result["threat_level"],
        risk_score=risk_result["risk_score"],
        action=response_cfg["action"],
        description=response_cfg["description"],
        event=event,
    )

    # ── 7. Assemble result ───────────────────────────────────────────────
    from datetime import datetime, timezone

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phishing": phishing_result,
        "anomaly": network_result,
        "process": process_result,
        "risk": risk_result,
        "response": response_record,
        "explanation": explanation,
    }

    last_result = result

    # ── 8. Persist to database ───────────────────────────────────────────
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

    # ── 9. Broadcast to WebSocket clients ────────────────────────────────
    try:
        await _broadcast(result)
    except Exception as e:
        logger.error(f"WebSocket broadcast error: {e}")

    return result


async def pipeline_consumer() -> None:
    """
    Background task that consumes events from the queue
    and processes them through the detection pipeline.
    Includes circuit breaker for stability.
    """
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
                logger.error(f"Pipeline error processing event: {e}", exc_info=True)
            finally:
                event_queue.task_done()
        except asyncio.CancelledError:
            logger.info("Pipeline consumer shutting down")
            break
        except Exception as e:
            logger.error(f"Pipeline consumer error: {e}", exc_info=True)
            await asyncio.sleep(1)

