import asyncio
import logging
from typing import Dict, Any

from trust_engine.storage.redis_client import redis_cache
from trust_engine.storage.graph import neo4j_graph
from trust_engine.models.ai_models import ai_models
from trust_engine.pipeline.kafka_stream import event_stream

log = logging.getLogger("trust_engine.scoring")

async def analyze_identity(request: Any) -> Dict[str, Any]:
    """Score identity risk via fast Redis intel lookups."""
    score = 100
    confidence = 0.95
    reasons = []

    is_threat = await redis_cache.is_threat_ip(request.ip_address)
    
    if is_threat:
        score -= 90
        confidence = 0.99
        reasons.append(f"[OpenPhish/URLHaus] IP address {request.ip_address} found in threat intelligence.")
        
    # Check if this user typically uses this device using simple caching (in DB it would be more thorough)
    known = await redis_cache.cache_get(f"user_device:{request.user_id}")
    if known and known != request.device_id:
        score -= 30
        confidence -= 0.1
        reasons.append(f"Unrecognized device for user {request.user_id}.")

    await event_stream.emit_event("identity_events", {"user_id": request.user_id, "ip": request.ip_address, "score": score})
    return {"score": max(0, score), "confidence": confidence, "reasons": reasons}

async def analyze_behavior(request: Any, time_penalty: float) -> Dict[str, Any]:
    """Score behavioral risk, adding time-based and Isolation Forest ML anomaly penalties."""
    score = 100 - time_penalty
    confidence = 0.85
    reasons = []
    
    if time_penalty > 0:
        reasons.append(f"High velocity/rate-limit anomaly. Time Penalty: -{time_penalty:.1f}")

    # Map action to a proxy ID for the ML model
    action_map = {"login": 0, "upload": 1, "transfer": 2, "delete_logs": 3, "admin_escalate": 4}
    action_id = action_map.get(request.action, 5)
    
    # Get ML Isolation Forest prediction
    from datetime import datetime
    current_hour = datetime.utcnow().hour
    # Get cached rate 
    rate = await redis_cache.get_recent_action_count(request.user_id)
    
    ml_result = await ai_models.analyze_behavior_anomaly(action_id, current_hour, rate)
    
    if ml_result["is_anomaly"]:
        penalty_amt = 40 + (ml_result["raw_score"] * -10) # score is negative
        score -= penalty_amt
        confidence = ml_result["confidence"]
        reasons.append(f"[IsolationForest AI] Abnormal behavior pattern detected. Confidence: {confidence:.2f}")

    # Hard-coded escalation logic to complement AI
    if request.action in ["admin_escalate", "delete_logs"]:
        score -= 50
        reasons.append(f"High-risk administrative action: {request.action}.")

    await event_stream.emit_event("behavior_events", {"user_id": request.user_id, "action": request.action, "score": score})
    return {"score": max(0, int(score)), "confidence": confidence, "reasons": reasons}

async def analyze_graph(request: Any) -> Dict[str, Any]:
    """Score graph risk by querying shortest paths to known COMPROMISED nodes in Neo4j."""
    score = 100
    confidence = 0.8
    reasons = []

    suspicious_degrees = await neo4j_graph.query_suspicious_degrees(request.user_id, request.device_id)
    
    if suspicious_degrees > 0:
        score -= min(80, suspicious_degrees * 20)
        confidence += 0.1
        reasons.append(f"[Neo4j Graph] Entity connected to {suspicious_degrees} known malicious nodes within 2 degrees.")

    return {"score": max(0, score), "confidence": confidence, "reasons": reasons}

async def analyze_ai_threat(request: Any) -> Dict[str, Any]:
    """Score text and content using HuggingFace Text Classification models."""
    score = 100
    confidence = 0.95
    reasons = []

    content = request.content or ""
    # 1. HuggingFace Deep NLP Model 
    nlp_res = await ai_models.analyze_text_threat(content)
    
    if nlp_res["threat_detected"]:
        score -= 90
        confidence = nlp_res["confidence"]
        reasons.append(f"[Transformer NLP] Conversational threat or payload detected: {nlp_res['reason']}")

    # 2. Heuristics fallback (always fast)
    bad_patterns = ["<script>", "DROP TABLE", "1=1", "base64", "exec("]
    if any(pat.lower() in content.lower() for pat in bad_patterns):
        score -= 80
        reasons.append("Static heuristic: Suspicious payload signature.")
        
    # Emit AI events
    await event_stream.emit_event("ai_events", {"user_id": request.user_id, "score": score})

    return {"score": max(0, score), "confidence": confidence, "reasons": reasons}
