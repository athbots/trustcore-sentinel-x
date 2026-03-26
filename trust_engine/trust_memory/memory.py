import logging
import time
from typing import Dict, Any, Optional
from trust_engine.storage.redis_client import redis_cache
from trust_engine.storage.db import get_db_session, DeviceTrustState
from sqlalchemy import select, update

log = logging.getLogger("trust_engine.memory")

class TrustMemory:
    def __init__(self):
        # Configuration for trust decay
        self.daily_decay_rate = 0.05
        self.maximum_penalty = 100.0

    async def get_user_risk_history(self, user_id: str) -> Dict[str, Any]:
        """
        Retrieves historical risk data for a user from Redis.
        """
        key = f"user_risk_history:{user_id}"
        data = await redis_cache.cache_get(key)
        if data:
            import json
            return json.loads(data)
        return {"total_anomalies": 0, "last_risk_score": 100, "risk_trend": "STABLE"}

    async def update_user_risk_history(self, user_id: str, current_score: int, is_anomaly: bool):
        """
        Updates the risk history for a user in Redis.
        """
        history = await self.get_user_risk_history(user_id)
        history["last_risk_score"] = current_score
        if is_anomaly:
            history["total_anomalies"] += 1
        
        # Simple trend analysis
        if current_score < history.get("last_risk_score", 100):
            history["risk_trend"] = "DEGRADING"
        else:
            history["risk_trend"] = "IMPROVING"

        import json
        await redis_cache.cache_set(f"user_risk_history:{user_id}", json.dumps(history), ttl=86400 * 7)

    async def get_device_trust_profile(self, device_id: str) -> Dict[str, Any]:
        """
        Retrieves long-term device trust profile from PostgreSQL.
        """
        async for session in get_db_session():
            result = await session.execute(
                select(DeviceTrustState).where(DeviceTrustState.device_id == device_id)
            )
            state = result.scalars().first()
            if not state:
                return {"trust_score": 50, "status": "NEW", "last_seen": None}
            
            return {
                "trust_score": 100 - state.trust_score_penalty,
                "status": "KNOWN",
                "last_seen": state.last_seen,
                "is_compromised": state.is_compromised
            }

    async def record_anomaly(self, user_id: str, device_id: str, weight: float = 1.0):
        """
        Increments anomaly frequency and adjusts penalties accordingly.
        """
        # Increment anomaly count in Redis for immediate rate-limiting awareness
        key = f"anomaly_freq:{user_id}:{device_id}"
        await redis_cache.increment_action_count(key, expiry=3600)  # 1 hour window
        
        # Also update the persistent penalty in PostgreSQL
        async for session in get_db_session():
            await session.execute(
                update(DeviceTrustState)
                .where(DeviceTrustState.device_id == device_id)
                .values(trust_score_penalty=DeviceTrustState.trust_score_penalty + (10 * weight))
            )
            await session.commit()
