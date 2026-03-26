import logging
import json
from typing import Dict, Any, List
from trust_engine.storage.redis_client import redis_cache
from trust_engine.storage.db import get_db_session, UserBehaviorLog
from sqlalchemy import text

log = logging.getLogger("trust_engine.learning")

class AdaptiveFeedbackLoop:
    def __init__(self):
        self.outcome_key_prefix = "attack_outcome:"
        self.threshold_key = "dynamic_threshold_adjustment"

    async def record_feedback(self, request_id: str, outcome: str, is_false_positive: bool = False):
        """
        Records the actual outcome of an evaluation and whether it was a false positive.
        """
        data = {
            "request_id": request_id,
            "outcome": outcome,
            "is_false_positive": is_false_positive,
            "timestamp": json.dumps(True) # placeholder for real time
        }
        await redis_cache.cache_set(f"{self.outcome_key_prefix}{request_id}", json.dumps(data), ttl=86400 * 30)
        
        if is_false_positive:
            await self._adjust_thresholds(outcome)

    async def _adjust_thresholds(self, outcome: str):
        """
        Dynamically adjusts anomaly thresholds in Redis based on false positive feedback.
        """
        current_adj = await redis_cache.cache_get(self.threshold_key)
        adjustment = float(current_adj) if current_adj else 0.0
        
        # If we have too many false positives, slightly relax the thresholds
        adjustment += 0.5
        await redis_cache.cache_set(self.threshold_key, str(adjustment), ttl=86400)
        log.info(f"Dynamic threshold adjustment updated to: {adjustment}")

    async def get_adaptive_weights(self) -> Dict[str, float]:
        """
        Calculates optimized model weights based on historical accuracy in PostgreSQL.
        """
        # In a real system, this would run a query to calculate weights based on TP/FP ratios
        # Here we return a default set that can be adjusted.
        return {
            "identity": 0.25,
            "behavior": 0.30,
            "graph": 0.25,
            "ai": 0.20
        }
        
    async def analyze_outcome_accuracy(self):
        """
        Periodically analyze historical logs to update global risk profiles.
        """
        # This function would be called by a background task/cron to train on outcomes
        pass
