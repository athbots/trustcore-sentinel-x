import random
import re
import logging
import asyncio
from typing import Dict, Any

from trust_engine.storage.db import get_db_session, DeviceTrustState
from sqlalchemy import select

log = logging.getLogger("trust_engine.defenses")

class SecurityDefenses:
    def __init__(self):
        # Defeats predictable adversarial thresholds (they won't know exactly when rate limiter drops)
        self.anomaly_threshold = random.randint(30, 60) # High volume threshold for < 1 min window
        
    def sanitize_input(self, content: str) -> str:
        """Production validation & sanitization layer"""
        if not content:
            return ""
        # Strictly bounds control characters and null bytes preventing SQLi wrappers
        clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', content)
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean

    def evaluate_time_based_risk(self, recent_count: int) -> float:
        """Calculates risk based on exponential penalty for hitting the randomized anomaly rate"""
        if recent_count <= 0:
            return 0.0
        
        # Exponential curve if hitting rate limits
        if recent_count >= self.anomaly_threshold:
            multiplier = random.uniform(1.2, 1.8)
            penalty = (recent_count - self.anomaly_threshold + 1) * 20 * multiplier
            log.warning(f"Time-based risk triggered. Count: {recent_count}, Penalty: {penalty}")
            return min(penalty, 100.0)
            
        return max(0.0, (recent_count / self.anomaly_threshold) * 10)  # Slight baseline penalty for activity
        
    async def get_device_trust_decay(self, device_id: str, current_time: float) -> float:
        """Fetches from PostgreSQL, applying trust decay if not seen recently"""
        async for session in get_db_session():
            result = await session.execute(
                select(DeviceTrustState).where(DeviceTrustState.device_id == device_id)
            )
            state = result.scalars().first()
            if not state:
                return 40.0  # High penalty for completely unseen devices
            
            if state.is_compromised:
                return 100.0 # Instant block

            days_since = (current_time - state.last_seen.timestamp()) / 86400
            
            penalty = state.trust_score_penalty
            if days_since > 30:
                penalty += 30.0
            elif days_since > 7:
                penalty += 10.0
                
            return min(penalty, 100.0)
