import logging
import asyncio
from typing import Dict, Any

from trust_engine.models.schemas import EngineRequest, EngineResponse, Decision
from trust_engine.storage.db import get_db_session, DeviceTrustState
from trust_engine.storage.redis_client import redis_cache
from sqlalchemy import update

log = logging.getLogger("trust_engine.responses")

class AutonomousResponseEngine:
    def __init__(self):
        pass

    async def execute_response(self, request: EngineRequest, evaluation: EngineResponse, tenant_id: str):
        """
        Executes real-time mitigations based on the evaluation result.
        """
        decision = evaluation.decision
        
        # Dispatch specific response playbooks
        if decision == Decision.BLOCK:
            await self._playbook_block_actor(request, evaluation, tenant_id)
        elif decision == Decision.CHALLENGE:
            await self._playbook_throttle_actor(request, evaluation, tenant_id)
            
        # Specific attack isolations
        for explanation in evaluation.explanation:
            if "Hardware signature mismatch" in explanation:
                await self._playbook_isolate_hardware(request, tenant_id)
            if "Bot Swarm" in explanation:
                await self._playbook_quarantine_subnet(request.ip_address, tenant_id)
                
    async def _playbook_block_actor(self, request: EngineRequest, evaluation: EngineResponse, tenant_id: str):
        """Immediately blackhole traffic from the offending session cache layer."""
        redis_key = f"firewall:block_ip:{tenant_id}:{request.ip_address}"
        await redis_cache.cache_set(redis_key, str(evaluation.trust_score), ttl=3600*24) # 24 hr block
        log.critical(f"[RESPONSE: BLOCK] IP {request.ip_address} blackholed for tenant {tenant_id}.")

    async def _playbook_throttle_actor(self, request: EngineRequest, evaluation: EngineResponse, tenant_id: str):
        """Insert artificial latency or strict captcha requirement headers."""
        redis_key = f"firewall:throttle:{tenant_id}:{request.session_id}"
        await redis_cache.cache_set(redis_key, "CAPTCHA_REQUIRED", ttl=1800) # 30 min throttle
        log.warning(f"[RESPONSE: THROTTLE] Session {request.session_id} challenged with Captcha.")

    async def _playbook_isolate_hardware(self, request: EngineRequest, tenant_id: str):
        """Mark hardware as permanently compromised in PostgreSQL to prevent future auth globally."""
        async for session in get_db_session():
            await session.execute(
                update(DeviceTrustState)
                .where(DeviceTrustState.device_id == request.device_id)
                .values(is_compromised=1)
            )
            await session.commit()
        log.critical(f"[RESPONSE: ISOLATE] Hardware Device {request.device_id} flagged as permanently compromised.")

    async def _playbook_quarantine_subnet(self, ip_address: str, tenant_id: str):
        """Blocks entire /24 subnet temporarily due to bot swarm coordination."""
        subnet = ".".join(ip_address.split(".")[:3]) + ".0/24"
        redis_key = f"firewall:block_subnet:{tenant_id}:{subnet}"
        await redis_cache.cache_set(redis_key, "BOT_SWARM_QUARANTINE", ttl=3600)
        log.critical(f"[RESPONSE: QUARANTINE] Subnet {subnet} quarantined due to swarm tracking.")

autonomous_defender = AutonomousResponseEngine()
