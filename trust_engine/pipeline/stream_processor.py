import asyncio
import json
import logging
from typing import Dict, Any, List
from trust_engine.storage.redis_client import redis_cache

try:
    from aiokafka import AIOKafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

log = logging.getLogger("trust_engine.stream_processor")

class StreamIntelligence:
    def __init__(self, broker="localhost:9092"):
        self.broker = broker
        self.consumer = None
        self.running = False

    async def start(self):
        """Starts the Kafka consumer to process events in real-time."""
        if not KAFKA_AVAILABLE:
            log.warning("aiokafka not installed. Stream Intelligence is disabled.")
            return

        self.consumer = AIOKafkaConsumer(
            "identity_events", "behavior_events", "trust_events",
            bootstrap_servers=self.broker,
            group_id="trustcore-processor",
            value_deserializer=lambda v: json.loads(v.decode('utf-8'))
        )
        await self.consumer.start()
        self.running = True
        asyncio.create_task(self._consume_loop())
        log.info(f"Stream Intelligence active on {self.broker}")

    async def stop(self):
        self.running = False
        if self.consumer:
            await self.consumer.stop()

    async def _consume_loop(self):
        """Main event consumption loop for pattern detection."""
        try:
            async for msg in self.consumer:
                if not self.running: break
                event = msg.value
                topic = msg.topic
                
                if topic == "identity_events":
                    await self._detect_bot_swarm(event)
                elif topic == "behavior_events":
                    await self._detect_credential_stuffing(event)
                elif topic == "trust_events":
                    await self._detect_coordinated_fraud(event)
        except Exception as e:
            log.error(f"Stream Processor loop error: {e}")

    async def _detect_bot_swarm(self, event: Dict[str, Any]):
        """Detects many unique user IDs coming from the same IP or device range."""
        ip = event.get("ip")
        key = f"ip_swarm:{ip}"
        await redis_cache.increment_action_count(key, expiry=60)
        count = await redis_cache.get_recent_action_count(key)
        
        if count > 50: # Example threshold for 1 minute
            log.warning(f"Bot Swarm detected from IP: {ip}. Active connections: {count}")
            await redis_cache.cache_set(f"threat_intel:ips:{ip}", "BOT_SWARM", ttl=3600)

    async def _detect_credential_stuffing(self, event: Dict[str, Any]):
        """Detects rapid login failures across multiple accounts."""
        if event.get("action") == "login" and event.get("score", 100) < 50:
            key = "global_login_failure_surge"
            await redis_cache.increment_action_count(key, expiry=300) # 5 min window
            count = await redis_cache.get_recent_action_count(key)
            
            if count > 100:
                log.critical("Credential Stuffing Attack Detected. Escalating global risk levels.")
                await redis_cache.cache_set("global_risk_escalation", "HIGH", ttl=300)

    async def _detect_coordinated_fraud(self, event: Dict[str, Any]):
        """Detects coordinated anomalies across trust evaluations."""
        if event.get("decision") == "BLOCK":
            key = "coordinated_fraud_pulse"
            await redis_cache.increment_action_count(key, expiry=60)
            count = await redis_cache.get_recent_action_count(key)
            if count > 20:
                log.warning(f"Coordinated Fraud Pulse detected: {count} blocks in 60s.")
