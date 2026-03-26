import os
import json
import logging
import asyncio
from typing import Dict, Any

try:
    from aiokafka import AIOKafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
log = logging.getLogger("trust_engine.pipeline")

class EventPublisher:
    def __init__(self):
        self.producer = None

    async def initialize(self):
        """Starts the Kafka producer loops"""
        if KAFKA_AVAILABLE:
            try:
                self.producer = AIOKafkaProducer(
                    bootstrap_servers=KAFKA_BROKER,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    acks='all'
                )
                await self.producer.start()
                log.info(f"Kafka Producer initialized for {KAFKA_BROKER}")
            except Exception as e:
                log.warning(f"Kafka connection failed, running without broker: {e}")
                self.producer = None
        else:
            log.warning("aiokafka not installed. Kafka events will be logged locally.")
            
    async def shutdown(self):
        if self.producer:
            await self.producer.stop()

    async def emit_event(self, topic: str, payload: Dict[str, Any]):
        """
        Pushes system events into Kafka asynchronously.
        Topics: 'identity_events', 'behavior_events', 'ai_events', 'trust_events'
        """
        if self.producer:
            try:
                await self.producer.send_and_wait(topic, payload)
            except Exception as e:
                log.error(f"Failed to push {topic} event to Kafka: {e}")
        else:
            # Fallback to standard logging if broker is down/unreachable
            log.debug(f"Event: [{topic}] -> {payload}")

event_stream = EventPublisher()
