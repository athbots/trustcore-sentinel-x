import os
import redis.asyncio as redis
from typing import Optional

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

class RedisClient:
    def __init__(self):
        self.pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
        self.client = redis.Redis(connection_pool=self.pool)

    async def get_recent_action_count(self, user_id: str, minutes: int = 1) -> int:
        """Get number of actions performed by user in the last N minutes for rate-based anomaly"""
        key = f"rate_limit:{user_id}"
        # Use Redis LIST or ZSET for sliding window, here we use simple counter with expiry for <200ms perf
        count = await self.client.get(key)
        return int(count) if count else 0

    async def increment_action_count(self, user_id: str, expiry: int = 60):
        key = f"rate_limit:{user_id}"
        pipe = self.client.pipeline()
        pipe.incr(key)
        pipe.expire(key, expiry)
        await pipe.execute()
        
    async def is_threat_ip(self, ip_address: str) -> bool:
        """Fast lookup in O(1) against threat intelligence IP sets (URLHaus, OpenPhish feeds loaded here)"""
        return await self.client.sismember("threat_intel:ips", ip_address)

    async def cache_set(self, key: str, value: str, ttl: int = 3600):
        await self.client.set(key, value, ex=ttl)

    async def cache_get(self, key: str) -> Optional[str]:
        return await self.client.get(key)

redis_cache = RedisClient()
