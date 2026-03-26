import logging
import time
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from trust_engine.storage.redis_client import redis_cache

log = logging.getLogger("trust_engine.middleware")

# Simulated Tenant Registry (Database/Redis backed in prod)
VALID_API_KEYS = {
    "sk_live_corporate_trust_xyz123": {"tenant_id": "org_cyberdyne", "tier": "enterprise"},
    "sk_test_dev_000": {"tenant_id": "org_dev_test", "tier": "free"}
}

async def enterprise_firewall_middleware(request: Request, call_next):
    """
    Multi-tenant authentication, anti-abuse firewall, and rate limiting validation.
    """
    if request.url.path in ["/health", "/metrics", "/docs", "/openapi.json"] or request.url.path.startswith("/frontend"):
        return await call_next(request)

    # 1. API Authentication Check
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Missing or malformed Authorization header."})
    
    token = api_key.split(" ")[1]
    tenant = VALID_API_KEYS.get(token)
    if not tenant:
        return JSONResponse(status_code=403, content={"error": "Invalid API Key. Tenant access denied."})

    request.state.tenant_id = tenant["tenant_id"]
    request.state.tier = tenant["tier"]

    # 2. Rate Limiting (Per Tenant & Per IP)
    client_ip = request.client.host
    tenant_limit = 1000 if tenant["tier"] == "enterprise" else 100
    
    # 2a. Check Tenant Burst Limit
    tenant_key = f"rate_limit:tenant:{tenant['tenant_id']}"
    await redis_cache.increment_action_count(tenant_key, expiry=60)
    tenant_count = await redis_cache.get_recent_action_count(tenant_key)
    if tenant_count > tenant_limit:
        log.warning(f"Tenant {tenant['tenant_id']} exceeded rate limit: {tenant_count} > {tenant_limit}")
        return JSONResponse(status_code=429, content={"error": "Tenant Rate limit exceeded."})

    # 2b. Check IP DDoS/Abuse Firewall
    ip_key = f"firewall:ip:{client_ip}"
    await redis_cache.increment_action_count(ip_key, expiry=10) # 10 sec window
    ip_count = await redis_cache.get_recent_action_count(ip_key)
    if ip_count > 50:
        log.critical(f"DDoS signature detected from IP {client_ip}. Dropping request.")
        return JSONResponse(status_code=403, content={"error": "Anti-abuse firewall triggered."})

    # 3. Proceed to application
    start_time = time.perf_counter()
    response = await call_next(request)
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    response.headers["X-Tenant-ID"] = tenant["tenant_id"]
    response.headers["X-Process-Time"] = str(round(latency_ms, 2))
    return response
