import time
from typing import Dict
from fastapi import Request, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from infra.config import API_KEY

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Invalid API Key"
        )
    return api_key

# Very raw in-memory IP rate limiter (Production would use Redis)
RATE_LIMIT_WINDOW = 60 # seconds
MAX_REQUESTS_PER_MIN = 30

ip_tracker: Dict[str, list[float]] = {}

async def rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Initialize Tracker
    if client_ip not in ip_tracker:
        ip_tracker[client_ip] = []
        
    # Flush expired tokens
    ip_tracker[client_ip] = [ts for ts in ip_tracker[client_ip] if now - ts < RATE_LIMIT_WINDOW]
    
    if len(ip_tracker[client_ip]) >= MAX_REQUESTS_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail="Too Many Requests: Rate limit exceeded"
        )
        
    ip_tracker[client_ip].append(now)
    return client_ip
