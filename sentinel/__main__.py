"""
TrustCore Sentinel X — CLI Runner

Allows running with: python -m sentinel
"""
import uvicorn
from sentinel.config import API_HOST, API_PORT

if __name__ == "__main__":
    print(f"\n🛡️  TrustCore Sentinel X — Starting on http://{API_HOST}:{API_PORT}\n")
    uvicorn.run(
        "sentinel.app:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,
        log_level="info",
    )
