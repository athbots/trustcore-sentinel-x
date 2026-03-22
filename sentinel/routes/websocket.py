"""
TrustCore Sentinel X — WebSocket Route (Production)

Provides real-time push updates to the dashboard via WebSocket.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sentinel.pipeline import register_ws, unregister_ws
from sentinel.utils.logger import get_logger

logger = get_logger("routes.websocket")
router = APIRouter()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event feed.
    Requires 'api_key' query parameter for authentication.
    """
    from sentinel.core.auth import get_api_key
    
    api_key = websocket.query_params.get("api_key")
    expected = get_api_key()

    # Validate key before accepting
    if expected and api_key != expected:
        # 1008 = Policy Violation
        await websocket.close(code=1008)
        return

    await websocket.accept()
    register_ws(websocket)
    logger.info("WebSocket client authenticated and connected")

    try:
        while True:
            # Keep connection alive — wait for client messages (pings)
            data = await websocket.receive_text()
            # Client can send "ping" to keep alive
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket closed: {e}")
    finally:
        unregister_ws(websocket)
        logger.info("WebSocket client disconnected")
