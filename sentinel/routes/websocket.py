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
    Clients connect here to receive live threat analysis results
    as they are processed by the pipeline.
    """
    await websocket.accept()
    register_ws(websocket)
    logger.info("WebSocket client connected")

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
