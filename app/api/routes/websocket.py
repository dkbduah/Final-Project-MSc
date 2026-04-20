"""SEAS WebSocket API – real-time aggregation event feed."""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_manager import manager

router = APIRouter()
logger = logging.getLogger("seas.websocket")


@router.websocket("/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time election aggregation events.

    The verification dashboard connects here to receive live broadcasts
    of submission, verification, aggregation, and finalisation events.
    The connection stays open until the client disconnects.

    Events emitted:
        SUBMISSION_RECEIVED    – A new valid submission arrived.
        SUBMISSION_REJECTED    – A submission failed signature verification.
        CONSTITUENCY_AGGREGATED – A constituency aggregate was computed.
        REGION_AGGREGATED      – A regional aggregate was computed.
        NATIONAL_AGGREGATED    – The national encrypted aggregate was updated.
        NATIONAL_FINALIZED     – Final decrypted results are available.

    Args:
        websocket: The incoming WebSocket connection.
    """
    client = websocket.client
    await manager.connect(websocket)
    logger.info(
        "WebSocket client connected | client=%s:%s active_connections=%d",
        client.host, client.port, manager.connection_count,
    )
    try:
        # Send current connection count on join
        await websocket.send_json({
            "event": "CONNECTED",
            "data": {"active_connections": manager.connection_count},
        })
        # Keep alive – receive ping/pong or close from client
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                logger.debug("WebSocket ping received | client=%s:%s", client.host, client.port)
                await websocket.send_text("pong")
            else:
                logger.debug(
                    "WebSocket unknown message received | client=%s:%s message='%s'",
                    client.host, client.port, data,
                )
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        logger.info(
            "WebSocket client disconnected | client=%s:%s active_connections=%d",
            client.host, client.port, manager.connection_count,
        )