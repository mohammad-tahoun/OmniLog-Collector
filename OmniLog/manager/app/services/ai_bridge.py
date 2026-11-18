import asyncio
import json
import logging
from typing import Set, Optional
from fastapi import WebSocket
from app.config import REDIS_URL
from app.schemas import UnifiedJSONEvent

logger = logging.getLogger("ai_bridge")

class AIBridgeService:
    def __init__(self):
        self.active_websockets: Set[WebSocket] = set()
        self.redis_client = None
        self._init_redis()

    def _init_redis(self):
        try:
            import redis
            self.redis_client = redis.from_url(REDIS_URL, socket_timeout=1.0)
            self.redis_client.ping()
            logger.info("[+] Redis connected for AI telemetry streaming.")
        except Exception:
            logger.info("[i] Redis not reachable; running with high-performance in-memory WebSocket broadcaster.")
            self.redis_client = None

    async def register(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        logger.info("[+] AI WebSocket client connected (active: %d)", len(self.active_websockets))

    def unregister(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)
        logger.info("[-] AI WebSocket client disconnected (active: %d)", len(self.active_websockets))

    async def broadcast(self, event: UnifiedJSONEvent):
        event_dict = event.model_dump()
        payload_str = json.dumps(event_dict)

        # 1. Publish to Redis if connected
        if self.redis_client:
            try:
                self.redis_client.publish("forcefields:telemetry:stream", payload_str)
            except Exception as e:
                logger.warning("[!] Redis publish failed: %v", e)

        # 2. In-memory WebSocket broadcasting
        if not self.active_websockets:
            return

        dead_connections = set()
        for ws in self.active_websockets:
            try:
                await ws.send_text(payload_str)
            except Exception:
                dead_connections.add(ws)

        for ws in dead_connections:
            self.unregister(ws)

ai_bridge = AIBridgeService()
