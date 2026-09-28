"""WebSocket Hub — Real-time alert broadcast to dashboard clients.

Messages are JSON objects {"type": ..., "data": ...}:
  alert      one alert in the v1 schema
  stats      pipeline counters (and replay completion)
  metrics    throughput / latency snapshot, once a second
  benchmark  benchmark progress and result
"""
import json
from fastapi import WebSocket


class WebSocketHub:
    """Manages WebSocket connections and broadcasts messages."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"  [~] Dashboard connected ({len(self.active_connections)} clients)")

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"  [~] Dashboard disconnected ({len(self.active_connections)} clients)")

    async def broadcast(self, kind: str, data) -> None:
        """Send one message to every connected client; drop dead sockets."""
        if not self.active_connections:
            return
        message = json.dumps({"type": kind, "data": data}, default=str)
        disconnected = []
        for ws in list(self.active_connections):
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)

    async def broadcast_alert(self, alert: dict):
        """Send an alert to all connected dashboard clients."""
        await self.broadcast("alert", alert)

    async def broadcast_stats(self, stats: dict):
        """Send pipeline stats update to all clients."""
        await self.broadcast("stats", stats)

    async def broadcast_metrics(self, metrics: dict):
        await self.broadcast("metrics", metrics)

    @property
    def client_count(self) -> int:
        return len(self.active_connections)
