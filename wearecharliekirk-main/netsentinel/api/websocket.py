"""WebSocket Hub — Real-time alert broadcast to dashboard clients.

Manages connected WebSocket clients and broadcasts alerts in real-time.
"""
import json
import asyncio
from fastapi import WebSocket, WebSocketDisconnect


class WebSocketHub:
    """Manages WebSocket connections and broadcasts alerts."""
    
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
    
    async def broadcast_alert(self, alert: dict):
        """Send an alert to all connected dashboard clients."""
        if not self.active_connections:
            return
        
        message = json.dumps({"type": "alert", "data": alert})
        disconnected = []
        
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        
        # Clean up dead connections
        for ws in disconnected:
            self.disconnect(ws)
    
    async def broadcast_stats(self, stats: dict):
        """Send pipeline stats update to all clients."""
        if not self.active_connections:
            return
        
        message = json.dumps({"type": "stats", "data": stats})
        disconnected = []
        
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        
        for ws in disconnected:
            self.disconnect(ws)
    
    @property
    def client_count(self) -> int:
        return len(self.active_connections)
