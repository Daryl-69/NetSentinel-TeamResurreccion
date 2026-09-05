"""NetSentinel — Main FastAPI Application.

This is the entry point. It:
1. Loads all 6 ONNX models on startup
2. Initializes the extraction layer (PCAP → features)
3. Starts a background traffic simulation loop
4. Serves WebSocket for real-time alerts to the React dashboard
5. Provides REST endpoints for health, alerts, stats, PCAP upload, live capture
"""
import asyncio
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.api.websocket import WebSocketHub
from netsentinel.api.routes import create_routes, router
from netsentinel.simulator.traffic_gen import generate_event
from netsentinel.extractor import PacketProcessor
from netsentinel.config import (
    MAX_ALERTS_STORED, FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT, SESSION_MIN_FLOWS,
)

# ============================================================
# Initialize Components
# ============================================================
app = FastAPI(
    title="NetSentinel",
    description="AI-Powered Network Threat Detection Pipeline",
    version="1.0.0",
)

# CORS — allow React dashboard (any origin for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared state
registry = ModelRegistry()
alert_manager = AlertManager(max_stored=MAX_ALERTS_STORED)
analyzer = FlowAnalyzer(registry, alert_manager)
ws_hub = WebSocketHub()
simulator_control = {"mode": "normal", "running": False, "rate": 10}
packet_processor = PacketProcessor(
    idle_timeout=FLOW_IDLE_TIMEOUT,
    active_timeout=FLOW_ACTIVE_TIMEOUT,
    session_min_flows=SESSION_MIN_FLOWS,
)


# ============================================================
# Startup Event — Load Models
# ============================================================
@app.on_event("startup")
async def startup():
    print("=" * 60)
    print("  NetSentinel — AI Threat Detection Pipeline")
    print("  'See Everything. Touch Nothing. Trust the Chain.'")
    print("=" * 60)
    
    registry.load_all()
    
    # Create routes with shared state (including extraction layer)
    create_routes(analyzer, alert_manager, ws_hub, simulator_control, packet_processor)
    app.include_router(router)
    
    # Start background simulation loop
    asyncio.create_task(simulation_loop())
    
    print("\n[>] Server ready!")
    print(f"   REST API:      http://localhost:8000/api/health")
    print(f"   WebSocket:     ws://localhost:8000/ws")
    print(f"   PCAP Upload:   POST http://localhost:8000/api/pcap/upload")
    print(f"   Live Capture:  POST http://localhost:8000/api/capture/start")
    print(f"   Docs:          http://localhost:8000/docs")


# ============================================================
# WebSocket Endpoint
# ============================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for client messages
            data = await websocket.receive_text()
            # Client can send commands like {"action": "start_sim", "mode": "ddos"}
            try:
                import json
                msg = json.loads(data)
                if msg.get("action") == "start_sim":
                    simulator_control["mode"] = msg.get("mode", "mixed")
                    simulator_control["running"] = True
                elif msg.get("action") == "stop_sim":
                    simulator_control["running"] = False
                    simulator_control["mode"] = "normal"
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)


# ============================================================
# Background Simulation Loop
# ============================================================
async def simulation_loop():
    """
    Background task that continuously generates traffic events,
    runs them through the AI pipeline, and broadcasts alerts.
    """
    print("  [~] Simulation loop started (send POST /api/simulate/mixed to begin)")
    
    stats_interval = 2.0  # Send stats every 2 seconds
    last_stats_time = time.time()
    
    while True:
        if not simulator_control["running"]:
            await asyncio.sleep(0.5)
            continue
        
        mode = simulator_control["mode"]
        rate = simulator_control.get("rate", 10)
        
        try:
            # Generate event
            event = generate_event(mode)
            
            # Run through pipeline
            alert = analyzer.analyze_flow(event)
            
            # If threat detected, broadcast to dashboard
            if alert:
                await ws_hub.broadcast_alert(alert)
        except Exception as e:
            # Log but don't crash — one bad event shouldn't kill the loop
            pass
        
        # Periodically send stats update
        now = time.time()
        if now - last_stats_time >= stats_interval:
            stats = analyzer.get_stats()
            stats["simulation_mode"] = mode
            await ws_hub.broadcast_stats(stats)
            last_stats_time = now
        
        # Rate control
        await asyncio.sleep(1.0 / rate)
