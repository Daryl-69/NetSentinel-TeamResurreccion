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

    # ── Integrity Layer Initialization ───────────────────────────
    from netsentinel.config import INTEGRITY_ENABLED
    if INTEGRITY_ENABLED:
        try:
            from netsentinel.config import (
                SENSOR_ID, INTEGRITY_KEY_PATH, INTEGRITY_LEDGER_PATH,
                INTEGRITY_PROOF_STORE_PATH, INTEGRITY_BLOB_STORE_PATH,
                INTEGRITY_BLOB_RETENTION_DAYS, INTEGRITY_WINDOW_SECONDS,
                INTEGRITY_CHECKPOINT_INTERVAL, INTEGRITY_SEQ_PATH,
            )
            from pathlib import Path
            from netsentinel.integrity.ledger import load_or_generate_key, IntegrityLedger
            from netsentinel.integrity.anchor_service import (
                AnchorService, ProofStore, GitAnchorBackend,
            )
            from netsentinel.integrity.blobstore import BlobStore
            from netsentinel.integrity.replay import ReplayEngine
            from netsentinel.integrity.claims import ClaimsVerifier, compute_policy_digest
            from netsentinel.integrity.receipt import ReceiptBuilder, SensorContext
            from netsentinel.integrity.envelope import sign_receipt, envelope_digest
            from netsentinel.integrity.encoding import canonical_digest

            print("\n[*] Initializing integrity layer...")

            # 1. Signing key
            sk = load_or_generate_key(INTEGRITY_KEY_PATH)

            # 2. Ledger
            ledger = IntegrityLedger(INTEGRITY_LEDGER_PATH, sk)
            print(f"  [OK] Ledger initialized ({ledger.size} blocks)")

            # 3. Proof store
            proof_store = ProofStore(INTEGRITY_PROOF_STORE_PATH)

            # 4. Git anchor backend
            import os
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            git_anchor = GitAnchorBackend(repo_root)

            # 5. Anchor service
            anchor_service = AnchorService(
                ledger=ledger,
                proof_store=proof_store,
                window_seconds=INTEGRITY_WINDOW_SECONDS,
                anchor_backends=[git_anchor],
            )

            # 6. Blob store (AES-GCM encrypted)
            blob_store = BlobStore(
                INTEGRITY_BLOB_STORE_PATH,
                retention_days=INTEGRITY_BLOB_RETENTION_DAYS,
            )

            # 7. Replay engine
            replay_engine = ReplayEngine(registry)

            # 8. Sensor context
            policy_digest = compute_policy_digest()
            runtime_digest = canonical_digest({
                "python": "3.11+",
                "onnxruntime": "cpu",
                "platform": "netsentinel-demo",
            })
            sensor_ctx = SensorContext(
                sensor_id=SENSOR_ID,
                signing_key=sk,
                codehash="",       # Phase 2: extractor code digest
                policy_digest=policy_digest,
                runtime_digest=runtime_digest,
                _seq_path=Path(INTEGRITY_SEQ_PATH),
            )

            # 9. Receipt builder
            receipt_builder = ReceiptBuilder()

            # 10. Claims verifier
            claims_verifier = ClaimsVerifier(
                registry=registry,
                blob_store=blob_store,
                replay_engine=replay_engine,
                proof_store=proof_store,
                ledger=ledger,
            )

            # Package everything for the analyzer and routes
            integrity_services = {
                "signing_key": sk,
                "ledger": ledger,
                "proof_store": proof_store,
                "anchor_service": anchor_service,
                "blob_store": blob_store,
                "replay_engine": replay_engine,
                "claims_verifier": claims_verifier,
                "receipt_builder": receipt_builder,
                "sensor_ctx": sensor_ctx,
                "sign_receipt": sign_receipt,
                "envelope_digest": envelope_digest,
            }
            analyzer._integrity = integrity_services

            # Store for routes
            app.state.integrity = integrity_services

            # Start background flush timer
            asyncio.create_task(
                _integrity_flush_loop(anchor_service, INTEGRITY_WINDOW_SECONDS)
            )
            # Start background STH/anchor timer
            asyncio.create_task(
                _integrity_sth_loop(anchor_service, INTEGRITY_CHECKPOINT_INTERVAL)
            )

            print(f"  [OK] Integrity layer ready (sensor={SENSOR_ID})")
            print(f"       Window: {INTEGRITY_WINDOW_SECONDS}s, "
                  f"Checkpoint: {INTEGRITY_CHECKPOINT_INTERVAL}s")

        except ImportError as e:
            print(f"\n[WARN] Integrity layer disabled — missing dependency: {e}")
            print("       Install with: pip install PyNaCl cryptography")
            app.state.integrity = None
        except Exception as e:
            print(f"\n[WARN] Integrity layer init failed: {e}")
            import traceback; traceback.print_exc()
            app.state.integrity = None
    else:
        print("\n[INFO] Integrity layer disabled (INTEGRITY_ENABLED=false)")
        app.state.integrity = None

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
    if getattr(app.state, 'integrity', None):
        print(f"   Verify Alert:  GET http://localhost:8000/api/integrity/verify/{{alert_id}}")
        print(f"   Replay Alert:  POST http://localhost:8000/api/integrity/replay/{{alert_id}}")


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
    port_scan_burst_counter = 0  # Track when to inject port scan bursts
    
    while True:
        if not simulator_control["running"]:
            await asyncio.sleep(0.5)
            port_scan_burst_counter = 0  # Reset when not running
            continue
        
        mode = simulator_control["mode"]
        rate = simulator_control.get("rate", 10)
        
        try:
            # Inject port scan burst every ~15 events in mixed mode (increased frequency)
            if mode == "mixed" and port_scan_burst_counter >= 15:
                from netsentinel.simulator.traffic_gen import generate_port_scan_burst
                print("\n" + "="*60)
                print("[🔍] Injecting port scan burst...")
                burst = generate_port_scan_burst()
                print(f"[🔍] Burst size: {len(burst)} flows from {burst[0]['source_ip'] if burst else 'N/A'}")
                
                # Process all flows in burst
                alerts_generated = 0
                for idx, event in enumerate(burst):
                    alert = analyzer.analyze_flow(event)
                    if alert:
                        alerts_generated += 1
                        await ws_hub.broadcast_alert(alert)
                        if alert.get("threat_class") == "Port Scan":
                            fan_out = alert.get("evidence", {}).get("fan_out", {})
                            print(f"[✓] Port Scan ALERT generated!")
                            print(f"    Source: {alert.get('source_ip')}")
                            print(f"    Ports scanned: {fan_out.get('total_ports', 0)}")
                            print(f"    Confidence: {alert.get('confidence', 0):.3f}")
                
                port_scan_burst_counter = 0
                print(f"[✓] Port scan burst complete: {alerts_generated}/{len(burst)} flows generated alerts")
                print("="*60 + "\n")
            else:
                # Generate single event
                event = generate_event(mode)
                
                # Run through pipeline
                alert = analyzer.analyze_flow(event)
                
                # If threat detected, broadcast to dashboard
                if alert:
                    await ws_hub.broadcast_alert(alert)
                    # Debug: log port scan detections
                    if alert.get("threat_class") == "Port Scan":
                        fan_out = alert.get("evidence", {}).get("fan_out", {})
                        print(f"[SCAN-ALERT] {alert.get('source_ip')} → {fan_out.get('total_ports', 0)} ports")
                
                port_scan_burst_counter += 1
        except Exception as e:
            # Log but don't crash — one bad event shouldn't kill the loop
            print(f"[!] Simulator error: {e}")
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


# ============================================================
# Integrity Background Tasks
# ============================================================
async def _integrity_flush_loop(anchor_service, window_seconds: int):
    """Periodically flush the integrity anchor service window."""
    first_sth_published = False
    while True:
        await asyncio.sleep(window_seconds)
        try:
            result = anchor_service.flush()
            if result:
                count = result.get("alert_count", 0)
                if count > 0:
                    print(f"  [INTEGRITY] Flushed window: {count} alerts → block #{result.get('index', '?')}")

                    # Auto-publish first STH after first non-empty flush
                    # so claims 8+9 light up immediately during demos
                    if not first_sth_published:
                        try:
                            sth_result = anchor_service.publish_sth()
                            sth = sth_result.get("sth", {})
                            print(
                                f"  [INTEGRITY] Auto-published initial STH: "
                                f"seq={sth.get('checkpoint_sequence', 0)}, "
                                f"tree_size={sth.get('tree_size', 0)}"
                            )
                            first_sth_published = True
                        except Exception as e:
                            print(f"  [INTEGRITY] Auto-STH failed: {e}")
        except Exception as e:
            print(f"  [INTEGRITY] Flush error: {e}")


async def _integrity_sth_loop(anchor_service, checkpoint_interval: int):
    """Periodically publish Signed Tree Head and submit to anchors."""
    while True:
        await asyncio.sleep(checkpoint_interval)
        try:
            result = anchor_service.publish_sth()
            sth = result.get("sth", {})
            print(
                f"  [INTEGRITY] STH published: seq={sth.get('checkpoint_sequence', 0)}, "
                f"tree_size={sth.get('tree_size', 0)}, "
                f"strongest_anchor={result.get('strongest', 'none')}"
            )
        except Exception as e:
            print(f"  [INTEGRITY] STH publish error: {e}")

