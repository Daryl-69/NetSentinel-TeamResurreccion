"""REST API Routes — Health, alerts, stats, simulation, PCAP, capture."""
import os
import time
import asyncio
import shutil
from fastapi import APIRouter, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse

from netsentinel.config import PCAP_UPLOAD_DIR, CAPTURE_INTERFACE, LIVE_FLUSH_INTERVAL_S
from netsentinel.extractor.pcap_reader import (
    LiveCaptureError, default_interface, list_interfaces,
)

router = APIRouter(prefix="/api")

# Module-level reference to the packet processor (set in create_routes)
_packet_processor = None


def create_routes(analyzer, alert_manager, ws_hub, simulator_control, packet_processor=None):
    """
    Create API routes with access to shared state.

    Args:
        analyzer: FlowAnalyzer instance
        alert_manager: AlertManager instance
        ws_hub: WebSocketHub instance
        simulator_control: dict with 'mode' and 'running' keys
        packet_processor: PacketProcessor instance (optional)
    """
    global _packet_processor
    _packet_processor = packet_processor

    @router.get("/health")
    async def health():
        """System health check."""
        result = {
            "status": "online",
            "models": analyzer.registry.get_status(),
            "pipeline": analyzer.get_stats(),
            "websocket_clients": ws_hub.client_count,
        }
        if _packet_processor:
            result["extractor"] = _packet_processor.stats
        return result

    @router.get("/alerts")
    async def get_alerts(limit: int = 50):
        """Get recent alerts."""
        return {
            "alerts": alert_manager.get_recent(limit),
            "total": alert_manager.total_count,
        }

    @router.get("/stats")
    async def get_stats():
        """Get pipeline statistics."""
        stats = analyzer.get_stats()
        if _packet_processor:
            stats["extractor"] = _packet_processor.stats
        return stats

    @router.post("/simulate/{attack_type}")
    async def start_simulation(attack_type: str):
        """
        Trigger an attack simulation.

        attack_type: "normal", "ddos", "dga", "c2", "mixed", "stop"
        """
        valid_modes = ["normal", "ddos", "dga", "c2", "mixed", "stop"]
        if attack_type not in valid_modes:
            return {"error": f"Invalid mode. Use: {valid_modes}"}

        if attack_type == "stop":
            simulator_control["running"] = False
            simulator_control["mode"] = "normal"
            return {"status": "Simulation stopped"}

        simulator_control["mode"] = attack_type
        simulator_control["running"] = True

        return {
            "status": f"Simulation started: {attack_type}",
            "mode": attack_type,
        }

    @router.get("/models")
    async def list_models():
        """List loaded models with their metrics."""
        return analyzer.registry.get_status()

    @router.post("/reset")
    async def reset_stats():
        """Reset pipeline stats and alerts (for testing)."""
        analyzer.flows_processed = 0
        alert_manager.reset()
        return {"status": "reset"}

    # ==================================================================
    # Extraction Layer Endpoints
    # ==================================================================

    @router.post("/pcap/upload")
    async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
        """Upload a PCAP file for offline analysis.

        The file is saved to disk and processed in the background.
        Events are routed through the analyzer and alerts broadcast via WS.
        """
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}

        # Validate file extension
        if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
            return {"error": "Invalid file type. Upload .pcap or .pcapng"}

        # Save uploaded file
        save_path = os.path.join(PCAP_UPLOAD_DIR, file.filename)
        with open(save_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # Process in background
        background_tasks.add_task(_process_pcap_background, save_path, analyzer, ws_hub)

        return {
            "status": "PCAP uploaded, processing started",
            "filename": file.filename,
            "size_bytes": os.path.getsize(save_path),
        }

    from pydantic import BaseModel
    class ProcessLocalPCAPRequest(BaseModel):
        filepath: str

    @router.post("/pcap/process")
    async def process_local_pcap(request: ProcessLocalPCAPRequest, background_tasks: BackgroundTasks):
        """Process a local PCAP file directly by filepath.
        Bypasses HTTP multipart upload limits, ideal for massive files (e.g. 8GB+).
        """
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}

        if not os.path.exists(request.filepath):
            return {"error": f"File not found: {request.filepath}"}

        # Process in background
        background_tasks.add_task(_process_pcap_background, request.filepath, analyzer, ws_hub)

        return {
            "status": "Local PCAP found, processing started",
            "filename": os.path.basename(request.filepath),
            "size_bytes": os.path.getsize(request.filepath),
        }

    @router.get("/capture/interfaces")
    async def capture_interfaces():
        """List interfaces available for live capture, and the default one."""
        return {
            "default": CAPTURE_INTERFACE or default_interface(),
            "interfaces": list_interfaces(),
        }

    @router.post("/capture/start")
    async def start_capture(interface: str = CAPTURE_INTERFACE):
        """Start live packet capture.

        interface: e.g. eth0 / wlan0 / en0 / Wi-Fi. Omit to use the interface
        carrying the default route. Needs root/admin (and Npcap on Windows).
        """
        if _packet_processor is None:
            return JSONResponse({"error": "Extraction layer not initialized"}, status_code=503)
        try:
            info = await start_live_capture(interface, analyzer, ws_hub)
        except LiveCaptureError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {
            "status": f"Live capture started on '{info['interface']}'",
            **info,
        }

    @router.post("/capture/stop")
    async def stop_capture():
        """Stop live packet capture."""
        if _packet_processor is None:
            return JSONResponse({"error": "Extraction layer not initialized"}, status_code=503)

        await asyncio.to_thread(_packet_processor.stop_live_capture)
        return {"status": "Live capture stopped"}

    @router.get("/extractor/stats")
    async def extractor_stats():
        """Get detailed extraction layer statistics."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        return _packet_processor.stats

    return router


# ======================================================================
# Background tasks for PCAP processing and live capture consumption
# ======================================================================

async def _process_pcap_background(pcap_path: str, analyzer, ws_hub):
    """Process a PCAP file in the background, sending alerts via WebSocket."""
    from netsentinel.extractor import PacketProcessor

    processor = PacketProcessor()
    alert_count = 0
    event_count = 0

    for event in processor.process_pcap(pcap_path):
        if event is None:
            # Yield control so WebSockets don't timeout
            await asyncio.sleep(0)
            continue
            
        event_count += 1
        alert = analyzer.analyze_flow(event)
        if alert:
            alert_count += 1
            await ws_hub.broadcast_alert(alert)

        # Still yield occasionally for events
        if event_count % 100 == 0:
            await asyncio.sleep(0)

    # Send completion stats
    await ws_hub.broadcast_stats({
        "pcap_complete": True,
        "pcap_file": os.path.basename(pcap_path),
        "events_processed": event_count,
        "alerts_generated": alert_count,
        **analyzer.get_stats(),
    })


async def start_live_capture(interface, analyzer, ws_hub) -> dict:
    """Open the capture on `interface` (None/"" = default route) and start
    feeding its events through the pipeline. Raises LiveCaptureError."""
    if _packet_processor is None:
        raise LiveCaptureError("Extraction layer not initialized")
    event_queue = asyncio.Queue(maxsize=10000)
    info = await _packet_processor.start_live_capture(
        interface or None, event_queue, flush_interval=LIVE_FLUSH_INTERVAL_S,
    )
    asyncio.create_task(_consume_live_events(event_queue, analyzer, ws_hub))
    return info


async def _consume_live_events(event_queue: asyncio.Queue, analyzer, ws_hub):
    """Consume events from live capture queue and run through pipeline.

    Also pushes a stats frame over the WebSocket every 2 s so dashboards see
    packet/flow counters move. Exits once capture has stopped and the queue
    is drained.
    """
    last_stats = 0.0
    while True:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            event = None

        if event is not None:
            try:
                alert = analyzer.analyze_flow(event)
                if alert:
                    await ws_hub.broadcast_alert(alert)
            except Exception as e:
                # One bad event must not kill live detection
                print(f"[!] Live pipeline error: {e}")

        now = time.time()
        if now - last_stats >= 2.0:
            last_stats = now
            stats = analyzer.get_stats()
            stats["extractor"] = _packet_processor.stats
            await ws_hub.broadcast_stats(stats)

        if event is None and not _packet_processor._live_running and event_queue.empty():
            break
