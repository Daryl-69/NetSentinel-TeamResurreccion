"""REST API Routes — Health, alerts, stats, simulation, PCAP, capture."""
import os
import asyncio
import shutil
from fastapi import APIRouter, UploadFile, File, BackgroundTasks

from netsentinel.config import PCAP_UPLOAD_DIR, CAPTURE_INTERFACE

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

    @router.post("/capture/start")
    async def start_capture(interface: str = CAPTURE_INTERFACE):
        """Start live packet capture on the specified interface."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}

        if _packet_processor._live_running:
            return {"error": "Live capture already running"}

        event_queue = asyncio.Queue(maxsize=10000)

        # Start capture
        await _packet_processor.start_live_capture(interface, event_queue)

        # Start consumer task
        asyncio.create_task(_consume_live_events(event_queue, analyzer, ws_hub))

        return {"status": f"Live capture started on '{interface}'"}

    @router.post("/capture/stop")
    async def stop_capture():
        """Stop live packet capture."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}

        _packet_processor.stop_live_capture()
        return {"status": "Live capture stopped"}

    @router.get("/extractor/stats")
    async def extractor_stats():
        """Get detailed extraction layer statistics."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        return _packet_processor.stats

    # ==================================================================
    # Integrity / Proof-Carrying Alert Endpoints
    # ==================================================================

    @router.get("/integrity/verify/{alert_id}")
    async def verify_alert(alert_id: str):
        """Run the 9-claim verification against an alert.

        This is the money-shot endpoint — the nine-row panel.
        """
        from fastapi import Request
        integrity = getattr(router, '_app_state_integrity', None)
        # Try to get integrity from app state
        if integrity is None:
            # Fallback: look up in the current scope
            if hasattr(analyzer, '_integrity') and analyzer._integrity:
                integrity = analyzer._integrity
        if not integrity:
            return {"error": "Integrity layer not enabled"}

        # Find the alert
        matching = [a for a in alert_manager.alerts if a.get("id") == alert_id]
        if not matching:
            return {"error": f"Alert {alert_id} not found"}

        verifier = integrity["claims_verifier"]
        return verifier.verify_all(alert_id, matching[0])

    @router.get("/integrity/receipt/{alert_id}")
    async def get_receipt(alert_id: str):
        """Get the portable Proof-Carrying Alert package for an alert."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        proof_record = svc["proof_store"].get(alert_id)
        if not proof_record:
            return {"error": f"No receipt for alert {alert_id}"}

        return {
            "alert_id": alert_id,
            "envelope": proof_record["envelope"],
            "merkle_proof": proof_record.get("proof"),
            "merkle_root": proof_record.get("merkle_root"),
            "block_index": proof_record.get("block_index"),
        }

    @router.post("/integrity/replay/{alert_id}")
    async def replay_alert(alert_id: str):
        """Deterministic inference replay for an alert."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        proof_record = svc["proof_store"].get(alert_id)
        if not proof_record:
            return {"error": f"No receipt for alert {alert_id}"}

        # Get feature blob
        if not svc["blob_store"].has(alert_id):
            return {"error": f"Feature blob not available for {alert_id}"}

        feature_blob, _ = svc["blob_store"].get(alert_id)
        if feature_blob is None:
            return {"error": "Feature blob decryption failed"}

        # Parse receipt for committed values
        import base64, json as _json
        envelope = proof_record["envelope"]
        statement = _json.loads(base64.b64decode(envelope["payload"]))
        decision = statement.get("predicate", {}).get("decision", {})
        model_info = statement.get("predicate", {}).get("model", {})

        result = svc["replay_engine"].replay(
            alert_id=alert_id,
            feature_blob=feature_blob,
            committed_class=decision.get("class", ""),
            committed_score_ppm=decision.get("score_ppm", 0),
            model_digest=model_info.get("model_digest", ""),
        )
        return result.to_dict()

    @router.get("/integrity/checkpoints")
    async def list_checkpoints():
        """List checkpoint (STH) history."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        sth_file = svc["proof_store"].store_dir / "sth_history.jsonl"
        checkpoints = []
        if sth_file.exists():
            import json as _json
            with open(sth_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        checkpoints.append(_json.loads(line))
        return {"checkpoints": checkpoints, "total": len(checkpoints)}

    @router.get("/integrity/consistency")
    async def check_consistency():
        """Verify ledger chain integrity and return current status."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        chain_ok, bad_idx = svc["ledger"].verify_chain()
        latest_sth = svc["proof_store"].get_latest_sth()

        return {
            "chain_valid": chain_ok,
            "bad_block_index": bad_idx,
            "ledger_size": svc["ledger"].size,
            "latest_sth": latest_sth.to_dict() if latest_sth else None,
            "anchor_buffer_size": svc["anchor_service"].buffer_size,
        }

    @router.post("/integrity/flush")
    async def force_flush():
        """Force an immediate integrity window flush (for demos)."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        result = svc["anchor_service"].flush()
        return {"status": "flushed", "block": result}

    @router.post("/integrity/publish-sth")
    async def force_publish_sth():
        """Force an immediate STH publication (for demos)."""
        if not hasattr(analyzer, '_integrity') or not analyzer._integrity:
            return {"error": "Integrity layer not enabled"}

        svc = analyzer._integrity
        result = svc["anchor_service"].publish_sth()
        return result

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
            await asyncio.sleep(0.001)
            continue
            
        event_count += 1
        alert = analyzer.analyze_flow(event)
        if alert:
            alert_count += 1
            await ws_hub.broadcast_alert(alert)

        # Yield control frequently to keep WebSocket + HTTP responsive
        if event_count % 10 == 0:
            await asyncio.sleep(0.001)

    # Send completion stats
    await ws_hub.broadcast_stats({
        "pcap_complete": True,
        "pcap_file": os.path.basename(pcap_path),
        "events_processed": event_count,
        "alerts_generated": alert_count,
        **analyzer.get_stats(),
    })


async def _consume_live_events(event_queue: asyncio.Queue, analyzer, ws_hub):
    """Consume events from live capture queue and run through pipeline."""
    while True:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=5.0)
            alert = analyzer.analyze_flow(event)
            if alert:
                await ws_hub.broadcast_alert(alert)
        except asyncio.TimeoutError:
            continue
        except Exception:
            break

