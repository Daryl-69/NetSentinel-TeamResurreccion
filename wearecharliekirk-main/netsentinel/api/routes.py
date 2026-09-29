"""REST API Routes — health, alerts, stats, metrics, schema, PS 26145 status,
simulation, PCAP replay, live capture, benchmark and integrity."""
import os
import json
import time
import asyncio
import shutil
import threading
from fastapi import APIRouter, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse

from netsentinel.config import PCAP_UPLOAD_DIR, CAPTURE_INTERFACE
from netsentinel.extractor.pcap_reader import (
    LiveCaptureError, default_interface, list_interfaces,
)
from netsentinel.pipeline.metrics import METRICS
from netsentinel.pipeline.alert_schema import ALERT_SCHEMA
from netsentinel.pipeline.ps26145 import build_status, THREATS
import netsentinel.config as config

router = APIRouter(prefix="/api")

# Module-level reference to the packet processor (set in create_routes)
_packet_processor = None
_last_replay_processor = None
_BENCH_FILE = os.path.join(PCAP_UPLOAD_DIR, "last_benchmark.json")
_bench = {"status": "idle", "progress": None, "result": None, "error": None, "started": None}


def _load_last_benchmark():
    try:
        with open(_BENCH_FILE, "r", encoding="utf-8") as fh:
            _bench["result"] = json.load(fh)
    except (OSError, ValueError):
        pass


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
    _load_last_benchmark()

    @router.get("/health")
    async def health():
        """System health check."""
        result = {
            "status": "online",
            "models": analyzer.registry.get_status(),
            "pipeline": analyzer.get_stats(),
            "websocket_clients": ws_hub.client_count,
            "config": {
                "quic_initial_parse": bool(config.QUIC_INITIAL_PARSE),
                "tls_fingerprinting": bool(config.TLS_FINGERPRINTING),
                "ett_alert_on_vpn": bool(config.ETT_ALERT_ON_VPN),
                "c2_bilstm_alerts": bool(getattr(config, "C2_BILSTM_ALERTS", False)),
                "sensor_id": config.SENSOR_ID,
            },
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

    @router.get("/metrics")
    async def get_metrics():
        """Throughput (10 s window and peak), latency percentiles, totals,
        per-second history, plus detector watch lists."""
        snap = METRICS.snapshot()
        snap["pipeline"] = analyzer.get_stats()
        snap["c2_watchlist"] = analyzer.c2_watchlist(5)
        snap["tls_fingerprints"] = analyzer.tls_detector.top_fingerprints(8)
        return snap

    @router.get("/schema/alert")
    async def alert_schema():
        """JSON Schema (draft 2020-12) every alert conforms to."""
        return ALERT_SCHEMA

    @router.get("/detectors")
    async def detectors():
        """Models and rule detectors, their parameters, digests and counters."""
        return {
            "models": analyzer.registry.get_status(),
            "rules": analyzer.detector_catalog(),
            "coverage": [{"id": t["id"], "title": t["title"], "detectors": t["detectors"]} for t in THREATS],
            "latency_ms": METRICS.snapshot(with_series=False)["latency_ms"],
        }

    @router.get("/ps26145")
    async def ps26145():
        """Coverage of the six threat families and the five constraints."""
        return build_status(analyzer, alert_manager, METRICS,
                            _last_replay_processor or _packet_processor, _bench.get("result"))

    @router.post("/simulate/{attack_type}")
    async def start_simulation(attack_type: str):
        """Start or stop the SYNTHETIC traffic simulator."""
        from netsentinel.simulator.traffic_gen import SIM_MODES
        valid_modes = SIM_MODES + ["stop"]
        if attack_type not in valid_modes:
            return {"error": f"Invalid mode. Use: {valid_modes}"}

        if attack_type == "stop":
            simulator_control["running"] = False
            simulator_control["mode"] = "normal"
            return {"status": "Simulation stopped"}

        simulator_control["mode"] = attack_type
        simulator_control["running"] = True
        return {"status": f"Simulation started: {attack_type} (synthetic)", "mode": attack_type}

    @router.get("/models")
    async def list_models():
        """List loaded models with their metrics."""
        return analyzer.registry.get_status()

    @router.post("/reset")
    async def reset_stats():
        """Reset pipeline stats, metrics and alerts (for testing)."""
        analyzer.flows_processed = 0
        alert_manager.reset()
        METRICS.reset()
        return {"status": "reset"}

    # ==================================================================
    # Extraction Layer Endpoints
    # ==================================================================

    @router.post("/pcap/upload")
    async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
        """Upload a PCAP file for offline analysis (processed in the background)."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
            return {"error": "Invalid file type. Upload .pcap or .pcapng"}
        save_path = os.path.join(PCAP_UPLOAD_DIR, os.path.basename(file.filename))
        with open(save_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        background_tasks.add_task(_process_pcap_background, save_path, analyzer, ws_hub)
        return {
            "status": "PCAP uploaded, processing started",
            "filename": os.path.basename(file.filename),
            "size_bytes": os.path.getsize(save_path),
        }

    from pydantic import BaseModel

    class ProcessLocalPCAPRequest(BaseModel):
        filepath: str

    @router.post("/pcap/process")
    async def process_local_pcap(request: ProcessLocalPCAPRequest, background_tasks: BackgroundTasks):
        """Process a local PCAP file by path (no upload size limit)."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        if not os.path.exists(request.filepath):
            return {"error": f"File not found: {request.filepath}"}
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
        """Start live (receive-only) capture.

        interface: e.g. eth0 / wlan0 / en0 / Wi-Fi. Omit to use the interface
        carrying the default route. Needs root/admin (and Npcap on Windows).
        """
        if _packet_processor is None:
            return JSONResponse({"error": "Extraction layer not initialized"}, status_code=503)
        try:
            info = await start_live_capture(interface, analyzer, ws_hub)
        except LiveCaptureError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {"status": f"Live capture started on '{info['interface']}'", **info}

    @router.post("/capture/stop")
    async def stop_capture():
        """Stop live packet capture."""
        if _packet_processor is None:
            return JSONResponse({"error": "Extraction layer not initialized"}, status_code=503)
        await asyncio.to_thread(_packet_processor.stop_live_capture)
        return {"status": "Live capture stopped"}

    @router.get("/extractor/stats")
    async def extractor_stats():
        """Extraction layer statistics (live processor, and the last replay)."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        out = dict(_packet_processor.stats)
        if _last_replay_processor is not None:
            out["replay"] = _last_replay_processor.stats
        return out

    # ==================================================================
    # Throughput benchmark (PS 26145 constraint d)
    # ==================================================================

    class BenchmarkRequest(BaseModel):
        synthetic_packets: int = 50000
        pcap_path: str | None = None

    @router.post("/benchmark")
    async def start_benchmark(req: BenchmarkRequest):
        """Replay a capture through extraction + every detector as fast as
        possible, in a worker thread with its own analyzer (no alerts or
        counts are added to the running sensor)."""
        if _bench["status"] in ("generating", "running"):
            return {"error": "A benchmark is already running"}
        if req.pcap_path and not os.path.exists(req.pcap_path):
            return {"error": f"File not found: {req.pcap_path}"}
        n = max(5000, min(int(req.synthetic_packets or 50000), 500000))
        loop = asyncio.get_running_loop()
        _bench.update(status="running", progress=None, error=None, started=time.time())
        threading.Thread(target=_run_benchmark_thread,
                         args=(analyzer.registry, req.pcap_path, n, loop, ws_hub, simulator_control),
                         daemon=True, name="benchmark").start()
        return {"status": "started", "input": req.pcap_path or f"synthetic {n} packets"}

    @router.get("/benchmark")
    async def benchmark_status():
        return _bench

    # ==================================================================
    # Tier 2 (Inspector-Sentry) and figures
    # ==================================================================
    from netsentinel import tier2_bridge

    @router.get("/tier2")
    async def tier2_status(refresh: bool = False):
        """Tier 2 as the console shows it: present or not, which Python runs
        it and whether that Python has PyTorch, headline numbers re-derived
        from tier2/*.json now, charts, and the cascade demo's state."""
        if refresh:
            await asyncio.to_thread(tier2_bridge.torch_available, True)
        return await asyncio.to_thread(tier2_bridge.status)

    class Tier2DemoRequest(BaseModel):
        fast: bool = True

    @router.post("/tier2/demo")
    async def tier2_demo_start(req: Tier2DemoRequest):
        """Run tier2/demo_scenario.py: the whole cascade on a synthetic
        organisation, about 30 s (fast) or a minute, streamed line by line."""
        return tier2_bridge.DEMO.start(fast=req.fast)

    @router.get("/tier2/demo")
    async def tier2_demo_status(since: int = 0):
        return tier2_bridge.DEMO.snapshot(max(0, since))

    # ---------------- live Inspector-Sentry cascade + event ingest (Sentinel view)
    from netsentinel.cascade_live import CASCADE

    class CascadeStart(BaseModel):
        tick: float = 0.8

    @router.post("/cascade/start")
    async def cascade_start(req: CascadeStart):
        return CASCADE.start(tick=max(0.2, min(req.tick, 5.0)))

    @router.get("/cascade/state")
    async def cascade_state(since: int = 0):
        return CASCADE.state(max(0, since))

    @router.post("/cascade/attack")
    async def cascade_attack():
        return CASCADE.attack()

    @router.post("/cascade/reset")
    async def cascade_reset():
        return CASCADE.reset()

    def _slim(a):
        return {"threat_class": a.get("threat_class"), "threat_subtype": a.get("threat_subtype"),
                "confidence": a.get("confidence"), "severity": a.get("severity"),
                "detector": a.get("detector"), "source_ip": a.get("source_ip"), "dest_ip": a.get("dest_ip")}

    class IngestRequest(BaseModel):
        events: list

    @router.post("/ingest")
    async def ingest(req: IngestRequest):
        """Flow / DNS events from a traffic source (e.g. the red-team tool),
        analysed by the same analyzer as captured traffic. Returns the alerts
        they raised."""
        out = []
        for ev in req.events[:5000]:
            if not isinstance(ev, dict):
                continue
            ev.setdefault("ingest_wall", time.time())
            try:
                alerts = analyzer.analyze(ev)
            except Exception as e:
                print(f"[!] ingest: {e}")
                continue
            for a in alerts:
                out.append(_slim(a))
                await ws_hub.broadcast_alert(a)
        # flush buffered port-scan windows so a scan in this batch is decided now
        try:
            for a in (analyzer.flush_portscan_buffer() or []):
                out.append(_slim(a))
                await ws_hub.broadcast_alert(a)
        except Exception as e:
            print(f"[!] ingest portscan flush: {e}")
        return {"accepted": len(req.events), "alerts": out}

    @router.get("/figures")
    async def figures_list():
        return {"models": tier2_bridge.model_figures(), "tier2": tier2_bridge.figures(),
                "ps26145": tier2_bridge.docs_figures()}

    @router.get("/figures/{group}/{name}")
    async def figure_file(group: str, name: str):
        from fastapi.responses import FileResponse, JSONResponse
        path = tier2_bridge.figure_path(group, name)
        if path is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(path), media_type="image/png",
                            headers={"Cache-Control": "public, max-age=3600"})

    # ==================================================================
    # Integrity / Proof-Carrying Alert Endpoints
    # ==================================================================

    @router.get("/integrity/verify/{alert_id}")
    async def verify_alert(alert_id: str):
        """Run the 9-claim verification against an alert."""
        integrity = getattr(analyzer, "_integrity", None)
        if not integrity:
            return {"error": "Integrity layer not enabled"}
        matching = [a for a in alert_manager.alerts if a.get("id") == alert_id]
        if not matching:
            return {"error": f"Alert {alert_id} not found"}
        return integrity["claims_verifier"].verify_all(alert_id, matching[0])

    @router.get("/integrity/receipt/{alert_id}")
    async def get_receipt(alert_id: str):
        """Get the portable Proof-Carrying Alert package for an alert."""
        if not getattr(analyzer, "_integrity", None):
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
        if not getattr(analyzer, "_integrity", None):
            return {"error": "Integrity layer not enabled"}
        svc = analyzer._integrity
        proof_record = svc["proof_store"].get(alert_id)
        if not proof_record:
            return {"error": f"No receipt for alert {alert_id}"}
        if not svc["blob_store"].has(alert_id):
            return {"error": f"Feature blob not available for {alert_id}"}
        feature_blob, _ = svc["blob_store"].get(alert_id)
        if feature_blob is None:
            return {"error": "Feature blob decryption failed"}
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
        if not getattr(analyzer, "_integrity", None):
            return {"error": "Integrity layer not enabled"}
        svc = analyzer._integrity
        sth_file = svc["proof_store"].store_dir / "sth_history.jsonl"
        checkpoints = []
        if sth_file.exists():
            with open(sth_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        checkpoints.append(json.loads(line))
        return {"checkpoints": checkpoints, "total": len(checkpoints)}

    @router.get("/integrity/consistency")
    async def check_consistency():
        """Verify ledger chain integrity and return current status."""
        if not getattr(analyzer, "_integrity", None):
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
        if not getattr(analyzer, "_integrity", None):
            return {"error": "Integrity layer not enabled"}
        result = analyzer._integrity["anchor_service"].flush()
        return {"status": "flushed", "block": result}

    @router.post("/integrity/publish-sth")
    async def force_publish_sth():
        """Force an immediate STH publication (for demos)."""
        if not getattr(analyzer, "_integrity", None):
            return {"error": "Integrity layer not enabled"}
        return analyzer._integrity["anchor_service"].publish_sth()

    return router


# ======================================================================
# Background tasks for PCAP processing, live capture and the benchmark
# ======================================================================

async def _process_pcap_background(pcap_path: str, analyzer, ws_hub):
    """Replay a capture through the pipeline, streaming alerts over WebSocket."""
    global _last_replay_processor
    from netsentinel.extractor import PacketProcessor

    processor = PacketProcessor()
    _last_replay_processor = processor
    alert_count = 0
    event_count = 0
    for event in processor.process_pcap(pcap_path):
        if event is None:
            await asyncio.sleep(0)
            continue
        event_count += 1
        try:
            alerts = analyzer.analyze(event)
        except Exception as e:           # one bad event must not end the replay
            print(f"[!] Analyzer error on replay event: {e}")
            continue
        for alert in alerts:
            alert_count += 1
            await ws_hub.broadcast_alert(alert)
        if event_count % 200 == 0:
            await asyncio.sleep(0)
    for alert in analyzer.finish():
        alert_count += 1
        await ws_hub.broadcast_alert(alert)

    await ws_hub.broadcast_stats({
        "pcap_complete": True,
        "pcap_file": os.path.basename(pcap_path),
        "events_processed": event_count,
        "alerts_generated": alert_count,
        "reader": processor.reader_used,
        **analyzer.get_stats(),
    })


async def start_live_capture(interface, analyzer, ws_hub) -> dict:
    """Open the capture on `interface` (None/"" = default route) and start
    feeding its events through the pipeline. Raises LiveCaptureError."""
    if _packet_processor is None:
        raise LiveCaptureError("Extraction layer not initialized")
    event_queue = asyncio.Queue(maxsize=10000)
    info = await _packet_processor.start_live_capture(interface or None, event_queue)
    asyncio.create_task(_consume_live_events(event_queue, analyzer, ws_hub))
    return info


async def _consume_live_events(event_queue: asyncio.Queue, analyzer, ws_hub):
    """Consume live-capture events; close quiet windows every few seconds."""
    last_tick = time.time()
    while True:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            event = None
        try:
            if event is not None:
                for alert in analyzer.analyze(event):
                    await ws_hub.broadcast_alert(alert)
            now = time.time()
            if now - last_tick >= float(config.LIVE_FLUSH_INTERVAL_S):
                last_tick = now
                for alert in analyzer.tick(now):
                    await ws_hub.broadcast_alert(alert)
        except Exception as e:
            print(f"[!] Live pipeline error: {e}")
        if (event is None and _packet_processor is not None
                and not _packet_processor._live_running and event_queue.empty()):
            break


def _run_benchmark_thread(registry, pcap_path, n_packets, loop, ws_hub, simulator_control):
    from netsentinel.bench import run_benchmark, synthetic_pcap, synthetic_path

    def push(kind, data):
        try:
            asyncio.run_coroutine_threadsafe(ws_hub.broadcast("benchmark", {"phase": kind, **data}), loop)
        except Exception:
            pass

    try:
        if pcap_path:
            path, kind = pcap_path, "pcap"
        else:
            path, kind = synthetic_path(n_packets), "synthetic"
            if not os.path.exists(path):
                _bench["status"] = "generating"
                push("generating", {"packets": n_packets})
                synthetic_pcap(path, n_packets,
                               progress=lambda c: _bench.update(progress={"generated": c, "of": n_packets}))
        _bench["status"] = "running"
        busy = {"simulator_running": bool(simulator_control.get("running")),
                "live_capture": bool(_packet_processor and _packet_processor._live_running)}

        def prog(p):
            _bench["progress"] = p
            push("running", p)

        res = run_benchmark(path, registry=registry, progress=prog, kind=kind)
        res["sensor_busy_during_run"] = busy
        _bench.update(status="done", result=res, progress=None)
        try:
            with open(_BENCH_FILE, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=1)
        except OSError:
            pass
        push("done", {"result": res})
    except Exception as e:
        _bench.update(status="error", error=str(e), progress=None)
        push("error", {"error": str(e)})
