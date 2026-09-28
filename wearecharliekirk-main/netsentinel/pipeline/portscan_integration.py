"""
netsentinel/pipeline/portscan_integration.py

Wiring shim for netsentinel/pipeline/analyzer.py (implementation plan §7).

This file does NOT modify analyzer.py directly (it lives outside this
sandbox's checkout), but it is the drop-in replacement for the code path
that currently sends CICFlowMeter events to the old per-flow XGBoost
port-scan model. Copy the call pattern below into analyzer.py where that
routing happens.

What to change in analyzer.py
------------------------------
1. Remove (or demote, see below) the call that sends CICFlowMeter flow
   batches to ``models/port_scan.py``'s per-flow XGBoost classifier as the
   thing that decides whether a "Port Scan" alert fires.
2. Construct one process-lifetime ``PortScanRouter`` (below) alongside the
   other model instances in the registry / analyzer startup.
3. For every batch of CICFlowMeter-tagged flows, call
   ``router.handle_batch(flows)`` and publish the returned alert dicts on
   the existing alert bus / WebSocket exactly like other model alerts are
   published today (same ``alert_manager.raise_alert(...)`` call, same
   schema keys).
4. If you want to retain the old model as a supplementary, non-driving
   signal, keep computing its probability and attach it to the alert dict
   as ``ml_flow_score`` only -- never use it to gate whether the alert
   fires, and never surface it as "the confidence" in the dashboard.

Example
-------
    from netsentinel.pipeline.portscan_integration import PortScanRouter

    portscan_router = PortScanRouter(
        network_info_path=cfg.portscan.network_info_path,
        cfg=cfg,
    )

    # ... inside the CICFlowMeter batch handler ...
    def on_cicflowmeter_batch(cic_flow_dicts, legacy_flow_model=None):
        alerts = portscan_router.handle_batch(
            cic_flow_dicts, legacy_flow_model=legacy_flow_model
        )
        for alert in alerts:
            alert_manager.raise_alert(alert)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from netsentinel.netinfo.network_info import NetworkInfo, load_network_info
from netsentinel.extractor.network_event_builder import Flow, SUCCESSION_CAP
from netsentinel.models.portscan_detector import (
    PortScanAlert,
    PortScanConfig,
    PortScanDetector,
)

logger = logging.getLogger("netsentinel.portscan_integration")


class PortScanRouter:
    """Owns the NetworkInfo + PortScanDetector lifecycle for the analyzer.

    One instance should be constructed at process startup (alongside the
    rest of the model registry) and reused across every CICFlowMeter batch
    so that succession state (slow-scan tracking) and UPSD likelihood
    ratios persist correctly across the whole capture / live session.
    """

    def __init__(
        self,
        network_info_path: str = "netsentinel/netinfo/network_info.json",
        cfg: Optional[object] = None,
    ):
        self.network_info: NetworkInfo = load_network_info(network_info_path)

        if cfg is not None and hasattr(cfg, "portscan"):
            self.detector = PortScanDetector.from_config(cfg, self.network_info)
        else:
            self.detector = PortScanDetector(
                network_info=self.network_info, cfg=PortScanConfig()
            )

        if self.network_info.degraded:
            logger.warning(
                "PortScanRouter: network_info is incomplete (degraded mode). "
                "NeIP/NeTCP indicators are suppressed; detection relies on "
                "ICMP/RST/RwA indicators and the fan-out backstop."
            )

    def handle_batch(
        self,
        cic_flow_records: List[dict],
        legacy_flow_model=None,
    ) -> List[Dict]:
        """Convert raw CICFlowMeter records to Flow objects, run the
        network-event port-scan detector, and return alert dicts matching
        the existing alert schema.

        ``legacy_flow_model`` is optional: if provided (the old per-flow
        XGBoost classifier), its score is attached as a clearly-labeled,
        non-driving ``ml_flow_score`` supplementary field per §7 of the
        plan. It never gates whether the alert fires.
        """
        flows = [Flow.from_cic_record(rec) for rec in cic_flow_records]
        alerts = self.detector.process(flows)

        out: List[Dict] = []
        for alert in alerts:
            if legacy_flow_model is not None:
                try:
                    alert.ml_flow_score = _score_legacy_model(
                        legacy_flow_model, alert, cic_flow_records
                    )
                except Exception:  # pragma: no cover - defensive, non-fatal
                    logger.exception(
                        "legacy per-flow port-scan model scoring failed; "
                        "continuing without ml_flow_score"
                    )
            out.append(_alert_to_dict(alert, self.model_name))
        return out

    @property
    def model_name(self) -> str:
        d = self.detector
        if d.spsd is not None and d.spsd.is_available:
            return "portscan_spsd"
        if d.upsd is not None:
            return "portscan_upsd"
        return "portscan_fanout"


class PortScanRule:
    """Receipt/replay adapter for the port-scan detector.

    Gives port-scan alerts the same integrity treatment as the other
    detectors: a digest of the decision parameters (mode, backstop
    thresholds, and the SPSD tree file's sha256), and a replay that re-runs
    the decision on the committed window indicators. UPSD keeps a running
    likelihood ratio per source, which one window's numbers cannot
    reproduce, so UPSD alerts replay as unverifiable.
    """
    key = "port_scan"
    name = "portscan_network_events"
    version = "2"
    confidence_kind = "model_probability"

    def __init__(self, router: "PortScanRouter"):
        import hashlib
        from pathlib import Path
        self.router = router
        det = router.detector
        model_sha = None
        path = Path(det.cfg.model_path)
        if det.spsd is not None and det.spsd.is_available and path.exists():
            model_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        self.params = {
            "mode": det.mode, "fanout_threshold": det.fanout_threshold,
            "sweep_threshold": det.sweep_threshold,
            "sweep_external_exempt_ports": sorted(det.sweep_exempt),
            "window_s": det.builder.window, "spsd_model_sha256": model_sha,
            "skip_group_destinations": True,
            "skip_external_service_ports": True,
            "succession_cap": SUCCESSION_CAP,
        }
        self.runs = self.alerts = self.suppressed = self.skipped_group = 0
        self.skipped_external_service = 0

    @property
    def digest(self) -> str:
        from netsentinel.detectors.base import params_digest
        return params_digest(self.name, self.version, self.params)

    def describe(self) -> dict:
        return {"key": self.key, "name": self.name, "version": self.version,
                "digest": self.digest, "params": self.params,
                "confidence_kind": self.confidence_kind, "model": self.router.model_name,
                "runs": self.runs, "alerts": self.alerts, "suppressed": self.suppressed,
                "skipped_group_destinations": self.skipped_group,
                "skipped_external_service_flows": self.skipped_external_service}

    def replay(self, inputs: dict):
        from netsentinel.extractor.network_event_builder import NetworkEvent
        det = self.router.detector
        if det.spsd is None or not det.spsd.is_available:
            return None
        ev = NetworkEvent(
            src_ip="replay", window_start=0.0,
            icmp_error_count=int(inputs.get("icmp_error", 0)), rst_count=int(inputs.get("rst", 0)),
            rwa_count=int(inputs.get("rwa", 0)), neip_count=int(inputs.get("neip", 0)),
            netcp_count=int(inputs.get("netcp", 0)), succession_count=int(inputs.get("succession", 0)),
        )
        fired, conf, _ = det._decide(ev, int(inputs.get("fanout", 0)), inputs.get("sweep_port"),
                                     int(inputs.get("sweep_hosts", 0)))
        return {"threat": "Port Scan" if fired else "Benign", "confidence": round(float(conf), 4)}


def _alert_to_dict(alert: PortScanAlert, model_name: str = "portscan_spsd") -> Dict:
    return {
        # AlertManager.create_alert() reads model_result["threat"] -- that is
        # the contract every other model wrapper follows (ddos.py, dga.py,
        # c2_beacon.py all emit "threat"). Emitting only "threat_type" made
        # create_alert() fall through to its "Unknown" default, so port-scan
        # alerts were built but arrived unclassified: threat_class "Unknown",
        # default MEDIUM severity and an Unknown MITRE mapping instead of
        # T1046. "threat_type" is kept for any existing consumer.
        "threat": alert.threat_type,
        "threat_type": alert.threat_type,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "confidence": alert.confidence,
        "severity": alert.severity,
        "mitre": alert.mitre,
        "evidence": alert.evidence,
        "scan_type": alert.scan_type,
        "subtype": {"horizontal": "host sweep", "vertical": "port scan",
                    "block": "block scan"}.get(alert.scan_type, alert.scan_type),
        "window_start": alert.window_start,
        "reason": alert.reason,
        "ml_flow_score": alert.ml_flow_score,
        "model": model_name,
    }


def _score_legacy_model(legacy_flow_model, alert: PortScanAlert, cic_flow_records) -> float:
    """Best-effort average of the legacy per-flow model's score across the
    flows from this alert's src_ip, purely for supplementary display."""
    scores = []
    for rec in cic_flow_records:
        src = rec.get("Src IP") or rec.get("src_ip")
        if src == alert.src_ip and hasattr(legacy_flow_model, "predict_proba"):
            scores.append(float(legacy_flow_model.predict_proba(rec)))
    if not scores:
        return 0.0
    return sum(scores) / len(scores)
