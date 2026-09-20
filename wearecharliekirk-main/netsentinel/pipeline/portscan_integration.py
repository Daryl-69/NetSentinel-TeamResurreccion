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
from netsentinel.extractor.network_event_builder import Flow
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
            out.append(_alert_to_dict(alert))
        return out


def _alert_to_dict(alert: PortScanAlert) -> Dict:
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
        "window_start": alert.window_start,
        "reason": alert.reason,
        "ml_flow_score": alert.ml_flow_score,
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
