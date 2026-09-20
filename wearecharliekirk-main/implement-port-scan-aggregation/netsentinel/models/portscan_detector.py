"""
netsentinel/models/portscan_detector.py

Network-event-based port-scan detector (SPSD + UPSD) with a destination-port
fan-out heuristic kept as a fast-path backstop.

This REPLACES the per-flow XGBoost model as the primary decision-maker on
the port-scan path. See netsentinel/pipeline/portscan_integration.py for how
to wire this into analyzer.py, and README notes there for removing/demoting
the old per-flow call.

Two primary detector modes (config: ``portscan.mode``):

* ``"spsd"`` (default, recommended) - Supervised Port Scan Detector: a
  ``sklearn.tree.DecisionTreeClassifier`` trained offline on CIDDS-001
  network events (see scripts/train_spsd.py). Fully explainable and gets
  0 false alarms in Ring et al. (2018).
* ``"upsd"`` - Unsupervised Port Scan Detector: Wald's sequential
  probability ratio test per source IP. No training data required; used as
  a cold-start fallback when no SPSD model is available yet.
"""

from __future__ import annotations

import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netsentinel.config.network_info import NetworkInfo
from netsentinel.extractor.network_event_builder import (
    Flow,
    NetworkEvent,
    NetworkEventBuilder,
)

logger = logging.getLogger("netsentinel.portscan_detector")

MITRE_PORT_SCAN = "T1046"  # Network Service Discovery


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
@dataclass
class UPSDParams:
    theta0: float = 0.8
    theta1: float = 0.2
    eta0: float = 0.001
    eta1: float = 999.0


@dataclass
class PortScanConfig:
    """Mirrors the ``portscan:`` block described in the implementation plan.

    Merge these fields into your existing ``netsentinel/config.py`` (either
    as a nested dataclass/attrs object named ``portscan``, or by copying the
    fields directly onto the module-level config), e.g.::

        class PortScanSettings:
            mode = "spsd"
            model_path = "netsentinel/models/weights/portscan_spsd_decisiontree.pkl"
            network_info_path = "netsentinel/config/network_info.json"
            fanout_threshold = 100
            upsd_params = {"theta0": 0.8, "theta1": 0.2, "eta0": 0.001, "eta1": 999}

        portscan = PortScanSettings()
    """

    mode: str = "spsd"  # "spsd" | "upsd"
    model_path: str = "netsentinel/models/weights/portscan_spsd_decisiontree.pkl"
    network_info_path: str = "netsentinel/config/network_info.json"
    fanout_threshold: int = 100
    upsd_params: UPSDParams = field(default_factory=UPSDParams)
    confidence_threshold: float = 0.5


# ----------------------------------------------------------------------
# SPSD - supervised
# ----------------------------------------------------------------------
class SPSDDetector:
    """DecisionTreeClassifier over the 6-element NetworkEvent feature vector."""

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        p = Path(model_path)
        if p.exists():
            with open(p, "rb") as fh:
                self.model = pickle.load(fh)
        else:
            logger.warning(
                "SPSDDetector: model not found at %s - SPSD predictions will "
                "be unavailable until scripts/train_spsd.py is run. Falling "
                "back to fan-out heuristic only for this detector instance.",
                model_path,
            )

    @property
    def is_available(self) -> bool:
        return self.model is not None

    def predict(self, ev: NetworkEvent) -> Tuple[bool, float]:
        if self.model is None:
            return False, 0.0
        proba = float(self.model.predict_proba([ev.feature_vector()])[0][1])
        return proba >= 0.5, proba


# ----------------------------------------------------------------------
# UPSD - unsupervised sequential hypothesis testing (Wald SPRT)
# ----------------------------------------------------------------------
class UPSDDetector:
    """Sequential hypothesis testing per source IP (paper Algorithm 1).

    Defaults are the paper's ``UPSD (minFP)`` configuration, which
    minimizes false positives at some cost to detection latency.
    """

    def __init__(
        self,
        theta0: float = 0.8,
        theta1: float = 0.2,
        eta0: float = 0.001,
        eta1: float = 999.0,
    ):
        self.theta0 = theta0
        self.theta1 = theta1
        self.eta0 = eta0
        self.eta1 = eta1
        self.ratios: Dict[str, float] = {}

    def update(self, ev: NetworkEvent) -> Tuple[Optional[str], float]:
        ip = ev.src_ip
        ratio = self.ratios.get(ip, 1.0)
        alpha = ev.indicator_sum()  # icmp + neip + netcp
        if alpha > 0:
            ratio *= alpha * (1 - self.theta1) / (1 - self.theta0)
        else:
            ratio *= 1.0 * (self.theta1 / self.theta0)
        self.ratios[ip] = ratio

        if ratio > self.eta1:  # H1: scanner
            self.ratios[ip] = 1.0
            return "scanner", ratio
        if ratio < self.eta0:  # H0: normal
            self.ratios[ip] = 1.0
            return "normal", ratio
        return None, ratio  # undecided, keep watching

    def predict(self, ev: NetworkEvent) -> Tuple[bool, float]:
        """Adapter so UPSD exposes the same (fired, confidence) shape as
        SPSD. Confidence is the likelihood ratio normalized into (0, 1)
        against the scanner decision threshold ``eta1``."""
        verdict, ratio = self.update(ev)
        fired = verdict == "scanner"
        confidence = min(1.0, ratio / self.eta1) if self.eta1 > 0 else 0.0
        return fired, confidence


# ----------------------------------------------------------------------
# Combined decision: SPSD/UPSD + fan-out backstop
# ----------------------------------------------------------------------
@dataclass
class PortScanAlert:
    threat_type: str
    src_ip: str
    dst_ip: str
    confidence: float
    severity: str
    mitre: str
    evidence: Dict[str, int]
    scan_type: str
    window_start: float
    reason: str
    ml_flow_score: Optional[float] = None  # optional, non-driving, see §7


class PortScanDetector:
    def __init__(
        self,
        network_info: NetworkInfo,
        cfg: Optional[PortScanConfig] = None,
    ):
        self.cfg = cfg or PortScanConfig()
        self.builder = NetworkEventBuilder(network_info)
        self.mode = self.cfg.mode

        self.spsd: Optional[SPSDDetector] = None
        self.upsd: Optional[UPSDDetector] = None

        if self.mode == "spsd":
            self.spsd = SPSDDetector(self.cfg.model_path)
            if not self.spsd.is_available:
                logger.warning(
                    "PortScanDetector: mode=spsd requested but no trained "
                    "model found; auto-falling back to UPSD for this run."
                )
                self.upsd = UPSDDetector(**_upsd_kwargs(self.cfg.upsd_params))
        else:
            self.upsd = UPSDDetector(**_upsd_kwargs(self.cfg.upsd_params))

        self.fanout_threshold = self.cfg.fanout_threshold

    @classmethod
    def from_config(cls, cfg, network_info: NetworkInfo) -> "PortScanDetector":
        """Build from an attribute-style config object shaped like
        ``cfg.portscan.mode``, ``cfg.portscan.model_path``, etc. (matches
        the pseudocode in the implementation plan)."""
        pc = cfg.portscan
        upsd_params = getattr(pc, "upsd_params", {}) or {}
        psc = PortScanConfig(
            mode=getattr(pc, "mode", "spsd"),
            model_path=getattr(pc, "model_path", PortScanConfig.model_path),
            network_info_path=getattr(
                pc, "network_info_path", PortScanConfig.network_info_path
            ),
            fanout_threshold=getattr(pc, "fanout_threshold", 100),
            upsd_params=UPSDParams(**upsd_params) if upsd_params else UPSDParams(),
        )
        return cls(network_info=network_info, cfg=psc)

    # ------------------------------------------------------------------
    def process(self, flows: List[Flow]) -> List[PortScanAlert]:
        events = self.builder.build(flows)
        if not events:
            return []

        fanout_by_key = self._fanout_by_src_window(flows)
        scan_type_by_key = self._scan_type_by_src_window(flows)

        alerts: List[PortScanAlert] = []
        for ev in events:
            key = (ev.src_ip, ev.window_start)
            fanout = fanout_by_key.get(key, ev.distinct_dst_ports)
            fired, confidence, reason = self._decide(ev, fanout)
            if not fired:
                continue
            severity = self._severity(confidence, fanout)
            alerts.append(
                PortScanAlert(
                    threat_type="Port Scan",
                    src_ip=ev.src_ip,
                    dst_ip=ev.top_dst_ip or "multiple",
                    confidence=confidence,
                    severity=severity,
                    mitre=MITRE_PORT_SCAN,
                    evidence={
                        "neip": ev.neip_count,
                        "netcp": ev.netcp_count,
                        "rst": ev.rst_count,
                        "rwa": ev.rwa_count,
                        "icmp_error": ev.icmp_error_count,
                        "succession": ev.succession_count,
                        "distinct_ports": fanout,
                        "distinct_dst_ips": ev.distinct_dst_ips,
                    },
                    scan_type=scan_type_by_key.get(key, "vertical"),
                    window_start=ev.window_start,
                    reason=reason,
                )
            )
        return alerts

    # ------------------------------------------------------------------
    def _decide(self, ev: NetworkEvent, fanout: int) -> Tuple[bool, float, str]:
        fired = False
        confidence = 0.0
        reasons: List[str] = []

        if self.spsd is not None and self.spsd.is_available:
            fired, confidence = self.spsd.predict(ev)
            if fired:
                reasons.append(
                    f"neip={ev.neip_count}, netcp={ev.netcp_count}, "
                    f"succession={ev.succession_count}"
                )
        elif self.upsd is not None:
            fired, confidence = self.upsd.predict(ev)
            if fired:
                reasons.append(
                    f"UPSD likelihood ratio scanner verdict "
                    f"(neip={ev.neip_count}, netcp={ev.netcp_count}, "
                    f"icmp_error={ev.icmp_error_count})"
                )

        # Fan-out backstop: fires regardless of model confidence.
        if fanout >= self.fanout_threshold:
            fired = True
            confidence = max(confidence, 0.9)
            reasons.append(f"high fan-out ({fanout} distinct ports)")

        reason = "; ".join(reasons) if reasons else "no indicators"
        return fired, confidence, reason

    def _fanout_by_src_window(
        self, flows: List[Flow]
    ) -> Dict[Tuple[str, float], int]:
        buckets = self.builder._bucket_by_window(flows)
        result: Dict[Tuple[str, float], int] = {}
        for window_start, window_flows in buckets.items():
            per_src: Dict[str, set] = {}
            for f in window_flows:
                per_src.setdefault(f.src_ip, set()).add(f.dst_port)
            for src_ip, ports in per_src.items():
                result[(src_ip, window_start)] = len(ports)
        return result

    def _scan_type_by_src_window(
        self, flows: List[Flow]
    ) -> Dict[Tuple[str, float], str]:
        buckets = self.builder._bucket_by_window(flows)
        result: Dict[Tuple[str, float], str] = {}
        for window_start, window_flows in buckets.items():
            per_src_ports: Dict[str, set] = {}
            per_src_ips: Dict[str, set] = {}
            for f in window_flows:
                per_src_ports.setdefault(f.src_ip, set()).add(f.dst_port)
                per_src_ips.setdefault(f.src_ip, set()).add(f.dst_ip)
            for src_ip in per_src_ports:
                n_ports = len(per_src_ports[src_ip])
                n_ips = len(per_src_ips.get(src_ip, set()))
                if n_ips <= 1 and n_ports > 1:
                    result[(src_ip, window_start)] = "vertical"
                elif n_ports <= 1 and n_ips > 1:
                    result[(src_ip, window_start)] = "horizontal"
                elif n_ports > 1 and n_ips > 1:
                    result[(src_ip, window_start)] = "block"
                else:
                    result[(src_ip, window_start)] = "vertical"
        return result

    @staticmethod
    def _severity(confidence: float, fanout: int) -> str:
        if fanout >= 100:
            return "HIGH"
        if confidence >= 0.85:
            return "HIGH"
        if confidence >= 0.5:
            return "MEDIUM"
        return "LOW"


def _upsd_kwargs(params) -> Dict[str, float]:
    if isinstance(params, UPSDParams):
        return {
            "theta0": params.theta0,
            "theta1": params.theta1,
            "eta0": params.eta0,
            "eta1": params.eta1,
        }
    if isinstance(params, dict):
        defaults = UPSDParams()
        return {
            "theta0": params.get("theta0", defaults.theta0),
            "theta1": params.get("theta1", defaults.theta1),
            "eta0": params.get("eta0", defaults.eta0),
            "eta1": params.get("eta1", defaults.eta1),
        }
    defaults = UPSDParams()
    return {
        "theta0": defaults.theta0,
        "theta1": defaults.theta1,
        "eta0": defaults.eta0,
        "eta1": defaults.eta1,
    }
