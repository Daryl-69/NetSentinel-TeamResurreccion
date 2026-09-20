"""
netsentinel/extractor/network_event_builder.py

Network-event aggregation layer for port-scan detection.

Implements Ring, Landes & Hotho (2018), "Detection of slow port scans in
flow-based network traffic" (PLOS ONE, doi:10.1371/journal.pone.0204507).

Port scanning is a cross-flow phenomenon: CICFlowMeter turns every probe
into its own flow, so a single SYN to a single port is indistinguishable
from a benign unanswered connection at the per-flow level. This module
groups all flows from one source IP inside a fixed time window into a
single ``NetworkEvent`` behavioral vector, which IS discriminative.

This module MUST be the single source of truth for feature computation.
``scripts/train_spsd.py`` imports this exact module to build training
features, and ``netsentinel/models/portscan_detector.py`` imports it for
inference. Any divergence between train-time and inference-time feature
computation reintroduces the covariate shift bug that broke the original
per-flow model.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from netsentinel.netinfo.network_info import NetworkInfo

# ICMP type 3 = "Destination Unreachable". Codes commonly seen in response
# to a UDP port scan: 1 (host unreachable), 2 (protocol unreachable),
# 3 (port unreachable), 9/10 (admin prohibited), 13 (communication
# administratively prohibited).
ICMP_UNREACHABLE_TYPE = 3
ICMP_UNREACHABLE_CODES = {0, 1, 2, 3, 9, 10, 13}


@dataclass
class Flow:
    """Normalized, protocol-agnostic bidirectional flow record.

    This is the minimal shape ``NetworkEventBuilder`` needs. Adapt your
    real extractor's flow objects (e.g. the CICFlowMeter wrapper's flow
    dicts) into this shape with :func:`Flow.from_cic_record` (or your own
    adapter) before calling :meth:`NetworkEventBuilder.build`.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" | "UDP" | "ICMP"
    timestamp: float  # flow start, epoch seconds

    fwd_packets: int = 0
    bwd_packets: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    # Only meaningful when protocol == "ICMP".
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    @property
    def has_reply(self) -> bool:
        """Any traffic at all came back from dst -> src in this flow."""
        return self.bwd_packets > 0

    @property
    def is_established(self) -> bool:
        """Crude full-handshake heuristic: SYN+ACK observed and a reply
        arrived, i.e. this is a genuine open connection, not a closed-port
        RST or a firewalled drop."""
        return self.syn_count > 0 and self.ack_count > 0 and self.bwd_packets > 0

    @property
    def is_icmp_unreachable(self) -> bool:
        return (
            self.protocol.upper() == "ICMP"
            and self.icmp_type == ICMP_UNREACHABLE_TYPE
            and (self.icmp_code in ICMP_UNREACHABLE_CODES or self.icmp_code is None)
        )

    @classmethod
    def from_cic_record(cls, rec: dict) -> "Flow":
        """Adapt a CICFlowMeter-style flow dict into a :class:`Flow`.

        Accepts either the CIC CSV-style column names (``"Src IP"``,
        ``"Dst Port"``, ``"Protocol"``, ...) or the raw python-cicflowmeter
        API names (``src_ip``, ``dst_port``, ``protocol``, ...). Extend the
        key lookups here if your wrapper renames fields differently.
        """

        def pick(*keys, default=None):
            for k in keys:
                if k in rec and rec[k] is not None:
                    return rec[k]
            return default

        proto_raw = pick("Protocol", "protocol", default="TCP")
        proto = _normalize_protocol(proto_raw)

        return cls(
            src_ip=str(pick("Src IP", "src_ip", "srcip")),
            dst_ip=str(pick("Dst IP", "dst_ip", "dstip")),
            src_port=int(pick("Src Port", "src_port", "sport", default=0)),
            dst_port=int(pick("Dst Port", "dst_port", "dport", default=0)),
            protocol=proto,
            timestamp=float(pick("Timestamp", "timestamp", "ts", default=0.0)),
            fwd_packets=int(pick("Tot Fwd Pkts", "fwd_pkts", "fwd_packets", default=0)),
            bwd_packets=int(pick("Tot Bwd Pkts", "bwd_pkts", "bwd_packets", default=0)),
            syn_count=int(pick("SYN Flag Cnt", "syn_flag_cnt", "syn_count", default=0)),
            ack_count=int(pick("ACK Flag Cnt", "ack_flag_cnt", "ack_count", default=0)),
            rst_count=int(pick("RST Flag Cnt", "rst_flag_cnt", "rst_count", default=0)),
            fin_count=int(pick("FIN Flag Cnt", "fin_flag_cnt", "fin_count", default=0)),
            icmp_type=pick("icmp_type"),
            icmp_code=pick("icmp_code"),
        )


def _normalize_protocol(raw) -> str:
    mapping = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    s = str(raw).strip().upper()
    return mapping.get(s, s)


@dataclass
class NetworkEvent:
    """One (src_ip, time-window) behavioral aggregate."""

    src_ip: str
    window_start: float  # epoch seconds
    icmp_error_count: int = 0  # UDP-scan indicator
    rst_count: int = 0  # closed-TCP-port indicator
    rwa_count: int = 0  # request-without-answer (firewalled) indicator
    neip_count: int = 0  # flows to non-existent internal IPs
    netcp_count: int = 0  # flows to non-open ports on existing internal hosts
    succession_count: int = 0  # consecutive windows this IP looked suspicious

    # Auxiliary, not part of the SPSD feature vector: useful for the
    # fan-out backstop and for alert evidence/scan_type classification.
    distinct_dst_ports: int = 0
    distinct_dst_ips: int = 0
    top_dst_ip: Optional[str] = None

    def indicator_sum(self) -> int:
        """UPSD uses only these three; RST/RwA are noisy for normal traffic."""
        return self.icmp_error_count + self.neip_count + self.netcp_count

    def feature_vector(self) -> List[float]:
        """Order MUST match SPSD training. IP is excluded."""
        return [
            float(self.icmp_error_count),
            float(self.rst_count),
            float(self.rwa_count),
            float(self.neip_count),
            float(self.netcp_count),
            float(self.succession_count),
        ]

    FEATURE_NAMES = (
        "icmp_error_count",
        "rst_count",
        "rwa_count",
        "neip_count",
        "netcp_count",
        "succession_count",
    )


class NetworkEventBuilder:
    """Groups flows into fixed windows and computes one NetworkEvent per
    (src_ip, window)."""

    def __init__(self, network_info: NetworkInfo):
        self.ni = network_info
        self.window = network_info.time_window_seconds or 60
        # src_ip -> running succession count, carried across build() calls
        # so that live/streaming batches accumulate correctly.
        self._succession: Dict[str, int] = {}

    def reset(self) -> None:
        """Clear cross-window succession state (e.g. between test cases or
        PCAP replays that should be treated independently)."""
        self._succession.clear()

    # ------------------------------------------------------------------
    def build(self, flows: Iterable[Flow]) -> List[NetworkEvent]:
        flows = list(flows)
        if not flows:
            return []

        windows = self._bucket_by_window(flows)
        events: List[NetworkEvent] = []

        for window_start in sorted(windows.keys()):
            window_flows = windows[window_start]
            candidate_ips = {
                f.src_ip for f in window_flows if f.src_ip and f.protocol != "ICMP"
            }
            # Also allow src IPs that appear only in ICMP-error-eliciting UDP
            # flows initiated by them.
            candidate_ips |= {
                f.src_ip for f in window_flows if f.protocol.upper() == "UDP"
            }

            for src_ip in sorted(candidate_ips):
                events.append(
                    self._build_event_for_src(src_ip, window_start, window_flows)
                )

        return events

    # ------------------------------------------------------------------
    def _bucket_by_window(self, flows: List[Flow]) -> Dict[float, List[Flow]]:
        buckets: Dict[float, List[Flow]] = {}
        for f in flows:
            window_start = math.floor(f.timestamp / self.window) * self.window
            buckets.setdefault(window_start, []).append(f)
        return buckets

    # ------------------------------------------------------------------
    def _build_event_for_src(
        self, src_ip: str, window_start: float, window_flows: List[Flow]
    ) -> NetworkEvent:
        ni = self.ni

        outgoing = [f for f in window_flows if f.src_ip == src_ip]
        incoming = [f for f in window_flows if f.dst_ip == src_ip]

        # 1. icmp_error_count: ICMP-unreachable messages received by src_ip.
        icmp_error_count = sum(1 for f in incoming if f.is_icmp_unreachable)

        # 2. rst_count: distinct (dst_ip, dst_port) targets that RST'd this
        #    src, where a SYN was sent and no established connection exists.
        rst_targets = set()
        for f in outgoing:
            if (
                f.protocol.upper() == "TCP"
                and f.syn_count > 0
                and f.rst_count > 0
                and not f.is_established
            ):
                rst_targets.add((f.dst_ip, f.dst_port))
        rst_count = len(rst_targets)

        # 3. rwa_count: distinct targets with a unidirectional flow (no
        #    reverse traffic at all in the window), excluding multicast/
        #    broadcast destinations, and excluding targets already counted
        #    as an RST response (those did get a reply).
        rwa_targets = set()
        for f in outgoing:
            if f.dst_ip in {t[0] for t in rst_targets} and f.dst_port in {
                t[1] for t in rst_targets if t[0] == f.dst_ip
            }:
                continue
            if ni.is_multicast_or_broadcast(f.dst_ip):
                continue
            if not f.has_reply:
                rwa_targets.add((f.dst_ip, f.dst_port))
        rwa_count = len(rwa_targets)

        # 4. neip_count: distinct internal destination IPs that do not exist.
        neip_ips = {
            f.dst_ip
            for f in outgoing
            if ni.is_internal(f.dst_ip) and not ni.host_exists(f.dst_ip)
        }
        neip_count = len(neip_ips)

        # 5. netcp_count: distinct (dst_ip, dst_port) targets on an existing
        #    internal host, on a port not documented as open.
        netcp_targets = {
            (f.dst_ip, f.dst_port)
            for f in outgoing
            if f.protocol.upper() in ("TCP", "UDP")
            and ni.is_internal(f.dst_ip)
            and ni.host_exists(f.dst_ip)
            and not ni.is_known_open(f.dst_ip, f.dst_port)
        }
        netcp_count = len(netcp_targets)

        # 6. succession_count: cross-window state machine (slow-scan signal).
        alpha = icmp_error_count + rst_count + rwa_count + neip_count + netcp_count
        prev = self._succession.get(src_ip, 0)
        if alpha == 0:
            succession_count = 0
            self._succession[src_ip] = 0
        else:
            succession_count = prev + 1
            self._succession[src_ip] = succession_count

        # Auxiliary fields for fan-out backstop / scan_type / evidence.
        distinct_dst_ports = len({f.dst_port for f in outgoing})
        distinct_dst_ips = len({f.dst_ip for f in outgoing})
        top_dst_ip = _most_common_dst(outgoing)

        return NetworkEvent(
            src_ip=src_ip,
            window_start=window_start,
            icmp_error_count=icmp_error_count,
            rst_count=rst_count,
            rwa_count=rwa_count,
            neip_count=neip_count,
            netcp_count=netcp_count,
            succession_count=succession_count,
            distinct_dst_ports=distinct_dst_ports,
            distinct_dst_ips=distinct_dst_ips,
            top_dst_ip=top_dst_ip,
        )


def _most_common_dst(outgoing: List[Flow]) -> Optional[str]:
    if not outgoing:
        return None
    counts: Dict[str, int] = {}
    for f in outgoing:
        counts[f.dst_ip] = counts.get(f.dst_ip, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]
