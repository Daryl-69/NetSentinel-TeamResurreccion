"""Flow Extractor — Reconstructs bidirectional flows from raw packets.

Computes two feature sets from accumulated per-flow state:
  1. 59 CIC-IDS2019 features → DDoS XGBoost model
  2. 29 ETT features → Encrypted Traffic Transformer

Design inspired by CICFlowMeter (hieulw/cicflowmeter) but purpose-built
for our exact model schemas. Uses Scapy packet objects as input.

Flow lifecycle:
  - Created on first packet matching a new 5-tuple
  - Updated on each subsequent packet (fwd/bwd stats, flags, IATs)
  - Completed when: TCP FIN/RST seen, idle timeout, or active timeout
  - On completion: features computed and returned as event dict
"""
import math
import time
import logging
from dataclasses import dataclass, field
from collections import Counter
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# TCP flag bitmasks
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80

# CIC-IDS activity threshold: if IAT > this, switch from active→idle
ACTIVITY_THRESHOLD = 5_000_000  # 5 seconds in microseconds


@dataclass
class PacketInfo:
    """Minimal per-packet record used during flow accumulation."""
    timestamp: float       # epoch seconds (high precision)
    size: int              # payload length in bytes
    header_size: int       # L4 header length
    flags: int = 0         # TCP flags (0 for UDP)
    window: int = 0        # TCP window size (0 for UDP)


@dataclass
class FlowState:
    """Accumulates per-flow statistics from individual packets.

    The 5-tuple key is (src_ip, dst_ip, src_port, dst_port, protocol).
    'Forward' = same direction as the first packet seen.
    'Backward' = reverse direction.
    """
    key: tuple                                    # 5-tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int                                 # 6=TCP, 17=UDP
    start_time: float = 0.0
    last_seen: float = 0.0
    fwd_packets: list = field(default_factory=list)   # list[PacketInfo]
    bwd_packets: list = field(default_factory=list)   # list[PacketInfo]
    init_fwd_win: int = -1                        # first fwd TCP window
    init_bwd_win: int = -1                        # first bwd TCP window
    fwd_psh_count: int = 0
    fwd_urg_count: int = 0
    fin_seen: bool = False
    rst_seen: bool = False

    # Active/idle period tracking
    _last_active_start: float = 0.0
    _last_packet_time: float = 0.0
    active_periods: list = field(default_factory=list)   # durations in µs
    idle_periods: list = field(default_factory=list)


class FlowExtractor:
    """Reconstructs bidirectional network flows from packets.

    Usage:
        extractor = FlowExtractor()
        for packet in packets:
            event = extractor.process_packet(packet)
            if event:
                # event is a completed flow dict ready for analyzer
                analyzer.analyze_flow(event)

        # At end, flush remaining flows
        for event in extractor.flush_all():
            analyzer.analyze_flow(event)
    """

    def __init__(self, idle_timeout: float = 120.0, active_timeout: float = 300.0):
        """
        Args:
            idle_timeout: Seconds of inactivity before a flow is flushed.
            active_timeout: Max seconds a flow can stay open regardless.
        """
        self.active_flows: dict[tuple, FlowState] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._completed_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> Optional[dict]:
        """Process a single Scapy packet. Returns completed flow event or None.

        Args:
            packet: A Scapy packet object (must have IP layer).

        Returns:
            Flow event dict (type="flow") if the flow completed, else None.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            logger.error("Scapy not installed — cannot extract flows")
            return None

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        proto = ip.proto

        # Only handle TCP (6) and UDP (17)
        if proto == 6 and packet.haslayer(TCP):
            transport = packet[TCP]
            src_port = transport.sport
            dst_port = transport.dport
            flags = int(transport.flags)
            window = transport.window
            header_size = transport.dataofs * 4 if transport.dataofs else 20
        elif proto == 17 and packet.haslayer(UDP):
            transport = packet[UDP]
            src_port = transport.sport
            dst_port = transport.dport
            flags = 0
            window = 0
            header_size = 8
        else:
            return None

        src_ip = ip.src
        dst_ip = ip.dst
        ts = float(packet.time)
        # Get payload size (transport layer payload, not including IP header)
        payload_size = len(ip.payload) if hasattr(ip, 'payload') else (ip.len - (ip.ihl * 4))

        # Build 5-tuple keys (forward and reverse)
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        # Determine if this is a forward or backward packet
        pkt_info = PacketInfo(
            timestamp=ts,
            size=max(payload_size, 0),
            header_size=header_size,
            flags=flags,
            window=window,
        )

        is_forward = True
        flow = self.active_flows.get(fwd_key)
        if flow is None:
            flow = self.active_flows.get(bwd_key)
            if flow is not None:
                is_forward = False
            else:
                # New flow — create it
                flow = FlowState(
                    key=fwd_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    start_time=ts,
                    last_seen=ts,
                    _last_active_start=ts,
                    _last_packet_time=ts,
                )
                self.active_flows[fwd_key] = flow

        # Update active/idle periods
        self._update_activity(flow, ts)

        # Add packet to appropriate direction
        if is_forward:
            flow.fwd_packets.append(pkt_info)
            if flow.init_fwd_win == -1 and proto == 6:
                flow.init_fwd_win = window
            if flags & FLAG_PSH:
                flow.fwd_psh_count += 1
            if flags & FLAG_URG:
                flow.fwd_urg_count += 1
        else:
            flow.bwd_packets.append(pkt_info)
            if flow.init_bwd_win == -1 and proto == 6:
                flow.init_bwd_win = window

        flow.last_seen = ts

        # Check termination conditions
        if proto == 6:
            if flags & FLAG_FIN:
                flow.fin_seen = True
            if flags & FLAG_RST:
                flow.rst_seen = True

        # Complete flow if TCP FIN/RST or active timeout exceeded
        if flow.fin_seen or flow.rst_seen:
            return self._complete_flow(flow)
        if (ts - flow.start_time) > self.active_timeout:
            return self._complete_flow(flow)

        return None

    def flush_expired(self, current_time: float = None) -> list[dict]:
        """Flush flows that have exceeded idle timeout.

        Call this periodically (e.g., every 10s) to emit idle flows.
        """
        if current_time is None:
            current_time = time.time()

        expired = []
        to_remove = []
        for key, flow in self.active_flows.items():
            if (current_time - flow.last_seen) > self.idle_timeout:
                to_remove.append(key)

        for key in to_remove:
            flow = self.active_flows.pop(key)
            event = self._build_event(flow)
            if event:
                expired.append(event)

        return expired

    def flush_all(self) -> list[dict]:
        """Flush all remaining active flows. Call at end of PCAP processing."""
        events = []
        for flow in list(self.active_flows.values()):
            event = self._build_event(flow)
            if event:
                events.append(event)
        self.active_flows.clear()
        return events

    @property
    def stats(self) -> dict:
        return {
            "active_flows": len(self.active_flows),
            "completed_flows": self._completed_count,
        }

    # ------------------------------------------------------------------
    # Internal — Flow completion
    # ------------------------------------------------------------------

    def _complete_flow(self, flow: FlowState) -> Optional[dict]:
        """Remove flow from active tracking and build event dict."""
        self.active_flows.pop(flow.key, None)
        return self._build_event(flow)

    def _build_event(self, flow: FlowState) -> Optional[dict]:
        """Build the event dict with all features from a completed flow."""
        # Skip flows with too few packets (noise)
        total_pkts = len(flow.fwd_packets) + len(flow.bwd_packets)
        if total_pkts < 2:
            return None

        self._completed_count += 1

        # Compute both feature sets
        cic_features = self._compute_cic_features(flow)
        ett_features = self._compute_ett_features(flow)

        # Merge into single features dict
        features = {**cic_features, **ett_features}

        return {
            "type": "flow",
            "source_ip": flow.src_ip,
            "dest_ip": flow.dst_ip,
            "source_port": flow.src_port,
            "dest_port": flow.dst_port,
            "protocol": flow.protocol,
            "features": features,
        }

    # ------------------------------------------------------------------
    # Internal — activity tracking
    # ------------------------------------------------------------------

    def _update_activity(self, flow: FlowState, ts: float):
        """Track active vs idle periods using CICFlowMeter algorithm.

        If the gap between packets > ACTIVITY_THRESHOLD:
          - Close current active period, record its duration
          - Record the idle gap duration
          - Start a new active period
        """
        if flow._last_packet_time == 0:
            flow._last_packet_time = ts
            flow._last_active_start = ts
            return

        gap_us = (ts - flow._last_packet_time) * 1_000_000  # to µs

        if gap_us > ACTIVITY_THRESHOLD:
            # Close active period
            active_dur = (flow._last_packet_time - flow._last_active_start) * 1_000_000
            if active_dur > 0:
                flow.active_periods.append(active_dur)
            # Record idle period
            flow.idle_periods.append(gap_us)
            # Start new active period
            flow._last_active_start = ts

        flow._last_packet_time = ts

    # ------------------------------------------------------------------
    # CIC-IDS2019 Feature Computation (59 features)
    # ------------------------------------------------------------------

    def _compute_cic_features(self, flow: FlowState) -> dict:
        """Compute the exact 59 features the DDoS XGBoost model expects.

        Feature names match feature_names.json from training.
        """
        fwd = flow.fwd_packets
        bwd = flow.bwd_packets

        # Packet sizes
        fwd_sizes = [p.size for p in fwd]
        bwd_sizes = [p.size for p in bwd]
        all_sizes = fwd_sizes + bwd_sizes

        # Timestamps
        fwd_times = [p.timestamp for p in fwd]
        bwd_times = [p.timestamp for p in bwd]
        all_times = sorted(fwd_times + bwd_times)

        # Duration in microseconds (CIC format)
        duration_us = (flow.last_seen - flow.start_time) * 1_000_000
        # Use at least 1 microsecond floor to avoid ÷0 and astronomical rates
        # for single-packet / very-short flows (CIC also clamps at ~1µs)
        duration_s = max(flow.last_seen - flow.start_time, 1e-6)

        # Inter-arrival times
        flow_iats = _compute_iats(all_times)      # whole flow
        fwd_iats = _compute_iats(fwd_times)
        bwd_iats = _compute_iats(bwd_times)

        # Convert IATs to microseconds (CIC convention)
        flow_iats_us = [i * 1_000_000 for i in flow_iats]
        fwd_iats_us = [i * 1_000_000 for i in fwd_iats]
        bwd_iats_us = [i * 1_000_000 for i in bwd_iats]

        # TCP flag counts — CICFlowMeter stores these as BINARY per flow
        # (0 = no packet had the flag, 1 = at least one packet had the flag)
        # NOT a count of how many packets had the flag.
        all_flags = [p.flags for p in fwd] + [p.flags for p in bwd]
        syn_count  = 1 if any(f & FLAG_SYN for f in all_flags) else 0
        rst_count  = 1 if any(f & FLAG_RST for f in all_flags) else 0
        ack_count  = 1 if any(f & FLAG_ACK for f in all_flags) else 0
        urg_count  = 1 if any(f & FLAG_URG for f in all_flags) else 0
        cwe_count  = 1 if any(f & FLAG_CWR for f in all_flags) else 0

        # Header lengths
        fwd_header_total = sum(p.header_size for p in fwd)
        bwd_header_total = sum(p.header_size for p in bwd)

        # Totals
        total_fwd = len(fwd)
        total_bwd = len(bwd)
        total_pkts = total_fwd + total_bwd
        fwd_bytes = sum(fwd_sizes)
        bwd_bytes = sum(bwd_sizes)
        total_bytes = fwd_bytes + bwd_bytes

        # Down/Up ratio
        down_up = total_bwd / max(total_fwd, 1)

        # Subflow (same as totals for single-subflow)
        sub_fwd_pkts = total_fwd
        sub_fwd_bytes = fwd_bytes
        sub_bwd_pkts = total_bwd
        sub_bwd_bytes = bwd_bytes

        # Active/Idle stats
        # Close the last active period
        if flow._last_packet_time > flow._last_active_start:
            final_active = (flow._last_packet_time - flow._last_active_start) * 1_000_000
            if final_active > 0:
                flow.active_periods.append(final_active)

        active = flow.active_periods if flow.active_periods else [0.0]
        idle = flow.idle_periods if flow.idle_periods else [0.0]

        # Fwd act data packets (packets with payload > 0)
        fwd_act_data = sum(1 for p in fwd if p.size > 0)

        # Fwd seg size min
        fwd_seg_min = min(fwd_sizes) if fwd_sizes else 0

        return {
            # The exact 59 features in order from feature_names.json
            "Protocol": flow.protocol,
            "Flow Duration": duration_us,
            "Total Fwd Packets": total_fwd,
            "Total Backward Packets": total_bwd,
            "Fwd Packets Length Total": fwd_bytes,
            "Bwd Packets Length Total": bwd_bytes,
            "Fwd Packet Length Max": max(fwd_sizes) if fwd_sizes else 0,
            "Fwd Packet Length Min": min(fwd_sizes) if fwd_sizes else 0,
            "Fwd Packet Length Mean": _mean(fwd_sizes),
            "Fwd Packet Length Std": _std(fwd_sizes),
            "Bwd Packet Length Max": max(bwd_sizes) if bwd_sizes else 0,
            "Bwd Packet Length Min": min(bwd_sizes) if bwd_sizes else 0,
            "Bwd Packet Length Mean": _mean(bwd_sizes),
            "Bwd Packet Length Std": _std(bwd_sizes),
            "Flow Bytes/s": total_bytes / duration_s,
            "Flow Packets/s": total_pkts / duration_s,
            "Flow IAT Mean": _mean(flow_iats_us),
            "Flow IAT Std": _std(flow_iats_us),
            "Flow IAT Max": max(flow_iats_us) if flow_iats_us else 0,
            "Flow IAT Min": min(flow_iats_us) if flow_iats_us else 0,
            "Fwd IAT Mean": _mean(fwd_iats_us),
            "Bwd IAT Total": sum(bwd_iats_us),
            "Bwd IAT Mean": _mean(bwd_iats_us),
            "Bwd IAT Std": _std(bwd_iats_us),
            "Bwd IAT Max": max(bwd_iats_us) if bwd_iats_us else 0,
            "Bwd IAT Min": min(bwd_iats_us) if bwd_iats_us else 0,
            # Fwd/Bwd PSH Flags — binary per flow (CICFlowMeter definition)
            "Fwd PSH Flags": 1 if flow.fwd_psh_count > 0 else 0,
            "Bwd PSH Flags": 1 if any(p.flags & FLAG_PSH for p in bwd) else 0,
            "Fwd Header Length": fwd_header_total,
            "Bwd Header Length": bwd_header_total,
            "Bwd Packets/s": total_bwd / duration_s,
            "Packet Length Max": max(all_sizes) if all_sizes else 0,
            "Packet Length Mean": _mean(all_sizes),
            "Packet Length Std": _std(all_sizes),
            "Packet Length Variance": _var(all_sizes),
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": urg_count,
            "CWE Flag Count": cwe_count,
            "Down/Up Ratio": down_up,
            "Avg Packet Size": _mean(all_sizes),
            "Avg Fwd Segment Size": _mean(fwd_sizes),
            "Avg Bwd Segment Size": _mean(bwd_sizes),
            "Subflow Fwd Packets": sub_fwd_pkts,
            "Subflow Fwd Bytes": sub_fwd_bytes,
            "Subflow Bwd Packets": sub_bwd_pkts,
            "Subflow Bwd Bytes": sub_bwd_bytes,
            "Init Fwd Win Bytes": flow.init_fwd_win if flow.init_fwd_win >= 0 else 0,
            "Init Bwd Win Bytes": flow.init_bwd_win if flow.init_bwd_win >= 0 else 0,
            "Fwd Act Data Packets": fwd_act_data,
            "Fwd Seg Size Min": fwd_seg_min,
            "Active Mean": _mean(active),
            "Active Std": _std(active),
            "Active Max": max(active),
            "Active Min": min(active),
            "Idle Mean": _mean(idle),
            "Idle Std": _std(idle),
            "Idle Max": max(idle),
            "Idle Min": min(idle),
        }

    # ------------------------------------------------------------------
    # ETT Feature Computation (29 features)
    # ------------------------------------------------------------------

    def _compute_ett_features(self, flow: FlowState) -> dict:
        """Compute the 29 features the Encrypted Traffic Transformer expects.

        Feature names match ett_scaler.json from training.
        These are ISCX-VPN-NonVPN style flow features.
        """
        fwd = flow.fwd_packets
        bwd = flow.bwd_packets

        fwd_times = [p.timestamp for p in fwd]
        bwd_times = [p.timestamp for p in bwd]
        all_times = sorted(fwd_times + bwd_times)

        # Duration in microseconds
        duration_us = (flow.last_seen - flow.start_time) * 1_000_000
        duration_s = max(flow.last_seen - flow.start_time, 1e-9)

        # Forward inter-arrival times (in µs)
        fwd_iats = _compute_iats(fwd_times)
        bwd_iats = _compute_iats(bwd_times)
        flow_iats = _compute_iats(all_times)

        fwd_iats_us = [i * 1_000_000 for i in fwd_iats]
        bwd_iats_us = [i * 1_000_000 for i in bwd_iats]
        flow_iats_us = [i * 1_000_000 for i in flow_iats]

        total_fwd = len(fwd)
        total_bwd = len(bwd)
        total_pkts = total_fwd + total_bwd
        fwd_bytes = sum(p.size for p in fwd)
        bwd_bytes = sum(p.size for p in bwd)
        total_bytes = fwd_bytes + bwd_bytes

        # Active/idle (already computed, reuse)
        active = flow.active_periods if flow.active_periods else [0.0]
        idle = flow.idle_periods if flow.idle_periods else [0.0]

        # Derived features
        fwd_bwd_ratio = total_fwd / max(total_bwd, 1)

        flow_iat_mean = _mean(flow_iats_us)
        flow_iat_std = _std(flow_iats_us)
        iat_cv = flow_iat_std / max(flow_iat_mean, 1e-9)

        flow_iat_max = max(flow_iats_us) if flow_iats_us else 0
        flow_iat_min = min(flow_iats_us) if flow_iats_us else 0
        iat_range = flow_iat_max - flow_iat_min
        iat_range_norm = iat_range / max(flow_iat_mean, 1e-9)

        active_total = sum(active)
        idle_total = sum(idle)
        active_idle_ratio = active_total / max(idle_total, 1e-9)

        duration_log = math.log1p(duration_us) if duration_us > 0 else 0.0
        bytes_per_packet = total_bytes / max(total_pkts, 1)

        return {
            "duration": duration_us,
            "total_fiat": sum(fwd_iats_us),
            "total_biat": sum(bwd_iats_us),
            "min_fiat": min(fwd_iats_us) if fwd_iats_us else 0,
            "min_biat": min(bwd_iats_us) if bwd_iats_us else 0,
            "max_fiat": max(fwd_iats_us) if fwd_iats_us else 0,
            "max_biat": max(bwd_iats_us) if bwd_iats_us else 0,
            "mean_fiat": _mean(fwd_iats_us),
            "mean_biat": _mean(bwd_iats_us),
            "flowPktsPerSecond": total_pkts / duration_s,
            "flowBytesPerSecond": total_bytes / duration_s,
            "min_flowiat": flow_iat_min,
            "max_flowiat": flow_iat_max,
            "mean_flowiat": flow_iat_mean,
            "std_flowiat": flow_iat_std,
            "min_active": min(active),
            "mean_active": _mean(active),
            "max_active": max(active),
            "std_active": _std(active),
            "min_idle": min(idle),
            "mean_idle": _mean(idle),
            "max_idle": max(idle),
            "std_idle": _std(idle),
            "fwd_bwd_ratio": fwd_bwd_ratio,
            "iat_cv": iat_cv,
            "iat_range_norm": iat_range_norm,
            "active_idle_ratio": active_idle_ratio,
            "duration_log": duration_log,
            "bytes_per_packet": bytes_per_packet,
        }


# ======================================================================
# Utility functions (module-level for reuse)
# ======================================================================

def _compute_iats(timestamps: list[float]) -> list[float]:
    """Compute inter-arrival times from sorted timestamps (in seconds)."""
    if len(timestamps) < 2:
        return []
    ts_sorted = sorted(timestamps)
    return [ts_sorted[i] - ts_sorted[i - 1] for i in range(1, len(ts_sorted))]


def _mean(values: list) -> float:
    """Safe mean of a list."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list) -> float:
    """Population standard deviation."""
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _var(values: list) -> float:
    """Population variance."""
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return sum((x - m) ** 2 for x in values) / len(values)
