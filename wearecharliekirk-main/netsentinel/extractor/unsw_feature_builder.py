"""UNSW-NB15 Feature Builder — Computes the 39 features for Port Scan detection.

The port_scan_xgboost model was trained on UNSW-NB15 features, which are
fundamentally different from CIC-IDS2019 features. This module:

  1. Maps per-flow data (from FlowState) to UNSW per-flow features
  2. Maintains a sliding window of recent connections to compute
     the UNSW connection-tracking aggregates (ct_srv_src, ct_dst_ltm, etc.)

The sliding window tracks the last 100 connections and answers questions like
"how many connections to the same service from this source in the last 100?"

Feature names match port_scan_features.json exactly (minus 'id').
"""
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# Maximum number of recent connections to track for ct_* features
CT_WINDOW_SIZE = 100


@dataclass
class ConnectionRecord:
    """Minimal record of a completed connection for ct_* aggregation."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int          # 6=TCP, 17=UDP
    service: str           # Derived from dst_port (e.g., "http", "dns", "ssh")
    state: str             # Simplified connection state (e.g., "FIN", "CON", "REQ")
    ttl: int               # Source TTL (sttl)


# Common port → service mapping (UNSW-NB15 convention)
_PORT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "ssl", 993: "ssl", 995: "ssl",
    3306: "mysql", 5432: "postgres", 8080: "http",
    3389: "rdp", 445: "smb", 139: "smb",
}


def _port_to_service(port: int, protocol: int) -> str:
    """Map destination port to UNSW-NB15 service label."""
    if port in _PORT_SERVICE_MAP:
        return _PORT_SERVICE_MAP[port]
    if protocol == 17:
        return "dns" if port == 53 else "other-udp"
    return "other"


class ConnectionTracker:
    """Sliding window tracker for UNSW-NB15 connection-tracking features.

    Maintains a deque of the last CT_WINDOW_SIZE connection records and
    provides efficient lookups for the ct_* aggregate features.
    """

    def __init__(self, window_size: int = CT_WINDOW_SIZE):
        self._window: deque[ConnectionRecord] = deque(maxlen=window_size)

    def record(self, conn: ConnectionRecord):
        """Add a completed connection to the window."""
        self._window.append(conn)

    def ct_srv_src(self, service: str, src_ip: str) -> int:
        """# connections with same service AND same src_ip in window."""
        return sum(1 for c in self._window
                   if c.service == service and c.src_ip == src_ip)

    def ct_srv_dst(self, service: str, dst_ip: str) -> int:
        """# connections with same service AND same dst_ip in window."""
        return sum(1 for c in self._window
                   if c.service == service and c.dst_ip == dst_ip)

    def ct_dst_ltm(self, dst_ip: str) -> int:
        """# connections to same dst_ip in window."""
        return sum(1 for c in self._window if c.dst_ip == dst_ip)

    def ct_src_ltm(self, src_ip: str) -> int:
        """# connections from same src_ip in window."""
        return sum(1 for c in self._window if c.src_ip == src_ip)

    def ct_src_dport_ltm(self, src_ip: str, dst_port: int) -> int:
        """# connections from same src_ip to same dst_port in window."""
        return sum(1 for c in self._window
                   if c.src_ip == src_ip and c.dst_port == dst_port)

    def ct_dst_sport_ltm(self, dst_ip: str, src_port: int) -> int:
        """# connections to same dst_ip from same src_port in window."""
        return sum(1 for c in self._window
                   if c.dst_ip == dst_ip and c.src_port == src_port)

    def ct_dst_src_ltm(self, dst_ip: str, src_ip: str) -> int:
        """# connections between same src_ip and dst_ip pair in window."""
        return sum(1 for c in self._window
                   if c.dst_ip == dst_ip and c.src_ip == src_ip)

    def ct_state_ttl(self, state: str, ttl_bucket: int) -> int:
        """# connections with same state AND same TTL bucket in window.

        TTL bucket: UNSW uses coarse bins (0-32, 32-64, 64-128, 128-255).
        """
        return sum(1 for c in self._window
                   if c.state == state and _ttl_bucket(c.ttl) == ttl_bucket)

    def ct_flw_http_mthd(self) -> int:
        """# connections using HTTP methods (simplified: count http service)."""
        return sum(1 for c in self._window if c.service == "http")

    def ct_ftp_cmd(self) -> int:
        """# connections using FTP commands (simplified: count ftp service)."""
        return sum(1 for c in self._window
                   if c.service in ("ftp", "ftp-data"))


def _ttl_bucket(ttl: int) -> int:
    """Coarse TTL bucket matching UNSW-NB15 convention."""
    if ttl <= 32:
        return 0
    elif ttl <= 64:
        return 1
    elif ttl <= 128:
        return 2
    else:
        return 3


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    """Safe division with fallback."""
    return a / b if b > 0 else default


def _jitter(iats: list[float]) -> float:
    """Compute jitter (mean absolute deviation of inter-arrival times)."""
    if len(iats) < 2:
        return 0.0
    mean_iat = sum(iats) / len(iats)
    return sum(abs(iat - mean_iat) for iat in iats) / len(iats)


def build_unsw_features(
    flow_event: dict,
    tracker: ConnectionTracker,
) -> Optional[dict]:
    """Build the 39 UNSW-NB15 features from a completed flow event.

    Args:
        flow_event: Event dict from FlowExtractor._build_event() with
                    type="flow", source_ip, dest_ip, source_port, dest_port,
                    protocol, and features dict.
        tracker: ConnectionTracker instance for ct_* aggregation.

    Returns:
        Dictionary with the 39 feature names matching port_scan_features.json,
        or None if the event doesn't have enough data.
    """
    features = flow_event.get("features", {})
    if not features:
        return None

    src_ip = flow_event.get("source_ip", "0.0.0.0")
    dst_ip = flow_event.get("dest_ip", "0.0.0.0")
    src_port = flow_event.get("source_port", 0)
    dst_port = flow_event.get("dest_port", 0)
    protocol = flow_event.get("protocol", 6)

    # --- Per-flow features (mapped from CIC-IDS features) ---

    # Duration in seconds (CIC stores in microseconds)
    duration_us = features.get("Flow Duration", 0)
    duration_s = duration_us / 1_000_000 if duration_us > 0 else 0.001

    src_pkts = features.get("Total Fwd Packets", 0)
    dst_pkts = features.get("Total Backward Packets", 0)
    src_bytes = features.get("Fwd Packets Length Total", 0)
    dst_bytes = features.get("Bwd Packets Length Total", 0)
    total_pkts = src_pkts + dst_pkts

    # Rate: packets per second
    rate = _safe_div(total_pkts, duration_s)

    # TTL defaults (we approximate from typical OS values since scapy
    # FlowState doesn't store TTL; 64 is Linux/macOS, 128 is Windows)
    sttl = 64
    dttl = 128

    # Load: bits per second in each direction
    sload = _safe_div(src_bytes * 8, duration_s)
    dload = _safe_div(dst_bytes * 8, duration_s)

    # Packet loss (approximated from retransmissions — use 0 since we
    # can't reliably detect retransmissions without TCP seq tracking)
    sloss = 0
    dloss = 0

    # Inter-packet arrival time (seconds)
    # Use the CIC IAT features (stored in microseconds) converted to seconds
    fwd_iat_mean_us = features.get("Fwd IAT Mean", 0)
    bwd_iat_mean_us = features.get("Bwd IAT Mean", 0)
    sinpkt = fwd_iat_mean_us / 1_000_000 if fwd_iat_mean_us > 0 else 0
    dinpkt = bwd_iat_mean_us / 1_000_000 if bwd_iat_mean_us > 0 else 0

    # Jitter (use IAT std as approximation — stored in microseconds)
    fwd_iat_std_us = features.get("Fwd Packet Length Std", 0)  # Not exact, use flow IAT
    bwd_iat_std_us = features.get("Bwd IAT Std", 0)
    # Better: compute from flow-level IAT std
    flow_iat_std = features.get("Flow IAT Std", 0) / 1_000_000
    sjit = flow_iat_std  # approximation
    djit = bwd_iat_std_us / 1_000_000 if bwd_iat_std_us > 0 else 0

    # TCP-specific features
    swin = features.get("Init Fwd Win Bytes", 0)
    dwin = features.get("Init Bwd Win Bytes", 0)
    stcpb = 0  # TCP base sequence number — not tracked in FlowState
    dtcpb = 0

    # TCP RTT and handshake timings (not precisely available from FlowState)
    tcprtt = 0.0
    synack = 0.0
    ackdat = 0.0

    # Mean packet sizes
    smean = _safe_div(src_bytes, src_pkts)
    dmean = _safe_div(dst_bytes, dst_pkts)

    # HTTP-specific (simplified)
    trans_depth = 0  # transaction depth — HTTP pipelining depth
    response_body_len = 0

    # FTP login
    is_ftp_login = 1 if dst_port in (21,) and src_pkts > 3 else 0

    # Same IP same port (source and dest have same IPs AND same ports)
    is_sm_ips_ports = 1 if (src_ip == dst_ip and src_port == dst_port) else 0

    # --- Service and state for connection tracking ---
    service = _port_to_service(dst_port, protocol)

    # Infer simplified connection state from TCP flags
    syn_count = features.get("SYN Flag Count", 0)
    rst_count = features.get("RST Flag Count", 0)
    ack_count = features.get("ACK Flag Count", 0)

    if protocol == 6:  # TCP
        if rst_count > 0:
            state = "RST"
        elif syn_count > 0 and ack_count > 0 and dst_pkts > 0:
            state = "FIN"  # Completed connection
        elif syn_count > 0 and dst_pkts == 0:
            state = "REQ"  # SYN only, no response (scan-like)
        elif ack_count > 0:
            state = "CON"  # Established
        else:
            state = "INT"  # Internal/other
    else:
        state = "CON"  # UDP — always "connected" if we see both dirs

    # Record this connection in the tracker BEFORE computing ct_* features
    conn = ConnectionRecord(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        service=service,
        state=state,
        ttl=sttl,
    )
    tracker.record(conn)

    # --- Connection-tracking aggregates ---
    ct_srv_src = tracker.ct_srv_src(service, src_ip)
    ct_state_ttl = tracker.ct_state_ttl(state, _ttl_bucket(sttl))
    ct_dst_ltm = tracker.ct_dst_ltm(dst_ip)
    ct_src_dport_ltm = tracker.ct_src_dport_ltm(src_ip, dst_port)
    ct_dst_sport_ltm = tracker.ct_dst_sport_ltm(dst_ip, src_port)
    ct_dst_src_ltm = tracker.ct_dst_src_ltm(dst_ip, src_ip)
    ct_src_ltm = tracker.ct_src_ltm(src_ip)
    ct_srv_dst = tracker.ct_srv_dst(service, dst_ip)
    ct_flw_http_mthd = tracker.ct_flw_http_mthd()
    ct_ftp_cmd = tracker.ct_ftp_cmd()

    # --- Assemble the 40 features (including 'id' placeholder) ---
    # The ONNX model was trained with 'id' as a feature column, so we must
    # include it. Value is always 0 (placeholder — doesn't affect XGBoost).
    return {
        "id": 0,
        "flow_duration": duration_s,
        "src_pkts": src_pkts,
        "dst_pkts": dst_pkts,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "rate": rate,
        "sttl": sttl,
        "dttl": dttl,
        "sload": sload,
        "dload": dload,
        "sloss": sloss,
        "dloss": dloss,
        "sinpkt": sinpkt,
        "dinpkt": dinpkt,
        "sjit": sjit,
        "djit": djit,
        "swin": swin,
        "stcpb": stcpb,
        "dtcpb": dtcpb,
        "dwin": dwin,
        "tcprtt": tcprtt,
        "synack": synack,
        "ackdat": ackdat,
        "smean": smean,
        "dmean": dmean,
        "transdepth": trans_depth,
        "responsebodylen": response_body_len,
        "ctsrvsrc": ct_srv_src,
        "ctstatettl": ct_state_ttl,
        "ctdstltm": ct_dst_ltm,
        "ctsrcdportltm": ct_src_dport_ltm,
        "ctdstsportltm": ct_dst_sport_ltm,
        "ctdstsrcltm": ct_dst_src_ltm,
        "isftplogin": is_ftp_login,
        "ctftpcmd": ct_ftp_cmd,
        "ctflwhttpmthd": ct_flw_http_mthd,
        "ctsrcltm": ct_src_ltm,
        "ctsrvdst": ct_srv_dst,
        "issmipsports": is_sm_ips_ports,
    }
