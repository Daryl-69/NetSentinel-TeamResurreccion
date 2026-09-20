"""Session Builder — Accumulates flows per (src, dst) pair for C2 detection.

The C2 Beacon BiLSTM model expects a time-series of 100 flows between
a single (src_ip, dst_ip) pair, each with:
  - iat: inter-arrival time between this flow and the previous one
  - packet_size: average packet size in the flow
  - bytes: total bytes transferred
  - direction: 1=outbound, 0=inbound

This module collects completed flow events from the FlowExtractor and
groups them by (src, dst). When a pair accumulates enough flows, it
emits a session event for the C2 detector.
"""
import time
import logging
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)


class SessionBuilder:
    """Accumulates completed flows into per-destination sessions.

    Usage:
        builder = SessionBuilder()
        # After FlowExtractor produces a flow event:
        session = builder.add_flow(flow_event)
        if session:
            # session is ready for C2BeaconDetector
            analyzer.analyze_flow(session)
    """

    def __init__(
        self,
        min_flows: int = 100,
        window_seconds: float = 3600.0,
        max_pairs: int = 10000,
    ):
        """
        Args:
            min_flows: Minimum flows needed before emitting a session.
            window_seconds: Only keep flows from the last N seconds.
            max_pairs: Max tracked (src, dst) pairs (memory limit).
        """
        self.min_flows = min_flows
        self.window_seconds = window_seconds
        self.max_pairs = max_pairs

        # {(src_ip, dst_ip): [flow_record, ...]}
        self._sessions: dict[tuple, list[dict]] = defaultdict(list)
        self._emitted_count = 0

    def add_flow(self, flow_event: dict) -> Optional[dict]:
        """Add a completed flow event. Returns session event if threshold met.

        Args:
            flow_event: Dict with type="flow", source_ip, dest_ip, features.

        Returns:
            Session event dict (type="session") if enough flows accumulated,
            else None.
        """
        src_ip = flow_event.get("source_ip", "")
        dst_ip = flow_event.get("dest_ip", "")
        features = flow_event.get("features", {})

        if not src_ip or not dst_ip:
            return None

        pair = (src_ip, dst_ip)

        # Build the flow record the C2 model expects
        ts = time.time()
        record = {
            "timestamp": ts,
            "packet_size": features.get(
                "Avg Fwd Segment Size",
                features.get("Fwd Packet Length Mean", 0),
            ),
            "bytes": features.get(
                "Fwd Packets Length Total",
                features.get("Subflow Fwd Bytes", 0),
            ),
            "direction": 1,  # Forward (src→dst)
        }

        self._sessions[pair].append(record)

        # Prune old entries from this pair
        self._prune_pair(pair, ts)

        # Memory guard: if too many pairs tracked, drop oldest
        if len(self._sessions) > self.max_pairs:
            self._evict_oldest()

        # Check if we have enough flows for this pair
        flows = self._sessions[pair]
        if len(flows) >= self.min_flows:
            return self._emit_session(pair)

        return None

    def check_all_pairs(self) -> list[dict]:
        """Check all pairs and emit sessions for any that meet threshold.

        Call periodically to catch pairs that accumulated slowly.
        """
        sessions = []
        pairs_ready = [
            p for p, flows in self._sessions.items()
            if len(flows) >= self.min_flows
        ]
        for pair in pairs_ready:
            session = self._emit_session(pair)
            if session:
                sessions.append(session)
        return sessions

    def _emit_session(self, pair: tuple) -> Optional[dict]:
        """Build and return a session event, consuming the stored flows."""
        flows = self._sessions.pop(pair, [])
        if len(flows) < self.min_flows:
            return None

        # Take the last min_flows entries
        flows = flows[-self.min_flows:]

        # Compute IATs between consecutive flows
        flow_series = []
        for i, record in enumerate(flows):
            if i == 0:
                iat = 0.0
            else:
                iat = record["timestamp"] - flows[i - 1]["timestamp"]
            flow_series.append({
                "iat": max(iat, 0.0),
                "packet_size": record["packet_size"],
                "bytes": record["bytes"],
                "direction": record["direction"],
            })

        self._emitted_count += 1

        return {
            "type": "session",
            "source_ip": pair[0],
            "dest_ip": pair[1],
            "flows": flow_series,
            "flow_count": len(flow_series),
        }

    def _prune_pair(self, pair: tuple, current_time: float):
        """Remove flows older than the window for a specific pair."""
        cutoff = current_time - self.window_seconds
        self._sessions[pair] = [
            f for f in self._sessions[pair] if f["timestamp"] > cutoff
        ]

    def _evict_oldest(self):
        """Remove the pair with the oldest last-seen timestamp."""
        if not self._sessions:
            return
        oldest_pair = min(
            self._sessions.keys(),
            key=lambda p: self._sessions[p][-1]["timestamp"] if self._sessions[p] else 0,
        )
        del self._sessions[oldest_pair]

    @property
    def stats(self) -> dict:
        return {
            "tracked_pairs": len(self._sessions),
            "sessions_emitted": self._emitted_count,
            "flows_buffered": sum(len(v) for v in self._sessions.values()),
        }
