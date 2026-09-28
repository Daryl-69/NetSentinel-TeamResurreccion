"""Packet Processor — Orchestrator for the extraction pipeline.

Routes each raw packet through all three extractors:
  1. FlowExtractor  → flow features, TLS handshake metadata, packet-size
                      sequence (type="flow", extractor="custom"); single-packet
                      flows go out as stubs (type="flow", stub=True)
  2. DNSExtractor   → queries (type="dns") and replies (type="dns_response")
  3. SessionBuilder → flow time-series (type="session")

PCAP file mode also runs CICFlowMeter (batch) for zero-drift
DDoS + Port Scan features (type="flow", extractor="cicflowmeter").

Supports two modes:
  - PCAP file replay: process_pcap("capture.pcap")
  - Live capture: start_live_capture(interface, queue)

Read-only by construction (PS 26145 constraint a): packets are only ever
read -- from a file, or from an interface in promiscuous/monitor mode via
Scapy's sniff(store=False). Nothing in the extraction path transmits.

Every event is stamped with ingest_wall (wall-clock time the extractor
emitted it), which the analyzer turns into the ingest-to-alert latency.
"""
import os
import time
import asyncio
import logging
import threading
from datetime import datetime
from typing import Generator, Optional

from netsentinel.extractor.flow_extractor import FlowExtractor
from netsentinel.extractor.dns_extractor import DNSExtractor
from netsentinel.extractor.session_builder import SessionBuilder

logger = logging.getLogger(__name__)


def _wire_len(packet) -> int:
    n = getattr(packet, "wirelen", None)
    if n:
        return int(n)
    raw = getattr(packet, "original", None)
    if raw:
        return len(raw)
    try:
        return len(packet)
    except Exception:
        return 0


class PacketProcessor:
    """Orchestrates packet → event extraction across all extractors.

    Hybrid architecture:
      - PCAP mode: CICFlowMeter (batch, zero-drift) for DDoS/PortScan
                   + custom extractor (streaming) for ETT/DGA/C2/Exfil/TLS
      - Live mode: custom extractor only (CICFlowMeter can't stream); its
                   flows and probe stubs then also feed the scan and flood
                   detectors (events carry cic_covered=False)

    Usage (PCAP replay):
        processor = PacketProcessor()
        for event in processor.process_pcap("capture.pcap"):
            alerts = analyzer.analyze(event)
    """

    def __init__(
        self,
        idle_timeout: float = 120.0,
        active_timeout: float = 300.0,
        session_min_flows: int = 100,
        use_cicflowmeter: bool = True,
        metrics=None,
        quic_initial_parse: Optional[bool] = None,
        probe_timeout: Optional[float] = None,
        fast_reader: bool = True,
    ):
        from netsentinel import config
        from netsentinel.pipeline.metrics import METRICS
        self.metrics = METRICS if metrics is None else metrics
        self.flow_extractor = FlowExtractor(
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
            emit_stubs=True,
            probe_timeout=config.PROBE_FLOW_TIMEOUT_S if probe_timeout is None else probe_timeout,
            tls_fingerprinting=config.TLS_FINGERPRINTING,
            quic_initial_parse=config.QUIC_INITIAL_PARSE if quic_initial_parse is None else quic_initial_parse,
        )
        self.dns_extractor = DNSExtractor()
        self.session_builder = SessionBuilder(min_flows=session_min_flows)
        self.use_cicflowmeter = use_cicflowmeter
        # Capture replay reads files with the struct-level reader in
        # fastpath.py (identical fields, several times faster than Scapy).
        self.fast_reader = fast_reader
        self.reader_used = None

        # Lazy-load CICFlowMeter wrapper (only when needed)
        self._cic_extractor = None
        self._cic_covered = False

        self._packet_count = 0
        self._byte_count = 0
        self._event_count = 0
        self._live_sniffer_thread: Optional[threading.Thread] = None
        self._live_running = False
        self._first_ts = None
        self._last_ts = None
        # The sniffer thread and the periodic flush on the event loop both
        # touch the flow table; this lock keeps them from interleaving.
        self._lock = threading.Lock()

    def _get_cic_extractor(self):
        """Lazy-load the CICFlowMeter wrapper."""
        if self._cic_extractor is None:
            try:
                from netsentinel.extractor.cicflowmeter_wrapper import CICFlowMeterExtractor
                self._cic_extractor = CICFlowMeterExtractor()
            except Exception as e:
                logger.warning(f"CICFlowMeter not available, falling back to custom: {e}")
                self.use_cicflowmeter = False
        return self._cic_extractor

    # ------------------------------------------------------------------
    # Core: process a single packet (custom extractor only)
    # ------------------------------------------------------------------

    def _tag(self, event: dict) -> dict:
        if event.get("type") == "flow":
            event["extractor"] = "custom"
            event["cic_covered"] = self._cic_covered
        event["ingest_wall"] = time.time()
        return event

    def _completed(self, flow_event: dict, events: list) -> None:
        """A flow finished: tag it and, if it is a real flow, feed sessions."""
        events.append(self._tag(flow_event))
        if not flow_event.get("stub"):
            session_event = self.session_builder.add_flow(flow_event)
            if session_event:
                events.append(self._tag(session_event))

    def process_packet(self, packet) -> list[dict]:
        """Process one Scapy packet through all extractors.

        Returns a list of 0 or more event dicts ready for the analyzer.
        """
        try:
            ts = float(packet.time)
        except (TypeError, ValueError, AttributeError):
            ts = time.time()
        self._count(ts, _wire_len(packet))
        events = []

        with self._lock:
            # 1. DNS extraction (fast, independent)
            dns_event = self.dns_extractor.process_packet(packet)
            if dns_event:
                events.append(self._tag(dns_event))

            # 2. Flow extraction (may complete a flow → event)
            flow_event = self.flow_extractor.process_packet(packet)
            if flow_event:
                self._completed(flow_event, events)

        self._event_count += len(events)
        return events

    def process_fast(self, p) -> list[dict]:
        """Same as process_packet, for a frame parsed by fastpath.parse_frame."""
        from netsentinel.extractor.fastpath import is_dns, parse_dns
        events = []
        with self._lock:
            if is_dns(p):
                d = parse_dns(p)
                if d:
                    ev = self.dns_extractor.process_fields(
                        p.ts, p.src, p.dst, d["qr"], d["qname"], d["qtype"],
                        d["rcode"], d["ancount"], d["msg_len"])
                    if ev:
                        events.append(self._tag(ev))
            flow_event = self.flow_extractor.process_fields(
                p.ts, p.src, p.dst, p.proto, p.sport, p.dport, p.flags, p.window,
                p.header_size, p.payload_size, p.l4_len, p.payload)
            if flow_event:
                self._completed(flow_event, events)
        self._event_count += len(events)
        return events

    def _count(self, ts: float, nbytes: int) -> None:
        self._packet_count += 1
        self._byte_count += nbytes
        self.metrics.packet(nbytes)
        if self._first_ts is None:
            self._first_ts = ts
        self._last_ts = ts

    def flush_expired(self, now: float) -> list[dict]:
        events = []
        with self._lock:
            for event in self.flow_extractor.flush_expired(now):
                self._completed(event, events)
        self._event_count += len(events)
        return events

    def flush_all(self) -> list[dict]:
        events = []
        with self._lock:
            for event in self.flow_extractor.flush_all():
                self._completed(event, events)
            for session in self.session_builder.check_all_pairs():
                events.append(self._tag(session))
        self._event_count += len(events)
        return events

    # ------------------------------------------------------------------
    # PCAP file replay — HYBRID mode (CICFlowMeter + custom)
    # ------------------------------------------------------------------

    def process_pcap(self, pcap_path: str) -> Generator[dict, None, None]:
        """Replay a PCAP file with hybrid extraction.

        Phase 1: Run CICFlowMeter (batch) → yields DDoS/PortScan flow events
        Phase 2: Stream custom extractor → yields flow/DNS/TLS/C2 events

        Yields event dicts, and None every 1000 packets as a cooperative
        yield point for the caller's event loop.
        """
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP not found: {pcap_path}")
            return

        logger.info(f"Processing PCAP: {pcap_path}")
        self.metrics.set_source("replay", os.path.basename(pcap_path))
        start_time = time.time()

        # ── Phase 1: CICFlowMeter batch extraction (DDoS + Port Scan) ──
        self._cic_covered = False
        if self.use_cicflowmeter:
            cic = self._get_cic_extractor()
            if cic is not None:
                logger.info("Phase 1: CICFlowMeter batch extraction (DDoS/PortScan)...")
                cic_events = cic.extract_from_pcap(pcap_path)
                for event in cic_events:
                    self._event_count += 1
                    event["ingest_wall"] = time.time()
                    yield event
                logger.info(f"Phase 1 complete: {len(cic_events)} CIC flows extracted")
                self._cic_covered = len(cic_events) > 0

                # Free CICFlowMeter memory before Phase 2
                del cic_events
                self._cic_extractor = None
                import gc; gc.collect()

        # ── Phase 2: Custom streaming extraction ──
        logger.info("Phase 2: Custom streaming extraction (ETT/DNS/TLS/C2/Exfil)...")
        last_flush_time = 0.0
        flush_interval = max(5.0, float(self.flow_extractor.probe_timeout))
        packet_count = 0

        # Fast reader first (struct-level parsing, same fields as Scapy);
        # Scapy only for link types the fast reader does not handle.
        fast = self.fast_reader
        if fast:
            from netsentinel.extractor.fastpath import iter_capture, parse_frame, UnsupportedCapture
            try:
                source = iter_capture(pcap_path)
                first = next(source, None)
            except (UnsupportedCapture, OSError) as e:
                logger.info(f"Fast reader not used ({e}); reading with Scapy")
                fast = False
        if fast:
            self.reader_used = "fast"
            import itertools
            for ts, lt, buf, wirelen in itertools.chain([first] if first else [], source):
                packet_count += 1
                self._count(ts, wirelen)
                p = parse_frame(ts, lt, buf, wirelen)
                if p is not None:
                    for event in self.process_fast(p):
                        yield event
                if packet_count % 1000 == 0:
                    yield None
                if ts - last_flush_time > flush_interval:
                    if last_flush_time:
                        for event in self.flush_expired(ts):
                            yield event
                    last_flush_time = ts
        else:
            self.reader_used = "scapy"
            try:
                # The link-layer registry is filled when the layer modules
                # are imported; without this PcapReader reads Ethernet
                # captures as Raw packets and no flow is ever extracted.
                import scapy.layers.l2, scapy.layers.inet, scapy.layers.inet6, scapy.layers.dns  # noqa: F401
                from scapy.utils import PcapReader
            except ImportError:
                logger.error("Scapy not installed — cannot read PCAPs")
                return
            try:
                reader = PcapReader(pcap_path)
            except Exception as e:
                logger.error(f"Failed to open PCAP: {e}")
                return
            for packet in reader:
                packet_count += 1
                for event in self.process_packet(packet):
                    yield event
                if packet_count % 1000 == 0:
                    yield None
                pkt_time = float(packet.time)
                if pkt_time - last_flush_time > flush_interval:
                    if last_flush_time:
                        for event in self.flush_expired(pkt_time):
                            yield event
                    last_flush_time = pkt_time
            if hasattr(reader, 'close'):
                reader.close()

        for event in self.flush_all():
            yield event

        elapsed = time.time() - start_time
        logger.info(
            f"PCAP processing complete: {self._packet_count} packets, "
            f"{self._event_count} events in {elapsed:.2f}s"
        )

    # ------------------------------------------------------------------
    # Live capture (async, runs Scapy sniff in a background thread)
    # ------------------------------------------------------------------

    async def start_live_capture(
        self,
        interface: str,
        event_queue: asyncio.Queue,
        bpf_filter: str = "ip or ip6",   # "ip" alone is IPv4-ONLY and drops all IPv6
    ):
        """Start live packet capture, pushing events into an asyncio Queue.

        Runs Scapy's sniff() in a background thread (receive only, store=False)
        and hands events to the event loop thread-safely.
        """
        if self._live_running:
            logger.warning("Live capture already running")
            return

        from netsentinel import config
        self._live_running = True
        self._cic_covered = False
        self.metrics.set_source("live", interface)
        loop = asyncio.get_event_loop()

        def _packet_callback(packet):
            if not self._live_running:
                return
            for event in self.process_packet(packet):
                loop.call_soon_threadsafe(_put, event)

        def _put(event):
            try:
                event_queue.put_nowait(event)
            except asyncio.QueueFull:
                self.metrics.dropped()

        def _run_sniffer():
            try:
                from scapy.all import sniff
                logger.info(f"Live capture started on '{interface}' (filter: {bpf_filter})")
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=_packet_callback,
                    store=False,
                    stop_filter=lambda _: not self._live_running,
                )
            except PermissionError:
                logger.error(
                    "Permission denied — live capture requires admin/root. "
                    "On Windows, run as Administrator with Npcap installed."
                )
            except Exception as e:
                logger.error(f"Live capture error: {e}")
            finally:
                self._live_running = False
                logger.info("Live capture stopped")

        self._live_sniffer_thread = threading.Thread(
            target=_run_sniffer, daemon=True, name="scapy-sniffer"
        )
        self._live_sniffer_thread.start()
        asyncio.create_task(self._periodic_flush(event_queue, float(config.LIVE_FLUSH_INTERVAL_S)))

    async def _periodic_flush(self, event_queue: asyncio.Queue, interval: float):
        """Periodically flush idle flows and unanswered probes during live capture."""
        while self._live_running:
            await asyncio.sleep(interval)
            for event in self.flush_expired(time.time()):
                try:
                    event_queue.put_nowait(event)
                except asyncio.QueueFull:
                    self.metrics.dropped()

    def stop_live_capture(self):
        """Stop the live capture thread."""
        self._live_running = False
        if self._live_sniffer_thread and self._live_sniffer_thread.is_alive():
            self._live_sniffer_thread.join(timeout=5)
        logger.info("Live capture stopped")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        span = (self._last_ts - self._first_ts) if (self._first_ts and self._last_ts) else None
        return {
            "packets_processed": self._packet_count,
            "bytes_processed": self._byte_count,
            "events_generated": self._event_count,
            "capture_span_s": round(span, 3) if span is not None else None,
            "live_capture_active": self._live_running,
            "cic_covered": self._cic_covered,
            "reader": self.reader_used,
            "flow_extractor": self.flow_extractor.stats,
            "dns_extractor": self.dns_extractor.stats,
            "session_builder": self.session_builder.stats,
        }
