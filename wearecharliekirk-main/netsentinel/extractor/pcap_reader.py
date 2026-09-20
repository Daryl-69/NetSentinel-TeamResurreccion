"""Packet Processor — Orchestrator for the extraction pipeline.

Routes each raw packet through all three extractors:
  1. FlowExtractor  → ETT features (type="flow", extractor="custom")
  2. DNSExtractor   → domain strings (type="dns")
  3. SessionBuilder → flow time-series (type="session")

PCAP file mode also runs CICFlowMeter (batch) for zero-drift
DDoS + Port Scan features (type="flow", extractor="cicflowmeter").

Supports two modes:
  - PCAP file replay: process_pcap("capture.pcap")
  - Live capture: start_live_capture(interface, queue)

The PCAP replay mode yields events synchronously (generator).
The live capture mode pushes events into an asyncio.Queue for
integration with the FastAPI background loop.
"""
import os
import time
import asyncio
import logging
import threading
from typing import Generator, Optional

from netsentinel.extractor.flow_extractor import FlowExtractor
from netsentinel.extractor.dns_extractor import DNSExtractor
from netsentinel.extractor.session_builder import SessionBuilder

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Orchestrates packet → event extraction across all extractors.

    Hybrid architecture:
      - PCAP mode: CICFlowMeter (batch, zero-drift) for DDoS/PortScan
                   + custom extractor (streaming) for ETT/DGA/C2/Exfil
      - Live mode: custom extractor only (CICFlowMeter can't stream)

    Usage (PCAP replay):
        processor = PacketProcessor()
        for event in processor.process_pcap("capture.pcap"):
            alert = analyzer.analyze_flow(event)

    Usage (live capture):
        processor = PacketProcessor()
        queue = asyncio.Queue()
        await processor.start_live_capture("Ethernet", queue)
        # Events appear in queue for the pipeline loop
    """

    def __init__(
        self,
        idle_timeout: float = 120.0,
        active_timeout: float = 300.0,
        session_min_flows: int = 100,
        use_cicflowmeter: bool = True,
    ):
        self.flow_extractor = FlowExtractor(
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
        )
        self.dns_extractor = DNSExtractor()
        self.session_builder = SessionBuilder(min_flows=session_min_flows)
        self.use_cicflowmeter = use_cicflowmeter

        # Lazy-load CICFlowMeter wrapper (only when needed)
        self._cic_extractor = None

        self._packet_count = 0
        self._event_count = 0
        self._live_sniffer_thread: Optional[threading.Thread] = None
        self._live_running = False

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

    def process_packet(self, packet) -> list[dict]:
        """Process one Scapy packet through all extractors.

        Returns a list of 0 or more event dicts ready for the analyzer.
        Typical: 0 events (mid-flow), 1 event (DNS query or completed flow),
                 or 2-3 events (flow completes + session ready).
        """
        self._packet_count += 1
        events = []

        # 1. DNS extraction (fast, independent)
        dns_event = self.dns_extractor.process_packet(packet)
        if dns_event:
            events.append(dns_event)

        # 2. Flow extraction (may complete a flow → event)
        flow_event = self.flow_extractor.process_packet(packet)
        if flow_event:
            # Tag with custom extractor origin
            flow_event["extractor"] = "custom"
            events.append(flow_event)

            # 3. Feed completed flow into session builder (for C2 detection)
            session_event = self.session_builder.add_flow(flow_event)
            if session_event:
                events.append(session_event)

        self._event_count += len(events)
        return events

    # ------------------------------------------------------------------
    # PCAP file replay — HYBRID mode (CICFlowMeter + custom)
    # ------------------------------------------------------------------

    def process_pcap(self, pcap_path: str) -> Generator[dict, None, None]:
        """Replay a PCAP file with hybrid extraction.

        Phase 1: Run CICFlowMeter (batch) → yields DDoS/PortScan flow events
        Phase 2: Stream custom extractor → yields ETT/DNS/C2/Exfil events

        Both phases yield events tagged with their extractor source so the
        analyzer can route them to the correct models.

        Args:
            pcap_path: Path to the PCAP/PCAPNG file.

        Yields:
            Event dicts (type="flow", "dns", or "session").
        """
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        logger.info(f"Processing PCAP: {pcap_path}")
        start_time = time.time()

        # ── Phase 1: CICFlowMeter batch extraction (DDoS + Port Scan) ──
        if self.use_cicflowmeter:
            cic = self._get_cic_extractor()
            if cic is not None:
                logger.info("Phase 1: CICFlowMeter batch extraction (DDoS/PortScan)...")
                cic_events = cic.extract_from_pcap(pcap_path)
                for event in cic_events:
                    self._event_count += 1
                    yield event
                logger.info(f"Phase 1 complete: {len(cic_events)} CIC flows extracted")

                # Free CICFlowMeter memory before Phase 2
                del cic_events
                self._cic_extractor = None
                import gc; gc.collect()

        # ── Phase 2: Custom streaming extraction (ETT, DNS, C2, Exfil) ──
        logger.info("Phase 2: Custom streaming extraction (ETT/DNS/C2/Exfil)...")

        try:
            from scapy.utils import PcapReader
        except ImportError:
            logger.error("Scapy not installed — cannot read PCAPs")
            return

        try:
            reader = PcapReader(pcap_path)
        except Exception as e:
            logger.error(f"Failed to open PCAP: {e}")
            return

        last_flush_time = 0.0
        flush_interval = 30.0

        packet_count = 0
        for packet in reader:
            packet_count += 1
            
            # Process packet through custom extractors
            for event in self.process_packet(packet):
                yield event
            
            # Periodically yield control
            if packet_count % 1000 == 0:
                yield None

            # Periodically flush expired flows
            pkt_time = float(packet.time)
            if pkt_time - last_flush_time > flush_interval:
                for event in self.flow_extractor.flush_expired(pkt_time):
                    event["extractor"] = "custom"
                    yield event
                    session = self.session_builder.add_flow(event)
                    if session:
                        yield session
                last_flush_time = pkt_time

        # Flush all remaining flows at end of PCAP
        for event in self.flow_extractor.flush_all():
            event["extractor"] = "custom"
            yield event
            session = self.session_builder.add_flow(event)
            if session:
                yield session

        # Check if any sessions are ready
        for session in self.session_builder.check_all_pairs():
            yield session

        if hasattr(reader, 'close'):
            reader.close()

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
        bpf_filter: str = "ip",
    ):
        """Start live packet capture, pushing events into an asyncio Queue.

        Runs Scapy's sniff() in a background thread using a thread-safe
        callback to push events into the asyncio queue.

        Args:
            interface: Network interface name (e.g., "Ethernet", "eth0").
            event_queue: asyncio.Queue where extracted events are pushed.
            bpf_filter: BPF filter string (default: "ip" = all IP traffic).
        """
        if self._live_running:
            logger.warning("Live capture already running")
            return

        self._live_running = True
        loop = asyncio.get_event_loop()

        def _packet_callback(packet):
            """Called by Scapy sniff thread for each captured packet."""
            if not self._live_running:
                return

            events = self.process_packet(packet)
            for event in events:
                # Thread-safe: schedule put on the asyncio loop
                loop.call_soon_threadsafe(event_queue.put_nowait, event)

        def _run_sniffer():
            """Blocking Scapy sniff — runs in dedicated thread."""
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

        # Start periodic flush task (flush idle flows every 30s)
        asyncio.create_task(self._periodic_flush(event_queue))

    async def _periodic_flush(self, event_queue: asyncio.Queue):
        """Periodically flush expired flows during live capture."""
        while self._live_running:
            await asyncio.sleep(30)
            current = time.time()
            for event in self.flow_extractor.flush_expired(current):
                await event_queue.put(event)
                session = self.session_builder.add_flow(event)
                if session:
                    await event_queue.put(session)

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
        return {
            "packets_processed": self._packet_count,
            "events_generated": self._event_count,
            "live_capture_active": self._live_running,
            "flow_extractor": self.flow_extractor.stats,
            "dns_extractor": self.dns_extractor.stats,
            "session_builder": self.session_builder.stats,
        }
