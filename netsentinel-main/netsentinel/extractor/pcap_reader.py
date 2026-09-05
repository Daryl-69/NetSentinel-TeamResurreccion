"""Packet Processor — Orchestrator for the extraction pipeline.

Routes each raw packet through all three extractors:
  1. FlowExtractor  → DDoS + ETT features (type="flow")
  2. DNSExtractor   → domain strings (type="dns")
  3. SessionBuilder → flow time-series (type="session")

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
    ):
        self.flow_extractor = FlowExtractor(
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
        )
        self.dns_extractor = DNSExtractor()
        self.session_builder = SessionBuilder(min_flows=session_min_flows)

        self._packet_count = 0
        self._event_count = 0
        self._live_sniffer_thread: Optional[threading.Thread] = None
        self._live_running = False

    # ------------------------------------------------------------------
    # Core: process a single packet
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
            events.append(flow_event)

            # 3. Feed completed flow into session builder (for C2 detection)
            session_event = self.session_builder.add_flow(flow_event)
            if session_event:
                events.append(session_event)

        self._event_count += len(events)
        return events

    # ------------------------------------------------------------------
    # PCAP file replay (synchronous generator)
    # ------------------------------------------------------------------

    def process_pcap(self, pcap_path: str) -> Generator[dict, None, None]:
        """Replay a PCAP file, yielding events as they are extracted.

        Uses Scapy's PcapReader for memory-efficient streaming.
        At the end, flushes all remaining active flows.

        Args:
            pcap_path: Path to the PCAP/PCAPNG file.

        Yields:
            Event dicts (type="flow", "dns", or "session").
        """
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        try:
            from scapy.utils import PcapReader
        except ImportError:
            logger.error("Scapy not installed — cannot read PCAPs")
            return

        logger.info(f"Processing PCAP: {pcap_path}")
        start_time = time.time()

        try:
            # Use streaming PcapReader — memory efficient, works for any file size.
            # (rdpcap loads the entire file into RAM which crashes on large PCAPs)
            from scapy.utils import PcapReader
            reader = PcapReader(pcap_path)
            logger.info(f"Streaming PCAP: {pcap_path}")
        except Exception as e:
            logger.error(f"Failed to open PCAP: {e}")
            return

        last_flush_time = 0.0
        flush_interval = 30.0  # Flush expired flows every 30s of PCAP time

        packet_count = 0
        for packet in reader:
            packet_count += 1
            
            # Process packet through all extractors
            for event in self.process_packet(packet):
                yield event
            
            # Periodically yield control so we don't starve the asyncio event loop
            if packet_count % 1000 == 0:
                yield None

            # Periodically flush expired flows (based on PCAP timestamps)
            pkt_time = float(packet.time)
            if pkt_time - last_flush_time > flush_interval:
                for event in self.flow_extractor.flush_expired(pkt_time):
                    yield event
                    # Also feed flushed flows to session builder
                    session = self.session_builder.add_flow(event)
                    if session:
                        yield session
                last_flush_time = pkt_time

        # Flush all remaining flows at end of PCAP
        for event in self.flow_extractor.flush_all():
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
