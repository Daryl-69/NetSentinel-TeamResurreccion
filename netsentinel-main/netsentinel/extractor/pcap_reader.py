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


class LiveCaptureError(RuntimeError):
    """Live capture could not be started (bad interface, no privileges, no Npcap)."""


# ----------------------------------------------------------------------
# Interface helpers for live capture
# ----------------------------------------------------------------------

def default_interface() -> Optional[str]:
    """Name of the interface that carries the default route (Scapy's pick)."""
    try:
        from scapy.all import conf
        iface = conf.iface
        return getattr(iface, "name", None) or (str(iface) if iface else None)
    except Exception:
        return None


def list_interfaces() -> list[dict]:
    """Interfaces Scapy can capture on, with their IPv4 address and MAC."""
    try:
        from scapy.all import conf
    except ImportError:
        return []
    out = []
    for iface in conf.ifaces.values():
        out.append({
            "name": iface.name,
            "description": getattr(iface, "description", "") or "",
            "ip": getattr(iface, "ip", "") or "",
            "mac": getattr(iface, "mac", "") or "",
        })
    return out


def open_live_socket(interface: str, bpf_filter: Optional[str]):
    """Open a receive-only capture socket on `interface`.

    Returns (socket, kernel_filter_applied). Raises LiveCaptureError with an
    actionable message when the interface is wrong or privileges are missing.

    Scapy compiles BPF filters with libpcap/tcpdump. Minimal Linux installs
    have neither, so instead of failing we capture unfiltered and let the
    caller filter in Python.
    """
    from scapy.all import conf

    def _hint(e: Exception) -> str:
        msg = str(e)
        if isinstance(e, PermissionError) or "Operation not permitted" in msg:
            return (f"Permission denied opening '{interface}'. Live capture needs root/admin: "
                    "run with sudo on Linux/macOS, or as Administrator with Npcap on Windows.")
        if "not found" in msg.lower() or "No such device" in msg:
            names = ", ".join(i["name"] for i in list_interfaces()) or "none found"
            return (f"Interface '{interface}' not found. Available: {names}. "
                    "See GET /api/capture/interfaces.")
        if os.name == "nt" and "pcap" in msg.lower():
            return f"{msg} — install Npcap from https://npcap.com/ (tick 'WinPcap API-compatible Mode')."
        return f"Could not open '{interface}' for capture: {msg}"

    if bpf_filter:
        try:
            return conf.L2listen(iface=interface, filter=bpf_filter), True
        except PermissionError as e:
            raise LiveCaptureError(_hint(e)) from e
        except Exception as e:
            if "filter" not in str(e).lower():
                raise LiveCaptureError(_hint(e)) from e
            logger.warning(f"Kernel BPF filter unavailable ({e}); filtering in Python instead")

    try:
        return conf.L2listen(iface=interface), False
    except Exception as e:
        raise LiveCaptureError(_hint(e)) from e


class PacketProcessor:
    """Orchestrates packet → event extraction across all extractors.

    Usage (PCAP replay):
        processor = PacketProcessor()
        for event in processor.process_pcap("capture.pcap"):
            alert = analyzer.analyze_flow(event)

    Usage (live capture):
        processor = PacketProcessor()
        queue = asyncio.Queue()
        await processor.start_live_capture("eth0", queue)   # None = default interface
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
        self._live_stop: Optional[threading.Event] = None
        self._live_interface: Optional[str] = None
        self._live_error: Optional[str] = None
        self._live_dropped = 0
        # The sniffer thread and the periodic flush on the event loop both
        # touch the flow table; this lock keeps them from interleaving.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Core: process a single packet
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> list[dict]:
        """Process one Scapy packet through all extractors.

        Returns a list of 0 or more event dicts ready for the analyzer.
        Typical: 0 events (mid-flow), 1 event (DNS query or completed flow),
                 or 2-3 events (flow completes + session ready).
        """
        events = []

        with self._lock:
            self._packet_count += 1

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
            # scapy.all (not scapy.utils) so the Ethernet/SLL link layers are
            # registered before the file is opened — otherwise the first PCAP
            # read in a fresh process decodes every packet as Raw (0 flows).
            from scapy.all import PcapReader
        except ImportError:
            logger.error("Scapy not installed — cannot read PCAPs")
            return

        logger.info(f"Processing PCAP: {pcap_path}")
        start_time = time.time()

        try:
            # Use streaming PcapReader — memory efficient, works for any file size.
            # (rdpcap loads the entire file into RAM which crashes on large PCAPs)
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
        interface: Optional[str],
        event_queue: asyncio.Queue,
        bpf_filter: str = "ip",
        flush_interval: float = 5.0,
    ) -> dict:
        """Start live packet capture, pushing events into an asyncio Queue.

        The capture socket is opened here, synchronously, so a wrong interface
        name or missing root/admin rights raises LiveCaptureError to the caller
        instead of failing silently in the background. Scapy's sniff() then
        runs in a dedicated thread (receive only, store=False).

        Args:
            interface: Network interface name (e.g., "eth0", "en0", "Wi-Fi").
                       None/"" = the interface carrying the default route.
            event_queue: asyncio.Queue where extracted events are pushed.
            bpf_filter: BPF filter string (default: "ip" = all IPv4 traffic).
            flush_interval: Seconds between sweeps for idle (e.g. UDP) flows.

        Returns:
            {"interface": ..., "kernel_filter": bool}
        """
        if self._live_running:
            raise LiveCaptureError("Live capture already running")

        interface = interface or default_interface()
        if not interface:
            raise LiveCaptureError(
                "No network interface found. Pass one explicitly, "
                "e.g. POST /api/capture/start?interface=eth0"
            )

        sock, kernel_filter = open_live_socket(interface, bpf_filter)

        lfilter = None
        if not kernel_filter:
            from scapy.layers.inet import IP
            lfilter = lambda p: IP in p

        loop = asyncio.get_running_loop()
        stop = threading.Event()
        self._live_stop = stop
        self._live_interface = interface
        self._live_error = None
        self._live_running = True

        def _put(event):
            try:
                event_queue.put_nowait(event)
            except asyncio.QueueFull:
                self._live_dropped += 1

        def _packet_callback(packet):
            """Called by the sniffer thread for each captured packet."""
            if stop.is_set():
                return
            try:
                events = self.process_packet(packet)
            except Exception as e:  # one malformed packet must not end the capture
                logger.debug(f"Skipping packet: {e}")
                return
            for event in events:
                # Thread-safe: schedule put on the asyncio loop
                loop.call_soon_threadsafe(_put, event)

        def _run_sniffer():
            """Blocking Scapy sniff — runs in dedicated thread.

            sniff() is called with a 1 s timeout in a loop so stop() takes
            effect within a second even on a quiet interface; the socket stays
            open between calls, so no packets are lost.
            """
            from scapy.all import sniff
            logger.info(
                f"Live capture started on '{interface}' "
                f"(filter: {bpf_filter} {'in kernel' if kernel_filter else 'in Python'})"
            )
            try:
                while not stop.is_set():
                    sniff(
                        opened_socket=sock,
                        prn=_packet_callback,
                        lfilter=lfilter,
                        store=False,
                        timeout=1,
                        stop_filter=lambda _: stop.is_set(),
                    )
                    if getattr(sock, "closed", False) and not stop.is_set():
                        # sniff() closes a socket that errors (interface went down)
                        raise LiveCaptureError(f"Capture socket on '{interface}' closed unexpectedly")
            except Exception as e:
                self._live_error = str(e)
                logger.error(f"Live capture error: {e}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
                if self._live_stop is stop:
                    self._live_running = False
                logger.info("Live capture stopped")

        self._live_sniffer_thread = threading.Thread(
            target=_run_sniffer, daemon=True, name="scapy-sniffer"
        )
        self._live_sniffer_thread.start()

        # Periodically flush idle flows (UDP and TCP without FIN/RST)
        asyncio.create_task(self._periodic_flush(event_queue, stop, flush_interval))

        return {"interface": interface, "kernel_filter": kernel_filter}

    async def _periodic_flush(self, event_queue: asyncio.Queue, stop: threading.Event,
                              interval: float):
        """Periodically flush expired flows during live capture."""
        while not stop.is_set():
            await asyncio.sleep(interval)
            events = []
            with self._lock:
                for event in self.flow_extractor.flush_expired(time.time()):
                    events.append(event)
                    session = self.session_builder.add_flow(event)
                    if session:
                        events.append(session)
                self._event_count += len(events)
            for event in events:
                try:
                    event_queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._live_dropped += 1

    def stop_live_capture(self):
        """Stop the live capture thread (returns within ~1 s)."""
        if self._live_stop is not None:
            self._live_stop.set()
        if self._live_sniffer_thread and self._live_sniffer_thread.is_alive():
            self._live_sniffer_thread.join(timeout=5)
        self._live_running = False
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
            "live_interface": self._live_interface,
            "live_error": self._live_error,
            "live_events_dropped": self._live_dropped,
            "flow_extractor": self.flow_extractor.stats,
            "dns_extractor": self.dns_extractor.stats,
            "session_builder": self.session_builder.stats,
        }
