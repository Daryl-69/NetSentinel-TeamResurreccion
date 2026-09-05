"""DNS Extractor — Extracts DNS query/response metadata from packets.

Parses DNS packets using Scapy's DNS/DNSQR/DNSRR layers to produce
event dicts that the DGA/DNS Tunnel detector expects.

Also tracks NXDOMAIN responses per source IP — a high NXDOMAIN rate
is a strong DGA indicator (bots querying many non-existent domains).
"""
import time
import logging
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)

# DNS query types we care about
INTERESTING_QTYPES = {1, 28, 5, 15, 16, 33}  # A, AAAA, CNAME, MX, TXT, SRV

# Domains to skip (internal/infrastructure)
SKIP_SUFFIXES = (
    ".arpa", ".local", ".localhost", ".internal",
    ".lan", ".home", ".corp", ".intranet",
)

# DNS response codes
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


class DNSExtractor:
    """Extracts DNS query domains and response metadata from packets.

    For each DNS query packet, emits:
        {"type": "dns", "domain": "example.com", "source_ip": "..."}

    Also maintains NXDOMAIN counters per source IP to detect DGA behavior.
    """

    def __init__(self, nxdomain_window: int = 300, nxdomain_threshold: int = 20):
        """
        Args:
            nxdomain_window: Seconds to track NXDOMAIN counts per IP.
            nxdomain_threshold: If a src_ip exceeds this many NXDOMAINs
                                in the window, flag it in subsequent events.
        """
        self.nxdomain_window = nxdomain_window
        self.nxdomain_threshold = nxdomain_threshold

        # Per-IP NXDOMAIN tracking: {ip: [(timestamp, domain), ...]}
        self._nxdomain_history: dict[str, list] = defaultdict(list)
        self._total_queries = 0
        self._total_nxdomains = 0

    def process_packet(self, packet) -> Optional[dict]:
        """Process a single packet. Returns DNS event dict or None.

        Handles both queries (QR=0) and responses (QR=1).
        Only emits events for queries — responses update NXDOMAIN stats.
        """
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP
        except ImportError:
            return None

        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]

        # Get source IP (from IP layer)
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        ts = float(packet.time)

        # --- Handle DNS Response (QR=1) → update NXDOMAIN stats ---
        if dns.qr == 1:
            self._handle_response(dns, dst_ip, ts)
            return None

        # --- Handle DNS Query (QR=0) → emit event ---
        if dns.qr == 0 and dns.qdcount > 0 and packet.haslayer(DNSQR):
            return self._handle_query(packet, dns, src_ip, ts)

        return None

    def _handle_query(self, packet, dns, src_ip: str, ts: float) -> Optional[dict]:
        """Extract domain from a DNS query and build event dict."""
        from scapy.layers.dns import DNSQR

        qr = packet[DNSQR]
        qname = qr.qname
        qtype = qr.qtype

        # Decode qname (Scapy returns bytes)
        if isinstance(qname, bytes):
            domain = qname.decode("utf-8", errors="ignore").rstrip(".")
        else:
            domain = str(qname).rstrip(".")

        # Skip uninteresting queries
        if not domain:
            return None
        if any(domain.endswith(s) for s in SKIP_SUFFIXES):
            return None
        if qtype not in INTERESTING_QTYPES:
            return None
        # Skip very short domains (likely not real)
        if len(domain) < 4:
            return None

        self._total_queries += 1

        # Check if this source has high NXDOMAIN rate (DGA indicator)
        nxdomain_rate = self._get_nxdomain_rate(src_ip, ts)

        event = {
            "type": "dns",
            "domain": domain,
            "source_ip": src_ip,
            "query_type": qtype,
            "timestamp": ts,
        }

        # Attach DGA risk indicator if NXDOMAIN rate is high
        if nxdomain_rate > self.nxdomain_threshold:
            event["nxdomain_flag"] = True
            event["nxdomain_count"] = nxdomain_rate

        return event

    def _handle_response(self, dns, client_ip: str, ts: float):
        """Track NXDOMAIN responses for DGA detection heuristic."""
        from scapy.layers.dns import DNSQR

        if dns.rcode == RCODE_NXDOMAIN:
            self._total_nxdomains += 1

            # Extract the queried domain from the response
            domain = ""
            if dns.qdcount > 0:
                try:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        domain = qname.decode("utf-8", errors="ignore").rstrip(".")
                    else:
                        domain = str(qname).rstrip(".")
                except Exception:
                    pass

            self._nxdomain_history[client_ip].append((ts, domain))

    def _get_nxdomain_rate(self, ip: str, current_time: float) -> int:
        """Get the number of NXDOMAINs from this IP in the tracking window."""
        history = self._nxdomain_history.get(ip, [])
        if not history:
            return 0

        # Prune old entries
        cutoff = current_time - self.nxdomain_window
        fresh = [(t, d) for t, d in history if t > cutoff]
        self._nxdomain_history[ip] = fresh

        return len(fresh)

    def get_nxdomain_suspects(self, current_time: float = None) -> list[dict]:
        """Get IPs with high NXDOMAIN rates (likely DGA-infected hosts).

        Useful for the dashboard to highlight suspicious hosts.
        """
        if current_time is None:
            current_time = time.time()

        suspects = []
        for ip, history in self._nxdomain_history.items():
            cutoff = current_time - self.nxdomain_window
            recent = [h for h in history if h[0] > cutoff]
            if len(recent) >= self.nxdomain_threshold:
                suspects.append({
                    "ip": ip,
                    "nxdomain_count": len(recent),
                    "sample_domains": [d for _, d in recent[:5]],
                })
        return suspects

    @property
    def stats(self) -> dict:
        return {
            "total_dns_queries": self._total_queries,
            "total_nxdomains": self._total_nxdomains,
            "tracked_ips": len(self._nxdomain_history),
        }
