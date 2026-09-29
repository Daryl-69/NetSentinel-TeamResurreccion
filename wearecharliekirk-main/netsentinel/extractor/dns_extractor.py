"""DNS Extractor — Extracts DNS query/response metadata from packets.

Parses DNS packets using Scapy's DNS/DNSQR layers to produce event dicts for
the DGA / DNS-tunnel models and for the DNS behaviour tracker.

Queries -> {"type": "dns", "domain", "source_ip", "dest_ip", "query_type",
            "query_bytes", "timestamp", "lexical"}
Replies -> {"type": "dns_response", "domain", "source_ip" (the client the
            reply went to), "dest_ip" (the resolver), "rcode", "answers",
            "response_bytes", "timestamp", "answer_ips" (A/AAAA, if any)}

PS 26145 (c) "record-type anomalies": every query type is kept. The earlier
version dropped anything that was not A/AAAA/CNAME/MX/TXT/SRV, which threw
away exactly the NULL, ANY and private-type queries tunnel tools use.
Names under .arpa/.local and similar are still passed on (they count toward
a host's record-type mix) but are marked lexical=False so the name models do
not score reverse lookups as if they were generated domains.

Also tracks NXDOMAIN responses per source IP — a high NXDOMAIN rate is a
strong DGA indicator (bots querying many non-existent domains).
"""
import time
import logging
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)

# Names the character-level models should not judge (infrastructure lookups)
SKIP_SUFFIXES = (
    ".arpa", ".local", ".localhost", ".internal",
    ".lan", ".home", ".corp", ".intranet",
)

# DNS response codes
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


def _qname(q) -> str:
    name = getattr(q, "qname", b"")
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="ignore").rstrip(".")
    return str(name).rstrip(".")


def _answer_ips(dns) -> list:
    """A / AAAA addresses from a Scapy DNS reply (lets Tier 2 name peers that
    were reached without TLS SNI)."""
    out = []
    try:
        an = dns.an
        rrs = list(an) if isinstance(an, list) else [an[i] for i in range(int(dns.ancount or 0))]
        for rr in rrs[:32]:
            if getattr(rr, "type", None) in (1, 28) and getattr(rr, "rdata", None):
                out.append(str(rr.rdata))
    except Exception:
        pass
    return out


def _dns_message_len(packet) -> int:
    """Length of the DNS message itself (UDP payload, or TCP payload minus
    the 2-byte length prefix)."""
    try:
        from scapy.layers.inet import UDP, TCP
        if packet.haslayer(UDP):
            u = packet[UDP]
            if u.len:
                return max(0, int(u.len) - 8)
            return len(bytes(u.payload))
        if packet.haslayer(TCP):
            return max(0, len(bytes(packet[TCP].payload)) - 2)
    except Exception:
        pass
    return 0


class DNSExtractor:
    """Extracts DNS query domains and response metadata from packets.

    Maintains NXDOMAIN counters per source IP to detect DGA behavior.
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
        self._total_responses = 0
        self._total_nxdomains = 0
        self._qtypes: dict[int, int] = defaultdict(int)

    def process_packet(self, packet) -> Optional[dict]:
        """Process a single Scapy packet. Returns a dns or dns_response event, or None."""
        try:
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP
        except ImportError:
            return None

        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]

        # IPv6 FIX (2026-09-21): IPv6 DNS queries reported src/dst as "unknown",
        # so every IPv6 resolver lookup lost its attribution.
        try:
            from scapy.layers.inet6 import IPv6
        except ImportError:
            IPv6 = None
        if packet.haslayer(IP):
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
        elif IPv6 is not None and packet.haslayer(IPv6):
            src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
        else:
            src_ip = dst_ip = "unknown"
        q = packet[DNSQR] if packet.haslayer(DNSQR) else None
        return self.process_fields(
            float(packet.time), src_ip, dst_ip, int(dns.qr or 0),
            _qname(q) if q is not None else None,
            int(getattr(q, "qtype", 1) or 1) if q is not None else None,
            int(getattr(dns, "rcode", 0) or 0), int(getattr(dns, "ancount", 0) or 0),
            _dns_message_len(packet),
            _answer_ips(dns) if dns.qr else None)

    def process_fields(self, ts: float, src_ip: str, dst_ip: str, qr: int, qname,
                       qtype, rcode: int, ancount: int, msg_len: int,
                       answer_ips: Optional[list] = None) -> Optional[dict]:
        """One DNS message as parsed fields (also called by the fast reader)."""
        if qr == 1:
            ev = self._handle_response(qname or "", qtype, rcode, ancount, msg_len,
                                       client_ip=dst_ip, resolver_ip=src_ip, ts=ts)
            if answer_ips:
                ev["answer_ips"] = answer_ips
            return ev
        if qname:
            return self._handle_query(qname, qtype or 1, msg_len, src_ip, ts, dst_ip)
        return None

    def _handle_query(self, domain: str, qtype: int, msg_len: int, src_ip: str, ts: float,
                      dst_ip: str = None) -> Optional[dict]:
        if not domain:
            return None
        qtype = int(qtype or 1)
        self._total_queries += 1
        self._qtypes[qtype] += 1
        lexical = len(domain) >= 4 and not any(domain.lower().endswith(s) for s in SKIP_SUFFIXES)

        nxdomain_rate = self._get_nxdomain_rate(src_ip, ts)
        event = {
            "type": "dns",
            "domain": domain,
            "source_ip": src_ip,
            # The resolver this query went to: the actionable destination of a
            # DNS-path alert (an exfiltration alert that cannot say where the
            # data went is not actionable).
            "dest_ip": dst_ip,
            "query_type": qtype,
            "query_bytes": int(msg_len or 0),
            "timestamp": ts,
            "lexical": lexical,
        }
        if nxdomain_rate > self.nxdomain_threshold:
            event["nxdomain_flag"] = True
            event["nxdomain_count"] = nxdomain_rate
        return event

    def _handle_response(self, domain: str, qtype, rcode: int, ancount: int, msg_len: int,
                         client_ip: str, resolver_ip: str, ts: float) -> dict:
        self._total_responses += 1
        if rcode == RCODE_NXDOMAIN:
            self._total_nxdomains += 1
            self._nxdomain_history[client_ip].append((ts, domain))
        return {
            "type": "dns_response",
            "domain": domain,
            "source_ip": client_ip,
            "dest_ip": resolver_ip,
            "query_type": int(qtype or 0),
            "rcode": int(rcode),
            "answers": int(ancount),
            "response_bytes": int(msg_len or 0),
            "timestamp": ts,
        }

    def _get_nxdomain_rate(self, ip: str, current_time: float) -> int:
        """Get the number of NXDOMAINs from this IP in the tracking window."""
        history = self._nxdomain_history.get(ip, [])
        if not history:
            return 0
        cutoff = current_time - self.nxdomain_window
        fresh = [(t, d) for t, d in history if t > cutoff]
        self._nxdomain_history[ip] = fresh
        return len(fresh)

    def get_nxdomain_suspects(self, current_time: float = None) -> list[dict]:
        """IPs with high NXDOMAIN rates (likely DGA-infected hosts)."""
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
            "total_dns_responses": self._total_responses,
            "total_nxdomains": self._total_nxdomains,
            "tracked_ips": len(self._nxdomain_history),
            "query_types": {str(k): v for k, v in sorted(self._qtypes.items(), key=lambda kv: -kv[1])[:12]},
        }
