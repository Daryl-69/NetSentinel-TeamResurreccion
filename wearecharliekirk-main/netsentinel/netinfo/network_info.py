"""
netsentinel/netinfo/network_info.py

Loader and lookup helpers for the domain-knowledge file ``network_info.json``.

This is the piece that lets the network-event port-scan detector tell the
difference between "probing things that don't exist / aren't open" (a scan)
and ordinary traffic to real, expected services.

Usage
-----
    from netsentinel.netinfo.network_info import load_network_info

    ni = load_network_info("netsentinel/netinfo/network_info.json")
    ni.is_internal("192.168.10.7")        -> True
    ni.host_exists("192.168.10.7")        -> False  (not in known_hosts)
    ni.is_known_open("192.168.10.50", 22) -> True

Cold start
----------
If the file is missing, malformed, or has empty ``known_hosts`` /
``known_open_ports``, ``load_network_info`` does NOT raise. It logs a
WARNING and returns a ``NetworkInfo`` that degrades gracefully: every
``host_exists`` / ``is_known_open`` lookup used for NeIP / NeTCP will
resolve in a way that avoids false accusations (i.e. those two indicators
effectively become inert), matching the plan's degraded-detection mode.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Set, Union

logger = logging.getLogger("netsentinel.network_info")

DEFAULT_TIME_WINDOW_SECONDS = 60

IPLike = Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetworkLike = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class NetworkInfo:
    """In-memory representation of the monitored network's domain knowledge."""

    internal_subnets: List[str] = field(default_factory=list)
    known_hosts: Set[str] = field(default_factory=set)
    known_open_ports: Dict[str, List[int]] = field(default_factory=dict)
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS

    # Populated lazily from internal_subnets for fast membership checks.
    _networks: List[IPNetworkLike] = field(
        default_factory=list, repr=False, compare=False
    )

    # True when known_hosts/known_open_ports are unknown at deploy time.
    # When degraded, NeIP/NeTCP indicators are suppressed (never accuse a
    # host of "not existing" or a port of "not being open" when we simply
    # don't have the data to know).
    degraded: bool = False

    def __post_init__(self) -> None:
        self._networks = []
        for cidr in self.internal_subnets:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("network_info: ignoring invalid CIDR %r", cidr)

        if not self.known_hosts or not self.known_open_ports:
            self.degraded = True
            logger.warning(
                "network_info: known_hosts/known_open_ports incomplete - "
                "NeIP/NeTCP indicators are degraded (fan-out backstop and "
                "ICMP/RST/RwA indicators remain active)."
            )

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------
    def is_internal(self, ip: IPLike) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def host_exists(self, ip: IPLike) -> bool:
        """Whether ``ip`` is a known/expected internal host.

        In degraded mode (no known_hosts configured) we cannot safely claim
        a host doesn't exist, so we return True for every internal IP to
        avoid manufacturing false NeIP hits.
        """
        if self.degraded and not self.known_hosts:
            return True
        return str(ip) in self.known_hosts

    def is_known_open(self, ip: IPLike, port: int) -> bool:
        """Whether ``port`` is a documented open port on host ``ip``.

        In degraded mode (no known_open_ports configured at all) we cannot
        safely claim a port is closed, so we return True to avoid
        manufacturing false NeTCP hits.
        """
        if self.degraded and not self.known_open_ports:
            return True
        ports = self.known_open_ports.get(str(ip))
        if ports is None:
            # Host has no documented port list -> can't say the port is
            # "not open" with confidence.
            return True
        return int(port) in set(ports)

    def is_multicast_or_broadcast(self, ip: IPLike) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        if addr.is_multicast:
            return True
        if str(addr) == "255.255.255.255":
            return True
        # Subnet-directed broadcast, e.g. 192.168.10.255/24
        for net in self._networks:
            if addr == net.broadcast_address:
                return True
        return False


def _empty_network_info(reason: str) -> NetworkInfo:
    logger.warning("network_info: %s - falling back to cold-start defaults", reason)
    return NetworkInfo(
        internal_subnets=[],
        known_hosts=set(),
        known_open_ports={},
        time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
    )


def load_network_info(path: Union[str, Path]) -> NetworkInfo:
    """Load ``NetworkInfo`` from a JSON file, degrading gracefully on error."""
    p = Path(path)
    if not p.exists():
        return _empty_network_info(f"file not found: {p}")

    try:
        raw = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return _empty_network_info(f"could not parse {p}: {exc}")

    internal_subnets: Iterable[str] = raw.get("internal_subnets", []) or []
    known_hosts = set(raw.get("known_hosts", []) or [])
    known_open_ports = {
        str(k): [int(p) for p in v]
        for k, v in (raw.get("known_open_ports", {}) or {}).items()
    }
    time_window_seconds = int(
        raw.get("time_window_seconds", DEFAULT_TIME_WINDOW_SECONDS)
    )

    return NetworkInfo(
        internal_subnets=list(internal_subnets),
        known_hosts=known_hosts,
        known_open_ports=known_open_ports,
        time_window_seconds=time_window_seconds,
    )
