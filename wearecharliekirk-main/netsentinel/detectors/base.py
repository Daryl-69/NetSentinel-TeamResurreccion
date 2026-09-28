"""Shared helpers for the rule-based and statistical detectors.

These detectors complement the trained models where PS 26145 asks for a
behaviour the models do not cover (source-IP entropy, record-type mix,
fingerprint rarity, out/in byte ratio, periodicity). Each one:

* has a fixed parameter set (from netsentinel/config.py) and a digest of it,
  so a receipt can say exactly which rule version made a call;
* returns its decision together with the numbers it used, so the alert's
  evidence shows why it fired;
* can re-derive its decision from those numbers (``replay``), which is what
  the integrity layer's reproducibility check runs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from collections import Counter
from typing import Iterable, Optional

import numpy as np


def params_digest(name: str, version: str, params: dict) -> str:
    """sha256 over the detector's name, version and parameters (canonical JSON)."""
    blob = json.dumps({"detector": name, "version": version, "params": params},
                      sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


class RuleDetector:
    """Base class: name, version, params, digest, replay."""
    key: str = "rule"
    name: str = "rule"
    version: str = "1"
    confidence_kind: str = "rule_score"

    def __init__(self, params: dict):
        self.params = dict(params)
        self.runs = 0
        self.alerts = 0
        self.suppressed = 0

    @property
    def digest(self) -> str:
        return params_digest(self.name, self.version, self.params)

    def describe(self) -> dict:
        return {
            "key": self.key, "name": self.name, "version": self.version,
            "digest": self.digest, "params": self.params,
            "confidence_kind": self.confidence_kind,
            "runs": self.runs, "alerts": self.alerts, "suppressed": self.suppressed,
        }

    def replay(self, inputs: dict) -> Optional[dict]:  # pragma: no cover - overridden
        return None


# ---------------------------------------------------------------- addresses
def ip_obj(ip):
    try:
        return ipaddress.ip_address(str(ip))
    except ValueError:
        return None


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def is_internal(ip) -> bool:
    """RFC 1918, CGNAT (RFC 6598) and IPv6 ULA space: the monitored side."""
    a = ip_obj(ip)
    return a is not None and any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def is_external(ip) -> bool:
    """Anything routable that is not internal (unicast, not loopback,
    link-local, multicast, unspecified or reserved)."""
    a = ip_obj(ip)
    if a is None or is_internal(ip):
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
                or (a.version == 4 and a.is_reserved) or str(a) == "255.255.255.255")


def is_skip_destination(ip) -> bool:
    """Multicast, link-local, broadcast, unspecified: never a beacon target."""
    a = ip_obj(ip)
    if a is None:
        return True
    return a.is_multicast or a.is_link_local or a.is_unspecified or str(a) == "255.255.255.255"


def is_group_destination(ip) -> bool:
    """Multicast, limited broadcast or unspecified: a packet no single host
    answers (mDNS, SSDP, LLMNR, DHCP discovery...). Unanswered by design, so
    never a scan target. Unknown or missing addresses are not group ones."""
    if not ip:
        return False
    a = ip_obj(ip)
    if a is None:
        return False
    return a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255"


def is_bogon(ip) -> bool:
    """Addresses that cannot be a real internet source."""
    a = ip_obj(ip)
    if a is None:
        return True
    return a.is_unspecified or a.is_loopback or a.is_multicast or a.is_reserved


# ---------------------------------------------------------------- statistics
def shannon_bits(counts: Iterable[int]) -> float:
    counts = [c for c in counts if c > 0]
    total = float(sum(counts))
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts)


def mad_ratio(x) -> float:
    """Median absolute deviation over the median (1.0 when undefined)."""
    x = np.asarray(x, dtype=np.float64)
    if x.size == 0:
        return 1.0
    med = np.median(x)
    return 1.0 if med <= 0 else float(np.median(np.abs(x - med)) / med)


def clamp01(v: float) -> float:
    return 0.0 if v != v else max(0.0, min(1.0, float(v)))


def most_common(counter: Counter):
    if not counter:
        return None, 0
    k, n = counter.most_common(1)[0]
    return k, n


def base_domain(name: str) -> str:
    """Registrable-domain approximation without a public-suffix list.

    "a.b.example.com" -> "example.com"; "x.example.co.in" -> "example.co.in".
    Good enough to group the queries of one tunnel; not a PSL substitute.
    """
    parts = [p for p in name.lower().strip().rstrip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu", "nic", "res", "gen", "ind", "mil"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class Cooldown:
    """At most one alert per key per `seconds` of wire time; counts the rest."""

    def __init__(self, seconds: float, max_keys: int = 50000):
        self.seconds = float(seconds)
        self.max_keys = max_keys
        self._last: dict = {}
        self._held: dict = {}

    def allow(self, key, ts: float) -> tuple[bool, int]:
        """Returns (allowed, suppressed_since_last_alert)."""
        last = self._last.get(key)
        if last is not None and ts - last < self.seconds:
            self._held[key] = self._held.get(key, 0) + 1
            return False, self._held[key]
        held = self._held.pop(key, 0)
        self._last[key] = ts
        if len(self._last) > self.max_keys:
            for k in list(self._last)[: len(self._last) // 4]:
                self._last.pop(k, None)
                self._held.pop(k, None)
        return True, held
