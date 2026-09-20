# netsentinel/extractor — PCAP → Model-Ready Feature Extraction
#
# This package translates raw network packets into the exact feature
# schemas each AI model expects:
#
#   PacketProcessor  ← orchestrator (use this)
#     ├── FlowExtractor          → 59 CIC features + 29 ETT features
#     ├── DNSExtractor           → domain strings for DGA model
#     ├── SessionBuilder         → 100-flow time-series for C2 model
#     ├── UNSWFeatureBuilder     → 39 UNSW-NB15 features for Port Scan model
#     └── DNSFeatureBuilder      → 24 DNS-lexical features for Exfil VAE model

from netsentinel.extractor.pcap_reader import PacketProcessor
from netsentinel.extractor.flow_extractor import FlowExtractor
from netsentinel.extractor.dns_extractor import DNSExtractor
from netsentinel.extractor.session_builder import SessionBuilder
from netsentinel.extractor.unsw_feature_builder import (
    build_unsw_features,
    ConnectionTracker,
)
from netsentinel.extractor.dns_feature_builder import build_dns_features

__all__ = [
    "PacketProcessor",
    "FlowExtractor",
    "DNSExtractor",
    "SessionBuilder",
    "build_unsw_features",
    "ConnectionTracker",
    "build_dns_features",
]

