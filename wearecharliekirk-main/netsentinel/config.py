"""NetSentinel Configuration — Paths, Thresholds, Constants."""
import os
from pathlib import Path

# ============================================================
# Hugging Face Model Repository
# ============================================================
HF_REPO_ID = "Unded-17/netsentinel-models"
HF_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "netsentinel", "models")
# Under `sudo` (needed for live capture) "~" is root's home; reuse the models
# the invoking user already downloaded instead of fetching them again.
SUDO_USER_CACHE_DIR = (
    os.path.join(os.path.expanduser(f"~{os.environ['SUDO_USER']}"), ".cache", "netsentinel", "models")
    if os.environ.get("SUDO_USER") else None
)

# ============================================================
# Model Paths (with auto-download from HuggingFace)
# ============================================================
def _is_real_file(path: str) -> bool:
    """True if `path` exists and is not a Git LFS pointer stub.

    models/ is tracked with Git LFS. A GitHub "Download ZIP" or a clone
    without git-lfs gives ~130-byte text stubs in place of the models;
    treating those as models makes every ONNX load fail with
    INVALID_PROTOBUF. Skip them so the lookup falls through to the cache
    and the HuggingFace download.
    """
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as f:
            return not f.read(64).startswith(b"version https://git-lfs")
    except OSError:
        return False


def get_model_path(relative_path: str) -> str:
    """
    Get model file path. Downloads from Hugging Face if not found locally.
    
    Priority:
    0. $NETSENTINEL_MODELS_DIR (explicit offline / air-gapped override)
    1. <repo>/models/ (offline bundle shipped with the checkout)
    2. ~/OneDrive/Desktop/models/ (local development)
    3. ~/.cache/netsentinel/models/ (downloaded from HF)
    4. Download from Hugging Face if not found
    
    Args:
        relative_path: Path relative to models folder (e.g., "Ddos_detection/ddos_binary_xgboost.onnx")
    
    Returns:
        Absolute path to the model file
    """
    # 0. Explicit override — offline / air-gapped installs point this at an
    #    out-of-band model bundle:  NETSENTINEL_MODELS_DIR=/path/to/models
    env_base = os.environ.get("NETSENTINEL_MODELS_DIR")
    if env_base:
        env_path = os.path.join(env_base, relative_path)
        if _is_real_file(env_path):
            return env_path

    # 1. A models/ directory shipped alongside the repo. This is the supported
    #    way to run without outbound internet, which is the normal case for a
    #    diode-protected or air-gapped site.
    repo_base = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"
    )
    repo_path = os.path.join(repo_base, relative_path)
    if _is_real_file(repo_path):
        return repo_path

    # Try local development path first
    local_base = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop", "models")
    local_path = os.path.join(local_base, relative_path)
    
    if _is_real_file(local_path):
        return local_path
    
    # Try cache directory
    cache_path = os.path.join(HF_CACHE_DIR, relative_path)
    
    if _is_real_file(cache_path):
        return cache_path

    if SUDO_USER_CACHE_DIR:
        sudo_path = os.path.join(SUDO_USER_CACHE_DIR, relative_path)
        if _is_real_file(sudo_path):
            return sudo_path
    
    # Download from Hugging Face
    print(f"  [INFO] Model not found locally, downloading from Hugging Face: {relative_path}")
    
    try:
        from huggingface_hub import hf_hub_download
        
        # Create cache directory
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        
        # Download file
        downloaded_path = hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=relative_path,
            local_dir=HF_CACHE_DIR,
        )

        # ONNX models exported with external weights need their companion
        # .onnx.data next to them (C2 Beacon, ETT, Exfil VAE); exfil_vae.onnx
        # references expert6_vae.onnx.data.
        if relative_path.endswith(".onnx"):
            companions = [relative_path + ".data"]
            if relative_path.endswith("exfil_vae.onnx"):
                companions.append(relative_path.replace("exfil_vae.onnx", "expert6_vae.onnx.data"))
            for companion in companions:
                if _is_real_file(os.path.join(HF_CACHE_DIR, companion)):
                    continue
                try:
                    hf_hub_download(repo_id=HF_REPO_ID, filename=companion, local_dir=HF_CACHE_DIR)
                    print(f"  [OK] Downloaded companion: {companion}")
                except Exception:
                    pass  # Not every model has external data
        
        print(f"  [OK] Downloaded: {relative_path}")
        return downloaded_path
        
    except ImportError:
        print(f"  [ERROR] huggingface_hub not installed. Install with: pip install huggingface_hub")
        print(f"  [ERROR] Or download models manually from: https://huggingface.co/{HF_REPO_ID}")
        raise
    except Exception as e:
        print(f"  [ERROR] Failed to download {relative_path}: {e}")
        print(f"  [INFO] Download manually from: https://huggingface.co/{HF_REPO_ID}/tree/main")
        raise


# Model paths using auto-download
DDOS_MODEL_PATH = get_model_path("Ddos_detection/ddos_binary_xgboost.onnx")
DDOS_FEATURES_PATH = get_model_path("Ddos_detection/feature_names.json")
DDOS_LABELS_PATH = get_model_path("Ddos_detection/label_mapping.json")

C2_MODEL_PATH = get_model_path("c2_beacon_detector/c2_beacon_bilstm.onnx")
C2_SEQ_MEAN_PATH = get_model_path("c2_beacon_detector/scaler_seq_mean.npy")
C2_SEQ_SCALE_PATH = get_model_path("c2_beacon_detector/scaler_seq_scale.npy")
C2_FFT_MEAN_PATH = get_model_path("c2_beacon_detector/scaler_fft_mean.npy")
C2_FFT_SCALE_PATH = get_model_path("c2_beacon_detector/scaler_fft_scale.npy")

DGA_MODEL_PATH = get_model_path("dga_dna_tunneling_detection/dga_cnn_bilstm.onnx")

ETT_MODEL_PATH = get_model_path("encrypted_traffic_transformer/encrypted_traffic_transformer.onnx")
ETT_SCALER_PATH = get_model_path("encrypted_traffic_transformer/ett_scaler.json")
ETT_CLASSES_PATH = get_model_path("encrypted_traffic_transformer/ett_classes.json")

PORT_SCAN_MODEL_PATH = get_model_path("portscan/port_scan_cic_xgboost.onnx")
PORT_SCAN_FEATURES_PATH = get_model_path("portscan/port_scan_cic_features.json")

EXFIL_MODEL_PATH = get_model_path("exfil/exfil_vae.onnx")
EXFIL_SCALER_PATH = get_model_path("exfil/exfil_scaler.joblib")
EXFIL_META_PATH = get_model_path("exfil/exfil_meta.json")

# ============================================================
# Detection Thresholds
# ============================================================
# If a model's confidence exceeds this threshold, an alert is generated.
# The encrypted-traffic transformer is a 14-class APPLICATION classifier
# (BROWSING/CHAT/FT/MAIL/P2P/STREAMING/VOIP and their VPN- variants, from the
# ISCX VPN-nonVPN dataset). "VPN-*" says a flow is tunnelled, NOT that it is
# malicious -- none of its classes are attack classes. Surfacing it as an alert
# made it 72% of all alert volume on ordinary traffic. It is now recorded as
# telemetry by default. Set True only if "a host is using a VPN" is a policy
# violation you actually want paged on.
ETT_ALERT_ON_VPN = False
# The encrypted-traffic application classifier costs ~1.5 ms per flow on one
# CPU core (its ONNX export takes one flow at a time) and produces telemetry,
# not alerts. Above this many flows per second it classifies a sample and
# counts the rest as not classified, so it cannot become the throughput
# ceiling of the detectors that do raise alerts. 0 = classify every flow.
ETT_MAX_PER_SECOND = 50

THRESHOLDS = {
    "ddos": 0.95,
    "c2_beacon": 0.80,
    "dga": 0.70,
    "encrypted_malware": 0.70,
    "port_scan": 0.85,  # Conservative threshold for production
    "exfiltration": 0.70,
}

# ============================================================
# Severity Mapping
# ============================================================
# Maps threat class → default severity (can be overridden by confidence)
SEVERITY_MAP = {
    "DDoS": "CRITICAL",
    "C2 Beacon": "HIGH",
    "DGA": "HIGH",
    "DNS Tunnel": "HIGH",
    "VPN Traffic": "MEDIUM",
    "Encrypted Malware": "CRITICAL",
    "Port Scan": "MEDIUM",
    "Data Exfiltration": "HIGH",
}

# ============================================================
# MITRE ATT&CK Mapping
# ============================================================
MITRE_MAP = {
    "DDoS": {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
    "C2 Beacon": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "DGA": {"tactic": "Command and Control", "technique": "T1568", "name": "Dynamic Resolution"},
    "DNS Tunnel": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "VPN Traffic": {"tactic": "Defense Evasion", "technique": "T1572", "name": "Protocol Tunneling"},
    "Encrypted Malware": {"tactic": "Command and Control", "technique": "T1573", "name": "Encrypted Channel"},
    "Port Scan": {"tactic": "Discovery", "technique": "T1046", "name": "Network Service Scanning"},
    "Data Exfiltration": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
}

# ============================================================
# Port Scan Detection Config (Network-Event Aggregation)
# ============================================================
class PortScanSettings:
    """Configuration for network-event-based port scan detection.
    
    Two detection modes:
    - "spsd": Supervised (DecisionTree trained on CIDDS-001) - recommended
    - "upsd": Unsupervised (sequential hypothesis testing) - no training needed
    """
    mode = "spsd"  # Permanent solution: trained DecisionTree model
    model_path = "netsentinel/models/weights/portscan_spsd_decisiontree.pkl"
    network_info_path = "netsentinel/netinfo/network_info.json"
    fanout_threshold = 100  # High fan-out (distinct ports) triggers alert regardless
    upsd_params = {
        "theta0": 0.8,    # H0 probability (normal traffic)
        "theta1": 0.2,    # H1 probability (scanner)
        "eta0": 0.001,    # Lower threshold (declare normal)
        "eta1": 999,      # Upper threshold (declare scanner) - minFP config
    }
    confidence_threshold = 0.5
    # Host-sweep backstop (horizontal scan): one source reaching this many
    # distinct hosts on the SAME destination port inside one window. Ports a
    # normal client fans out on towards the internet (DNS, web, NTP, DoT,
    # mDNS) are only counted when the targets are internal addresses.
    sweep_threshold = 32
    sweep_external_exempt_ports = (53, 80, 123, 443, 853, 5353)

# Create instance for easy access
portscan = PortScanSettings()

# ============================================================
# Server Config
# ============================================================
HOST = "0.0.0.0"
PORT = 8000
MAX_ALERTS_STORED = 1000  # Keep last N alerts in memory

# ============================================================
# Simulator Config
# ============================================================
SIMULATOR_NORMAL_RATE = 10    # Normal flows per second
SIMULATOR_ATTACK_RATE = 100   # Attack flows per second during burst

# Addresses the SYNTHETIC traffic simulator uses for its made-up attackers.
# Only netsentinel/simulator uses these. Alerts never carry geolocation: the
# sensor ships no GeoIP database, and the old code that attached made-up
# demo locations to real alerts (and filled a missing destination with
# TARGET) has been removed from alert_manager.py.
FAKE_GEO = {
    # RFC 5737 documentation addresses: never a real third party.
    "attacker_1": {"ip": "203.0.113.34"},
    "attacker_2": {"ip": "198.51.100.42"},
    "attacker_3": {"ip": "192.0.2.156"},
    "attacker_4": {"ip": "203.0.113.88"},
    "attacker_5": {"ip": "198.51.100.250"},
}

# Victim address used by the synthetic simulator only.
TARGET = {"ip": "10.0.0.1"}

# C2: the BiLSTM+FFT model scores 100-flow sessions and its verdict is
# attached to combined-score alerts as evidence. Set True to also let it
# raise alerts on its own (the pre-PS-26145 behaviour).
C2_BILSTM_ALERTS = False

# DGA / DNS-exfiltration model alerts: at most one per (source, base domain)
# per this many seconds of wire time. A name queried every minute used to
# raise an alert every minute (hundreds a day for one name on real traffic);
# the repeats are now counted in the next alert's evidence instead.
DNS_MODEL_ALERT_REPEAT_S = 600

# ============================================================
# Extraction Layer Config
# ============================================================
FLOW_IDLE_TIMEOUT = 120       # Seconds of inactivity before a flow is flushed
FLOW_ACTIVE_TIMEOUT = 300     # Max seconds a flow can stay open
SESSION_MIN_FLOWS = 100       # Flows needed per (src, dst) pair for C2 detection
# Interface for live capture. Empty = auto-detect the interface carrying the
# default route (eth0 / wlan0 / en0 / "Wi-Fi" ...). Override per request with
# POST /api/capture/start?interface=<name>, or set NETSENTINEL_IFACE.
CAPTURE_INTERFACE = os.environ.get("NETSENTINEL_IFACE", "")
PCAP_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "uploads")
os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)

# Live capture: how often idle flows are swept out, and how long a flow that
# has seen a single packet (an unanswered SYN, a lone UDP probe) waits before
# it is emitted as a probe record. These two numbers bound how late a scan or
# SYN-flood probe can reach the detectors in live mode.
LIVE_FLUSH_INTERVAL_S = 5
PROBE_FLOW_TIMEOUT_S = 5

# ============================================================
# PS 26145 detectors (rule-based and statistical)
# ============================================================
# Every threshold below was fixed before the detector was run on any capture.
# They are starting points for a new site, not tuned results.

# (b) No payload decryption. TLS fingerprints (JA3/JA3S/JA4) are computed
# from the cleartext ClientHello/ServerHello only. A QUIC ClientHello is
# inside the Initial packet, which is encrypted with keys anyone can derive
# from the packet header (RFC 9001 s5.2). Reading it means running that
# decryption, so it is OFF by default; set NETSENTINEL_QUIC_INITIAL_PARSE=1
# only if the site accepts that reading. Nothing else is ever decrypted.
QUIC_INITIAL_PARSE = os.getenv("NETSENTINEL_QUIC_INITIAL_PARSE", "false").lower() in ("true", "1", "yes")
TLS_FINGERPRINTING = True
TLS_BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "intel", "tls_fingerprint_blocklist.json")

# (a) DDoS: per-destination rate and source-IP entropy (flow level)
DDOS_VOLUME = {
    "window_s": 10,              # sliding window per destination (wire time)
    "min_flows_per_s": 100,      # new flows per second toward one destination
    "min_sources": 10,           # distributed: at least this many distinct sources in the window
    "shape_share": 0.8,          # share of the window's flows that are SYN-only / UDP
    "port_concentration": 0.5,   # top destination port share; below this a SYN burst is a scan, not a flood
    "baseline_multiplier": 5.0,  # once a baseline exists, the rate must exceed it this many times
    "baseline_alpha": 0.05,      # EWMA weight of each evaluation in the per-destination baseline
    "spoof_min_sources": 100,    # "spoofed sources likely" needs at least this many distinct sources...
    "spoof_unique_share": 0.9,   # ...almost every flow from a new source...
    "spoof_max_handshake": 0.05, # ...and almost no completed handshakes
    "cooldown_s": 30,            # one alert per destination and attack family per 30 s
}

# (c) DNS behaviour: record-type mix, NXDOMAIN rate, subdomain fan-out
DNS_BEHAVIOUR = {
    "window_s": 300,
    "nx_min_responses": 20,      # NXDOMAIN burst (DGA-style resolution failures)
    "nx_min_rate": 0.5,
    "nx_min_queries": 25,
    "nx_min_base_domains": 10,
    "tunnel_min_queries": 30,    # record-type anomaly toward one base domain
    "tunnel_min_unique_names": 20,
    "tunnel_rare_type_share": 0.5,
    "rare_types": ["TXT", "NULL", "CNAME", "MX", "SRV", "ANY", "PRIVATE"],
    "fanout_min_unique_names": 50,   # many unique long subdomains under one base domain
    "fanout_min_mean_label_len": 20,
    "cooldown_s": 300,
}

# (d) Encrypted sessions: JA3/JA4 rarity, session timing/size regularity,
# ClientHello anomalies. Unsupervised; no malware traffic was used to set it.
TLS_SESSIONS = {
    "window_s": 21600,
    "min_sessions": 8,
    "alert_score": 0.70,
    "weights": {"rarity": 0.30, "timing": 0.20, "size": 0.15, "shape": 0.15, "hello": 0.20},
    "rarity_min_population": 5,  # distinct TLS clients the sensor must have seen before rarity counts
    "cooldown_s": 3600,
    "tls_ports": [443, 8443, 993, 995, 465, 853, 5061, 636, 989, 990, 992, 994, 563, 5223],
}

# (f) Exfiltration by volume: out/in byte ratio of internal -> external flows
EXFIL_RATIO = {
    "window_s": 900,
    "min_out_bytes": 5_000_000,
    "min_ratio": 10.0,
    "cooldown_s": 900,
}

# (b) C2 beaconing: the combined periodicity score, run live. Same formula,
# weights and 0.80 threshold as model_comparisons/c2_beacon_score.py.
C2_COMBINED = {
    "window_s": 21600,
    "weights": {"T": 0.30, "F": 0.20, "S": 0.20, "R": 0.15, "C": 0.15},
    "threshold": 0.80,
    "min_checkins": 20,
    "min_span_s": 1800,
    "merge_gap_s": 5.0,
    "known_ports": [53, 123, 1900, 5353, 5355, 137, 138, 67, 68, 546, 547],
    "rescore_every": 5,
}

# ============================================================
# Integrity / Proof-Carrying Alerts Config
# ============================================================
INTEGRITY_ENABLED = os.getenv("INTEGRITY_ENABLED", "true").lower() in ("true", "1", "yes")
SENSOR_ID = os.getenv("SENSOR_ID", "sensor-07")
INTEGRITY_WINDOW_SECONDS = int(os.getenv("INTEGRITY_WINDOW_SECONDS", "60"))
INTEGRITY_CHECKPOINT_INTERVAL = int(os.getenv("INTEGRITY_CHECKPOINT_INTERVAL", "120"))
INTEGRITY_LEDGER_PATH = os.getenv(
    "INTEGRITY_LEDGER_PATH",
    os.path.join(os.path.dirname(__file__), "integrity", "data", "ledger.jsonl"),
)
INTEGRITY_KEY_PATH = os.getenv(
    "INTEGRITY_KEY_PATH",
    os.path.join(os.path.dirname(__file__), "integrity", "data", "nid_ed25519.key"),
)
INTEGRITY_PROOF_STORE_PATH = os.path.join(
    os.path.dirname(__file__), "integrity", "data", "proofs",
)
INTEGRITY_BLOB_STORE_PATH = os.path.join(
    os.path.dirname(__file__), "integrity", "data", "blobs",
)
INTEGRITY_BLOB_RETENTION_DAYS = int(os.getenv("INTEGRITY_BLOB_RETENTION_DAYS", "30"))
INTEGRITY_ANCHORS = ["git"]  # Start with git; add "opentimestamps", "rfc3161" later
MODEL_RELEASE_POLICY = "FLAG"  # "FLAG" = warn, "REFUSE" = block (Phase 2)
INTEGRITY_SEQ_PATH = os.path.join(
    os.path.dirname(__file__), "integrity", "data", "seq_state.json",
)

