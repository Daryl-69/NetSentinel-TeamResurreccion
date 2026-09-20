"""NetSentinel Configuration — Paths, Thresholds, Constants."""
import os
from pathlib import Path

# ============================================================
# Hugging Face Model Repository
# ============================================================
HF_REPO_ID = "Unded-17/netsentinel-models"
HF_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "netsentinel", "models")

# ============================================================
# Model Paths (with auto-download from HuggingFace)
# ============================================================
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
        if os.path.exists(env_path):
            return env_path

    # 1. A models/ directory shipped alongside the repo. This is the supported
    #    way to run without outbound internet, which is the normal case for a
    #    diode-protected or air-gapped site.
    repo_base = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"
    )
    repo_path = os.path.join(repo_base, relative_path)
    if os.path.exists(repo_path):
        return repo_path

    # Try local development path first
    local_base = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop", "models")
    local_path = os.path.join(local_base, relative_path)
    
    if os.path.exists(local_path):
        return local_path
    
    # Try cache directory
    cache_path = os.path.join(HF_CACHE_DIR, relative_path)
    
    if os.path.exists(cache_path):
        return cache_path
    
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
            cache_dir=HF_CACHE_DIR,
            local_dir=HF_CACHE_DIR,
            local_dir_use_symlinks=False,  # Copy file directly, don't use symlinks
        )
        
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

# Fake geo-IP locations for demo (attacker origins)
FAKE_GEO = {
    "attacker_1": {"ip": "185.220.101.34", "country": "RU", "lat": 55.75, "lon": 37.62, "city": "Moscow"},
    "attacker_2": {"ip": "116.31.116.42", "country": "CN", "lat": 23.13, "lon": 113.26, "city": "Guangzhou"},
    "attacker_3": {"ip": "45.33.32.156", "country": "US", "lat": 37.39, "lon": -122.08, "city": "Mountain View"},
    "attacker_4": {"ip": "91.189.89.88", "country": "GB", "lat": 51.51, "lon": -0.13, "city": "London"},
    "attacker_5": {"ip": "103.224.182.250", "country": "IN", "lat": 19.08, "lon": 72.88, "city": "Mumbai"},
}

# Target server (your "protected" server)
TARGET = {"ip": "10.0.0.1", "country": "IN", "lat": 28.61, "lon": 77.21, "city": "New Delhi"}

# ============================================================
# Extraction Layer Config
# ============================================================
FLOW_IDLE_TIMEOUT = 120       # Seconds of inactivity before a flow is flushed
FLOW_ACTIVE_TIMEOUT = 300     # Max seconds a flow can stay open
SESSION_MIN_FLOWS = 100       # Flows needed per (src, dst) pair for C2 detection
CAPTURE_INTERFACE = "Ethernet"  # Default Windows interface name (change for Linux)
PCAP_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "uploads")
os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)

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

