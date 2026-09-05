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
    1. Check ~/OneDrive/Desktop/models/ (local development)
    2. Check ~/.cache/netsentinel/models/ (downloaded from HF)
    3. Download from Hugging Face if not found
    
    Args:
        relative_path: Path relative to models folder (e.g., "Ddos_detection/ddos_binary_xgboost.onnx")
    
    Returns:
        Absolute path to the model file
    """
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

DGA_MODEL_PATH = get_model_path("dga_dna_tunneling_detection/dga_cnn_bilstm_v2.onnx")

ETT_MODEL_PATH = get_model_path("encrypted_traffic_transformer/encrypted_traffic_transformer.onnx")
ETT_SCALER_PATH = get_model_path("encrypted_traffic_transformer/ett_scaler.json")
ETT_CLASSES_PATH = get_model_path("encrypted_traffic_transformer/ett_classes.json")

PORT_SCAN_MODEL_PATH = get_model_path("port_scan/port_scan_xgboost.onnx")
PORT_SCAN_FEATURES_PATH = get_model_path("port_scan/port_scan_features.json")

EXFIL_MODEL_PATH = get_model_path("exfil/exfil_vae.onnx")
EXFIL_SCALER_PATH = get_model_path("exfil/exfil_scaler.joblib")
EXFIL_META_PATH = get_model_path("exfil/exfil_meta.json")

# ============================================================
# Detection Thresholds
# ============================================================
# If a model's confidence exceeds this threshold, an alert is generated.
THRESHOLDS = {
    "ddos": 0.95,
    "c2_beacon": 0.80,
    "dga": 0.80,
    "encrypted_malware": 0.70,
    "port_scan": 0.85,
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
