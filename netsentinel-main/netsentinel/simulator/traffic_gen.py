"""Traffic Generator — Synthetic normal + attack traffic for demo.

Generates events that match what the models expect:
  - Normal flows (random browsing-like patterns)
  - DDoS flows (massive spike, small packets)
  - C2 Beacon sessions (periodic flows)
  - DGA DNS queries (random-looking domains)
  - Mixed mode (normal + random attacks)
"""
import random
import string
import numpy as np
from netsentinel.config import FAKE_GEO


# ============================================================
# Normal Traffic Generators
# ============================================================

def generate_normal_flow() -> dict:
    """Generate a single benign flow event (browsing-like)."""
    return {
        "type": "flow",
        "source_ip": f"192.168.1.{random.randint(2, 254)}",
        "dest_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "features": {
            # DDoS model features (59 features — fill key ones, rest 0)
            "Protocol": random.choice([6, 17]),  # TCP or UDP
            "Flow Duration": random.uniform(1000000, 60000000),
            "Total Fwd Packets": random.randint(5, 50),
            "Total Backward Packets": random.randint(5, 50),
            "Fwd Packets Length Total": random.uniform(500, 5000),
            "Bwd Packets Length Total": random.uniform(500, 5000),
            "Fwd Packet Length Max": random.uniform(100, 500),
            "Fwd Packet Length Min": random.uniform(40, 60),
            "Fwd Packet Length Mean": random.uniform(100, 300),
            "Fwd Packet Length Std": random.uniform(10, 50),
            "Bwd Packet Length Max": random.uniform(100, 500),
            "Bwd Packet Length Min": random.uniform(40, 60),
            "Bwd Packet Length Mean": random.uniform(100, 300),
            "Bwd Packet Length Std": random.uniform(10, 50),
            "Flow Bytes/s": random.uniform(100, 5000),
            "Flow Packets/s": random.uniform(1, 20),
            "Flow IAT Mean": random.uniform(10000, 500000),
            "Flow IAT Std": random.uniform(5000, 200000),
            "Flow IAT Max": random.uniform(100000, 1000000),
            "Flow IAT Min": random.uniform(1000, 5000),
            "SYN Flag Count": 0,
            "ACK Flag Count": random.randint(10, 50),
            "PSH Flag Count": random.randint(0, 5),
            "RST Flag Count": 0,
            "URG Flag Count": 0,
            "Avg Fwd Segment Size": random.uniform(100, 800),
            "Init Fwd Win Bytes": random.randint(8000, 65535),
            "Idle Mean": random.uniform(0, 500000),
            "Idle Std": random.uniform(0, 100000),
            # ETT model features
            "duration": random.uniform(100000, 60000000),
            "total_fiat": random.uniform(100000, 60000000),
            "total_biat": random.uniform(100000, 60000000),
            "min_fiat": random.uniform(5, 5000),
            "min_biat": random.uniform(0, 5000),
            "max_fiat": random.uniform(50000, 5000000),
            "max_biat": random.uniform(50000, 5000000),
            "mean_fiat": random.uniform(1000, 500000),
            "mean_biat": random.uniform(1000, 500000),
            "flowPktsPerSecond": random.uniform(5, 500),
            "flowBytesPerSecond": random.uniform(1000, 500000),
            "min_flowiat": random.uniform(0, 1000),
            "max_flowiat": random.uniform(10000, 5000000),
            "mean_flowiat": random.uniform(1000, 500000),
            "std_flowiat": random.uniform(500, 200000),
            "min_active": random.uniform(0, 1000000),
            "mean_active": random.uniform(0, 5000000),
            "max_active": random.uniform(0, 10000000),
            "std_active": random.uniform(0, 2000000),
            "min_idle": random.uniform(0, 1000000),
            "mean_idle": random.uniform(0, 5000000),
            "max_idle": random.uniform(0, 10000000),
            "std_idle": random.uniform(0, 2000000),
            "fwd_bwd_ratio": random.uniform(0.5, 2.0),
            "iat_cv": random.uniform(0.5, 3.0),
            "iat_range_norm": random.uniform(1, 10),
            "active_idle_ratio": random.uniform(0.1, 5.0),
            "duration_log": random.uniform(10, 18),
            "bytes_per_packet": random.uniform(50, 1000),
        }
    }


def generate_normal_dns() -> dict:
    """Generate a benign DNS query."""
    legit_domains = [
        "google.com", "facebook.com", "youtube.com", "amazon.com",
        "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
        "reddit.com", "netflix.com", "github.com", "stackoverflow.com",
        "microsoft.com", "apple.com", "cloudflare.com", "aws.amazon.com",
        "mail.google.com", "docs.google.com", "drive.google.com",
    ]
    return {
        "type": "dns",
        "domain": random.choice(legit_domains),
        "source_ip": f"192.168.1.{random.randint(2, 254)}",
    }


# ============================================================
# Attack Traffic Generators
# ============================================================

def generate_ddos_flow() -> dict:
    """Generate a DDoS attack flow (SYN flood characteristics)."""
    attacker = random.choice(list(FAKE_GEO.values()))
    return {
        "type": "flow",
        "source_ip": attacker["ip"],
        "dest_ip": "10.0.0.1",
        "features": {
            "Protocol": 6,  # TCP
            "Flow Duration": random.uniform(0, 1000),  # Very short
            "Total Fwd Packets": random.randint(1, 3),  # Minimal packets
            "Total Backward Packets": 0,  # No response (SYN flood)
            "Fwd Packets Length Total": random.uniform(40, 80),  # Tiny
            "Bwd Packets Length Total": 0,
            "Fwd Packet Length Max": 60,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 50,
            "Fwd Packet Length Std": 5,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": random.uniform(5000000, 50000000),  # Very high
            "Flow Packets/s": random.uniform(50000, 500000),  # Very high
            "Flow IAT Mean": random.uniform(0, 10),  # Rapid-fire
            "Flow IAT Std": random.uniform(0, 5),
            "Flow IAT Max": random.uniform(0, 50),
            "Flow IAT Min": 0,
            "SYN Flag Count": random.randint(1, 5),  # SYN flood
            "ACK Flag Count": 0,  # No ACK
            "PSH Flag Count": 0,
            "RST Flag Count": 0,
            "URG Flag Count": 0,
            "Avg Fwd Segment Size": 50,
            "Init Fwd Win Bytes": random.randint(1024, 4096),
            "Idle Mean": 0,
            "Idle Std": 0,
            # ETT features (short attack flow)
            "duration": random.uniform(0, 1000),
            "total_fiat": random.uniform(0, 1000),
            "total_biat": 0,
            "min_fiat": 0,
            "min_biat": 0,
            "max_fiat": random.uniform(0, 100),
            "max_biat": 0,
            "mean_fiat": random.uniform(0, 50),
            "mean_biat": 0,
            "flowPktsPerSecond": random.uniform(50000, 500000),
            "flowBytesPerSecond": random.uniform(5000000, 50000000),
            "min_flowiat": 0,
            "max_flowiat": random.uniform(0, 50),
            "mean_flowiat": random.uniform(0, 10),
            "std_flowiat": random.uniform(0, 5),
            "min_active": 0, "mean_active": 0, "max_active": 0, "std_active": 0,
            "min_idle": 0, "mean_idle": 0, "max_idle": 0, "std_idle": 0,
            "fwd_bwd_ratio": 999.0,  # All outbound
            "iat_cv": 0.1,  # Very periodic
            "iat_range_norm": 0.5,
            "active_idle_ratio": 999.0,
            "duration_log": 2.0,
            "bytes_per_packet": 50,
        }
    }


def generate_dga_dns() -> dict:
    """Generate a DGA-style DNS query (random-looking domain)."""
    # Generate random domain that looks like DGA output
    length = random.randint(8, 20)
    chars = string.ascii_lowercase + string.digits
    random_domain = ''.join(random.choice(chars) for _ in range(length))
    tld = random.choice([".com", ".xyz", ".top", ".tk", ".net", ".info"])
    
    attacker = random.choice(list(FAKE_GEO.values()))
    return {
        "type": "dns",
        "domain": random_domain + tld,
        "source_ip": attacker["ip"],
    }


def generate_c2_session() -> dict:
    """Generate a C2 beacon session (periodic flows)."""
    beacon_interval = random.uniform(30, 120)  # seconds
    jitter = beacon_interval * 0.05  # 5% jitter
    
    flows = []
    for i in range(100):
        iat = beacon_interval + random.uniform(-jitter, jitter)
        flows.append({
            "iat": iat,
            "packet_size": random.randint(60, 200),  # Small C2 packets
            "bytes": random.randint(100, 500),
            "direction": 1 if i % 2 == 0 else 0,  # Alternating
        })
    
    attacker = random.choice(list(FAKE_GEO.values()))
    return {
        "type": "session",
        "flows": flows,
        "source_ip": f"192.168.1.{random.randint(2, 254)}",
        "dest_ip": attacker["ip"],
    }


def generate_port_scan_flow() -> dict:
    """Generate a port-scan flow event (SYN scan characteristics).
    
    Port scans have: high connection rate, low packets per flow,
    sequential port targeting, and mostly SYN-only packets.
    """
    attacker = random.choice(list(FAKE_GEO.values()))
    target_port = random.randint(1, 65535)
    return {
        "type": "flow",
        "source_ip": attacker["ip"],
        "dest_ip": "10.0.0.1",
        "source_port": random.randint(49152, 65535),
        "dest_port": target_port,
        "protocol": 6,
        "features": {
            "Protocol": 6,  # TCP
            "Flow Duration": random.uniform(0, 500),  # Very short
            "Total Fwd Packets": 1,  # SYN only
            "Total Backward Packets": random.choice([0, 1]),  # Maybe SYN-ACK
            "Fwd Packets Length Total": 40,
            "Bwd Packets Length Total": random.choice([0, 40]),
            "Fwd Packet Length Max": 40,
            "Fwd Packet Length Min": 40,
            "Fwd Packet Length Mean": 40,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": random.uniform(1000, 10000),
            "Flow Packets/s": random.uniform(50, 500),  # Moderate rate
            "Flow IAT Mean": random.uniform(0, 100),
            "Flow IAT Std": random.uniform(0, 50),
            "Flow IAT Max": random.uniform(0, 200),
            "Flow IAT Min": 0,
            "Fwd IAT Mean": 0,
            "Bwd IAT Total": 0,
            "Bwd IAT Mean": 0,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "SYN Flag Count": 1,  # SYN scan
            "ACK Flag Count": 0,
            "RST Flag Count": random.choice([0, 1]),  # Port closed → RST
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "Fwd PSH Flags": 0,
            "Fwd Header Length": 20,
            "Bwd Header Length": 0,
            "Bwd Packets/s": 0,
            "Packet Length Max": 40,
            "Packet Length Mean": 40,
            "Packet Length Std": 0,
            "Packet Length Variance": 0,
            "Down/Up Ratio": 0,
            "Avg Packet Size": 40,
            "Avg Fwd Segment Size": 40,
            "Avg Bwd Segment Size": 0,
            "Subflow Fwd Packets": 1,
            "Subflow Fwd Bytes": 40,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init Fwd Win Bytes": random.randint(1024, 4096),
            "Init Bwd Win Bytes": 0,
            "Fwd Act Data Packets": 0,
            "Fwd Seg Size Min": 40,
            "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0,
            "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
            # ETT features (minimal for scan)
            "duration": random.uniform(0, 500),
            "total_fiat": 0, "total_biat": 0,
            "min_fiat": 0, "min_biat": 0,
            "max_fiat": 0, "max_biat": 0,
            "mean_fiat": 0, "mean_biat": 0,
            "flowPktsPerSecond": random.uniform(50, 500),
            "flowBytesPerSecond": random.uniform(1000, 10000),
            "min_flowiat": 0, "max_flowiat": 0,
            "mean_flowiat": 0, "std_flowiat": 0,
            "min_active": 0, "mean_active": 0, "max_active": 0, "std_active": 0,
            "min_idle": 0, "mean_idle": 0, "max_idle": 0, "std_idle": 0,
            "fwd_bwd_ratio": 999.0,
            "iat_cv": 0.1,
            "iat_range_norm": 0.5,
            "active_idle_ratio": 999.0,
            "duration_log": 2.0,
            "bytes_per_packet": 40,
        }
    }


def generate_exfil_dns() -> dict:
    """Generate a DNS-tunneling exfiltration query.
    
    DNS tunnel domains have: very long subdomains, high entropy,
    hex-encoded data payloads, many labels.
    """
    # Generate a domain that looks like DNS tunneling
    # Encode "data" as hex in the subdomain
    data_len = random.randint(20, 50)
    hex_data = ''.join(random.choice('0123456789abcdef') for _ in range(data_len))
    # Split into chunks for subdomain labels
    chunk_size = random.randint(10, 20)
    chunks = [hex_data[i:i+chunk_size] for i in range(0, len(hex_data), chunk_size)]
    tunnel_domain = '.'.join(chunks) + '.' + random.choice([
        'evil-tunnel.com', 'data-exfil.net', 'c2-dns.xyz',
        'exfiltrate.top', 'tunnel-data.info',
    ])
    
    attacker = random.choice(list(FAKE_GEO.values()))
    return {
        "type": "dns",
        "domain": tunnel_domain,
        "source_ip": f"192.168.1.{random.randint(2, 254)}",
    }


# ============================================================
# Mixed Mode Generator
# ============================================================

def generate_event(attack_mode: str = "normal") -> dict:
    """
    Generate a single event based on attack mode.
    
    Args:
        attack_mode: "normal", "ddos", "dga", "c2", "port_scan",
                     "exfil", or "mixed"
    
    Returns:
        Event dict ready for FlowAnalyzer
    """
    if attack_mode == "normal":
        # 80% flow, 20% DNS
        if random.random() < 0.8:
            return generate_normal_flow()
        return generate_normal_dns()
    
    elif attack_mode == "ddos":
        return generate_ddos_flow()
    
    elif attack_mode == "dga":
        return generate_dga_dns()
    
    elif attack_mode == "c2":
        return generate_c2_session()

    elif attack_mode == "port_scan":
        return generate_port_scan_flow()

    elif attack_mode == "exfil":
        return generate_exfil_dns()
    
    elif attack_mode == "mixed":
        # Normal background with random attack injection (all 6 classes)
        r = random.random()
        if r < 0.45:
            return generate_normal_flow()
        elif r < 0.55:
            return generate_normal_dns()
        elif r < 0.65:
            return generate_ddos_flow()
        elif r < 0.73:
            return generate_dga_dns()
        elif r < 0.80:
            return generate_c2_session()
        elif r < 0.88:
            return generate_port_scan_flow()
        elif r < 0.95:
            return generate_exfil_dns()
        else:
            return generate_normal_flow()
    
    return generate_normal_flow()
