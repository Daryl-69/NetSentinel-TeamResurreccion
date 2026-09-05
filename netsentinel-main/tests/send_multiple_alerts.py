"""Send multiple test alerts to demonstrate all threat types."""
import asyncio
import websockets
import json
from datetime import datetime, timezone
import time

async def send_alerts():
    uri = "ws://localhost:8000/ws"
    
    alerts = [
        # 1. DDoS Attack
        {
            "id": "test-ddos-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "threat_class": "DDoS",
            "confidence": 0.9937,
            "severity": "CRITICAL",
            "model_name": "DDoS XGBoost",
            "evidence": {"pps": 52450, "avg_pkt_size": 64, "syn_ack_ratio": 0.95},
            "mitre": {"tactic": "Impact", "technique": "T1498"},
            "geo": {"src_lat": 55.75, "src_lon": 37.62, "dst_lat": 28.61, "dst_lon": 77.21}
        },
        
        # 2. C2 Beacon
        {
            "id": "test-c2-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.75",
            "dest_ip": "185.220.101.34",
            "threat_class": "C2 Beacon",
            "confidence": 0.932,
            "severity": "HIGH",
            "model_name": "C2 BiLSTM+FFT",
            "evidence": {"beacon_interval": 58.3, "jitter": 0.12},
            "mitre": {"tactic": "Command and Control", "technique": "T1071"},
            "geo": {"src_lat": 28.61, "src_lon": 77.21, "dst_lat": 55.75, "dst_lon": 37.62}
        },
        
        # 3. DGA Domain
        {
            "id": "test-dga-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.42",
            "dest_ip": "8.8.8.8",
            "threat_class": "DGA",
            "confidence": 0.918,
            "severity": "HIGH",
            "model_name": "DGA CNN-BiLSTM",
            "evidence": {"domain": "xkqw8f3m.xyz", "entropy": 4.2, "bigram_score": 0.03},
            "mitre": {"tactic": "Command and Control", "technique": "T1568"},
            "geo": {"src_lat": 28.61, "src_lon": 77.21, "dst_lat": 37.39, "dst_lon": -122.08}
        },
        
        # 4. Port Scan
        {
            "id": "test-portscan-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.0.15",
            "dest_ip": "192.168.1.1",
            "threat_class": "Port Scan",
            "confidence": 0.873,
            "severity": "MEDIUM",
            "model_name": "DDoS XGBoost",
            "evidence": {"scan_rate": 120, "ports_targeted": 45},
            "mitre": {"tactic": "Discovery", "technique": "T1046"},
            "geo": {"src_lat": 51.51, "src_lon": -0.13, "dst_lat": 28.61, "dst_lon": 77.21}
        },
        
        # 5. Encrypted Malware
        {
            "id": "test-encrypted-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.88",
            "dest_ip": "103.224.182.250",
            "threat_class": "Encrypted",
            "confidence": 0.845,
            "severity": "HIGH",
            "model_name": "ETT Transformer",
            "evidence": {"flow_duration": 12.3, "bytes_per_packet": 512},
            "mitre": {"tactic": "Defense Evasion", "technique": "T1027"},
            "geo": {"src_lat": 28.61, "src_lon": 77.21, "dst_lat": 19.08, "dst_lon": 72.88}
        }
    ]
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"✓ Connected to {uri}\n")
            
            for i, alert in enumerate(alerts, 1):
                await websocket.send(json.dumps(alert))
                print(f"✓ Sent Alert {i}/5: {alert['threat_class']}")
                print(f"  - Source: {alert['source_ip']}")
                print(f"  - Confidence: {alert['confidence']*100:.1f}%")
                print(f"  - Severity: {alert['severity']}\n")
                
                # Wait 2 seconds between alerts
                await asyncio.sleep(2)
            
            print("✓ All alerts sent successfully!")
            print("\nCheck your dashboard at http://localhost:8443")
            print("You should see:")
            print("  - 5 alerts in the feed")
            print("  - Critical alert panel showing DDoS (highest severity)")
            print("  - 5 nodes in 3D graph")
            print("  - All 4 model cards active at different times")
            print("  - MITRE heatmap cells lit up")
            
            # Keep connection open briefly
            await asyncio.sleep(2)
            
    except ConnectionRefusedError:
        print("✗ Error: Could not connect to WebSocket")
        print("  Make sure backend is running: python run.py")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    asyncio.run(send_alerts())
