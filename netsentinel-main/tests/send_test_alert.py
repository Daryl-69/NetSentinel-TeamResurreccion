"""Send a test alert directly to the WebSocket for dashboard testing."""
import asyncio
import websockets
import json
from datetime import datetime, timezone

async def send_test_alert():
    uri = "ws://localhost:8000/ws"
    
    # Test alert matching backend schema
    alert = {
        "id": "test-ddos-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "threat_class": "DDoS",
        "threat_subtype": "SYN Flood",
        "confidence": 0.9937,
        "severity": "CRITICAL",
        "model_name": "DDoS XGBoost",
        "evidence": {
            "pps": 52450,
            "avg_pkt_size": 64,
            "syn_ack_ratio": 0.95
        },
        "mitre": {
            "tactic": "Impact",
            "technique": "T1498",
            "name": "Network Denial of Service"
        },
        "geo": {
            "src_country": "RU",
            "src_city": "Moscow",
            "src_lat": 55.75,
            "src_lon": 37.62,
            "dst_country": "IN",
            "dst_city": "New Delhi",
            "dst_lat": 28.61,
            "dst_lon": 77.21
        }
    }
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"✓ Connected to {uri}")
            
            # Send alert
            await websocket.send(json.dumps(alert))
            print(f"✓ Sent DDoS alert")
            print(f"  - Source: {alert['source_ip']}")
            print(f"  - Confidence: {alert['confidence']*100:.1f}%")
            print(f"  - Severity: {alert['severity']}")
            
            print("\n✓ Alert sent successfully!")
            print("  Check your dashboard at http://localhost:8443")
            print("  You should see:")
            print("    - Critical Alert Panel (top-center, red border)")
            print("    - New row in Alert Feed")
            print("    - 3D Graph nodes (Moscow → New Delhi)")
            print("    - Chart spike")
            print("    - DDoS XGBoost model card active (green dot)")
            
            # Keep connection open briefly to see any responses
            await asyncio.sleep(1)
            
    except ConnectionRefusedError:
        print("✗ Error: Could not connect to WebSocket")
        print("  Make sure backend is running: python run.py")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    asyncio.run(send_test_alert())
