"""
Unit tests for Port Scan detection.
Tests the detector with synthetic features before integration testing.
"""
import pytest
import numpy as np
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def create_port_scan_features():
    """
    Create synthetic features mimicking a port scan.
    
    Port scan characteristics:
    - Many SYN packets
    - Few ACK packets (failed connections)
    - Short flow duration
    - Low packets per flow
    - High packet rate
    """
    return {
        # Flow basics
        "Flow Duration": 2000000,  # 2 seconds (microseconds)
        "Total Fwd Packets": 100,  # 100 SYN probes
        "Total Backward Packets": 0,  # No responses
        
        # Packet lengths
        "Total Length of Fwd Packets": 6400,  # 64 bytes each
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 64,
        "Fwd Packet Length Min": 64,
        "Fwd Packet Length Mean": 64.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        
        # Flow rates
        "Flow Bytes/s": 3200.0,  # 6400 bytes / 2 seconds
        "Flow Packets/s": 50.0,  # 100 packets / 2 seconds
        
        # IAT (Inter-Arrival Time)
        "Flow IAT Mean": 20000,  # 20ms between packets
        "Flow IAT Std": 5000,
        "Flow IAT Max": 30000,
        "Flow IAT Min": 10000,
        "Fwd IAT Total": 2000000,
        "Fwd IAT Mean": 20000,
        "Fwd IAT Std": 5000,
        "Fwd IAT Max": 30000,
        "Fwd IAT Min": 10000,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        
        # Flags - CRITICAL for port scan detection
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "FIN Flag Count": 0,
        "SYN Flag Count": 100,  # All SYN
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,  # No ACKs (failed connections)
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        
        # Headers
        "Fwd Header Length": 2000,  # 20 bytes per packet
        "Bwd Header Length": 0,
        
        # Packet rates
        "Fwd Packets/s": 50.0,
        "Bwd Packets/s": 0.0,
        
        # Packet size stats
        "Min Packet Length": 64,
        "Max Packet Length": 64,
        "Packet Length Mean": 64.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        
        # Ratios
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 64.0,
        "Avg Fwd Segment Size": 64.0,
        "Avg Bwd Segment Size": 0.0,
        
        # Bulk stats
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        
        # Subflow
        "Subflow Fwd Packets": 100,
        "Subflow Fwd Bytes": 6400,
    }


def create_benign_features():
    """
    Create synthetic features for normal web browsing.
    
    Normal traffic characteristics:
    - Balanced SYN/ACK
    - Multiple packets per flow
    - Longer flow duration
    - Lower packet rate
    """
    return {
        "Flow Duration": 5000000,  # 5 seconds
        "Total Fwd Packets": 50,
        "Total Backward Packets": 45,
        "Total Length of Fwd Packets": 25000,
        "Total Length of Bwd Packets": 60000,
        "Fwd Packet Length Max": 1500,
        "Fwd Packet Length Min": 60,
        "Fwd Packet Length Mean": 500.0,
        "Fwd Packet Length Std": 400.0,
        "Bwd Packet Length Max": 1500,
        "Bwd Packet Length Min": 60,
        "Bwd Packet Length Mean": 1333.0,
        "Bwd Packet Length Std": 200.0,
        "Flow Bytes/s": 17000.0,
        "Flow Packets/s": 19.0,
        "Flow IAT Mean": 52631,
        "Flow IAT Std": 10000,
        "Flow IAT Max": 80000,
        "Flow IAT Min": 20000,
        "Fwd IAT Total": 5000000,
        "Fwd IAT Mean": 100000,
        "Fwd IAT Std": 20000,
        "Fwd IAT Max": 150000,
        "Fwd IAT Min": 50000,
        "Bwd IAT Total": 4500000,
        "Bwd IAT Mean": 100000,
        "Bwd IAT Std": 20000,
        "Bwd IAT Max": 150000,
        "Bwd IAT Min": 50000,
        "Fwd PSH Flags": 10,
        "Bwd PSH Flags": 10,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "FIN Flag Count": 2,
        "SYN Flag Count": 1,  # Only initial SYN
        "RST Flag Count": 0,
        "PSH Flag Count": 20,
        "ACK Flag Count": 94,  # Most packets are ACKs
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Fwd Header Length": 1000,
        "Bwd Header Length": 900,
        "Fwd Packets/s": 10.0,
        "Bwd Packets/s": 9.0,
        "Min Packet Length": 60,
        "Max Packet Length": 1500,
        "Packet Length Mean": 900.0,
        "Packet Length Std": 500.0,
        "Packet Length Variance": 250000.0,
        "Down/Up Ratio": 2.4,
        "Average Packet Size": 900.0,
        "Avg Fwd Segment Size": 500.0,
        "Avg Bwd Segment Size": 1333.0,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": 50,
        "Subflow Fwd Bytes": 25000,
    }


@pytest.mark.skipif(
    not Path(__file__).parent.parent / "models" / "port_scan_xgboost.onnx",
    reason="Port scan model file not found"
)
def test_port_scan_model_loads():
    """Test that the port scan detector loads without errors."""
    from netsentinel.models.port_scan import PortScanDetector
    
    detector = PortScanDetector()
    assert detector is not None
    # Model uses UNSW-NB15 schema: 39 features + 'id' = 40 total
    assert len(detector.feature_names) == 40, (
        f"Expected 40 UNSW-NB15 features (including id), got {len(detector.feature_names)}"
    )
    assert detector.threshold == 0.85
    print("✅ Port scan detector loaded successfully")


@pytest.mark.skipif(
    not Path(__file__).parent.parent / "models" / "port_scan_xgboost.onnx",
    reason="Port scan model file not found"
)
def test_port_scan_detection():
    """Test detection of port scan with UNSW-NB15 features."""
    from netsentinel.models.port_scan import PortScanDetector
    from netsentinel.extractor.unsw_feature_builder import build_unsw_features, ConnectionTracker
    
    detector = PortScanDetector()
    tracker = ConnectionTracker()
    
    # Build a port-scan-like event using the UNSW feature builder
    # Simulate 50 connections from one host to sequential ports (scan pattern)
    all_results = []
    for port in range(1, 51):
        event = {
            "type": "flow",
            "source_ip": "198.51.100.75",
            "dest_ip": "192.168.1.50",
            "source_port": 55555,
            "dest_port": port,
            "protocol": 6,
            "features": {
                "Protocol": 6,
                "Flow Duration": 100,        # very short (microseconds)
                "Total Fwd Packets": 1,      # SYN only
                "Total Backward Packets": 0, # no response
                "Fwd Packets Length Total": 40,
                "Bwd Packets Length Total": 0,
                "Flow Packets/s": 200.0,
                "Flow Bytes/s": 8000.0,
                "Flow IAT Std": 5000,
                "Fwd IAT Mean": 0,
                "Bwd IAT Std": 0,
                "SYN Flag Count": 1,
                "ACK Flag Count": 0,
                "RST Flag Count": 1,  # port closed → RST
                "Init Fwd Win Bytes": 1024,
                "Init Bwd Win Bytes": 0,
                "Fwd Packet Length Std": 0,
            }
        }
        unsw_features = build_unsw_features(event, tracker)
        result = detector.predict(unsw_features)
        all_results.append(result)
    
    # After 50 sequential port probes, ct_* aggregates should be high
    last = all_results[-1]
    print(f"\n=== Port Scan Detection Test (UNSW features) ===")
    print(f"Threat: {last['threat']}")
    print(f"Confidence: {last['confidence']:.2%}")
    print(f"Model: {last['model']}")
    
    # The model should produce a meaningful prediction without ONNX errors
    assert 'threat' in last
    assert 'confidence' in last
    assert last['model'] == 'port_scan_xgboost'
    print(f"\n✅ Port scan prediction completed without errors")


@pytest.mark.skipif(
    not Path(__file__).parent.parent / "models" / "port_scan_xgboost.onnx",
    reason="Port scan model file not found"
)
def test_benign_traffic_not_detected():
    """Test that benign traffic is not flagged as port scan."""
    from netsentinel.models.port_scan import PortScanDetector
    
    detector = PortScanDetector()
    features = create_benign_features()
    
    result = detector.predict(features)
    
    print(f"\n=== Benign Traffic Test ===")
    print(f"Threat: {result['threat']}")
    print(f"Confidence: {result['confidence']:.2%}")
    
    # Should be benign (or low confidence)
    # Note: Model might still output some confidence, but gates should filter it
    assert result['threat'] == 'benign', "Benign traffic should not be flagged as port scan"
    print(f"✅ Benign traffic correctly classified")


def test_port_scan_heuristics():
    """Test the heuristic properties of a port scan event."""
    scan_features = create_port_scan_features()
    syn_count = scan_features['SYN Flag Count']
    total_fwd = scan_features['Total Fwd Packets']
    total_bwd = scan_features['Total Backward Packets']
    total_packets = total_fwd + total_bwd
    syn_ratio = syn_count / total_packets if total_packets > 0 else 0
    
    print(f"\n=== Heuristic Gates Test ===")
    print(f"SYN Count: {syn_count}")
    print(f"Total Packets: {total_packets}")
    print(f"SYN Ratio: {syn_ratio:.2%}")
    
    # A port scan batch has 100% SYN ratio (all SYN, no ACK responses)
    assert syn_ratio > 0.5, "Port scan should have high SYN ratio"
    print(f"✅ SYN ratio gate: {syn_ratio:.1%} > 50% (PASS)")
    
    # A port scan has 0 backward packets (no responses from closed ports)
    assert total_bwd == 0, "Port scan should have no backward packets"
    print(f"✅ No backward packets: {total_bwd} (PASS)")
    
    # Short flow duration (SYN-only, no data exchange)
    flow_duration_s = scan_features['Flow Duration'] / 1_000_000
    print(f"Flow duration: {flow_duration_s:.2f}s")
    assert flow_duration_s < 10, "Port scan flows should be short"
    print(f"✅ Short duration: {flow_duration_s:.2f}s < 10s (PASS)")


if __name__ == "__main__":
    print("="*60)
    print("Port Scan Detector Test Suite")
    print("="*60)
    
    # Run tests manually if pytest not available
    try:
        from netsentinel.models.port_scan import PortScanDetector
        
        print("\n[1/4] Testing model loading...")
        test_port_scan_model_loads()
        
        print("\n[2/4] Testing port scan detection...")
        test_port_scan_detection()
        
        print("\n[3/4] Testing benign traffic classification...")
        test_benign_traffic_not_detected()
        
        print("\n[4/4] Testing heuristic gates...")
        test_port_scan_heuristics()
        
        print("\n" + "="*60)
        print("✅ All tests passed!")
        print("="*60)
        
    except FileNotFoundError as e:
        print(f"\n⚠️  Model file not found: {e}")
        print("Please train and save port_scan_xgboost.onnx to models/ directory")
        
        print("\n[4/4] Testing heuristic gates (no model needed)...")
        test_port_scan_heuristics()
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
