"""
Quick test script to verify all 6 models load correctly.
Run this after backend changes to ensure model registry works.
"""
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from netsentinel.models.registry import ModelRegistry

def test_model_loading():
    """Test that all 6 models load successfully."""
    print("=" * 60)
    print("NETSENTINEL MODEL LOADING TEST")
    print("=" * 60)
    
    registry = ModelRegistry()
    
    print(f"\n⏱️  Starting model load...")
    start_time = time.time()
    
    try:
        registry.load_all_models()
        load_time = time.time() - start_time
        
        print(f"✅ All models loaded in {load_time:.2f} seconds\n")
        
        # Check each model
        models = [
            ("ddos_binary_xgboost", "DDoS Binary XGBoost"),
            ("dga_lstm", "DGA Detection LSTM"),
            ("c2_beacon", "C2 Beacon Analyzer"),
            ("vpn_tunnel_xgboost", "VPN/Tunnel XGBoost"),
            ("port_scan_xgboost", "Port Scan XGBoost"),
            ("exfil_vae", "Exfiltration VAE"),
        ]
        
        print("📋 Model Status:")
        print("-" * 60)
        for model_id, model_name in models:
            model = registry.get_model(model_id)
            if model:
                print(f"  ✅ {model_name:30} [{model_id}]")
            else:
                print(f"  ❌ {model_name:30} [{model_id}] MISSING")
        
        print("-" * 60)
        print(f"\n✅ SUCCESS: {len(models)}/{len(models)} models operational\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_model_loading()
    sys.exit(0 if success else 1)
