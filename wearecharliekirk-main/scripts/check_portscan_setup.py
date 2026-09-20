"""
Port Scan Detection Setup Checker
==================================

Verifies that all components are properly configured for port scan testing.
"""

import os
import sys
from pathlib import Path


def check_component(name: str, check_func, fix_hint: str = None) -> bool:
    """Check a component and print status."""
    print(f"  {'Checking':12} {name:40} ... ", end="", flush=True)
    try:
        result = check_func()
        if result:
            print("✅")
            return True
        else:
            print("❌")
            if fix_hint:
                print(f"    💡 {fix_hint}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        if fix_hint:
            print(f"    💡 {fix_hint}")
        return False


def main():
    print(f"\n{'='*70}")
    print("🔍 Port Scan Detection - Setup Verification")
    print(f"{'='*70}\n")
    
    checks_passed = 0
    checks_total = 0
    
    # 1. Check Python packages
    print("📦 Python Dependencies:")
    
    def check_scapy():
        import scapy.all  # noqa: F401
        return True
    
    checks_total += 1
    if check_component("scapy", check_scapy, "pip install scapy"):
        checks_passed += 1
    
    def check_cicflowmeter():
        import cicflowmeter  # noqa: F401
        return True
    
    checks_total += 1
    if check_component("cicflowmeter", check_cicflowmeter, "pip install cicflowmeter"):
        checks_passed += 1
    
    def check_onnx():
        import onnxruntime  # noqa: F401
        return True
    
    checks_total += 1
    if check_component("onnxruntime", check_onnx, "pip install onnxruntime"):
        checks_passed += 1
    
    # 2. Check model files
    print("\n🤖 Model Files:")
    
    def check_model():
        return os.path.exists("models/portscan/port_scan_cic_xgboost.onnx")
    
    checks_total += 1
    if check_component("port_scan_cic_xgboost.onnx", check_model, 
                      "Ensure model is trained and exported to models/portscan/"):
        checks_passed += 1
    
    def check_features():
        return os.path.exists("models/portscan/port_scan_cic_features.json")
    
    checks_total += 1
    if check_component("port_scan_cic_features.json", check_features,
                      "Feature list should accompany the model"):
        checks_passed += 1
    
    # 3. Check PCAP files
    print("\n📁 PCAP Test Files:")
    
    pcap_files = list(Path(".").glob("*.pcap"))
    pcap_files.extend(Path(".").glob("**/*.pcap"))
    pcap_files = list(set(pcap_files))
    
    def check_pcaps():
        return len(pcap_files) > 0
    
    checks_total += 1
    if check_component(f"PCAP files ({len(pcap_files)} found)", check_pcaps,
                      "Download CIC-IDS2017 or UNSW-NB15 datasets"):
        checks_passed += 1
        
        # Show available PCAPs
        print("\n    Available PCAPs:")
        for pcap in sorted(pcap_files, key=lambda p: p.stat().st_size)[:5]:
            size_mb = pcap.stat().st_size / (1024 * 1024)
            print(f"      • {pcap.name:45} ({size_mb:>8.2f} MB)")
        if len(pcap_files) > 5:
            print(f"      ... and {len(pcap_files) - 5} more")
    
    # 4. Check testing scripts
    print("\n📜 Testing Scripts:")
    
    def check_script(name):
        return lambda: os.path.exists(name)
    
    scripts = [
        "test_portscan_pcap.py",
        "scan_pcaps_for_scans.py",
        "PORT_SCAN_TEST_GUIDE.md",
        "PORTSCAN_TESTING_README.md"
    ]
    
    for script in scripts:
        checks_total += 1
        if check_component(script, check_script(script)):
            checks_passed += 1
    
    # 5. Check code modifications
    print("\n🔧 Code Modifications:")
    
    def check_analyzer_improvements():
        with open("netsentinel/pipeline/analyzer.py", "r") as f:
            content = f.read()
            return "RELAXED DETECTION LOGIC" in content
    
    checks_total += 1
    if check_component("Relaxed detection logic", check_analyzer_improvements,
                      "Re-apply analyzer.py changes"):
        checks_passed += 1
    
    def check_main_improvements():
        with open("netsentinel/main.py", "r") as f:
            content = f.read()
            return "port_scan_burst_counter >= 15" in content
    
    checks_total += 1
    if check_component("Improved burst injection", check_main_improvements,
                      "Re-apply main.py changes"):
        checks_passed += 1
    
    def check_traffic_gen():
        with open("netsentinel/simulator/traffic_gen.py", "r") as f:
            content = f.read()
            return "15-40" in content or "random.randint(15, 40)" in content
    
    checks_total += 1
    if check_component("Larger burst size", check_traffic_gen,
                      "Re-apply traffic_gen.py changes"):
        checks_passed += 1
    
    # Summary
    print(f"\n{'='*70}")
    print(f"📊 Setup Summary")
    print(f"{'='*70}\n")
    
    percentage = (checks_passed / checks_total * 100) if checks_total > 0 else 0
    
    print(f"  Checks passed: {checks_passed}/{checks_total} ({percentage:.1f}%)")
    
    if checks_passed == checks_total:
        print("\n  ✅ All checks passed! You're ready to test.")
        print("\n  🚀 Next steps:")
        print("     1. python scan_pcaps_for_scans.py")
        print("     2. python test_portscan_pcap.py <best-file>.pcap")
        print("     3. python run.py + .\\start_mixed.ps1")
    elif checks_passed >= checks_total * 0.7:
        print("\n  ⚠️  Most checks passed. Review failures above.")
        print("     You can likely still test with some limitations.")
    else:
        print("\n  ❌ Several components missing. Review failures above.")
        print("     Install missing dependencies and ensure model files exist.")
    
    print(f"\n{'='*70}\n")
    
    return checks_passed == checks_total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
