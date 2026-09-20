"""
Live system test with real PCAP file.
Tests the full pipeline: PCAP → Feature Extraction → Model Inference → Alerts
"""
import sys
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from netsentinel.extractor import PacketProcessor
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.pipeline.alert_manager import AlertManager


def test_live_pcap(pcap_path: str):
    """Test full pipeline with a real PCAP file."""
    print("=" * 80)
    print("NETSENTINEL LIVE SYSTEM TEST")
    print("=" * 80)

    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        print(f"❌ ERROR: PCAP file not found: {pcap_path}")
        return False

    print(f"\n📁 PCAP File: {pcap_file.name}")
    print(f"   Size: {pcap_file.stat().st_size / (1024**2):.2f} MB")

    # Initialize components
    print("\n⏱️  Loading models...")
    registry = ModelRegistry()
    registry.load_all()
    print("✅ Models loaded")

    print("\n⏱️  Initializing pipeline...")
    alert_manager = AlertManager()
    analyzer = FlowAnalyzer(registry, alert_manager)
    processor = PacketProcessor()
    print("✅ Pipeline ready")

    # Process PCAP
    print(f"\n⏱️  Processing PCAP file: {pcap_file.name}")
    print("   (This may take a while for large files...)")

    start_time = time.time()
    flow_count = 0
    alert_count = 0
    alert_types = Counter()

    try:
        for event in processor.process_pcap(str(pcap_file)):
            flow_count += 1

            alert = analyzer.analyze_flow(event)

            if alert:
                alert_count += 1
                alert_types[alert.get("threat_class", "unknown")] += 1

            if flow_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = flow_count / elapsed if elapsed > 0 else 0
                print(f"   Processed {flow_count} events ({rate:.1f}/sec)...", end="\r")

        # Final results
        elapsed = time.time() - start_time
        print(f"\n\n{'=' * 80}")
        print("RESULTS")
        print("=" * 80)
        print(f"⏱️  Processing time: {elapsed:.2f} seconds")
        print(f"📊 Total events:    {flow_count}")
        print(f"🚨 Total alerts:    {alert_count}")
        if flow_count:
            print(f"📈 Detection rate:  {(alert_count/flow_count*100):.1f}%")

        if alert_types:
            print(f"\n🎯 Alert Breakdown:")
            for threat_type, count in alert_types.most_common():
                print(f"   {threat_type:25} {count:5} alert(s)")
        else:
            print("\n✅ No threats detected (clean traffic)")

        print("=" * 80)
        return True

    except Exception as e:
        print(f"\n\n❌ ERROR during processing: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_live_system.py <path_to_pcap>")
        print("\nExample:")
        print('  python test_live_system.py "Friday-WorkingHours.pcap"')
        sys.exit(1)

    pcap_path = sys.argv[1]
    success = test_live_pcap(pcap_path)
    sys.exit(0 if success else 1)
