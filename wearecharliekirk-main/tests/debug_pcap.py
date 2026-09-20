"""Debug script - manually process PCAP and show what happens."""
from netsentinel.extractor import PacketProcessor
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.pipeline.alert_manager import AlertManager

# Initialize
print("[*] Loading models...")
registry = ModelRegistry()
registry.load_all()

alert_manager = AlertManager()
analyzer = FlowAnalyzer(registry, alert_manager)

# Process PCAP
pcap_file = "uploads/test_attacks.pcap"
print(f"\n[*] Processing {pcap_file}...")

processor = PacketProcessor()
event_count = 0
alert_count = 0

for event in processor.process_pcap(pcap_file):
    event_count += 1
    event_type = event.get('type', 'unknown')
    
    if event_type == 'flow':
        src = event.get('source_ip', '?')
        sport = event.get('source_port', '?')
        dst = event.get('dest_ip', '?')
        dport = event.get('dest_port', '?')
        print(f"  Event {event_count}: type=flow, {src}:{sport} -> {dst}:{dport}")
    elif event_type == 'dns':
        print(f"  Event {event_count}: type=dns, domain={event.get('domain')}")
    else:
        print(f"  Event {event_count}: type={event_type}")
    
    # Run through analyzer
    alert = analyzer.analyze_flow(event)
    if alert:
        alert_count += 1
        print(f"    🚨 ALERT: {alert['threat_class']} (confidence: {alert['confidence']*100:.1f}%)")

print(f"\n[✓] Processed {event_count} events")
print(f"[✓] Generated {alert_count} alerts")

if alert_count == 0:
    print("\n[!] No alerts generated - possible reasons:")
    print("    1. Attack features didn't meet model thresholds")
    print("    2. PCAP packets didn't form complete flows")
    print("    3. Model confidence < 85%")
