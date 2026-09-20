# Port Scan Detection Testing Guide

## 🎯 Quick Start

### Test with your existing PCAP files:

```powershell
# Best option - CIC-IDS2017 Thursday (contains port scans)
python test_portscan_pcap.py Thursday-WorkingHours.pcap

# Alternative - Botnet traffic (may have scanning)
python test_portscan_pcap.py botnet-capture-20110812-rbot.pcap

# Quick test with small file
python test_portscan_pcap.py test_attacks.pcap
```

## 📦 Your Existing PCAP Files

| File | Size | Contains Port Scans? | Priority |
|------|------|---------------------|----------|
| `Thursday-WorkingHours.pcap` | 8.3 GB | ✅ **YES** (CIC-IDS2017) | ⭐⭐⭐ BEST |
| `Friday-WorkingHours.pcap` | 8.8 GB | ❓ DDoS (some scan recon) | ⭐⭐ |
| `botnet-capture-20110812-rbot.pcap` | 128 MB | ✅ Likely (botnet recon) | ⭐⭐ |
| `2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap` | 15 MB | ❓ Malware (possible) | ⭐ |
| `test_attacks.pcap` | 10 KB | ❓ Test file | ⭐ |

## 🎓 What Makes a Good Port Scan PCAP?

A PCAP is good for port scan testing if it contains:

1. **Sequential port targeting** - One source IP connecting to many different ports on same target
2. **High connection rate** - Many connection attempts in short time window
3. **Failed connections** - SYN packets without completed handshakes
4. **Well-known ports** - Targeting 21, 22, 23, 80, 443, 3389, etc.
5. **Vertical scanning** - Same source → many ports on ONE target
6. **Horizontal scanning** - Same source → same port on MANY targets

## 📥 Recommended Datasets to Download

### 1. CIC-IDS2017 (Already have Thursday!)
- **Source**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Thursday file**: Contains port scans (afternoon)
- **Size**: ~8 GB
- **Status**: ✅ You already have this!

### 2. UNSW-NB15 - Reconnaissance Category
- **Source**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Attack type**: "Reconnaissance" (includes port scans)
- **Size**: ~100 GB total (download specific PCAP files)
- **Look for**: Files tagged with "reconnaissance" or "analysis"

### 3. CTU-13 Botnet Dataset
- **Source**: https://www.stratosphereips.org/datasets-ctu13
- **Contains**: Botnet traffic with scanning phases
- **Size**: Variable (multiple scenarios)

### 4. Wireshark Sample Captures (Quick Testing)
- **Source**: https://wiki.wireshark.org/SampleCaptures
- **Look for**: `nmap*.pcap`, `port-scan*.pcap`
- **Size**: Small (< 10 MB) - perfect for quick tests

### 5. PacketLife PCAP Library
- **Source**: https://packetlife.net/captures/protocol/all/
- **Filter**: Search for "nmap" or "scan"
- **Size**: Small captures (< 1 MB)

## 🔬 Understanding the Output

### What the script shows:

1. **Total flows analyzed** - How many network conversations processed
2. **Port scan alerts** - ML model detections
3. **Top scanners by fan-out** - IPs hitting most unique ports
4. **ML detection status** - Whether model caught the behavioral pattern

### Example output interpretation:

```
Top Port Scanners (by fan-out):
  1. 192.168.10.50 →   64 ports  ✅ ML DETECTED
  2. 10.0.0.25     →   15 ports  ❌ ML MISSED
  3. 172.16.0.5    →    8 ports  ❌ ML MISSED
```

- **✅ ML DETECTED** = Your retrained model successfully caught it
- **❌ ML MISSED** = Behavioral evidence exists but model didn't flag it
  - May indicate threshold tuning needed
  - Or legitimate traffic (false positive avoided)

## 🔧 Troubleshooting

### "CICFlowMeter not installed"
```powershell
pip install cicflowmeter
```

### "Port Scan model not found"
Check that these files exist:
```
models/portscan/port_scan_cic_xgboost.onnx
models/portscan/port_scan_cic_features.json
```

### Out of Memory (large PCAP)
The script auto-limits packets for large files, but you can also:
```python
# Edit test_portscan_pcap.py line, change max_packets
analyze_pcap_for_scans("Thursday-WorkingHours.pcap", max_packets=10000)
```

### No scans detected
- Try lower threshold in analyzer.py (already relaxed)
- File might not contain port scans
- Check "Top Scanners" section - if fan-out exists but ML missed it, model may need retraining

## 🎯 Creating Your Own Test PCAPs

### Option 1: Nmap Scan + Wireshark Capture

```bash
# On victim machine: Start Wireshark capture
# On attacker machine: Run nmap
nmap -sS -p 1-1000 192.168.1.100

# Save Wireshark capture as .pcap
```

### Option 2: Python Scapy Script

```python
from scapy.all import *

target = "192.168.1.100"
for port in range(20, 100):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    send(pkt, verbose=0)
```

Run tcpdump during execution:
```bash
sudo tcpdump -i eth0 -w my_portscan.pcap
```

## 📊 Expected Results from Thursday PCAP

The CIC-IDS2017 Thursday dataset contains documented port scan attacks in the afternoon period. You should see:

- Multiple source IPs with high port fan-out (>20 ports)
- ML model detecting scans with confidence >0.7
- Target IPs within the 192.168.10.0/24 network
- Well-known service ports being probed

## 🚀 Next Steps

1. ✅ Test with `Thursday-WorkingHours.pcap` first
2. 📊 Analyze detection rate vs. behavioral patterns
3. 🎛️ Tune thresholds if needed (in `analyzer.py`)
4. 📥 Download UNSW-NB15 reconnaissance PCAPs for more tests
5. 🔬 Create custom test PCAPs with controlled scan patterns

---

**Note**: The script processes PCAPs in batches to avoid memory issues with large files. For the 8GB Thursday file, it will automatically limit to ~20,000 packets (first few minutes of capture).
