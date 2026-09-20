# 🔍 Port Scan Testing - Quick Start Guide

## TL;DR - Three Commands to Test Everything

```powershell
# 1. Find which PCAPs have port scans (quick survey)
python scan_pcaps_for_scans.py

# 2. Deep test the best PCAP with your ML model
python test_portscan_pcap.py Thursday-WorkingHours.pcap

# 3. Test in the live dashboard (with improved detection)
python run.py
# Then in another terminal:
.\start_mixed.ps1
```

## 📋 What I've Set Up For You

### 1. **Fixed Mixed Simulation** ✅
   - Port scan bursts now inject every **15 events** (was 20)
   - Burst size increased to **15-40 flows** (was 10-30)
   - Better logging shows when scans are detected
   - Detection thresholds relaxed for your retrained CIC model

### 2. **Created Testing Scripts** ✅

#### `scan_pcaps_for_scans.py` - Quick Survey
- Scans all your PCAP files using heuristics
- Tells you which ones likely contain port scans
- Fast - uses packet sampling, no ML overhead
- **Run this first!**

#### `test_portscan_pcap.py <file>` - Deep Analysis  
- Uses your actual CICFlowMeter + XGBoost model
- Shows ML detection vs behavioral patterns
- Compares fan-out evidence with model predictions
- Detailed per-source-IP analysis

### 3. **Created Documentation** ✅
   - `PORT_SCAN_TEST_GUIDE.md` - Complete testing guide
   - Recommended datasets to download
   - Troubleshooting tips

## 🎯 Your Best Test Files (Already Downloaded)

| Priority | File | Why? |
|----------|------|------|
| ⭐⭐⭐ | `Thursday-WorkingHours.pcap` (8.3 GB) | **CIC-IDS2017 with documented port scans** |
| ⭐⭐ | `botnet-capture-20110812-rbot.pcap` (128 MB) | Botnet recon phases |
| ⭐ | `test_attacks.pcap` (10 KB) | Quick sanity check |

## 🚀 Step-by-Step Testing Workflow

### Step 1: Quick Survey (2 minutes)
```powershell
python scan_pcaps_for_scans.py
```

**What it shows:**
- ✅ Files with high-confidence port scan patterns
- ⚠️ Files without clear patterns
- 💡 Best file recommendation

**Sample output:**
```
✅ Files likely containing port scans:
  Thursday-WorkingHours.pcap                (85% confidence)
  botnet-capture-20110812-rbot.pcap        (62% confidence)

Best file for testing: Thursday-WorkingHours.pcap
```

### Step 2: ML Model Test (5-10 minutes)
```powershell
python test_portscan_pcap.py Thursday-WorkingHours.pcap
```

**What it shows:**
- 🎯 Top scanners by port fan-out
- 🤖 Which ones your ML model caught
- 📊 Detection rate and confidence scores
- 🔍 Sample ports scanned

**Sample output:**
```
Top Port Scanners (by fan-out):
  1. 192.168.10.50 →   64 ports  ✅ ML DETECTED
  2. 10.0.0.25     →   15 ports  ❌ ML MISSED

ML Model Detections:
  Source: 192.168.10.50
  Flows flagged: 42
  Ports scanned: 64
  Avg confidence: 0.873
```

### Step 3: Live Dashboard Test (ongoing)
```powershell
# Terminal 1: Start backend
python run.py

# Terminal 2: Start mixed simulation
.\start_mixed.ps1

# Watch the console for:
[🔍] Injecting port scan burst...
[SCAN-ALERT] Triggering: ≥20 ports + behavioral evidence (0.78)
[✓] Port Scan ALERT generated!
    Ports scanned: 25
    Confidence: 0.821
```

**Check frontend:** The "Port Fan-Out" panel should now populate!

## 🎓 Understanding What Makes a Port Scan

### Classic Patterns (Your model looks for these):

1. **Vertical Scan** (Most common)
   - One attacker → Many ports on ONE target
   - Example: `192.168.1.100` scans ports 1-1000 on `10.0.0.50`

2. **Horizontal Scan**
   - One attacker → Same port on MANY targets  
   - Example: `192.168.1.100` checks port 445 on entire /24 subnet

3. **TCP Characteristics**
   - High SYN rate (connection attempts)
   - Low or zero ACK rate (failed handshakes)
   - Short flow durations (<1 second)
   - Small packet counts (1-3 packets per flow)

4. **Timing Patterns**
   - Sequential ports (21, 22, 23, 24...)
   - Rapid succession (<100ms between probes)
   - Well-known service ports targeted (22, 80, 443, 3389)

## 📥 Download More Test Data

### Recommended Datasets:

1. **UNSW-NB15 - Reconnaissance Category** ⭐⭐⭐
   - https://research.unsw.edu.au/projects/unsw-nb15-dataset
   - Look for "reconnaissance" attack files
   - ~100 GB total (download selectively)

2. **Wireshark Sample Captures** ⭐⭐ (Quick tests)
   - https://wiki.wireshark.org/SampleCaptures
   - Search: "nmap" or "port scan"
   - Small files (<10 MB)

3. **PacketLife Library** ⭐
   - https://packetlife.net/captures/
   - Has dedicated nmap captures

## 🔧 Troubleshooting

### "No scans detected" but heuristics show fan-out

**Possible causes:**
1. Model threshold too strict → Already relaxed in code
2. Feature drift → Check if PCAP features match training data
3. Legitimate reconnaissance → Model correctly ignoring stealthy scans

**Debug:**
```python
# Check what model sees (in analyzer.py, already added):
# Look for this output:
[SCAN] Port scan check: 192.168.1.50 -> 15 ports, ML says: Port Scan @ 0.7234
```

### Out of Memory with large PCAPs

**Solution:** Scripts auto-limit packets
- <100 MB → 100,000 packets
- 100MB-1GB → 50,000 packets  
- >1GB → 20,000 packets

**Manual override:**
```python
# In test_portscan_pcap.py
analyze_pcap_for_scans("file.pcap", max_packets=5000)
```

### CICFlowMeter not installed

```powershell
pip install cicflowmeter
```

### Model files missing

Check these exist:
```
models/portscan/port_scan_cic_xgboost.onnx
models/portscan/port_scan_cic_features.json
```

## 📊 Expected Results

### Thursday-WorkingHours.pcap (CIC-IDS2017)

**Should see:**
- ✅ Multiple source IPs with >20 port fan-out
- ✅ ML confidence >0.7 for clear scans
- ✅ Target IPs in 192.168.10.0/24 range
- ✅ Well-known ports (21, 22, 23, 80, 443, 3389)

**If not:** Check that you're processing the **afternoon** portion where attacks occur.

## 🎯 Success Criteria

Your port scan detection is working well if:

1. ✅ **Heuristics match ML detections** - High fan-out IPs are flagged
2. ✅ **Confidence scores >0.7** - Model is certain
3. ✅ **Dashboard visualizes** - Frontend "Port Fan-Out" grid populates
4. ✅ **Low false positives** - Legitimate high-port-usage (DNS servers, etc.) not flagged

## 📞 Next Steps After Testing

1. **Tune thresholds** if needed (in `analyzer.py`)
2. **Test with UNSW-NB15** for different attack styles
3. **Create custom test PCAPs** with known scan patterns
4. **Benchmark detection rate** against labeled datasets

---

**Happy Testing! 🚀**

See `PORT_SCAN_TEST_GUIDE.md` for detailed instructions.
