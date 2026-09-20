# NetSentinel Live Capture Guide

> **Real-time network threat detection**: Capture packets directly from your network interface and analyze them with ML models in real-time.

---

## 🎯 Overview

**Live capture** is the production mode for NetSentinel. Instead of uploading PCAPs, it sniffs packets directly from your network interface and analyzes them on-the-fly.

```
Your Network
    ↓
Network Interface (Ethernet/Wi-Fi)
    ↓
Scapy Sniffer (live capture)
    ↓
PacketProcessor (extract flows/DNS/sessions)
    ↓
4 ML Models (DDoS, DGA, C2, ETT)
    ↓
AlertManager (generate alerts)
    ↓
WebSocket → Dashboard (real-time display)
```

---

## 📋 Prerequisites

### Windows Requirements

1. **Npcap** (packet capture driver)
   - Download: https://npcap.com/
   - Install with **"WinPcap compatibility mode"** enabled
   - Required because Windows doesn't have native packet capture

2. **Administrator privileges**
   - Packet capture requires elevated permissions
   - Right-click PowerShell/CMD → "Run as Administrator"

3. **Python packages**
   ```bash
   pip install scapy
   ```

### Linux/Mac Requirements

1. **libpcap** (usually pre-installed)
   ```bash
   # Ubuntu/Debian
   sudo apt install libpcap-dev
   
   # macOS (via Homebrew)
   brew install libpcap
   ```

2. **Root/sudo privileges**
   ```bash
   sudo python -m netsentinel.main
   ```

---

## 🚀 Quick Start

### Step 1: Find Your Network Interface

**Windows (PowerShell):**
```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
```

**Output example:**
```
Name                      InterfaceDescription                Status
----                      --------------------                ------
Ethernet                  Intel(R) Ethernet Connection        Up
Wi-Fi                     Realtek RTL8822CE 802.11ac          Up
```

**Linux:**
```bash
ip link show
# or
ifconfig
```

**Common interface names:**
- Windows: `Ethernet`, `Wi-Fi`, `Local Area Connection`
- Linux: `eth0`, `wlan0`, `ens33`
- macOS: `en0`, `en1`

---

### Step 2: Start Backend (if not running)

**Windows (PowerShell as Admin):**
```powershell
cd C:\Users\gtrip\OneDrive\Desktop\netsentinel
python -m netsentinel.main
```

**Linux/Mac:**
```bash
sudo python -m netsentinel.main
```

**Expected output:**
```
[*] Loading DDoS model... ✓ (0.21s)
[*] Loading DGA model... ✓ (0.33s)
[*] Loading C2 model... ✓ (0.19s)
[*] Loading ETT model... ✓ (0.23s)
[*] WebSocket hub started
[*] API server listening on http://0.0.0.0:8000
```

---

### Step 3: Start Live Capture

**Replace `Ethernet` with your interface name from Step 1:**

```bash
curl -X POST "http://localhost:8000/api/capture/start?interface=Ethernet"
```

**Response:**
```json
{
  "status": "Live capture started on 'Ethernet'"
}
```

**Backend console output:**
```
[*] Live capture started on 'Ethernet' (filter: ip)
[*] Packet capture active...
```

---

### Step 4: Watch Dashboard

Open http://localhost:8443 in your browser.

**What you'll see:**
- Top-right corner: `🟢 Live`
- Status: `"Live Capture (Ethernet)"`
- Packet rate chart updates in real-time
- Alerts appear as threats are detected

**Normal traffic (benign):**
- Browsing websites → no alerts (benign flows)
- Downloading files → no alerts
- Streaming video → no alerts

**Attack traffic (alerts triggered):**
- Port scans → Discovery alerts
- DDoS floods → DDoS alerts
- DNS tunneling → DGA alerts
- C2 beacons → C2 alerts

---

### Step 5: Generate Test Traffic (Optional)

To verify live capture is working, generate some attack traffic:

#### Option A: Port Scan (from another machine)

**Linux/Mac:**
```bash
# Scan ports 1-100 on NetSentinel host
nmap -sS 192.168.1.X
```

**Windows (PowerShell):**
```powershell
# Port scan using Test-NetConnection
1..100 | ForEach-Object { Test-NetConnection -ComputerName 192.168.1.X -Port $_ -InformationLevel Quiet }
```

**Expected result:**
- Dashboard shows "Port Scan" or "Discovery" alert
- Source IP: attacker's IP
- Dest IP: your NetSentinel host

#### Option B: DDoS SYN Flood (from another machine)

**Linux (requires hping3):**
```bash
sudo apt install hping3
sudo hping3 -S --flood -p 80 192.168.1.X
```

**Expected result:**
- Dashboard shows "DDoS SYN Flood" alert (critical severity)
- High confidence (>95%)
- Evidence: high pps, imbalanced SYN/ACK ratio

#### Option C: DNS Tunneling (simulate DGA)

**Linux/Mac:**
```bash
# Query suspicious random domains
dig xkqw8f3m2pqr.malware.net
dig 9fj2kd8s4lqp.evil.org
dig m4lw4r3c2srv.cc
```

**Expected result:**
- Dashboard shows "DGA" alert
- Model: CNN-BiLSTM
- Evidence: suspicious domain entropy

---

### Step 6: Stop Live Capture

When done testing:

```bash
curl -X POST http://localhost:8000/api/capture/stop
```

**Response:**
```json
{
  "status": "Live capture stopped"
}
```

---

## 🔍 Monitoring Live Capture

### Check Capture Status

```bash
curl http://localhost:8000/api/extractor/stats
```

**Response:**
```json
{
  "packets_processed": 15420,
  "events_generated": 342,
  "live_capture_active": true,
  "flow_extractor": {
    "flows_active": 28,
    "flows_completed": 314
  },
  "dns_extractor": {
    "queries_processed": 87
  },
  "session_builder": {
    "sessions_active": 3,
    "sessions_completed": 11
  }
}
```

### View Recent Alerts

```bash
curl http://localhost:8000/api/alerts?limit=10
```

---

## 🐛 Troubleshooting

### Issue 1: "Permission denied"

**Error:**
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
- Windows: Run PowerShell/CMD as Administrator
- Linux/Mac: Use `sudo python -m netsentinel.main`

---

### Issue 2: "Could not find interface 'Ethernet'"

**Error:**
```json
{
  "error": "Could not find interface 'Ethernet'"
}
```

**Solution:**
1. List available interfaces (Step 1)
2. Use exact interface name (case-sensitive):
   ```bash
   curl -X POST "http://localhost:8000/api/capture/start?interface=Wi-Fi"
   ```

---

### Issue 3: "Npcap not found" (Windows)

**Error:**
```
RuntimeError: Npcap is not installed
```

**Solution:**
1. Download Npcap: https://npcap.com/
2. Install with "WinPcap compatibility mode" enabled
3. Restart terminal
4. Verify:
   ```powershell
   scapy
   >>> conf.use_pcap
   True
   ```

---

### Issue 4: No alerts appearing

**Possible causes:**

1. **Only benign traffic on network**
   - Normal browsing doesn't trigger alerts
   - Solution: Generate test attacks (Step 5)

2. **BPF filter too restrictive**
   - Default filter: `"ip"` (all IP traffic)
   - Solution: Remove filter by editing `routes.py`:
     ```python
     bpf_filter: str = ""  # Capture all packets
     ```

3. **Models not loaded**
   - Check: `curl http://localhost:8000/api/models`
   - All models should show `"loaded": true`

4. **Dashboard not connected**
   - Check top-right corner: Should show `🟢 Live`
   - If `⚪ Mock`, WebSocket failed to connect
   - Solution: Restart both servers

---

### Issue 5: High CPU usage

**Cause:** Processing every packet in real-time is CPU-intensive.

**Solutions:**

1. **Use BPF filter to reduce packet count:**
   ```python
   # In routes.py, change bpf_filter
   bpf_filter: str = "tcp"  # Only TCP traffic
   bpf_filter: str = "port 80 or port 443"  # Only HTTP/HTTPS
   ```

2. **Increase flow timeout (process fewer flows):**
   ```python
   # In main.py
   packet_processor = PacketProcessor(
       idle_timeout=300.0,  # 5 minutes (default: 120s)
       active_timeout=600.0  # 10 minutes (default: 300s)
   )
   ```

3. **Use PCAP upload instead of live capture** for offline analysis

---

## 📊 Live Capture vs PCAP Upload

| Feature | Live Capture | PCAP Upload |
|:---|:---|:---|
| **Use Case** | Production monitoring | Forensic analysis |
| **Latency** | Real-time (ms) | Batch (seconds) |
| **Requirements** | Admin, Npcap | None |
| **CPU Usage** | High | Medium |
| **Storage** | No PCAP saved | PCAP file persists |
| **Replay** | No | Yes (re-upload) |

---

## 🎯 Production Deployment

For 24/7 monitoring:

### Option 1: Run as System Service (Windows)

**Create `netsentinel-service.xml`:**
```xml
<service>
  <id>netsentinel</id>
  <name>NetSentinel Threat Detection</name>
  <description>Real-time network threat detection with ML</description>
  <executable>C:\Python39\python.exe</executable>
  <arguments>-m netsentinel.main</arguments>
  <workingdirectory>C:\Users\gtrip\OneDrive\Desktop\netsentinel</workingdirectory>
  <logpath>C:\netsentinel\logs</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>
```

**Install using NSSM** (Non-Sucking Service Manager):
```powershell
nssm install NetSentinel "C:\Python39\python.exe" "-m netsentinel.main"
nssm start NetSentinel
```

### Option 2: Run as Systemd Service (Linux)

**Create `/etc/systemd/system/netsentinel.service`:**
```ini
[Unit]
Description=NetSentinel Network Threat Detection
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netsentinel
ExecStart=/usr/bin/python3 -m netsentinel.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable netsentinel
sudo systemctl start netsentinel
sudo systemctl status netsentinel
```

---

## 🔒 Security Considerations

1. **Admin/root privileges**
   - Live capture requires elevated permissions
   - Run backend as dedicated service user (not your personal account)

2. **Network exposure**
   - Backend listens on `0.0.0.0:8000` (all interfaces)
   - In production, bind to `127.0.0.1` or use firewall rules

3. **Packet data privacy**
   - NetSentinel extracts metadata (IPs, ports, packet counts)
   - Does NOT log full packet payloads or application data
   - DNS queries are logged (domains only, no query payloads)

4. **Alert storage**
   - Alerts stored in memory (lost on restart)
   - For persistence, integrate with SIEM or database

---

## 📈 Performance Tuning

### Recommended Settings by Traffic Volume

**Low traffic (<100 Mbps):**
```python
PacketProcessor(
    idle_timeout=120.0,  # 2 minutes
    active_timeout=300.0,  # 5 minutes
    session_min_flows=50
)
```

**Medium traffic (100-500 Mbps):**
```python
PacketProcessor(
    idle_timeout=60.0,  # 1 minute
    active_timeout=180.0,  # 3 minutes
    session_min_flows=100
)
```

**High traffic (>500 Mbps):**
```python
PacketProcessor(
    idle_timeout=30.0,  # 30 seconds
    active_timeout=90.0,  # 1.5 minutes
    session_min_flows=200
)
# Also use BPF filter: "tcp" (ignore UDP/ICMP)
```

---

## ✅ Summary

**Live capture is the REAL production mode:**
- ✅ Captures packets directly from network interface
- ✅ Processes through extraction layer (59 CIC features)
- ✅ Runs through all 4 ML models (ONNX inference)
- ✅ Generates alerts based on model predictions
- ✅ Broadcasts to dashboard via WebSocket in real-time

**Commands to remember:**
```bash
# Start capture
curl -X POST "http://localhost:8000/api/capture/start?interface=Ethernet"

# Check status
curl http://localhost:8000/api/extractor/stats

# Stop capture
curl -X POST http://localhost:8000/api/capture/stop

# View alerts
curl http://localhost:8000/api/alerts
```

**Next steps:**
1. Test with `test_real_pipeline.py` (PCAP upload)
2. Try live capture with your actual network traffic
3. Generate test attacks to verify detection
4. Deploy as a service for 24/7 monitoring
