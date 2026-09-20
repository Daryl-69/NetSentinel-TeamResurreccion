# Testing Evidence Panels Guide

## Quick Start

### 1. Start Backend
```powershell
cd C:\Users\gtrip\OneDrive\Desktop\netsentinel
python run.py
```
Wait for: `[>] Server ready!`

### 2. Start Frontend
```powershell
cd C:\Users\gtrip\OneDrive\Desktop\netsentinel\frontend
npm run dev
```
Open browser to: `http://localhost:5173`

### 3. Run Mixed Simulation
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/mixed" -Method Post
```

## What to Expect

### Timeline
You should see alerts appearing for all 6 threat types:
- 🔴 **DDoS** (Critical) - High packet/byte rates
- 🟡 **Port Scan** (Medium) - Multiple ports probed
- 🔴 **Data Exfiltration** (High) - DNS tunneling detected
- 🟠 **C2 Beacon** (High) - Periodic communication
- 🟡 **Encrypted Malware** (Medium) - VPN/tunnel traffic
- 🟠 **DGA** (High) - Algorithmically generated domains

### Evidence Panels (Bottom Left)

#### 1. Source-IP Entropy (DDoS)
- **Should show**: ~2.0-4.0 bits when DDoS alerts appear
- **Meaning**: Diversity of attacking source IPs
- **Threshold**: >12 bits = volumetric flood

#### 2. Port Fan-Out (Port Scan)
- **Should show**: Grid of scanned ports (10-30 ports)
- **Meaning**: Ports targeted by scanner
- **Threshold**: ≥10 ports = recon activity

#### 3. Byte Ratio (Exfiltration)
- **Should show**: Asymmetric bar chart (heavy outbound)
- **Meaning**: Outbound >> inbound (data being exfiltrated)
- **Typical ratio**: 20:1 to 50:1 (outbound:inbound)

## Troubleshooting

### Byte Ratio Not Showing
**Check**:
1. Are exfiltration alerts appearing in timeline?
2. Does alert have threat_class = "Data Exfiltration"?
3. Check browser console for mapping errors

**Debug**:
```powershell
# Check recent alerts
Invoke-RestMethod -Uri "http://localhost:8000/api/alerts" | 
    Select-Object -ExpandProperty alerts | 
    Where-Object { $_.threat_class -eq "Data Exfiltration" } | 
    Select-Object -First 1 -ExpandProperty evidence
```

Should show:
```json
{
  "reconstruction_error": 0.21,
  "dns_entropy": 2.84,
  "subdomain_length": 10,
  "anomaly_type": "dns_tunneling",
  "byte_ratio": {
    "outbound": 3826,
    "inbound": 123
  }
}
```

### Port Fan-Out Not Showing
**Symptoms**: Port scan alerts appear but grid is empty

**Fix**: Check if heuristic detector is working:
```powershell
# Should see debug output in backend terminal:
# [🔍] Injecting port scan burst...
# [🎯] Port scan heuristic: X.X.X.X -> 15 ports
```

If not appearing, the burst injection may not be triggering.

### Source-IP Entropy Always Zero
**Symptoms**: DDoS alerts appear but entropy gauge stays at 0

**Cause**: Not enough variety in source IPs

**Solution**: Simulator uses 5 fake attacker IPs from different countries. Entropy should be ~2.0-2.5 bits. If it's 0, check that DDoS generator is using `FAKE_GEO` attackers.

## Stopping Simulation

```powershell
# Stop simulation (backend keeps running)
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/stop" -Method Post

# Or restart with different mode:
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/ddos" -Method Post
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/port_scan" -Method Post
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/exfil" -Method Post
```

## Simulation Modes

### Mixed (Recommended for Testing)
- All 6 threat types + normal traffic
- Best for seeing all evidence panels populate
- ~60% attacks, 40% benign

### Individual Modes
- `ddos` - Only DDoS attacks (tests entropy gauge)
- `port_scan` - Only port scans (tests fan-out grid)
- `exfil` - Only DNS tunneling (tests byte ratio)
- `dga` - Only DGA domains
- `c2` - Only C2 beacons
- `normal` - Only benign traffic (false positive testing)

### Normal Mode
⚠️ **Normal mode should NOT trigger alerts!**
- It generates only legitimate traffic
- Used to verify false positive rate is low
- If normal mode triggers alerts, that's a bug

## Expected Behavior

### First 30 Seconds
- Alerts start appearing immediately
- Evidence panels start populating as relevant alerts appear
- Timeline fills from bottom to top

### Steady State (After 1 Minute)
- Continuous stream of alerts (mixed types)
- All 3 evidence panels should have populated at least once
- Packet rate chart shows varying traffic levels
- MITRE heatmap lights up across tactics

### Performance
- Frontend should stay smooth (60fps)
- Backend should process 10-20 events/sec
- Alerts should appear within 1-2 seconds of generation

## Clean Slate Testing

To start fresh:
```powershell
# Stop backend
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force

# Wait for port to clear
Start-Sleep -Seconds 3

# Restart
python run.py
```

In browser:
- Refresh page (F5)
- Clear console (Ctrl+L in DevTools)
- Start simulation

## Success Criteria

✅ **All working if**:
1. Timeline shows mix of all 6 threat types
2. Source-IP Entropy panel shows ~2.0 bits during DDoS
3. Port Fan-Out panel shows grid of 10-30 ports during scans
4. Byte Ratio panel shows 20:1+ ratio during exfiltration
5. No console errors in browser DevTools
6. Backend shows no Python exceptions

❌ **Issues if**:
- Timeline empty → Simulation not started or backend down
- Evidence panels always "NO ACTIVITY" → Model predictions not including evidence fields
- Browser console errors → Frontend mapping issues
- Backend Python errors → Model loading or inference errors
