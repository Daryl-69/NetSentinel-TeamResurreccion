# Test Port Scan Detection Now

## Quick Test Steps

### 1. Restart Backend
```powershell
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
cd C:\Users\gtrip\OneDrive\Desktop\netsentinel
python run.py
```

Wait for: `[>] Server ready!`

### 2. Start Mixed Simulation
```powershell
Start-Sleep -Seconds 10
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/mixed" -Method Post
```

### 3. Watch Backend Terminal

You should see debug output like:
```
[🔍] Injecting port scan burst...
[🔍] Burst size: 18 flows
[🔍] Port scan check: 185.220.101.34 -> 18 ports, ML confidence: 0.6743
[✓] Port scan: ML moderate confidence (0.67) + clear pattern (18 ports)
[✓] Port scan burst injection complete
```

### 4. Check Frontend Dashboard

**Port Fan-Out Panel** (bottom left) should show:
- Grid of colored squares (scanned ports)
- "18 ports / 8s → 10.0.0.1" header
- Filled squares = well-known ports (22, 80, 443, etc.)

### 5. Check Timeline

Should show Port Scan alerts appearing every ~20 seconds:
```
🟡 Port Scan [MEDIUM]  XX.X%
192.168.1.XXX → 10.0.0.1
```

## What Each Component Shows

### Debug Output Explained:
```
[🔍] Port scan check: 185.220.101.34 -> 18 ports, ML confidence: 0.6743
```
- **Source IP**: 185.220.101.34
- **Ports scanned**: 18 different destination ports
- **ML confidence**: 67.43% (between 0.60-0.85, triggers secondary threshold)

```
[✓] Port scan: ML moderate confidence (0.67) + clear pattern (18 ports)
```
- **Decision**: Alert created
- **Reason**: ML model detects scan (67%) + port count confirms (18 >= 15)

### Frontend Evidence Panel:
- **Ports grid**: Visual of which ports were targeted
- **Target IP**: Victim/scanned server (usually 10.0.0.1)
- **Window**: Time window for scan (8 seconds)
- **Total ports**: Count of unique ports hit

## If Port Scan Still Doesn't Show

### Debug Checklist:

**1. Check ML model confidence:**
```
Look for: [🔍] Port scan check: ... ML confidence: 0.XXXX
```
- If confidence < 0.60 → ML model not detecting scan pattern
- If confidence > 0.60 but < 0.85 → Should trigger secondary
- If no output at all → Port scan bursts not being injected

**2. Check port count:**
```
Look for: ... -> XX ports ...
```
- If ports < 15 → Won't trigger secondary threshold
- Burst generator should create 10-30 ports per burst

**3. Check burst injection:**
```
Look for: [🔍] Injecting port scan burst...
```
- Should appear every 20 events in mixed mode
- If missing → Simulator loop issue

**4. Check frontend mapping:**
- Open browser DevTools (F12)
- Check Console for errors
- Look for WebSocket messages with Port Scan alerts

## Troubleshooting

### No Debug Output at All:
**Cause**: Backend not restarted, old code still running
**Fix**:
```powershell
Get-Process python | Stop-Process -Force
python run.py
```

### Debug Output But No Alert:
**Cause**: ML confidence too low or port count too low
**Solution**: Temporarily lower thresholds for testing:
```python
# In analyzer.py, change line ~280:
elif ml_detects_scan and ml_confidence >= 0.50 and num_ports >= 10:
    # ^^ Lowered from 0.60 and 15 for testing
```

### Alerts But Panel Empty:
**Cause**: Frontend not receiving evidence or mapping incorrect
**Check**:
1. Browser console for WebSocket messages
2. Alert JSON has `evidence.fan_out` field
3. Frontend mapping in `useThreatFeed.ts` line 162-168

### Too Many Alerts:
**Cause**: Secondary threshold too permissive
**Solution**: Tighten thresholds:
```python
elif ml_confidence >= 0.70 and num_ports >= 20:
    # ^^ More conservative
```

## Expected Results

### Normal Mode:
- ❌ No port scan alerts (no scanning in normal traffic)
- Panel shows: "NO SCANNING ACTIVITY"

### Mixed Mode:
- ✅ Port scan alerts every ~20 seconds
- ✅ Panel shows grid of 10-30 scanned ports
- ✅ Debug output confirms ML confidence + port count

### Port Scan Only Mode:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/simulate/port_scan" -Method Post
```
- ✅ Continuous port scan alerts
- ✅ Panel constantly updating with new scans

## Success Criteria

✅ **Working correctly if**:
1. Debug output shows ML confidence between 0.60-0.85
2. Port count shows 15+ ports scanned
3. Alert created message appears
4. Frontend Port Fan-Out panel shows grid
5. Timeline shows Port Scan alerts

❌ **Not working if**:
- No debug output → Backend not restarted
- ML confidence <0.60 → Model not detecting scan pattern
- Ports <15 → Burst size too small
- No alerts created → Threshold logic broken
- Panel empty → Evidence not passing to frontend
