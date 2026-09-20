# NetSentinel Simulation Commands

## Fixed PowerShell Scripts

The simulation commands have been fixed. Use these scripts to control the traffic simulator:

### Available Scripts

1. **Start Mixed Attacks** (recommended for demo)
   ```powershell
   .\start_mixed.ps1
   ```
   Generates DDoS, Port Scans, DGA/DNS Tunnels, C2 Beacons, Encrypted Traffic, and Exfiltration

2. **Start DDoS Only**
   ```powershell
   .\start_ddos.ps1
   ```

3. **Start Normal Traffic**
   ```powershell
   .\start_normal.ps1
   ```

4. **Stop Simulation**
   ```powershell
   .\stop_simulation.ps1
   ```

### Usage Workflow

1. **Start the backend** (in one terminal):
   ```powershell
   python run.py
   ```

2. **Start the frontend** (in another terminal):
   ```powershell
   cd frontend
   npm run dev
   ```

3. **Start simulation** (in a third terminal or the same one):
   ```powershell
   .\start_mixed.ps1
   ```

4. **Watch the dashboard** at http://localhost:5173

5. **Stop simulation** when done:
   ```powershell
   .\stop_simulation.ps1
   ```

### For Video Recording

To ensure smooth recording without mock data interference:

1. Start backend: `python run.py`
2. Start frontend: `cd frontend && npm run dev`
3. Open browser to http://localhost:5173
4. **Wait 5 seconds** for WebSocket connection to establish
5. Start recording
6. Run: `.\start_mixed.ps1`
7. Let it run for 30-60 seconds
8. Stop recording
9. Run: `.\stop_simulation.ps1`

### Troubleshooting

**If scripts don't work:**
- Ensure backend is running: `python run.py`
- Check backend logs for errors
- Verify port 8000 is not blocked by firewall
- Try running the backend in a fresh terminal

**If you see "execution policy" error:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**To test backend is running:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/health" -Method Get
```
