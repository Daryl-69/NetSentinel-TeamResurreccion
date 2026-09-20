# NetSentinel Scripts

This directory contains utility and testing scripts for NetSentinel.

## Testing Scripts

### check_portscan_setup.py
Validates port scan model configuration and feature extraction pipeline.

Usage:
```bash
python scripts/check_portscan_setup.py
```

### scan_pcaps_for_scans.py
Scans PCAP files for port scanning behavior patterns.

Usage:
```bash
python scripts/scan_pcaps_for_scans.py <pcap_file>
```

### test_portscan_pcap.py
Tests port scan detection on specific PCAP captures.

Usage:
```bash
python scripts/test_portscan_pcap.py <pcap_file>
```

## Simulation Control Scripts

### start_ddos.ps1
Starts traffic simulator in DDoS attack mode.

Usage:
```powershell
.\scripts\start_ddos.ps1
```

### start_mixed.ps1
Starts traffic simulator with mixed benign and attack traffic.

Usage:
```powershell
.\scripts\start_mixed.ps1
```

### start_normal.ps1
Starts traffic simulator with only benign traffic.

Usage:
```powershell
.\scripts\start_normal.ps1
```

### stop_simulation.ps1
Stops all running traffic simulators.

Usage:
```powershell
.\scripts\stop_simulation.ps1
```

## Development Scripts

### lol.py
Development utility script (purpose varies).

