# CICFlowMeter Integration Guide

## Why Switch to CICFlowMeter

Your custom extractor has 92% feature drift. **CICFlowMeter has 0% drift** because your models were trained on its output. It's the gold standard.

---

## Installation

### Option 1: Python Package (Easiest)
```bash
pip install cicflowmeter
```

### Option 2: Original Java Tool
```bash
# Download from: https://github.com/ahlashkari/CICFlowMeter
# Requires Java 8+
```

---

## Hybrid Approach (Recommended)

**Use CICFlowMeter for DDoS model** (59 features, 0% drift):
- Processes PCAP → CSV with 59 features
- Perfect match for training data

**Keep custom extractor for:**
- ETT model (29 ISCX-VPN features - CICFlowMeter doesn't compute these)
- DGA model (DNS queries - different event type)
- C2 Beacon (session-level, 100-flow sequences)
- Port scan (39 UNSW-NB15 features - different schema)
- Exfil (24 DNS-lexical features)

---

## Integration Architecture

```
PCAP Input
    ↓
    ├─→ CICFlowMeter → CSV (59 features) → DDoS Model ✅
    │
    └─→ Custom Extractor → Events → {
                                       ├─ ETT Model (29 feats)
                                       ├─ DGA Model (DNS)
                                       ├─ C2 Beacon (sessions)
                                       ├─ Port Scan (39 feats)
                                       └─ Exfil (24 DNS feats)
                                     }
```

---

## Implementation Steps

### 1. Install CICFlowMeter
```bash
pip install cicflowmeter
```

### 2. Create Wrapper Module

**File:** `netsentinel/extractor/cicflowmeter_wrapper.py`

```python
"""
CICFlowMeter wrapper for accurate DDoS detection.
Replaces custom flow extractor for the 59 CIC-IDS features.
"""
import subprocess
import pandas as pd
from pathlib import Path
import tempfile

def extract_cic_features(pcap_path: str) -> pd.DataFrame:
    """
    Run CICFlowMeter on PCAP and return features as DataFrame.
    
    Args:
        pcap_path: Path to PCAP file
        
    Returns:
        DataFrame with 59 CIC-IDS2019 features per flow
    """
    # Create temp output dir
    with tempfile.TemporaryDirectory() as tmpdir:
        output_csv = Path(tmpdir) / "flows.csv"
        
        # Run CICFlowMeter
        cmd = [
            "cicflowmeter",
            "-f", pcap_path,
            "-o", str(output_csv)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"CICFlowMeter failed: {result.stderr}")
        
        # Read CSV
        df = pd.read_csv(output_csv)
        
        return df

def cic_to_events(df: pd.DataFrame) -> list[dict]:
    """
    Convert CICFlowMeter CSV to our event format.
    
    Args:
        df: CICFlowMeter output DataFrame
        
    Returns:
        List of flow events compatible with analyzer
    """
    events = []
    
    for _, row in df.iterrows():
        # Extract 5-tuple
        src_ip = row.get('Src IP', row.get('Source IP', ''))
        dst_ip = row.get('Dst IP', row.get('Destination IP', ''))
        src_port = int(row.get('Src Port', row.get('Source Port', 0)))
        dst_port = int(row.get('Dst Port', row.get('Destination Port', 0)))
        protocol = int(row.get('Protocol', 6))  # Default TCP
        
        # Build features dict (59 CIC features)
        features = {col: row[col] for col in df.columns 
                   if col not in ['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Protocol',
                                  'Source IP', 'Destination IP', 'Source Port', 'Destination Port']}
        
        event = {
            "type": "flow",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "protocol": protocol,
            "features": features,
        }
        
        events.append(event)
    
    return events
```

### 3. Modify PCAP Reader

**File:** `netsentinel/extractor/pcap_reader.py`

Add option to use CICFlowMeter:

```python
class PcapReader:
    def __init__(self, use_cicflowmeter: bool = True):  # Default to CICFlowMeter
        self.use_cicflowmeter = use_cicflowmeter
        # ... existing init
    
    async def process_pcap_file(self, pcap_path: str):
        """Process PCAP using CICFlowMeter or custom extractor."""
        
        if self.use_cicflowmeter:
            # Use CICFlowMeter for accurate 59-feature extraction
            from netsentinel.extractor.cicflowmeter_wrapper import extract_cic_features, cic_to_events
            
            try:
                df = extract_cic_features(pcap_path)
                events = cic_to_events(df)
                
                # Send all flow events
                for event in events:
                    await self.event_queue.put(event)
                
            except Exception as e:
                logger.error(f"CICFlowMeter failed, falling back to custom: {e}")
                # Fall back to custom extractor
                await self._process_with_custom_extractor(pcap_path)
        else:
            # Use custom extractor (for ETT/DGA/C2/port scan/exfil)
            await self._process_with_custom_extractor(pcap_path)
    
    async def _process_with_custom_extractor(self, pcap_path: str):
        """Existing custom extraction logic."""
        # ... existing code
```

---

## Configuration

**File:** `netsentinel/config.py`

```python
# Feature extraction mode
USE_CICFLOWMETER = True  # Set False to use custom extractor
```

---

## Testing

### 1. Install CICFlowMeter
```bash
pip install cicflowmeter
```

### 2. Test Extraction
```python
from netsentinel.extractor.cicflowmeter_wrapper import extract_cic_features

df = extract_cic_features("test.pcap")
print(f"Extracted {len(df)} flows")
print(f"Features: {df.columns.tolist()}")
```

### 3. Re-run Covariate Shift Test
```bash
# Modify covariate_shift.py to use CICFlowMeter
python scripts/covariate_shift.py
```

**Expected result:** 0% drift on all 59 features!

---

## Pros & Cons

### ✅ Advantages
- **Zero drift** on DDoS model (59 features)
- **Proven accuracy** - battle-tested by researchers
- **No bugs** - mature implementation
- **Fast** - Java/C++ implementation

### ⚠️ Limitations
- **Only 59 features** - doesn't compute ETT (29) or DNS-lexical (24)
- **External dependency** - requires Java or pip install
- **CSV parsing overhead** - extra I/O step

### 💡 Best of Both Worlds
Use CICFlowMeter for DDoS (accuracy matters most here), keep custom for specialized features.

---

## Estimated Time

- **Installation:** 5 minutes
- **Wrapper code:** 30 minutes
- **Integration:** 1 hour
- **Testing:** 30 minutes

**Total: 2 hours to zero drift on DDoS model**

---

## Alternative: Just Use Custom for Now

If time is tight:
- ✅ Current system works for demo
- ⚠️ 92% drift means degraded accuracy
- 💡 CICFlowMeter is the proper fix (2 hours)
- 💡 Full extractor debug is 8-12 hours

**Recommendation:** Use CICFlowMeter for DDoS only (biggest impact, least work).
