# NetSentinel Port Scan Detector Models

This directory contains trained model weights for the SPSD (Supervised Port Scan Detector).

## Current Status

**⚠️ No trained model present** — The system is currently running in **UPSD mode** (Unsupervised Port Scan Detector), which requires no training data and uses sequential hypothesis testing.

## Training the SPSD Model (Recommended for Production)

The SPSD model is a DecisionTree trained on CIDDS-001 network events and provides:
- ✅ Genuine scan-vs-benign probability (not the old ~1% per-flow score)
- ✅ Zero false alarms (paper results: 100% detection, 0 false positives)
- ✅ Full explainability (decision tree shows exact rules)
- ✅ Detects slow scans via succession tracking

### Prerequisites

1. **Download CIDDS-001 Dataset**
   - Visit: https://www.hs-coburg.de/cidds
   - Request the OpenStack internal unidirectional NetFlow CSVs
   - Files needed: `CIDDS-001-internal-week1.csv` and `CIDDS-001-internal-week2.csv`
   - Place them in: `data/cidds/`

2. **Install Training Dependencies**
   ```bash
   pip install scikit-learn pandas numpy
   ```

3. **Verify Network Info**
   - Training uses: `netsentinel/netinfo/network_info_cidds.json` (CIDDS topology)
   - This file already exists and documents CIDDS network layout

### Training Steps

```bash
# Create data directory
mkdir -p data/cidds

# Place CIDDS-001 CSV files in data/cidds/

# Run the trainer
python scripts/train_spsd.py \
  --week1 data/cidds/CIDDS-001-internal-week1.csv \
  --week2 data/cidds/CIDDS-001-internal-week2.csv \
  --network-info netsentinel/netinfo/network_info_cidds.json \
  --out netsentinel/models/weights/portscan_spsd_decisiontree.pkl

# Optional: Cross-validation (train on week2, validate on week1)
python scripts/train_spsd.py \
  --week1 data/cidds/CIDDS-001-internal-week1.csv \
  --week2 data/cidds/CIDDS-001-internal-week2.csv \
  --network-info netsentinel/netinfo/network_info_cidds.json \
  --out netsentinel/models/weights/portscan_spsd_decisiontree.pkl \
  --swap
```

### Acceptance Criteria

The training script must report:
- ✅ **Detection rate ≥ 90%** of labeled scans
- ✅ **False alarms ≤ 5** on validation week

If these aren't met, check:
1. `network_info_cidds.json` has complete `known_open_ports` mappings
2. CIDDS CSV files are complete and uncorrupted
3. Feature computation in `NetworkEventBuilder` matches paper exactly

### Switching to SPSD Mode

Once `portscan_spsd_decisiontree.pkl` exists in this directory:

1. Edit `netsentinel/config.py`:
   ```python
   class PortScanSettings:
       mode = "spsd"  # Change from "upsd" to "spsd"
       # ... rest stays the same
   ```

2. Restart NetSentinel — it will auto-load the trained model

## Model Files

- `portscan_spsd_decisiontree.pkl` — DecisionTree classifier (6 features → scan probability)
  - **Status:** ❌ Not trained yet
  - **Size:** ~10-50 KB (decision tree is very compact)
  - **Training time:** ~5-30 minutes on CIDDS-001

## Feature Vector (CRITICAL — Do Not Modify Order)

The model expects features in this exact order:
1. `icmp_error_count` — ICMP unreachable responses (UDP scan indicator)
2. `rst_count` — Distinct targets that RST'd (closed TCP ports)
3. `rwa_count` — Request-without-answer (firewalled targets)
4. `neip_count` — Non-existent internal IPs contacted
5. `netcp_count` — Non-open ports on existing hosts contacted
6. `succession_count` — Consecutive suspicious windows (slow-scan tracking)

This order is defined in:
- `netsentinel/extractor/network_event_builder.py` → `NetworkEvent.feature_vector()`
- `scripts/train_spsd.py` (uses the same method)

**⚠️ Any mismatch between training and inference reintroduces the covariate-shift bug that broke the old per-flow model.**

## Fallback: UPSD Mode (Current Default)

If you cannot obtain CIDDS-001 or need immediate deployment:

- UPSD mode requires **zero training data**
- Uses Wald's sequential probability ratio test
- Slightly weaker on borderline slow scans vs. SPSD
- Still detects obvious scans via fan-out backstop + behavioral indicators
- Configured in `config.py` → `PortScanSettings.upsd_params`

UPSD is production-ready and runs by default until SPSD model is trained.

## Testing

After training, verify with:
```bash
pytest tests/test_portscan.py -v
```

Expected results:
- ✅ Feature builder matches paper Table-4
- ✅ Succession tracking works (1→2→3, resets to 0)
- ✅ `portscan_real.pcap` → Port Scan alert with confidence ≥ 0.5
- ✅ Benign PCAP → zero port scan alerts
- ✅ Cold-start (empty network_info) → no crash, degraded detection via fan-out

## References

- Paper: Ring, Landes & Hotho (2018), "Detection of slow port scans in flow-based network traffic"
  - DOI: 10.1371/journal.pone.0204507
  - https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0204507
- Implementation plan: `../../PORTSCAN_FIX_IMPLEMENTATION_PLAN.md`
- Remaining work: `../../PORTSCAN_REMAINING_WORK_PLAN.md`
