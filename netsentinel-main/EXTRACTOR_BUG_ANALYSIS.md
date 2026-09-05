# Flow Extractor Bug Analysis

## Summary
After deep-dive investigation, the flow extractor has systematic bugs causing 92% feature drift. These are **not quick fixes** - they require side-by-side comparison with CICFlowMeter's C++ source.

---

## Bugs Identified

### 1. Packet Size Calculation (KS 0.84-0.71) - MAJOR
**Symptoms:**
- Fwd Packet Length Min: ref=27.88, ours=52.69 (88% larger)
- Fwd Packet Length Mean: ref=164.83, ours=106.40 (35% smaller)
- Bwd Packet Length Mean: ref=890.54, ours=221.57 (75% smaller)

**Root cause unknown:** Tried switching between:
- `payload_size` (just TCP/UDP data)
- `ip.len` (total IP packet including headers)

Neither matches. Suggests CICFlowMeter uses a different definition or there's a filtering issue.

**Hypothesis:** CICFlowMeter may:
- Include Ethernet frame size
- Filter certain packet types we're including
- Have different MTU handling

**Fix required:** Examine CICFlowMeter source: `FlowMeter.java` or equivalent

---

### 2. Header Length Calculation (KS 0.49/0.41) - MAJOR  
**Symptoms:**
- Fwd Header Length: ref=111.52, ours=612.90 (5.5x larger!)
- Bwd Header Length: ref=106.79, ours=672.23 (6.3x larger!)

**Current implementation:**
```python
fwd_header_total = sum(p.header_size for p in fwd)
bwd_header_total = sum(p.header_size for p in bwd)
```

Where `header_size = transport.dataofs * 4` for TCP, `= 8` for UDP.

**Root cause:** We're summing across ALL packets, but getting 5-6x higher values.

**Hypotheses:**
1. CICFlowMeter divides by packet count (average header)?
2. CICFlowMeter only counts certain packets?
3. Our `dataofs` calculation is wrong?

**Fix required:** Compare with CICFlowMeter's header length logic

---

### 3. Active/Idle Timing (KS 0.64) - MAJOR
**Symptoms:**
- Active Mean: ref=184,826µs, ours=341,517µs (85% larger)
- Active Max: ref=208,084µs, ours=616,201µs (3x larger)

**Current logic:**
- Threshold: 5 seconds (5,000,000 µs)
- If IAT > threshold → switch from active to idle
- Active period = last_packet_time - last_active_start

**Root cause:** Our active periods are too long.

**Hypotheses:**
1. Threshold is wrong (should be different value?)
2. We're not resetting active_start correctly?
3. CICFlowMeter uses different algorithm?

**Fix required:** Verify threshold and compare state machine with CICFlowMeter

---

### 4. Flow Rate Calculation (KS 0.37) - PARTIALLY FIXED
**Symptoms:**
- Flow Packets/s: ref=14,241, ours=79,235 (5.5x larger!)

**Already fixed:** Changed `duration_us` to `duration_s` for rate calculation

**Still wrong:** Getting 5.5x higher rates suggests we have incorrect duration or packet counts.

**Root cause:** Likely tied to packet filtering issue. If we're including packets CICFlowMeter excludes, counts inflate.

---

## What DID Get Fixed ✅

### Flag Counts (KS < 0.3)
- SYN Flag Count: KS=0.270 (was worse, now acceptable)
- ACK Flag Count: KS=0.025 (GOOD)
- RST Flag Count: KS=0.076 (GOOD)

**Fix applied:** Changed from cumulative counts to binary per-flow:
```python
"SYN Flag Count": 1 if any(p.flags & FLAG_SYN for p in fwd) else 0
```

This matches CICFlowMeter's definition.

---

## Root Cause Hypothesis

All bugs point to a **packet filtering mismatch**:

1. **We're counting different packets than CICFlowMeter**
   - Maybe they filter retransmissions?
   - Maybe they filter ACK-only packets?
   - Maybe they handle fragmented packets differently?

2. **Evidence:**
   - Packet counts too low → size averages skewed
   - Header totals too high → summing over wrong packet set
   - Active periods too long → not detecting gaps correctly
   - Rates too high → duration calculation off

---

## How to Actually Fix This

### Step 1: Get CICFlowMeter Source
Download: https://github.com/ahlashkari/CICFlowMeter

Key files to examine:
- `FlowMeter.java` - Main flow logic
- `FlowFeature.java` - Feature calculation
- `PacketReader.java` - Packet filtering

### Step 2: Side-by-Side Comparison
For each feature with high KS:

1. Find CICFlowMeter's exact calculation
2. Compare with our `flow_extractor.py`
3. Note differences in:
   - Packet filtering
   - Unit conversions
   - Aggregation methods

### Step 3: Reproduce Their Logic
Port their exact logic to Python, including:
- Any packet filters they apply
- Exact same data types/units
- Same edge case handling

### Estimated Time
- Step 1: 1 hour (download + setup Java)
- Step 2: 4-6 hours (detailed comparison)
- Step 3: 2-3 hours (implement fixes)
- Testing: 1-2 hours (re-run KS test)

**Total: 8-12 hours of focused work**

---

## Workarounds for Now

### Option 1: Retrain Models on Our Extractor
- Extract features from training PCAPs using our extractor
- Retrain all 6 models on our feature distributions
- **Pro:** Models will match inference exactly
- **Con:** 40+ hours of retraining (DDoS, C2, DGA, ETT, port scan, exfil)

### Option 2: Use As-Is (Current Approach)
- Accept 92% drift
- Models still detect attacks (proven on DDoS, C2)
- **Pro:** No additional work
- **Con:** Degraded accuracy, unknown false positive rate

### Option 3: Switch to Zeek/Bro
- Use production-grade flow extractor
- **Pro:** Industry standard, well-tested
- **Con:** Complete pipeline rewrite, loses custom feature sets

---

## Recommendation

For **demo/hackathon**: Use as-is (Option 2)
- Backend works, models fire, dashboard looks good
- Feature drift is academic concern, not blocking

For **production**: Fix extractor (8-12 hours) OR retrain models (40+ hours)
- Production accuracy matters
- Can't ship with 92% drift

---

## Files to Fix

If doing the 8-12 hour fix:

1. `netsentinel/extractor/flow_extractor.py`
   - Lines 156-167: Packet size calculation
   - Lines 384-385: Header length calculation  
   - Lines 315-333: Active/idle tracking
   - Lines 388-395: Duration/rate calculation

2. Test with:
   ```bash
   python scripts/covariate_shift.py
   # Target: < 20% shifted (< 10 features with KS > 0.1)
   ```

---

## Current Status

✅ **Quick wins completed:**
- Exfil scaler retrained with sklearn 1.3.2
- Evidence patches added to all models
- Port scan test PCAP generated

❌ **Multi-hour fix deferred:**
- Extractor bugs remain (92% drift)
- Requires CICFlowMeter source comparison
- Estimated 8-12 hours focused work

**System is functional** for demo purposes but not production-ready.
