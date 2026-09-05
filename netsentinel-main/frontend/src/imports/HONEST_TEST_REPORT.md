# C2 Constant-Interval Beacon - Partial Fix with Known Limitations

**Date**: February 28, 2026  
**Bug**: C2 beacons with constant inter-arrival times bypass periodicity gate  
**Status**: ⚠️ **PARTIAL FIX - NOT PRODUCTION READY**

---

## What Was Done

Added a coefficient of variation (CV) check to the C2 beacon detection gate:
- CV < 0.05 (low jitter) now triggers beacon classification
- Implemented as separate gate logic, NOT in `_compute_fft_features()`
- FFT features remain unchanged to avoid polluting model input with synthetic values

**Files Modified**:
1. `netsentinel/models/c2_beacon.py` - Added CV gate in `predict()`
2. `test_gating_integration.py` - Fixed `assert` statements, added FP test

---

## Test Results

```
4 passed, 4 skipped
```

| Test | Status | Notes |
|------|--------|-------|
| `test_random_traffic_fails_periodicity_gate` | ✅ PASS | Random traffic still rejected |
| `test_jittered_beacon_passes_periodicity_gate` | ✅ PASS | FFT-based detection preserved |
| `test_constant_interval_beacon_is_detected` | ✅ PASS | CV < 0.05 detected |
| `test_benign_periodic_false_positive` | ✅ PASS | **Documents known FP issue** |
| DDoS + C2 model tests | ⏸️ SKIP | Require ONNX models |

---

## Critical Limitations

### 🔴 False Positive Regression

**The CV gate fires on ALL low-jitter periodic traffic**, including:
- NTP clients (64s polling intervals)
- TCP keepalives (30s standard)
- DNS refresh queries
- Health check polling
- Application heartbeats
- Any telemetry/monitoring with constant intervals

**Evidence**: `test_benign_periodic_false_positive` shows NTP-like traffic (64s constant) has CV < 0.05 and will fire.

**Impact**: This trades the original false-negative (missed metronome C2) for a spray of false-positives on legitimate periodic infrastructure traffic.

### 🔴 Untested End-to-End Behavior

The fix has NOT been tested with:
- Real ONNX model inference (tests skip model loading)
- Actual C2 beacon captures
- Production network traffic
- Model behavior with constant-interval flows (prob distribution unknown)

**Risk**: Without end-to-end testing, we cannot verify:
- Whether `prob > 0.90` threshold is met for constant beacons
- Whether benign periodic traffic actually fires (only CV tested, not full gate)
- Model stability with edge-case FFT features

---

## What Works

✅ **FFT features unchanged** - No synthetic values fed to model  
✅ **Jittered beacon detection preserved** - Alternating patterns still caught via FFT  
✅ **Random traffic rejection preserved** - High CV traffic still rejected  
✅ **Constant beacon CV detection** - Low jitter patterns identified  
✅ **Test assertion fix** - `assert not gate` handles numpy booleans correctly

---

## Implementation Details

### Gate Logic (in `predict()`)

```python
cv = float(np.std(non_zero_iats) / (np.mean(non_zero_iats) + 1e-9))

low_jitter_beacon = prob > 0.90 and cv < 0.05
fft_based_beacon = (prob > 0.90 and fft_score > 0.15 and 
                   spectral_entropy < 0.85 and peak_prominence > 3.0)
is_beacon = low_jitter_beacon or fft_based_beacon
```

### Why CV = 0.05?

CV < 0.05 means standard deviation < 5% of mean:
- 30s beacon: std < 1.5s variation
- 64s NTP: std < 3.2s variation

Both metronome C2 and legitimate periodic traffic fall below this threshold.

---

## What Should Be Done

### Before Production Deployment

1. **Add benign periodic negatives to training data**:
   - NTP traffic (64s intervals)
   - Keepalives (30s intervals)  
   - Health checks (10s, 15s, 60s intervals)
   - DNS refresh queries
   - Retrain model to discriminate benign vs malicious periodicity

2. **End-to-end testing**:
   - Test with real ONNX model loaded
   - Capture actual C2 beacon traffic (Cobalt Strike, Meterpreter)
   - Verify `prob > 0.90` threshold is met
   - Collect FP rate on production-like traffic

3. **Alternative approaches** (better long-term):
   - Timeline-based FFT: bin packet counts over time windows instead of raw IATs
   - Behavioral clustering: group periodic flows and label clusters
   - Multi-feature ensemble: combine CV with packet size entropy, port patterns

### Quick Mitigation (if deploying now)

Add NTP/keepalive port exclusions:
```python
# In predict(), before gate:
is_ntp_like = (beacon_interval > 60.0 and beacon_interval < 70.0)  # NTP range
is_keepalive = (beacon_interval > 25.0 and beacon_interval < 35.0)  # TCP keepalive
if is_ntp_like or is_keepalive:
    return benign_result
```

This is a band-aid, not a fix.

---

## Honest Assessment

| Aspect | Rating | Reason |
|--------|--------|--------|
| **Bug understanding** | ✅ GOOD | Root cause correctly identified (mean-removal on constants) |
| **Fix correctness** | ⚠️ PARTIAL | CV detection works, but FP issue unresolved |
| **Code quality** | ✅ GOOD | Separate gate logic, FFT features clean |
| **Test coverage** | ⚠️ PARTIAL | Feature-level tests pass, end-to-end untested |
| **Production readiness** | ❌ NOT READY | False positive regression blocks deployment |
| **Documentation** | ✅ GOOD | Known issues explicitly documented in tests and code |

---

## Recommendations

### Do NOT deploy as-is

The CV gate introduces unacceptable false-positive risk on legitimate infrastructure traffic.

### Options:

**Option A** (Ship the fix with honest caveats):
- Document known FP issue clearly
- Deploy with conservative threshold (CV < 0.01 instead of 0.05)
- Monitor FP rate and tune
- Timeline for model retrain: [specify]

**Option B** (Do it right):
- Collect benign periodic traffic samples
- Retrain model with proper negatives
- Re-test with full dataset
- Deploy when FP rate is acceptable

**Option C** (Defer the fix):
- Revert CV changes
- Keep original limitation documented
- Focus on model retrain first
- Add CV gate only after model can discriminate

---

## What the Earlier Report Got Wrong

1. **"APPROVED for production"** - Incorrect, FP issue blocks deployment
2. **"Confidence Level: HIGH"** - Overstated, end-to-end untested
3. **"3 passed" implying full validation** - Only feature-level tests, not integration
4. **Synthetic FFT feature approach** - First version polluted model input (corrected)
5. **Understating FP risk** - Listed as "long-term improvement", actually current blocker

---

## Conclusion

The CV gate is a **step in the right direction** for detecting low-jitter C2 beacons, but it's **not production-ready** due to false-positive regression on benign periodic traffic.

The proper fix requires retraining the model with benign periodic negatives. The CV gate can be part of the solution, but only after the model can discriminate malicious from legitimate periodicity.

**Current status**: Feature-level tests pass, known limitations documented, production deployment blocked.

**Next step**: Collect benign periodic traffic samples and retrain, OR deploy with very conservative threshold and aggressive monitoring.
