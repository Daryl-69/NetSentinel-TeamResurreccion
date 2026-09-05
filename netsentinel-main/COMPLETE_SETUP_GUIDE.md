# NetSentinel — Complete Setup Guide

Follow these steps in order to get a fully working system.

## 🎯 Current Status

✅ **Fixed:**
- Dependencies added to requirements.txt
- Model loading architecture unified
- Benign alert leak fixed
- Vestigial files removed

⚠️ **Needs Action:**
1. Upload port_scan and exfil models to HuggingFace
2. Downgrade scikit-learn to 1.3.2

---

## Step 1: Fix scikit-learn Version

**Problem:** You have 1.7.1, need 1.3.2 (causes 50% exfil false positives)

```bash
python fix_sklearn_version.py
```

**Manual alternative:**
```bash
pip uninstall scikit-learn
pip install scikit-learn==1.3.2
```

**Verify:**
```bash
python -c "import sklearn; print(sklearn.__version__)"
# Should print: 1.3.2
```

---

## Step 2: Upload Models to HuggingFace

**Files are already prepared** in `hf_upload/` folder.

### Option A: Python Script (Recommended)

```bash
# 1. Login (one-time)
huggingface-cli login
# Paste your token from: https://huggingface.co/settings/tokens

# 2. Upload
python upload_to_hf.py
```

### Option B: Web Interface

See detailed instructions in: **`HF_UPLOAD_GUIDE.md`**

Quick summary:
1. Go to https://huggingface.co/Unded-17/netsentinel-models
2. Click "Add file" → "Upload files"
3. Upload `hf_upload/port_scan/` contents to `port_scan/` folder
4. Upload `hf_upload/exfil/` contents to `exfil/` folder

---

## Step 3: Validate Everything Works

```bash
python validate_fixes.py
```

**Expected output:**
```
[1/5] Checking dependencies...
  ✅ huggingface_hub
  ✅ joblib
  ✅ scikit-learn

[2/5] Checking scikit-learn version...
  ✅ scikit-learn version: 1.3.2 (correct)

[3/5] Checking config.py model paths...
  ✅ DDOS_MODEL_PATH defined
  ✅ C2_MODEL_PATH defined
  ✅ DGA_MODEL_PATH defined
  ✅ ETT_MODEL_PATH defined
  ✅ PORT_SCAN_MODEL_PATH defined
  ✅ EXFIL_MODEL_PATH defined

[4/5] Checking model wrappers...
  ✅ PortScanDetector uses config.py
  ✅ ExfiltrationDetector uses config.py

[5/5] Checking for vestigial files...
  ✅ No vestigial files found

✅ All validation checks passed!
```

---

## Step 4: Start the Backend

```bash
python run.py
```

**Expected output:**
```
[*] Loading AI models...
  [INFO] Downloading from Hugging Face: port_scan/port_scan_xgboost.onnx
  [OK] Downloaded: port_scan/port_scan_xgboost.onnx
  [OK] DDoS Detector loaded (59 features)
  [OK] C2 Beacon BiLSTM+FFT loaded
  [OK] DGA CNN-BiLSTM loaded
  [OK] Encrypted Traffic Transformer loaded
  [OK] Port Scan XGBoost loaded (40 features)
  [OK] Exfiltration VAE loaded (24 features)

[OK] 6/6 models loaded in 8.43s

INFO:     Uvicorn running on http://0.0.0.0:8000
WebSocket:   ws://localhost:8000/ws
PCAP Upload: POST http://localhost:8000/api/pcap/upload
```

---

## Step 5: Start the Frontend

```bash
cd frontend
pnpm install
pnpm dev
```

Open browser to the URL shown (typically http://localhost:5173)

---

## Step 6: Test with PCAP

```bash
# Upload a test PCAP
curl -F "file=@Friday-WorkingHours-Afternoon-DDos.pcap" http://localhost:8000/api/pcap/upload

# Check stats
curl http://localhost:8000/api/stats | jq
```

**Expected exfil rate:** < 10% of flows (was 51.8% before fix)

---

## Troubleshooting

### Issue: validate_fixes.py fails on step 3
**Cause:** Models not uploaded to HF yet
**Fix:** Complete Step 2 above

### Issue: scikit-learn version still 1.7.1
**Cause:** pip cache or environment issue
**Fix:**
```bash
pip cache purge
pip uninstall -y scikit-learn
pip install scikit-learn==1.3.2
```

### Issue: Backend crashes on startup
**Cause:** Model files not found
**Fix:** Check HF upload completed successfully:
```bash
# Should succeed without 404
python -c "from netsentinel.config import PORT_SCAN_MODEL_PATH, EXFIL_MODEL_PATH"
```

### Issue: Exfil still high false positive rate
**Cause:** Old scaler loaded, scikit-learn version
**Fix:**
1. Verify sklearn: `python -c "import sklearn; print(sklearn.__version__)"`
2. Restart backend: `Ctrl+C` then `python run.py`
3. Clear cache: `rm -rf ~/.cache/netsentinel/`

---

## Quick Reference Commands

```bash
# Fix sklearn version
python fix_sklearn_version.py

# Prepare HF upload (already done ✅)
python prepare_hf_upload.py

# Upload to HuggingFace
python upload_to_hf.py

# Validate everything
python validate_fixes.py

# Start backend
python run.py

# Start frontend
cd frontend && pnpm dev

# Test with PCAP
curl -F "file=@test.pcap" http://localhost:8000/api/pcap/upload
```

---

## Files Created for Setup

| File | Purpose |
|------|---------|
| `fix_sklearn_version.py` | Downgrade to 1.3.2 |
| `prepare_hf_upload.py` | Organize model files |
| `upload_to_hf.py` | Upload to HuggingFace |
| `validate_fixes.py` | Verify all fixes applied |
| `HF_UPLOAD_GUIDE.md` | Detailed upload instructions |
| `hf_upload/` | Prepared model files |

---

## Summary Checklist

- [ ] Downgrade scikit-learn to 1.3.2
- [ ] Upload port_scan model to HF
- [ ] Upload exfil model to HF
- [ ] Run validate_fixes.py (all green)
- [ ] Start backend (6/6 models load)
- [ ] Start frontend
- [ ] Test with PCAP (exfil < 10%)

**Once all checked, system is fully operational!** 🎉
