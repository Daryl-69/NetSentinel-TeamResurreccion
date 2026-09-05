# HuggingFace Upload Guide — Port Scan & Exfil Models

## Quick Upload (2 options)

### Option 1: Python Script (Recommended)

```bash
# 1. Prepare files (already done ✅)
python prepare_hf_upload.py

# 2. Login to HuggingFace (one-time)
huggingface-cli login
# Paste your token from: https://huggingface.co/settings/tokens

# 3. Upload
python upload_to_hf.py
```

### Option 2: Web Interface

1. **Go to:** https://huggingface.co/Unded-17/netsentinel-models/tree/main

2. **Upload port_scan folder:**
   - Click "Add file" → "Upload files"
   - Navigate to: `./hf_upload/port_scan\`
   - Select all 2 files:
     - `port_scan_xgboost.onnx` (742.7 KB)
     - `port_scan_features.json` (0.5 KB)
   - **Important:** Set upload path to `port_scan/` (create folder)
   - Commit message: "Add port_scan model files"
   - Click "Commit"

3. **Upload exfil folder:**
   - Click "Add file" → "Upload files" again
   - Navigate to: `./hf_upload/exfil\`
   - Select all 4 files:
     - `exfil_vae.onnx` (3.2 KB)
     - `exfil_vae.onnx.data` (323.0 KB)
     - `exfil_scaler.joblib` (0.8 KB)
     - `exfil_meta.json` (1.1 KB)
   - **Important:** Set upload path to `exfil/` (create folder)
   - Commit message: "Add exfil model files"
   - Click "Commit"

---

## What Gets Uploaded

### Port Scan Model
```
port_scan/
├── port_scan_xgboost.onnx        (ONNX model, 742.7 KB)
└── port_scan_features.json       (40 feature names with 'id')
```

### Data Exfiltration Model
```
exfil/
├── exfil_vae.onnx                (ONNX model, 3.2 KB)
├── exfil_vae.onnx.data           (ONNX weights, 323.0 KB)
├── exfil_scaler.joblib           (scikit-learn scaler)
└── exfil_meta.json               (24 feature names)
```

---

## After Upload

### Verify Upload
```bash
# Check if files are accessible
python -c "from netsentinel.config import PORT_SCAN_MODEL_PATH, EXFIL_MODEL_PATH; print('✅ Paths resolved')"
```

### Test Loading
```bash
# Should now pass all checks
python validate_fixes.py
```

### Start Backend
```bash
python run.py
# Should see:
#   [OK] Port Scan XGBoost loaded (40 features)
#   [OK] Exfiltration VAE loaded (24 features)
#   [OK] 6/6 models loaded
```

---

## Troubleshooting

### "huggingface-cli: command not found"
```bash
pip install huggingface_hub
```

### "Repository not found"
Make sure you have write access to `Unded-17/netsentinel-models`

### "Authentication required"
```bash
huggingface-cli login
# Or set environment variable:
export HF_TOKEN="your_token_here"  # Linux/Mac
set HF_TOKEN=your_token_here       # Windows CMD
$env:HF_TOKEN="your_token_here"    # Windows PowerShell
```

### "Files uploaded but still 404"
Wait 1-2 minutes for HF cache to update, then retry

---

## File Mapping Reference

Source files from Desktop were renamed for consistency:

| Source (Desktop) | Destination (HF) |
|-----------------|------------------|
| `expert5_portscan_xgboost.onnx` | `port_scan/port_scan_xgboost.onnx` |
| `expert5_feature_names.json` | `port_scan/port_scan_features.json` |
| `expert6_vae.onnx` | `exfil/exfil_vae.onnx` |
| `expert6_vae.onnx.data` | `exfil/exfil_vae.onnx.data` |
| `expert6_scaler.joblib` | `exfil/exfil_scaler.joblib` |
| `expert6_meta.json` | `exfil/exfil_meta.json` |

---

## Expected Repository Structure After Upload

```
Unded-17/netsentinel-models/
├── Ddos_detection/
│   ├── ddos_binary_xgboost.onnx
│   ├── feature_names.json
│   └── label_mapping.json
├── c2_beacon_detector/
│   ├── c2_beacon_bilstm.onnx
│   ├── scaler_seq_mean.npy
│   ├── scaler_seq_scale.npy
│   ├── scaler_fft_mean.npy
│   └── scaler_fft_scale.npy
├── dga_dna_tunneling_detection/
│   └── dga_cnn_bilstm_v2.onnx
├── encrypted_traffic_transformer/
│   ├── encrypted_traffic_transformer.onnx
│   ├── ett_scaler.json
│   └── ett_classes.json
├── port_scan/                     ← NEW
│   ├── port_scan_xgboost.onnx
│   └── port_scan_features.json
└── exfil/                         ← NEW
    ├── exfil_vae.onnx
    ├── exfil_vae.onnx.data
    ├── exfil_scaler.joblib
    └── exfil_meta.json
```

---

**Once uploaded, all 6 models will auto-download on first run!** 🎉
