# Model Files Download Instructions

Due to GitHub's file size limitations, the trained ML model files are not included in this repository.

## Required Models

NetSentinel requires six trained models:

1. **DDoS Detector**: XGBoost model (14 MB)
2. **DGA Detector**: CNN-BiLSTM model (2.8 MB)
3. **C2 Beacon Detector**: BiLSTM+FFT model (1.2 MB)
4. **Encrypted Traffic Transformer**: FT-Transformer model (8.1 MB)
5. **Port Scan Detector**: XGBoost model (varies)
6. **Exfiltration Detector**: VAE model (varies)

## Download Options

### Option 1: Download from Release Assets

Visit the [Releases](https://github.com/yourusername/netsentinel/releases) page and download the model package:

```bash
# Extract to models directory
unzip netsentinel-models-v1.0.zip -d ~/models/
```

### Option 2: Direct Download Links

Models are hosted on [your hosting solution]:

- DDoS Model: [link]
- DGA Model: [link]
- C2 Beacon Model: [link]
- ETT Model: [link]
- Port Scan Model: [link]
- Exfiltration Model: [link]

### Option 3: Train Your Own Models

Refer to docs/MODEL_TRAINING.md for instructions on training models from scratch using the provided Jupyter notebooks.

## Model Directory Structure

After downloading, your directory structure should look like:

```
~/models/
├── Ddos_detection/
│   └── ddos_binary_xgboost.onnx
├── dga_dna_tunneling_detection/
│   └── dga_cnn_bilstm.onnx
├── c2_beacon_detector/
│   └── c2_beacon_bilstm.onnx
├── encrypted_traffic_transformer/
│   └── encrypted_traffic_transformer.onnx
├── portscan/
│   ├── port_scan_cic_xgboost.onnx
│   └── port_scan_cic_features.json
└── exfil/
    ├── exfil_vae.onnx
    ├── exfil_scaler.joblib
    └── exfil_meta.json
```

## Configuration

Update 
etsentinel/config.py with your model path:

```python
MODELS_DIR = "~/models"  # Or your custom path
```

