# NetSentinel Technical Session Handoff & Architecture Context

**Target Audience:** Future AI Agents / Developers
**Purpose:** Provide exhaustive, code-level context on the NetSentinel pipeline's current state, the precise history of bugs and architectural decisions made in the previous session, and a detailed roadmap for remaining SIH 2026 milestones.

---

## 1. Project Overview & Architecture

NetSentinel is a hybrid, multi-modal network threat detection pipeline built for SIH 2026. It processes PCAP files (and eventually live traffic) to detect 6 distinct classes of threats using 6 specialized AI models.

### 1.1 The Extraction Layer (`netsentinel/extractor/`)
The `PacketProcessor` orchestrates traffic extraction. It uses a hybrid approach:
1.  **CICFlowMeter (Batch)**: Used strictly for PCAP replays to extract zero-drift statistical features. These features are routed to the DDoS and Port Scan models.
2.  **Custom Extractor (Streaming)**: Built on Scapy, this operates in real-time. It splits traffic into three paths:
    *   `FlowExtractor`: Extracts streaming features for the Encrypted Traffic Transformer (ETT) model.
    *   `DNSExtractor`: Extracts DNS queries and NXDOMAIN rates for the DGA and Exfiltration models.
    *   `SessionBuilder`: Aggregates flows into 100-flow time-series for the C2 Beacon detector.

### 1.2 The Analysis Layer (`netsentinel/pipeline/analyzer.py`)
The `FlowAnalyzer` acts as the routing engine. It receives event dictionaries from the extractors (tagged with `type="flow"`, `"dns"`, or `"session"`) and routes them to the appropriate models via `self.registry`.

---

## 2. Deep Dive: DGA Model Restoration & Optimization

A significant portion of the session was spent debugging the Domain Generation Algorithm (DGA) detector, which was exhibiting a 0% True Positive Rate (TPR).

### 2.1 The Degenerate ONNX Export Bug
*   **The Problem:** The `dga_cnn_bilstm_v2.onnx` model was returning identical, constant logits for every input domain.
*   **The Investigation:** By extracting the model definition from `dgatrain(3).ipynb` and matching the state dict keys in `dga_best_model_v2.pt`, it was discovered that the legacy ONNX exporter (via TorchScript tracing) failed to correctly capture the dynamic RNN graph, resulting in a frozen computational graph.
*   **The Fix:** A reconstruction script (`fix_dga_onnx.py`) was written to rebuild the PyTorch architecture (CNN + BiLSTM + 7 Stat Features) and re-export it using standard `torch.onnx.export` with dynamic axes for sequence length.

### 2.2 Model Versioning (v2 vs v1) & The Generalization Gap
*   **Evaluating v2:** After fixing the ONNX export, the v2 model (Dual-input: `domain_chars` [1x128] + `stat_features` [1x7]) was evaluated against the UMUDGA dataset (3,000 domains across 30 families). It achieved only a **39% TPR**. While it detected random-character DGAs (like `cryptolocker`), it completely failed on dictionary-based DGAs.
*   **Discovering v1:** Research into the project directories revealed a previous version (`dga_best_model.pt` -> `dga_cnn_bilstm_v1.onnx`). This was a **single-input** model (character-level only) trained on the DGArchive dataset.
*   **Evaluating v1:** Testing the v1 model against UMUDGA yielded a **76.3% TPR** and **98.0% TNR**. It detected 20/30 families perfectly (>90%) but struggled with 5 families (e.g., `matsnu`, `suppobox`, `nymaim`) which generate purely dictionary-based, pronounceable English domains.
*   **The Resolution:** The pipeline was updated in `config.py` to point to the v1 model. `dga.py` was refactored to dynamically handle single-input ONNX execution, dropping the 7 statistical features which were causing the v2 model to overfit on its specific training set.

---

## 3. Deep Dive: Pipeline Routing, Gating, and Deduplication

After fixing the DGA model, testing against a `dnscat2` PCAP (DNS Tunneling) revealed severe pipeline routing issues.

### 3.1 The Early Return Bug
*   **The Problem:** Exfiltration (DNS Tunnel) alerts were never firing.
*   **The Cause:** In `_analyze_dns`, the logic ran the DGA model first. If DGA triggered an alert, the function hit an early `return`, meaning the Exfiltration VAE model was bypassed completely. 

### 3.2 The Tunnel Probability Gate Bug
*   **The Problem:** To prevent duplicate alerts, a logic gate was placed in the DGA block: `if tunnel_prob < 0.05`. If the DGA model suspected a tunnel, it suppressed its own alert, assuming the Exfiltration model would catch it.
*   **The Catch-22:** The Exfiltration model has its own strict gating (requiring high reconstruction error OR high entropy + long subdomains). For some `dnscat2` domains, the evidence wasn't strong enough to pass the Exfil gate, AND the DGA model suppressed itself because `tunnel_prob` was > 0.05. Result: Zero alerts.
*   **The Fix:** 
    1. Removed the `tunnel_prob` gate. DGA and Exfiltration are recognized as **complementary multi-signals**.
    2. Lowered the DGA threshold (`THRESHOLDS["dga"]`) from 0.80 to 0.70 because it is safely gated by a secondary requirement: `entropy > 3.0`.
    3. Removed the early return. Both models are evaluated. If both trigger, the Exfiltration alert is returned preferentially (as it is more specific to tunneling), with DGA acting as a fallback.

### 3.3 Alert Spam & Deduplication
*   **The Problem:** DNS tunnels generate thousands of queries. The UI was crashing due to alert spam.
*   **The Fix:** Implemented stateful deduplication in `_analyze_dns` using `_dns_alert_times` and `_dns_query_counts`. 
*   **Mechanism:** Extracts the `base_domain` (e.g., `dnscat.evil.com` -> `evil.com`). It suppresses duplicate alerts for the combination of `(alert_type, base_domain, source_ip)` within a **60-second window**. It tracks the `query_count` and attaches it to the alert to provide volume context without spam.

---

## 4. Deep Dive: Dependency Failures (The Exfil Bug)

Even after fixing the routing, Exfiltration alerts failed to appear in the UI.

*   **The Problem:** The `ExfiltrationDetector` was failing silently in the background task during startup.
*   **The Cause:** A binary incompatibility when `joblib` attempted to load the `scikit-learn` scaler (`ett_scaler.json` / `exfil_scaler.npy`). The error was: `ValueError: numpy.dtype size changed, may indicate binary incompatibility. Expected 96 from C header, got 88 from PyObject`. This occurs when a model is trained on `numpy 1.x` but inferred on `numpy 2.x`, breaking C-extension compatibility.
*   **The Fix:** Executed `pip install "numpy<2.0.0"` to downgrade NumPy to version 1.26.4 in the environment. This immediately resolved the issue, and the Exfiltration VAE successfully triggered with 1.000 confidence on `dnscat2` traffic.

---

## 5. Dataset Locations & Context

The user has provided several datasets locally that are critical for upcoming retraining tasks.

1.  **UMUDGA (University of Murcia DGA Dataset):**
    *   Path: `C:\Users\gtrip\Downloads\UMUDGA - University of Murcia Domain Generation Algorithm Dataset`
    *   Use: Primary evaluation dataset for DGA (30 families, 3000 domains).
2.  **DGArchive & Deception Domains:**
    *   Path 1: `C:\Users\gtrip\Downloads\2024-11-28-dgarchive_full.tgz`
    *   Path 2: `C:\Users\gtrip\Downloads\Compressed\2019-02-20-deception_dga-20260904T121832Z-1-001`
    *   Path 3: `C:\Users\gtrip\Downloads\tranco_XN67N.csv`
    *   Use: To be combined with UMUDGA for retraining the DGA model.
3.  **DGA Training Script:**
    *   Path: `C:\Users\gtrip\Downloads\dgatrain(3).ipynb`
    *   Use: The original notebook used to train the v1 model.
4.  **CIC-IDS-2017 (Port Scan & DDoS):**
    *   Path: (User needs to extract `Friday-WorkingHours.pcap` using CICFlowMeter to generate CSVs).

---

## 6. Roadmap & Remaining Tasks (For the Next Agent)

The next AI agent picking up this session must execute the following roadmap to align with the SIH 2026 validation strategy:

### Task 1: Retrain the Port Scan Model
*   **Current State:** The `port_scan_xgboost` model was trained on UNSW-NB15 features. The live extraction pipeline (via CICFlowMeter) outputs CIC-IDS-2017 features. This mismatch causes total failure for Port Scan detection.
*   **Action Required:** Guide the user to extract features from the `Friday-WorkingHours.pcap` (from CIC-IDS-2017) using the project's `cicflowmeter_wrapper.py`. Retrain the XGBoost model on these extracted features to align the data schemas.

### Task 2: Retrain the DGA Model
*   **Current State:** The v1 single-input model has a 76.3% TPR but fails on dictionary-based DGAs (`matsnu`, `suppobox`).
*   **Action Required:** Modify the `dgatrain(3).ipynb` script. Combine the UMUDGA, DGArchive, Deception, and Tranco datasets. Retrain the `CNN-BiLSTM` architecture. Ensure the ONNX export is tested dynamically before deploying it to the pipeline.

### Task 3: LSA (C2 Beacon) Detection Implementation
*   **Current State:** The SIH strategy document (`VALIDATION_AND_STRATEGY.md`) mandates Telegram Bot C2 detection.
*   **Action Required:** Investigate how to simulate or acquire Telegram Bot C2 traffic. Ensure the `SessionBuilder` and the `C2 Beacon Detector` (Expert 4) are tuned to identify the time-series frequency clustering inherent in Telegram long-polling.

### Task 4: DDoS Model Review
*   **Current State:** The user requested an "excellent" DDoS model to replace the current one.
*   **Action Required:** Investigate combining CIC-DDoS2019 and CIC-IDS-2017 datasets to train a highly robust XGBoost or LightGBM model to replace the existing DDoS implementation.

### Task 5: Exfiltration Feature Fallback Verification
*   **Current State:** The Exfiltration model requires `total_fwd_bytes` and `total_bwd_bytes`. The simulator provides these directly, but the PCAP pipeline (custom extractor) does not provide `Fwd Packets Length Total` organically unless it relies on CICFlowMeter.
*   **Action Required:** Ensure the `DNSExtractor` or `build_dns_features` has a robust mechanism for estimating or extracting byte ratios when full flow data is unavailable. (Currently, it estimates `subdomain_len * 50` for outbound, but this should be verified for accuracy).
