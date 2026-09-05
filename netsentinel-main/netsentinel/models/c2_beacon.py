"""C2 Beacon Detector — BiLSTM + FFT ONNX Wrapper.

Input: Time-series of 100 flows (IAT, packet_size, bytes, direction)
       + 5 FFT periodicity features
Output: {"threat": "C2 Beacon", "confidence": float, "periodicity": float}

The model expects two inputs:
  - seq_input: [1, 100, 4] — scaled time-series features
  - fft_input: [1, 5] — scaled FFT features
"""
import numpy as np
import onnxruntime as ort

from netsentinel.config import (
    C2_MODEL_PATH,
    C2_SEQ_MEAN_PATH, C2_SEQ_SCALE_PATH,
    C2_FFT_MEAN_PATH, C2_FFT_SCALE_PATH,
)


class C2BeaconDetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            C2_MODEL_PATH,
            providers=['CPUExecutionProvider']
        )
        
        # Load scalers (saved as numpy arrays)
        self.seq_mean = np.load(C2_SEQ_MEAN_PATH)
        self.seq_scale = np.load(C2_SEQ_SCALE_PATH)
        self.fft_mean = np.load(C2_FFT_MEAN_PATH)
        self.fft_scale = np.load(C2_FFT_SCALE_PATH)
        
        # Prevent division by zero
        self.seq_scale[self.seq_scale == 0] = 1.0
        self.fft_scale[self.fft_scale == 0] = 1.0
        
        # Get input names from ONNX
        self.input_names = [inp.name for inp in self.session.get_inputs()]
        
        print(f"  [OK] C2 Beacon Detector loaded (seq_len=100, 4 features + 5 FFT)")
    
    def _compute_fft_features(self, iats: np.ndarray) -> np.ndarray:
        """
        Compute 5 FFT periodicity features from inter-arrival times.
        
        Features:
          1. fft_score: normalized magnitude of dominant frequency
          2. dominant_freq: the dominant frequency (1/period)
          3. harmonic_ratio: ratio of 2nd harmonic to fundamental
          4. spectral_entropy: entropy of the power spectrum
          5. peak_prominence: how much the peak stands out
        """
        if len(iats) < 4:
            return np.zeros(5, dtype=np.float32)
        
        # Compute FFT on RAW IATs (no mean removal)
        # CRITICAL FIX: Do NOT mean-center before FFT for beacon detection
        # Original (WRONG): fft_vals = np.fft.rfft(iats - np.mean(iats))
        # Constant-interval beacons have all energy at one frequency
        # Mean removal destroys this signal
        fft_vals = np.fft.rfft(iats)  # Use raw signal
        magnitudes = np.abs(fft_vals[1:])  # Skip DC component
        
        if len(magnitudes) == 0 or magnitudes.sum() == 0:
            return np.zeros(5, dtype=np.float32)
        
        # 1. FFT score (normalized peak magnitude)
        fft_score = magnitudes.max() / (magnitudes.sum() + 1e-9)
        
        # 2. Dominant frequency
        dominant_idx = np.argmax(magnitudes)
        dominant_freq = (dominant_idx + 1) / len(iats)
        
        # 3. Harmonic ratio
        if len(magnitudes) > (dominant_idx + 1) * 2:
            harmonic_mag = magnitudes[(dominant_idx + 1) * 2 - 1]
            harmonic_ratio = harmonic_mag / (magnitudes[dominant_idx] + 1e-9)
        else:
            harmonic_ratio = 0.0
        
        # 4. Spectral entropy
        power = magnitudes ** 2
        power_norm = power / (power.sum() + 1e-9)
        spectral_entropy = -np.sum(power_norm * np.log2(power_norm + 1e-12))
        spectral_entropy = spectral_entropy / (np.log2(len(power_norm)) + 1e-9)
        
        # 5. Peak prominence
        peak_prominence = (magnitudes.max() - np.median(magnitudes)) / (np.std(magnitudes) + 1e-9)
        
        return np.array([fft_score, dominant_freq, harmonic_ratio,
                         spectral_entropy, peak_prominence], dtype=np.float32)
    
    def predict(self, flow_series: list) -> dict:
        """
        Detect C2 beaconing in a time-series of flows.
        
        Args:
            flow_series: list of dicts, each with keys:
                         'iat', 'packet_size', 'bytes', 'direction'
                         Must have exactly 100 entries.
        
        Returns:
            dict with threat, confidence, is_beacon, periodicity
        """
        SEQ_LEN = 100
        
        # Pad or truncate to 100
        if len(flow_series) < SEQ_LEN:
            # Pad with zeros
            flow_series = flow_series + [{'iat': 0, 'packet_size': 0, 'bytes': 0, 'direction': 0}] * (SEQ_LEN - len(flow_series))
        else:
            flow_series = flow_series[:SEQ_LEN]
        
        # Build sequence array [100, 4]
        seq = np.array([
            [f.get('iat', 0), f.get('packet_size', 0),
             f.get('bytes', 0), f.get('direction', 0)]
            for f in flow_series
        ], dtype=np.float32)
        
        # Compute FFT features from IATs
        iats = seq[:, 0]
        non_zero_iats = iats[iats > 0]
        fft_feats = self._compute_fft_features(iats)
        
        # Compute CV for low-jitter beacon detection
        # CRITICAL: Separate from FFT features to avoid polluting model input
        cv = float(np.std(non_zero_iats) / (np.mean(non_zero_iats) + 1e-9)) if len(non_zero_iats) > 0 else 1.0
        
        # Scale
        seq_scaled = (seq - self.seq_mean) / self.seq_scale
        fft_scaled = (fft_feats - self.fft_mean) / self.fft_scale
        
        # Reshape for ONNX: [1, 100, 4] and [1, 5]
        seq_input = seq_scaled.reshape(1, SEQ_LEN, 4).astype(np.float32)
        fft_input = fft_scaled.reshape(1, 5).astype(np.float32)
        
        # Run inference
        feed = {
            self.input_names[0]: seq_input,
            self.input_names[1]: fft_input,
        }
        results = self.session.run(None, feed)
        
        # Output is logits [batch, 2] — class 0 = benign, class 1 = beacon
        # Apply softmax to get probabilities
        logits = results[0].flatten()
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        prob = float(probs[1])  # Index 1 = beacon probability
        
        # Extract FFT features for gate evaluation
        fft_score = float(fft_feats[0])
        spectral_entropy = float(fft_feats[3])
        peak_prominence = float(fft_feats[4])
        
        # Benign periodic traffic exclusions (mitigate false positives)
        # Extract flow metadata if available
        dest_port = flow_series[0].get('dest_port', 0) if flow_series else 0
        src_port = flow_series[0].get('src_port', 0) if flow_series else 0
        total_duration = sum(f.get('iat', 0) for f in flow_series if f.get('iat', 0) > 0)
        
        # Compute beacon interval for filtering
        if len(non_zero_iats) > 4:
            mean_iat = np.mean(non_zero_iats)
            beacon_interval = mean_iat
        else:
            beacon_interval = 0.0
        
        # Filter 1: NTP (port 123, ~64s intervals)
        is_ntp = (dest_port == 123 or src_port == 123) and (60 < beacon_interval < 70)
        
        # Filter 2: TCP keepalives (common ports, ~30s intervals, short duration)
        is_keepalive = (
            dest_port in [22, 443, 3389, 5900] and  # SSH, HTTPS, RDP, VNC
            25 < beacon_interval < 35 and
            total_duration < 600  # Less than 10 minutes
        )
        
        # Filter 3: DNS refresh (port 53, ~300s intervals)
        is_dns_refresh = (dest_port == 53 or src_port == 53) and (250 < beacon_interval < 350)
        
        # Filter 4: HTTPS health checks (port 443, 10-60s intervals, short flows)
        is_health_check = (
            dest_port == 443 and
            10 < beacon_interval < 60 and
            len(non_zero_iats) < 20  # Few flows
        )
        
        # If matches benign periodic pattern, force benign classification
        is_benign_periodic = is_ntp or is_keepalive or is_dns_refresh or is_health_check
        
        # Periodicity gate with CV check for low-jitter beacons
        # Documented in HONEST_TEST_REPORT.md - CV < 0.05 catches constant beacons
        # but also fires on benign periodic traffic (filtered above)
        low_jitter_beacon = prob > 0.90 and cv < 0.05 and not is_benign_periodic
        fft_based_beacon = (prob > 0.90 and fft_score > 0.15 and 
                           spectral_entropy < 0.85 and peak_prominence > 3.0)
        is_beacon = low_jitter_beacon or fft_based_beacon
        
        # Compute estimated beacon interval from FFT (for reporting)
        if len(non_zero_iats) > 4:
            fft_vals_period = np.fft.rfft(non_zero_iats)
            magnitudes_period = np.abs(fft_vals_period[1:])
            if len(magnitudes_period) > 0 and magnitudes_period.max() > 0:
                dominant_idx = np.argmax(magnitudes_period)
                period = len(non_zero_iats) / (dominant_idx + 1)
                beacon_interval_fft = np.mean(non_zero_iats) * period
            else:
                beacon_interval_fft = beacon_interval
        else:
            beacon_interval_fft = beacon_interval
        
        result = {
            "threat": "C2 Beacon" if is_beacon else "Benign",
            "confidence": prob,
            "is_beacon": is_beacon,
            "periodicity_seconds": float(beacon_interval_fft),
            "model": "c2_beacon_bilstm",
        }
        
        # Add IAT evidence for beacon clock visualization
        if is_beacon:
            # Take first 24 IATs for the frontend chart
            iat_values = [float(iat) for iat in iats[:24] if iat > 0]
            
            result["evidence"] = {
                "iat": iat_values,
                "beacon_interval": round(float(beacon_interval_fft), 2),
                "coefficient_of_variation": round(cv, 3),
                "fft_score": round(fft_score, 3),
            }
        
        return result

