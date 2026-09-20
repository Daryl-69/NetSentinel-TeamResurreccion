"""Model Registry — Loads all ONNX models on startup.

Usage:
    registry = ModelRegistry()
    registry.load_all()
    
    result = registry.ddos.predict(flow_features)
"""
import hashlib
import time
from pathlib import Path

from netsentinel.models.ddos import DDoSDetector
from netsentinel.models.c2_beacon import C2BeaconDetector
from netsentinel.models.dga import DGADetector
from netsentinel.models.encrypted import EncryptedTrafficDetector
from netsentinel.models.port_scan import PortScanDetector
from netsentinel.models.exfiltration import ExfiltrationDetector


class ModelRegistry:
    """Loads and holds all ONNX model sessions."""
    
    def __init__(self):
        self.ddos = None
        self.c2 = None
        self.dga = None
        self.ett = None
        self.port_scan = None
        self.exfiltration = None
        self._load_times = {}
        self._model_digests: dict[str, str] = {}   # attr_name → "sha256:..."
        self._model_paths: dict[str, str] = {}     # attr_name → file path
    
    def load_all(self):
        """Load all models. Call once on server startup."""
        print("\n[*] Loading AI models...")
        total_start = time.time()
        
        from netsentinel.config import (
            DDOS_MODEL_PATH, C2_MODEL_PATH, DGA_MODEL_PATH,
            ETT_MODEL_PATH, PORT_SCAN_MODEL_PATH, EXFIL_MODEL_PATH,
        )

        models = [
            ("DDoS XGBoost", "ddos", DDoSDetector, DDOS_MODEL_PATH),
            ("C2 Beacon BiLSTM+FFT", "c2", C2BeaconDetector, C2_MODEL_PATH),
            ("DGA CNN-BiLSTM", "dga", DGADetector, DGA_MODEL_PATH),
            ("Encrypted Traffic Transformer", "ett", EncryptedTrafficDetector, ETT_MODEL_PATH),
            ("Port Scan XGBoost", "port_scan", PortScanDetector, PORT_SCAN_MODEL_PATH),
            ("Exfiltration VAE", "exfiltration", ExfiltrationDetector, EXFIL_MODEL_PATH),
        ]
        
        for name, attr, cls, model_path in models:
            start = time.time()
            try:
                instance = cls()
                setattr(self, attr, instance)
                elapsed = time.time() - start
                self._load_times[name] = elapsed

                # Compute SHA-256 digest of the ONNX file for integrity
                self._model_paths[attr] = str(model_path)
                self._model_digests[attr] = self._hash_file(model_path)
            except FileNotFoundError as e:
                # Model file not found - this is expected for untrained models
                print(f"  [SKIP] {name}: Model file not found")
                setattr(self, attr, None)
                self._load_times[name] = -1
            except Exception as e:
                print(f"  [FAIL] Failed to load {name}: {e}")
                setattr(self, attr, None)
                self._load_times[name] = -1
        
        total_elapsed = time.time() - total_start
        loaded = sum(1 for v in self._load_times.values() if v >= 0)
        print(f"\n[OK] {loaded}/6 models loaded in {total_elapsed:.2f}s")
        if self._model_digests:
            print(f"[OK] {len(self._model_digests)} model digests computed")
        
        return self

    def model_digest(self, attr_name: str) -> str:
        """Return the ``sha256:...`` digest of a loaded model's ONNX file.

        Args:
            attr_name: registry attribute (e.g. ``"ddos"``, ``"c2"``).

        Returns:
            Prefixed digest string, or empty string if model not loaded.
        """
        return self._model_digests.get(attr_name, "")

    @staticmethod
    def _hash_file(path: str) -> str:
        """Compute ``sha256:<hex>`` of a file's bytes."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return "sha256:" + h.hexdigest()
        except (FileNotFoundError, OSError):
            return ""
    
    def get_status(self) -> dict:
        """Return model status for the /health endpoint."""
        return {
            "models_loaded": {
                "ddos": self.ddos is not None,
                "c2_beacon": self.c2 is not None,
                "dga": self.dga is not None,
                "encrypted_traffic": self.ett is not None,
                "port_scan": self.port_scan is not None,
                "exfiltration": self.exfiltration is not None,
            },
            "load_times": self._load_times,
            "model_digests": dict(self._model_digests),
        }
