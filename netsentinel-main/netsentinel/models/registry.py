"""Model Registry — Loads all ONNX models on startup.

Usage:
    registry = ModelRegistry()
    registry.load_all()
    
    result = registry.ddos.predict(flow_features)
"""
import time
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
    
    def load_all(self):
        """Load all models. Call once on server startup."""
        print("\n[*] Loading AI models...")
        total_start = time.time()
        
        models = [
            ("DDoS XGBoost", "ddos", DDoSDetector),
            ("C2 Beacon BiLSTM+FFT", "c2", C2BeaconDetector),
            ("DGA CNN-BiLSTM", "dga", DGADetector),
            ("Encrypted Traffic Transformer", "ett", EncryptedTrafficDetector),
            ("Port Scan XGBoost", "port_scan", PortScanDetector),
            ("Exfiltration VAE", "exfiltration", ExfiltrationDetector),
        ]
        
        for name, attr, cls in models:
            start = time.time()
            try:
                instance = cls()
                setattr(self, attr, instance)
                elapsed = time.time() - start
                self._load_times[name] = elapsed
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
        
        return self
    
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
        }
