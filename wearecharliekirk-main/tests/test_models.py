"""Verify all 6 detection models load through the registry.

Runnable two ways:
    pytest tests/test_models.py
    python tests/test_models.py
"""
import sys
from pathlib import Path

# Repo root on sys.path so `netsentinel` resolves when run directly as a
# script. (tests/conftest.py already handles this for pytest runs.)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netsentinel.models.registry import ModelRegistry

# Registry ATTRIBUTE -> human name. These are the real attribute names set in
# ModelRegistry.__init__; the previous version of this file used invented ids
# ("ddos_binary_xgboost", "dga_lstm", "vpn_tunnel_xgboost", ...) that the
# registry has never exposed.
EXPECTED_MODELS = [
    ("ddos",         "DDoS Binary XGBoost"),
    ("dga",          "DGA / DNS-Tunnel CNN-BiLSTM"),
    ("c2",           "C2 Beacon BiLSTM + FFT"),
    ("ett",          "Encrypted Traffic Transformer"),
    ("port_scan",    "Port Scan XGBoost"),
    ("exfiltration", "Exfiltration VAE"),
]


def test_model_loading():
    """All 6 models must load and be non-None.

    REWRITTEN 2026-09-20 -- the previous version was a test that COULD NOT
    FAIL. It called `registry.load_all_models()` and `registry.get_model(...)`,
    neither of which exists on ModelRegistry (the real API is `load_all()`
    plus the attributes above). Every run therefore raised AttributeError,
    hit a bare `except Exception`, printed the error and did `return False`
    -- and pytest counts a returned value as a PASS. So it reported PASSED on
    every single run while asserting nothing and in fact failing. Returning a
    value also raised PytestReturnNotNoneWarning, which is scheduled to become
    a hard error in a future pytest. It now asserts.
    """
    registry = ModelRegistry()
    registry.load_all()

    missing = []
    for attr, name in EXPECTED_MODELS:
        loaded = getattr(registry, attr, None) is not None
        print(f"  [{'OK ' if loaded else 'MISSING'}] {name:32s} registry.{attr}")
        if not loaded:
            missing.append(f"{name} (registry.{attr})")

    assert not missing, f"{len(missing)} model(s) failed to load: {missing}"


if __name__ == "__main__":
    try:
        test_model_loading()
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        sys.exit(1)
    print(f"OK: {len(EXPECTED_MODELS)}/{len(EXPECTED_MODELS)} models operational")
    sys.exit(0)
