"""Pytest configuration for the NetSentinel backend suite.

Three separate problems made `pytest tests/` unusable. All three are fixed
here, rather than by rewriting the modules that cause them.

1. `tests/` mixes real pytest modules with standalone SCRIPTS.
   `test_advanced.py` is a live-API stress script: it executes at import time
   and calls `sys.exit(1)` when nothing is listening on localhost:8000.
   pytest imports every `test_*.py` during collection, so that `sys.exit`
   aborted the ENTIRE run with INTERNALERROR before a single test could run.
   It is excluded from collection below and remains perfectly runnable as
   `python tests/test_advanced.py` against a live server.

2. `test_live_system.py::test_live_pcap(pcap_path)` declares an argument,
   which pytest interprets as a fixture request. No such fixture existed, so
   it errored at setup on every run. A `pcap_path` fixture is provided below,
   fed by a new `--pcap` option; without that option the test SKIPS instead
   of erroring, which is the correct outcome for an opt-in integration test
   that needs a capture file the repo does not ship.

3. These modules import `netsentinel`, which only resolves when the repo root
   is on sys.path. That previously forced every caller to set PYTHONPATH by
   hand (`python tests/x.py` failed with ModuleNotFoundError otherwise).
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Standalone scripts that must not be collected as tests (see 1 above).
collect_ignore = ["test_advanced.py"]


def pytest_addoption(parser):
    parser.addoption(
        "--pcap",
        action="store",
        default=None,
        help="Path to a real .pcap file for the opt-in live pipeline test.",
    )


@pytest.fixture
def pcap_path(request):
    """Real capture for test_live_system; skips when --pcap is not given."""
    path = request.config.getoption("--pcap")
    if not path:
        pytest.skip("needs --pcap=/path/to/capture.pcap")
    if not Path(path).exists():
        pytest.skip(f"--pcap file not found: {path}")
    return path
