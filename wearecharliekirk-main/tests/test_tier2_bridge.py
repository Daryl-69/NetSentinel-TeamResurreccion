"""The console's view of Tier 2: numbers re-derived from tier2/*.json must
match their documented values, and the figure route must only serve PNGs
from the known folders."""
import pytest

from netsentinel import tier2_bridge as T

pytestmark = pytest.mark.skipif(not (T.TIER2 / "lanl_novelty.json").exists(), reason="tier2/ results not present")


def test_headline_numbers_match_their_documented_values():
    groups = T.headline_numbers()
    rows = [r for g in groups for r in g["rows"]]
    assert len(rows) >= 12
    assert [r["label"] for r in rows if r["status"] == "differs"] == []
    real = [g for g in groups if g["kind"] == "real"]
    assert real and any("within a host" in r["label"] and r["display"].startswith("0.557") for r in real[0]["rows"])
    assert any("not a detection rate" in r["note"] for r in real[0]["rows"])


def test_figure_route_only_serves_known_pngs():
    assert T.figure_path("tier2", "chart_escalation_budget.png") is not None
    assert T.figure_path("tier2", "../netsentinel/config.py") is None
    assert T.figure_path("tier2", "verify_all.py") is None
    assert T.figure_path("nowhere", "x.png") is None


def test_demo_output_is_parsed():
    text = """  Sentry agreement with the Inspector (AUC)   0.773
  Inspector flags recovered at 5% budget        23.7%
  Host-days the Inspector never had to see     61.9%
  Model size                                  205,546 -> 14,992  (13.7x)
  Attack windows present in the test period   289
    reached the Inspector via escalation      22  (8%)   <-- INDICATIVE ONLY, synthetic
  total runtime 26s"""
    r = T.parse_demo(text)
    assert r["router_auc"] == "0.773" and r["recovered_pct"] == "23.7" and r["never_woken_pct"] == "61.9"
    assert r["params"] == ["205546", "14992", "13.7"] and r["attack_reached"] == ["22", "8"]
