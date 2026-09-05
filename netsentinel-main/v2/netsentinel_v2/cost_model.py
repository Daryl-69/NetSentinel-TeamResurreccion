"""Inspector-hour cost model.

    GPU-host-days = H*D                (one-time commissioning)
                  + H*(r + e)*365      (ongoing: random sampling + escalation)
    vs inspect-all = H*365

Steady state should require ZERO GPU: the Sentry is a small encoder plus a
Mahalanobis/deferral evaluation, both CPU. Measured parameter counts and
per-window latencies are filled in by the experiment so the number quoted is
ours, not a citation.

Detection-latency bound (V2_HARDENING B6, corrected by G8):
    ETTE = 1 / (r * P(detect | inspected))     -- NOT 1/r.
If the attacker is quiet in most windows, an Inspector visit may see nothing.
"""

from __future__ import annotations


def gpu_host_days(H, D, r, e, days=365):
    one_time = H * D
    ongoing = H * (r + e) * days
    return dict(one_time=one_time, ongoing_per_year=ongoing,
                inspect_all_per_year=H * days,
                steady_state_reduction=1.0 - ongoing / (H * days))


def ette_days(r, p_detect_given_inspected, windows_per_day=24,
              p_visible_per_window=0.0):
    """Expected time to escalation, in days.

    Two paths: the Sentry sees a deviation (fast), or random sampling catches
    it (slow bound). Reported separately -- an honest bound beats a vague
    reassurance, and it is what a buyer puts in a risk register.
    """
    out = {"sampling_only_days": float("inf")}
    denom = r * max(p_detect_given_inspected, 1e-9)
    if denom > 0:
        out["sampling_only_days"] = 1.0 / denom
    if p_visible_per_window > 0:
        out["anomaly_path_days"] = 1.0 / (p_visible_per_window * windows_per_day)
    return out


def summarise(H=1000, D=14, r=1 / 30, e=0.02):
    c = gpu_host_days(H, D, r, e)
    lines = [
        f"hosts={H}  commissioning={D}d  sample_rate={r:.4f}/host-day  escalation={e:.4f}/host-day",
        f"  inspect-all              : {c['inspect_all_per_year']:>10,.0f} GPU-host-days/yr",
        f"  NetSentinel one-time     : {c['one_time']:>10,.0f} GPU-host-days",
        f"  NetSentinel ongoing      : {c['ongoing_per_year']:>10,.0f} GPU-host-days/yr",
        f"  steady-state reduction   : {c['steady_state_reduction'] * 100:>10.1f} %",
    ]
    return c, "\n".join(lines)
