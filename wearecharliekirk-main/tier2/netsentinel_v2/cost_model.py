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


def gpu_host_days(H, D, r, e, days=365, audit=0.0):
    """
    All rates are PER HOST-DAY, because a host-day is the unit of work the
    Inspector actually consumes: the sequence encoder takes the whole 24-hour
    window, so there is no such thing as inspecting one hour.

    r      recommissioning / retention re-inspection rate
    e      escalation rate
    audit  blind random-audit rate. NOT free -- calibration.py can only track
           drift using windows the auditor drew, and every one of those is an
           Inspector run. It used to be missing from this model entirely,
           which made the escalation budget look like the whole bill.

    WARNING, measured 12 Sep 2026 (escalate.py, 200 hosts x 16 days):
    escalating the top 5% of WINDOWS caused the Inspector to re-run on 49% of
    HOST-DAYS, because 5% of windows scatter across almost every host-day.
    5% of windows is not 5% of Inspector load. If you quote a recall number
    measured at a window-level budget, you may not also quote the cost number
    from a host-day-level rate. Use `windows_budget_to_host_day_load` to
    convert, or budget at host-day granularity in the first place.
    """
    one_time = H * D
    ongoing = H * (r + e + audit) * days
    return dict(one_time=one_time, ongoing_per_year=ongoing,
                inspect_all_per_year=H * days,
                steady_state_reduction=1.0 - ongoing / (H * days),
                rates=dict(recommission=r, escalation=e, audit=audit,
                           total_per_host_day=r + e + audit))


def windows_budget_to_host_day_load(window_budget, windows_per_host_day=24,
                                    scatter=None):
    """How much Inspector load does a WINDOW-level escalation budget cost?

    If the escalated windows were perfectly concentrated, b*W windows would
    touch b host-days. They are not concentrated: they scatter. `scatter` is
    the measured ratio of distinct host-days touched to the naive expectation.

    Measured on synth (escalate.py): a 5% window budget touched 49% of
    host-days, i.e. the load is ~9.8x the naive reading of "5%".
    Pass your own measurement; the default is that measurement.
    """
    if scatter is None:
        scatter = 0.49 / 0.05                     # measured, not assumed
    return min(1.0, window_budget * scatter)


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


def summarise(H=1000, D=14, r=1 / 30, e=0.02, audit=0.0):
    c = gpu_host_days(H, D, r, e, audit=audit)
    lines = [
        f"hosts={H}  commissioning={D}d  sample_rate={r:.4f}/host-day  "
        f"escalation={e:.4f}/host-day  audit={audit:.4f}/host-day",
        f"  inspect-all              : {c['inspect_all_per_year']:>10,.0f} GPU-host-days/yr",
        f"  NetSentinel one-time     : {c['one_time']:>10,.0f} GPU-host-days",
        f"  NetSentinel ongoing      : {c['ongoing_per_year']:>10,.0f} GPU-host-days/yr",
        f"  steady-state reduction   : {c['steady_state_reduction'] * 100:>10.1f} %",
    ]
    return c, "\n".join(lines)
