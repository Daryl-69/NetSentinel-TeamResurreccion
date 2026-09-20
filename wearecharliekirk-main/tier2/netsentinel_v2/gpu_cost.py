"""
netsentinel_v2.gpu_cost -- the industrial cost model for the Inspector-Sentry
cascade, in the units a buyer actually uses.

WHY THIS FILE EXISTS, AND WHAT IT REPLACES
------------------------------------------
`cost_model.py` counts "GPU host-days" and reports a percentage reduction. Two
problems with that as an industry-grade claim:

  1. It never converts host-days to wall-clock or currency, so "365,000
     GPU-host-days/year" sounds enormous when at the CURRENT teacher size it is
     a couple of CPU-minutes. A reviewer who does that conversion finds a
     headline saving on a workload that costs almost nothing, and stops
     believing the rest of the deck.

  2. A percentage hides the thing that makes the architecture worth buying.
     The router is a FIXED 14,992 parameters regardless of how large the
     teacher grows. So the saving is not a constant 94.7% -- it is a ratio that
     IMPROVES as the teacher scales. That is a scaling property, and it is a
     much stronger claim than any single number.

THE ACTUAL ARCHITECTURAL CLAIM
------------------------------
The Sentry does not run on the GPU. At all.

    Sentry    CPU, commodity, already in the rack, covers 100% of windows
    Inspector GPU, covers commissioning + escalations + blind audit only

GPU spend therefore scales with the ESCALATION RATE, not with fleet size. A
customer who doubles their endpoint count does not double their GPU bill; a
customer whose analysts tighten the escalation budget cuts it directly.

A MEASUREMENT THAT DOES NOT EXIST YET AND MUST BEFORE ANY OF THIS IS QUOTED
---------------------------------------------------------------------------
`escalate.json` measured 8.6x, Sentry over Inspector, CPU-to-CPU on one core.
That number MUST NOT be carried onto a GPU slide, because the two models have
opposite parallelism profiles:

    Inspector  2-layer Transformer over 24 windows -- all 24 timesteps are
               computed in parallel. Near-ideal GPU utilisation.
    Sentry     unidirectional GRU -- 24 SEQUENTIAL dependent steps. A GPU
               cannot parallelise the time axis at all.

On GPU the Inspector's relative position improves, possibly a lot. The 8.6x
could shrink toward 1x or invert. This is not a flaw in the design -- it is the
reason the Sentry belongs on CPU, where its small dense ops are efficient and
where capacity is cheap. But it has to be stated as a deliberate placement
decision backed by a measurement, not assumed.

Set `sentry_on_gpu=True` to model the (worse) alternative and see for yourself.

EVERY DEFAULT BELOW IS A LABELLED ASSUMPTION, NOT A MEASUREMENT.
Replace `inspector_win_per_s_gpu` with a real benchmark before quoting output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

# --------------------------------------------------------------------- inputs

# MEASURED (escalate.json, 12 Sep 2026, one CPU core, 205,546-param teacher).
INSPECTOR_WIN_PER_S_CPU = 70_950.0
SENTRY_WIN_PER_S_CPU = 609_187.0

# ASSUMPTION, NOT MEASURED. A small transformer at batch typically lands
# 20-60x a single CPU core; 40x is the midpoint. Benchmark and replace.
GPU_SPEEDUP_ASSUMED = 40.0

# ASSUMPTION. Representative on-demand cloud rates, mid-2026, USD/hour.
# Reserved and spot pricing is materially lower; use your own contract rate.
GPU_USD_PER_HOUR = 1.80          # ~A100 40GB class on-demand
CPU_CORE_USD_PER_HOUR = 0.021    # ~general-purpose vCPU on-demand


@dataclass
class Fleet:
    """What is being monitored."""
    hosts: int = 100_000
    windows_per_day: int = 24
    commissioning_days: int = 14
    days_per_year: int = 365

    def windows_per_year(self) -> int:
        return self.hosts * self.windows_per_day * self.days_per_year

    def host_days_per_year(self) -> int:
        return self.hosts * self.days_per_year


@dataclass
class Policy:
    """How much of the fleet reaches the Inspector.

    All rates are PER HOST-DAY, because a host-day is the Inspector's unit of
    work -- its sequence encoder consumes a whole 24-window day, so there is no
    such thing as inspecting a single hour.

    WARNING (measured, escalate.json): a WINDOW-level budget does not convert
    1:1. Escalating the top 5% of windows caused the Inspector to re-run on 49%
    of host-days, because those windows scatter across nearly every day --
    a 9.8x multiplier. Use `window_budget_to_host_day` rather than passing a
    window budget straight in as `escalation`.
    """
    escalation: float = 0.05         # host-days sent to the Inspector
    audit: float = 0.02              # blind random audit; calibration needs it
    recommission: float = 1 / 30     # visibility changes, incident releases
    scatter: float = 0.49 / 0.05     # MEASURED window -> host-day multiplier

    def total_rate(self) -> float:
        return self.escalation + self.audit + self.recommission

    def window_budget_to_host_day(self, window_budget: float) -> float:
        """Convert a window-level escalation budget to actual Inspector load."""
        return min(1.0, window_budget * self.scatter)


@dataclass
class Models:
    """Teacher and router. The point of the whole exercise is that only the
    teacher's cost grows."""
    teacher_params: int = 205_546
    router_params: int = 14_992
    inspector_win_per_s_gpu: float = INSPECTOR_WIN_PER_S_CPU * GPU_SPEEDUP_ASSUMED
    sentry_win_per_s_cpu: float = SENTRY_WIN_PER_S_CPU
    sentry_on_gpu: bool = False
    gpu_usd_per_hour: float = GPU_USD_PER_HOUR
    cpu_usd_per_hour: float = CPU_CORE_USD_PER_HOUR
    throughput_is_measured: bool = False    # flip to True once benchmarked

    def scaled_to(self, teacher_params: int) -> "Models":
        """A larger teacher, assuming throughput falls linearly in parameter
        count. That is optimistic for attention (which is quadratic in sequence
        length, though the sequence here is fixed at 24) and pessimistic for
        wide-but-shallow models. It is a planning estimate, not a measurement."""
        ratio = self.teacher_params / teacher_params
        return Models(teacher_params=teacher_params,
                      router_params=self.router_params,
                      inspector_win_per_s_gpu=self.inspector_win_per_s_gpu * ratio,
                      sentry_win_per_s_cpu=self.sentry_win_per_s_cpu,
                      sentry_on_gpu=self.sentry_on_gpu,
                      gpu_usd_per_hour=self.gpu_usd_per_hour,
                      cpu_usd_per_hour=self.cpu_usd_per_hour,
                      throughput_is_measured=False)


# -------------------------------------------------------------------- costing

def cost(fleet: Fleet, policy: Policy, models: Models) -> dict:
    """Annual cost of the cascade against inspect-everything."""
    W = fleet.windows_per_year()
    wpd = fleet.windows_per_day

    # --- baseline: the Inspector sees every window, on GPU ------------------
    gpu_h_all = W / models.inspector_win_per_s_gpu / 3600.0
    usd_all = gpu_h_all * models.gpu_usd_per_hour

    # --- cascade ------------------------------------------------------------
    # Router: every window, every day. On CPU unless explicitly modelled on GPU.
    if models.sentry_on_gpu:
        router_h = W / (models.sentry_win_per_s_cpu * GPU_SPEEDUP_ASSUMED) / 3600.0
        router_usd = router_h * models.gpu_usd_per_hour
        router_where = "GPU (not recommended -- a GRU cannot use one)"
    else:
        router_h = W / models.sentry_win_per_s_cpu / 3600.0
        router_usd = router_h * models.cpu_usd_per_hour
        router_where = "CPU"

    # Teacher: commissioning once, then escalation + audit + recommission.
    commissioning_windows = fleet.hosts * fleet.commissioning_days * wpd
    ongoing_host_days = fleet.host_days_per_year() * policy.total_rate()
    ongoing_windows = ongoing_host_days * wpd

    gpu_h_commission = commissioning_windows / models.inspector_win_per_s_gpu / 3600.0
    gpu_h_ongoing = ongoing_windows / models.inspector_win_per_s_gpu / 3600.0
    usd_commission = gpu_h_commission * models.gpu_usd_per_hour
    usd_ongoing = gpu_h_ongoing * models.gpu_usd_per_hour

    total_usd = router_usd + usd_ongoing
    reduction = 1.0 - (gpu_h_ongoing / gpu_h_all) if gpu_h_all else 0.0

    # How many hosts one continuously-busy GPU can carry on the cascade.
    per_host_gpu_h = gpu_h_ongoing / fleet.hosts if fleet.hosts else 0.0
    hosts_per_gpu = (8760.0 / per_host_gpu_h) if per_host_gpu_h > 0 else float("inf")
    per_host_gpu_h_all = gpu_h_all / fleet.hosts if fleet.hosts else 0.0
    hosts_per_gpu_all = (8760.0 / per_host_gpu_h_all
                         if per_host_gpu_h_all > 0 else float("inf"))

    return dict(
        teacher_params=models.teacher_params,
        router_params=models.router_params,
        router_where=router_where,
        gpu_hours_inspect_all=gpu_h_all,
        gpu_hours_commissioning=gpu_h_commission,
        gpu_hours_ongoing=gpu_h_ongoing,
        cpu_hours_router=router_h if not models.sentry_on_gpu else 0.0,
        usd_inspect_all_per_year=usd_all,
        usd_commissioning_one_time=usd_commission,
        usd_ongoing_per_year=usd_ongoing,
        usd_router_per_year=router_usd,
        usd_total_per_year=total_usd,
        usd_per_host_per_year=total_usd / fleet.hosts if fleet.hosts else 0.0,
        usd_per_host_per_year_inspect_all=(usd_all / fleet.hosts
                                           if fleet.hosts else 0.0),
        gpu_reduction=reduction,
        hosts_per_gpu_cascade=hosts_per_gpu,
        hosts_per_gpu_inspect_all=hosts_per_gpu_all,
        inspector_load_host_days=ongoing_host_days,
        throughput_is_measured=models.throughput_is_measured,
    )


def teacher_scaling(fleet: Fleet, policy: Policy, models: Models,
                    sizes=(205_546, 2_000_000, 20_000_000, 200_000_000)) -> list:
    """The argument that actually sells the cascade.

    The router is fixed at 14,992 parameters. The teacher is not. So the
    absolute saving grows with teacher size while the router's cost stays
    flat -- meaning the cascade is worth MORE the more serious your teacher is,
    which is the opposite of how a prototype-scale saving reads.
    """
    out = []
    for p in sizes:
        m = models.scaled_to(p)
        c = cost(fleet, policy, m)
        c["teacher_to_router_ratio"] = p / models.router_params
        out.append(c)
    return out


@dataclass
class SOC:
    """The resource that is actually scarce.

    Measured against our own numbers, GPU is not the constraint at any
    plausible fleet size or teacher size -- see `teacher_scaling`. Analyst
    capacity is. A tier-2 analyst costs 4-6 orders of magnitude more per hour
    than the GPU time needed to produce the alert they are reading.
    """
    analyst_usd_per_year: float = 80_000.0      # ASSUMPTION: loaded cost
    productive_hours_per_year: float = 1_600.0  # ASSUMPTION
    minutes_per_alert: float = 12.0             # ASSUMPTION: triage to disposition
    inspector_flag_rate: float = 0.0256         # MEASURED, lanl_novelty.json

    def usd_per_hour(self) -> float:
        return self.analyst_usd_per_year / self.productive_hours_per_year

    def alerts_per_analyst_per_year(self) -> float:
        return self.productive_hours_per_year * 60.0 / self.minutes_per_alert


def triage_economics(fleet: Fleet, policy: Policy, soc: SOC,
                     teacher_flag_recovery: float = 0.969,
                     confirm_precision: float = 0.127,
                     confirm_rate: float = 1.0,
                     attack_recall: float | None = None) -> dict:
    """Analyst load -- and an honest statement of what the cascade does NOT do.

    THE CASCADE DOES NOT REDUCE ALERT VOLUME, AND IT IS NOT SUPPOSED TO.

    Router A recovers 96.9% of the Inspector's own flags at a 5% escalation
    budget (MEASURED, lanl_novelty.json, 3 seeds, LANL cyber1). Faithfulness to
    the teacher is the router's entire design goal -- so by construction the
    analyst still receives ~96.9% of the alerts an inspect-everything system
    would have produced. The cascade saves INSPECTION, not TRIAGE. Anyone
    presenting it as an alert-fatigue solution is misreading their own number.

    What actually bounds analyst load is the CONFIRMATION THRESHOLD applied
    after the Inspector re-scores an escalated host-day. That is a separate
    knob. At the 3-robust-sigma default the measured confirmation precision is
    12.7% (escalate.json) -- roughly 7 of every 8 confirmations are false --
    and moving the cut to 6 sigma takes it to 40.3% while cutting alerts per
    1,000 host-days from 40.0 to 16.0, for 1.4 points of attack recall
    (sweep_threshold.json). This function exists to make that visible in the
    units a buyer cares about, not to claim a saving we cannot support.

    `confirm_precision` is the lever, and it is no longer untuned:
    `sweep_threshold.py` sweeps it. Pass BOTH numbers from a row of
    `sweep_threshold.json` -- `confirm_precision` and `confirm_rate`
    (= confirmed / escalated) -- because raising the threshold does two things
    at once. It raises precision AND it cuts the number of alerts. An earlier
    version of this function took precision alone and so held alert volume
    fixed while precision improved, which credited the threshold with a saving
    it does not produce and hid the recall it costs. Pass `attack_recall` from
    the same row and the missed-detection side is reported too, so the trade is
    visible in both directions rather than only the flattering one.
    """
    host_days = fleet.host_days_per_year()

    # What the teacher would raise if it saw everything.
    flags_all = host_days * soc.inspector_flag_rate
    # What reaches an analyst through the cascade: the same flags, minus the
    # ones the router failed to escalate.
    flags_cascade = flags_all * teacher_flag_recovery

    # The confirmation threshold decides how many of those escalations become
    # alerts at all. confirm_rate = 1.0 reproduces the old behaviour: every
    # escalation reaches an analyst.
    alerts = flags_cascade * confirm_rate
    true_positives = alerts * confirm_precision
    false_positives = alerts - true_positives

    def analysts(n):
        return n / soc.alerts_per_analyst_per_year()

    a_casc = analysts(alerts)
    a_all = analysts(flags_all)
    wasted_usd = analysts(false_positives) * soc.analyst_usd_per_year

    return dict(
        host_days_per_year=host_days,
        alerts_inspect_all_per_year=flags_all,
        alerts_inspect_all_per_day=flags_all / 365.0,
        escalations_per_year=flags_cascade,
        alerts_cascade_per_year=alerts,
        alerts_cascade_per_day=alerts / 365.0,
        alert_volume_reduction=1.0 - alerts / flags_all if flags_all else 0.0,
        teacher_flags_recovered=teacher_flag_recovery,
        confirm_precision=confirm_precision,
        confirm_rate=confirm_rate,
        attack_recall=attack_recall,
        true_positives_per_year=true_positives,
        false_positives_per_year=false_positives,
        analysts_needed_inspect_all=a_all,
        analysts_needed_cascade=a_casc,
        analyst_usd_cascade=a_casc * soc.analyst_usd_per_year,
        analyst_usd_wasted_on_false_positives=wasted_usd,
        note=("The cascade saves inspection, not triage. Alert volume is "
              "controlled by the confirmation threshold. That threshold has "
              "now been swept (sweep_threshold.json): on synthetic data at "
              "maximum stealth, moving 3.0 -> 6.0 robust sigma raised "
              "confirmation precision 17.7% -> 40.3% and cut alerts per 1,000 "
              "host-days 40.0 -> 16.0, for 1.4 points of attack recall. Pass a "
              "row of that file rather than trusting these defaults, and quote "
              "the recall cost alongside the saving."),
    )


def report(fleet=None, policy=None, models=None) -> str:
    fleet = fleet or Fleet()
    policy = policy or Policy()
    models = models or Models()
    c = cost(fleet, policy, models)

    L = []
    A = L.append
    A("=" * 74)
    A("  Inspector-Sentry GPU cost model")
    A("=" * 74)
    if not c["throughput_is_measured"]:
        A("  !! GPU throughput is an ASSUMPTION "
          f"({GPU_SPEEDUP_ASSUMED:.0f}x one CPU core), not a benchmark.")
        A("  !! Benchmark both models on the target GPU before quoting any")
        A("  !! figure below. The Sentry is a GRU: 24 SEQUENTIAL steps that a")
        A("  !! GPU cannot parallelise, while the Inspector's Transformer")
        A("  !! parallelises fully. The 8.6x measured on CPU will NOT hold.")
        A("")
    A(f"  fleet          {fleet.hosts:,} hosts x {fleet.windows_per_day} "
      f"windows/day  = {fleet.windows_per_year():,} windows/yr")
    A(f"  teacher        {c['teacher_params']:,} params  (GPU)")
    A(f"  router         {c['router_params']:,} params  ({c['router_where']})")
    A(f"  Inspector load {policy.total_rate() * 100:.1f}% of host-days "
      f"= escalation {policy.escalation * 100:.0f}% + audit "
      f"{policy.audit * 100:.0f}% + recommission "
      f"{policy.recommission * 100:.1f}%")
    A("")
    A("  ANNUAL GPU")
    A(f"    inspect everything      {c['gpu_hours_inspect_all']:>12,.0f} GPU-hours"
      f"   ${c['usd_inspect_all_per_year']:>12,.0f}")
    A(f"    cascade, ongoing        {c['gpu_hours_ongoing']:>12,.0f} GPU-hours"
      f"   ${c['usd_ongoing_per_year']:>12,.0f}")
    A(f"    cascade, commissioning  {c['gpu_hours_commissioning']:>12,.0f} GPU-hours"
      f"   ${c['usd_commissioning_one_time']:>12,.0f}  (one time)")
    A(f"    router on CPU           {c['cpu_hours_router']:>12,.0f} core-hours"
      f"   ${c['usd_router_per_year']:>12,.0f}")
    A("")
    A(f"    GPU reduction           {c['gpu_reduction'] * 100:>12.1f} %")
    A(f"    total run rate                       "
      f"        ${c['usd_total_per_year']:>12,.0f} /yr")
    A(f"    per host                             "
      f"        ${c['usd_per_host_per_year']:>12.4f} /host/yr"
      f"   (vs ${c['usd_per_host_per_year_inspect_all']:.4f} inspect-all)")
    A("")
    A("  CAPACITY -- the number a buyer sizes hardware from")
    A(f"    hosts per GPU, cascade        {c['hosts_per_gpu_cascade']:>14,.0f}")
    A(f"    hosts per GPU, inspect-all    {c['hosts_per_gpu_inspect_all']:>14,.0f}")
    A("")
    A("  TEACHER SCALING -- the router stays 14,992 params at every row")
    A(f"    {'teacher':>14}  {'ratio':>8}  {'inspect-all $/yr':>18}"
      f"  {'cascade $/yr':>14}  {'saved':>10}")
    for r in teacher_scaling(fleet, policy, models):
        A(f"    {r['teacher_params']:>14,}  "
          f"{r['teacher_to_router_ratio']:>7,.0f}x  "
          f"${r['usd_inspect_all_per_year']:>17,.0f}  "
          f"${r['usd_ongoing_per_year'] + r['usd_router_per_year']:>13,.0f}  "
          f"${r['usd_inspect_all_per_year'] - r['usd_ongoing_per_year'] - r['usd_router_per_year']:>9,.0f}")
    A("")
    A("  The percentage is flat across those rows. The DOLLARS are not.")
    A("  That is the claim: the cascade is worth more the larger the teacher,")
    A("  because the router never grows.")
    return "\n".join(L)


if __name__ == "__main__":
    print(report())
