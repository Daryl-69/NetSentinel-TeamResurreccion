"""Synthetic host-day generator.

>>> HONESTY NOTE — read before quoting any number produced from this file. <<<
This is a STAND-IN, not a dataset. A detector evaluated on the generator that
made its attacks learns the generator, not the adversary (CRITIQUE A5/B2).
Its only legitimate uses are:
  (1) exercising the harness end-to-end before real data exists, and
  (2) the teacher-vs-student agreement experiment, which does NOT depend on
      the attacks being realistic because the teacher is the reference oracle.
Detection numbers against `is_attack` are indicative ONLY. Swap in real
benign capture + Mythic-emulated chains before reporting anything externally.

What it does try to get right, because these decide whether the experiment is
meaningful at all:
  * benign behaviour is MULTIMODAL (workday / evening / weekend) -- G4
  * DevOps hosts legitimately produce Recon->Repo->Messaging->Cloud -- B3
    with HUMAN timing. These are the hard negatives. Without them the
    experiment is trivially easy and the result is worthless.
  * edge features are COMPUTED from generated inter-arrival times, not
    invented, so the KS/FFT automation features are real statistics.
"""

from __future__ import annotations

import numpy as np
from scipy import stats

from .categories import (
    CAT_INDEX, N_CATEGORIES, N_EDGE_FEATURES, ROLES, ROLE_PREPATH,
)

WINDOWS_PER_DAY = 24  # one-hour windows

# --------------------------------------------------------------------------
# "Worlds" — two organisations with the SAME mechanism but different shape.
# World A is what the encoder trains on. World B is a different customer:
# different role mix, different human rhythms, different data volumes.
# Deploying an encoder trained on A into B, with baselines re-fit on B, is
# exactly the distribution shift a real deployment faces. If the learned
# "normal" is brittle, this is where it shows.
# --------------------------------------------------------------------------
WORLDS = {
    "A": dict(role_probs=[.30, .34, .10, .14, .12],   # dev-heavy software org
              human_sigma=1.10, iat_scale=1.00, volume=1.00,
              devops_p=0.35, offhours=0.25, work_lo=9, work_hi=18),
    "B": dict(role_probs=[.10, .30, .18, .30, .12],   # OT/plant-heavy, few devs
              human_sigma=1.55, iat_scale=2.20, volume=0.45,
              devops_p=0.12, offhours=0.60, work_lo=6, work_hi=22),
}


def world(name_or_dict):
    if name_or_dict is None:
        return dict(WORLDS["A"])
    if isinstance(name_or_dict, str):
        return dict(WORLDS[name_or_dict])
    w = dict(WORLDS["A"]); w.update(name_or_dict); return w


# --------------------------------------------------------------------------
# Edge features are derived from an actual IAT sample, so ks_uniform /
# ks_exponential / fft_prominence mean what they claim to mean.
# --------------------------------------------------------------------------
def _ks(x_sorted: np.ndarray, cdf: np.ndarray) -> float:
    """One-sample KS statistic, vectorised (scipy.kstest is ~100x slower and
    this is called once per host-window-category)."""
    n = x_sorted.size
    i = np.arange(1, n + 1)
    return float(np.maximum(i / n - cdf, cdf - (i - 1) / n).max())


def _iat_stats(iats: np.ndarray) -> tuple[float, float, float, float]:
    """Return (cv, ks_uniform, ks_exponential, fft_prominence)."""
    if iats.size < 4:
        return 0.0, 1.0, 1.0, 0.0
    mu = float(iats.mean())
    if mu <= 0:
        return 0.0, 1.0, 1.0, 0.0
    cv = float(iats.std() / mu)

    xs = np.sort(iats)
    lo, hi = float(xs[0]), float(xs[-1])
    if hi - lo < 1e-9:
        ks_u = 1.0                      # constant: maximally un-uniform
    else:
        ks_u = _ks(xs, np.clip((xs - lo) / (hi - lo), 0, 1))
    ks_e = _ks(xs, 1.0 - np.exp(-xs / mu))

    # Periodicity: prominence of the dominant non-DC frequency of the
    # pulse train implied by the IATs.
    n = min(iats.size, 128)
    x = iats[:n] - iats[:n].mean()
    if np.allclose(x, 0):
        prom = 1.0                      # perfectly periodic
    else:
        mag = np.abs(np.fft.rfft(x))[1:]
        prom = float(mag.max() / (mag.mean() + 1e-9) / n) if mag.size else 0.0
        prom = min(prom, 1.0)
    return cv, ks_u, ks_e, prom


def _edge_row(rng, n_flows, bytes_up, bytes_down, iats, distinct_ratio, dur_mean):
    cv, ks_u, ks_e, prom = _iat_stats(iats)
    tot = bytes_up + bytes_down + 1.0
    return np.array([
        np.log1p(n_flows),
        np.log1p(bytes_up),
        np.log1p(bytes_down),
        (bytes_up - bytes_down) / tot,
        cv,
        ks_u,
        ks_e,
        prom,
        distinct_ratio,
        np.log1p(dur_mean),
    ], dtype=np.float32)


def _human_iats(rng, n, scale, sigma=1.1):
    """Humans are bursty / heavy-tailed, not uniform and not constant."""
    return rng.lognormal(mean=np.log(max(scale, 1e-6)), sigma=sigma, size=n)


def _beacon_iats(rng, n, sleep, jitter):
    """Beacon with jitter -> UNIFORM IATs. The evasion is the signature."""
    return rng.uniform(sleep * (1 - jitter), sleep * (1 + jitter), size=n)


# --------------------------------------------------------------------------
def _benign_window(rng, role, hour, is_weekend, devops_chain_today, W):
    """One (N_CATEGORIES, N_EDGE_FEATURES) window plus a presence mask."""
    edges = np.zeros((N_CATEGORIES, N_EDGE_FEATURES), dtype=np.float32)
    mask = np.zeros(N_CATEGORIES, dtype=np.float32)

    working = (W["work_lo"] <= hour <= W["work_hi"]) and not is_weekend
    # Multimodality: intensity depends on hour AND weekday (G4).
    intensity = (1.0 if working else (W["offhours"] if 7 <= hour <= 22 else 0.05))
    prepath = ROLE_PREPATH[role]
    V = W["volume"]

    for cat in prepath:
        # not every allowed category is touched every window
        p = 0.75 * intensity if cat in ("Browse", "Internal") else 0.35 * intensity
        if rng.random() > p:
            continue
        ci = CAT_INDEX[cat]
        n = max(2, int(rng.gamma(3.0, 6.0 * intensity)))
        iats = _human_iats(rng, n, 3600.0 / max(n, 1) * W["iat_scale"], W["human_sigma"])

        if cat == "Sync":
            up, down = rng.gamma(2, 4e5*V), rng.gamma(2, 8e5*V)
            # sync agents are semi-periodic -> genuinely confusable, keep it
            iats = rng.normal(300, 60, size=n).clip(30, None)
        elif cat == "Cloud_Storage":
            up, down = rng.gamma(2, 3e5*V), rng.gamma(2, 6e5*V)
        elif cat == "Code_Repo_Paste":
            up, down = rng.gamma(2, 2e4*V), rng.gamma(2, 9e5*V)
        elif cat == "CI_CD":
            up, down = rng.gamma(2, 1e5*V), rng.gamma(2, 5e5*V)
            iats = rng.normal(600, 240, size=n).clip(30, None)  # scheduled jobs
        elif cat == "Messaging_API":
            up, down = rng.gamma(2, 8e3*V), rng.gamma(2, 3e4*V)
        else:
            up, down = rng.gamma(2, 3e4*V), rng.gamma(2, 4e5*V)

        edges[ci] = _edge_row(rng, n, up, down, iats,
                              distinct_ratio=rng.uniform(0.05, 0.45),
                              dur_mean=rng.gamma(2, 4))
        mask[ci] = 1.0

    # ---- HARD NEGATIVE (B3): a real DevOps chain, human-timed --------------
    # Same category sequence as the attack. Different shape. If the model
    # cannot separate these, the category-transition hypothesis is dead and
    # the experiment must say so.
    if devops_chain_today and working and role == "developer":
        stage = {10: "Recon_API", 11: "Code_Repo_Paste",
                 12: "Messaging_API", 14: "Cloud_Storage"}.get(hour)
        if stage:
            ci = CAT_INDEX[stage]
            n = max(3, int(rng.gamma(3.0, 5.0)))
            iats = _human_iats(rng, n, 200.0 * W["iat_scale"], W["human_sigma"])
            if stage == "Cloud_Storage":
                up, down = rng.gamma(2, 8e5), rng.gamma(2, 3e5)  # real upload!
            elif stage == "Recon_API":
                up, down = rng.gamma(2, 2e3), rng.gamma(2, 4e3)
            elif stage == "Code_Repo_Paste":
                up, down = rng.gamma(2, 2e4), rng.gamma(2, 1e6)
            else:
                up, down = rng.gamma(2, 1e4), rng.gamma(2, 4e4)
            edges[ci] = _edge_row(rng, n, up, down, iats,
                                  distinct_ratio=rng.uniform(0.1, 0.5),
                                  dur_mean=rng.gamma(2, 5))
            mask[ci] = 1.0
    return edges, mask


def _habits(rng, n_hosts, roles, enabled):
    """Assign persistent benign habits that LOOK like the attack.

    Measured 2026-09-11 with ablation_order.py: without these, the single
    feature "longest consecutive run of Messaging_API in the day" separates
    attack days from benign days at ROC-AUC 1.000, at every stealth level.
    A one-line counter solved the entire benchmark. That means no result
    measured on the old generator -- ours or anyone's -- said anything about
    the model, the cascade, or sequence reasoning. It only said the attacker
    was the only host that ever chatted for nine hours straight.

    Two habits fix that, and both are things real networks are full of:

      chatty : a person with a chat client open all day. Produces the same
               long Messaging_API presence run the C2 beacon produces.
               Kills the presence/run-length shortcut.
      poller : a legitimate integration on a schedule -- backup agent, CI
               webhook, monitoring probe. Produces LOW-jitter, near-uniform
               inter-arrival times, which is precisely the surface our
               "Jitter-Trap" keys on. This is the hard negative that tests
               whether uniform IATs mean "beacon" or just "cron".

    If the detector cannot separate the attack from these, the honest
    conclusion is that it was never separating anything difficult.
    """
    out = [dict() for _ in range(n_hosts)]
    if not enabled:
        return out
    for h in range(n_hosts):
        if rng.random() < 0.35:
            out[h]["chatty"] = True
        if rng.random() < 0.25:
            out[h]["poller"] = rng.choice(["Messaging_API", "CI_CD", "Sync"])
            out[h]["poll_period"] = float(rng.choice([60, 120, 300, 900]))
    return out


def _apply_habits(rng, edges, mask, hour, is_weekend, habit, W):
    """Overlay one host's benign habits onto a window."""
    if habit.get("chatty") and 6 <= hour <= 23 and rng.random() < 0.85:
        ci = CAT_INDEX["Messaging_API"]
        n = max(3, int(rng.gamma(3.0, 7.0)))
        iats = _human_iats(rng, n, 3600.0 / max(n, 1) * W["iat_scale"],
                           W["human_sigma"])
        up, down = rng.gamma(2, 1e4), rng.gamma(2, 4e4)
        edges[ci] = _edge_row(rng, n, up, down, iats,
                              distinct_ratio=rng.uniform(0.05, 0.3),
                              dur_mean=rng.gamma(2, 3))
        mask[ci] = 1.0

    pol = habit.get("poller")
    if pol and rng.random() < 0.9:
        ci = CAT_INDEX[pol]
        period = habit.get("poll_period", 300.0)
        n = max(2, int(3600.0 / period))
        # a scheduler is regular but not perfect: small proportional jitter.
        iats = rng.normal(period, period * 0.06, size=n).clip(5, None)
        up, down = rng.gamma(2, 5e3), rng.gamma(2, 2e4)
        edges[ci] = _edge_row(rng, n, up, down, iats,
                              distinct_ratio=rng.uniform(0.02, 0.15),
                              dur_mean=rng.gamma(2, 2))
        mask[ci] = 1.0


def _inject_lsa(rng, edges, mask, hour, stage_hours, stealth):
    """Overlay one LSA stage. `stealth` in [0,1]: 1.0 = fully shaped adversary.

    A high-stealth attacker mimics human IAT distributions and dribbles the
    exfil, which is exactly the adversary CRITIQUE B4 says defeats the timing
    channel. Keeping it in the generator is the only way the experiment can
    report an honest degradation curve.
    """
    stage = stage_hours.get(hour)
    if stage is None:
        return False
    ci = CAT_INDEX[stage]

    if stage == "Recon_API":
        n = rng.integers(1, 4)
        iats = _human_iats(rng, n, 60) if stealth > .5 else _beacon_iats(rng, n, 30, .1)
        up, down = rng.gamma(2, 5e2), rng.gamma(2, 1.5e3)
        dr = rng.uniform(0.8, 1.0)
    elif stage == "Code_Repo_Paste":
        n = rng.integers(1, 3)
        iats = _human_iats(rng, n, 120)
        up, down = rng.gamma(2, 1e3), rng.gamma(2, 2e5)
        dr = rng.uniform(0.6, 1.0)
    elif stage == "Messaging_API":
        # C2 polling: the core beacon. Jitter grows with stealth.
        n = max(6, int(rng.gamma(6.0, 6.0)))
        jitter = 0.05 + 0.55 * stealth
        iats = (_human_iats(rng, n, 45) if stealth > 0.85
                else _beacon_iats(rng, n, 45, jitter))
        up, down = rng.gamma(2, 6e2), rng.gamma(2, 9e2)   # tiny both ways
        dr = rng.uniform(0.7, 1.0)
    else:  # Cloud_Storage exfil
        n = rng.integers(1, 5)
        iats = _human_iats(rng, n, 90)
        # stealth dribbles the upload -> defeats egress asymmetry gate
        vol = 6e6 * (1.0 - 0.92 * stealth)
        up, down = rng.gamma(2, vol), rng.gamma(2, 2e4)
        dr = rng.uniform(0.5, 0.9)

    row = _edge_row(rng, n, up, down, np.asarray(iats, dtype=float), dr,
                    dur_mean=rng.gamma(2, 2))
    if mask[ci] > 0:                      # blend into existing benign traffic
        edges[ci] = 0.5 * edges[ci] + 0.5 * row
    else:
        edges[ci] = row
    mask[ci] = 1.0
    return True


def generate(n_hosts=300, n_days=24, attack_host_frac=0.08, seed=0,
             stealth_range=(0.0, 1.0), world_cfg="A", hard_negatives=False):
    """Return dict of arrays.

    edges : (H, D, W, C, F)   host-day-window-category-feature
    mask  : (H, D, W, C)
    is_attack_day : (H, D) bool
    stealth       : (H,) float, 0 for benign hosts
    roles, host_ids
    """
    rng = np.random.default_rng(seed)
    W = world(world_cfg)
    roles = rng.choice(ROLES, size=n_hosts, p=W["role_probs"])  # dev/office/kiosk/ot/server
    n_attack = max(1, int(n_hosts * attack_host_frac))
    attack_hosts = rng.choice(n_hosts, size=n_attack, replace=False)
    stealth = np.zeros(n_hosts, dtype=np.float32)
    stealth[attack_hosts] = rng.uniform(*stealth_range, size=n_attack)
    # attacker activates partway through, after commissioning -> dormant-then-active
    activate_day = rng.integers(n_days // 2, n_days, size=n_hosts)

    E = np.zeros((n_hosts, n_days, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES),
                 dtype=np.float32)
    M = np.zeros((n_hosts, n_days, WINDOWS_PER_DAY, N_CATEGORIES), dtype=np.float32)
    A = np.zeros((n_hosts, n_days), dtype=bool)

    stage_hours = {9: "Recon_API", 10: "Code_Repo_Paste",
                   **{h: "Messaging_API" for h in range(11, 20)},
                   20: "Cloud_Storage"}

    habits = _habits(rng, n_hosts, roles, hard_negatives)

    for h in range(n_hosts):
        role = roles[h]
        is_attacker = stealth[h] > 0 or h in attack_hosts
        for d in range(n_days):
            weekend = (d % 7) in (5, 6)
            devops_today = (role == "developer") and (rng.random() < W["devops_p"])
            attacking = is_attacker and d >= activate_day[h]
            hit = False
            for w in range(WINDOWS_PER_DAY):
                e, m = _benign_window(rng, role, w, weekend, devops_today, W)
                _apply_habits(rng, e, m, w, weekend, habits[h], W)
                if attacking:
                    hit |= _inject_lsa(rng, e, m, w, stage_hours, float(stealth[h]))
                E[h, d, w] = e
                M[h, d, w] = m
            A[h, d] = attacking and hit

    return dict(edges=E, mask=M, is_attack_day=A, stealth=stealth,
                roles=roles, activate_day=activate_day, habits=habits,
                hard_negatives=hard_negatives,
                host_ids=np.arange(n_hosts), world=W)
