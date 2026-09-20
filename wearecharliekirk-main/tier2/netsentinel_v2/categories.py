"""Service Category Resolver — taxonomy and the edge-feature schema.

The GNN never sees a domain. It sees a *category* and the shape of the
communication with it. That is what makes the model learn the behavioural
concept of a kill chain instead of memorising infrastructure.
"""

from __future__ import annotations

# --- Category taxonomy -----------------------------------------------------
# Order is fixed and load-bearing: it indexes the per-window edge tensor.
CATEGORIES = [
    "Recon_API",        # ip-api.com, ipify.org        -> victim fingerprinting
    "Code_Repo_Paste",  # raw.githubusercontent, pastebin -> stager pull
    "Messaging_API",    # api.telegram.org, discord     -> C2 polling
    "Cloud_Storage",    # drive.google.com, dropbox     -> exfil (T1567)
    "Browse",           # general web
    "Sync",             # OneDrive/Dropbox desktop agents
    "CI_CD",            # build runners, artifact stores
    "Internal",         # east-west (the OT/diode generalisation lives here)
    "Unknown_External", # resolver could not categorise (ECH/DoH fallback)
]
N_CATEGORIES = len(CATEGORIES)
CAT_INDEX = {c: i for i, c in enumerate(CATEGORIES)}

# --- Edge feature schema ---------------------------------------------------
# One row per (host, category) per window. Features are deliberately the ones
# CRITIQUE B4 says are evadable, PLUS the distribution-family tests that turn
# the evasion itself into a signature (the "Jitter-Trap" inversion).
EDGE_FEATURES = [
    "log_n_flows",             # volume
    "log_bytes_up",
    "log_bytes_down",
    "egress_asymmetry",        # (up-down)/(up+down)  -> exfil signal
    "iat_cv",                  # classic beacon CoV (weak on its own)
    "ks_uniform",              # KS stat vs Uniform  -> LOW means jittered beacon
    "ks_exponential",          # KS stat vs Exponential -> LOW means human/Poisson
    "fft_prominence",          # dominant-frequency prominence -> automation
    "distinct_endpoint_ratio", # ->1.0 means URL/domain randomiser
    "log_duration_mean",
]
N_EDGE_FEATURES = len(EDGE_FEATURES)

# Which categories a role is *expected* to reach (the pre-path model).
# Off-pre-path traffic is the primary signal, but only in conjunction with
# the automation and egress gates (CRITIQUE B3).
# TUPLES, NOT SETS -- and this is not a style preference.
#
# These were sets. `synth._benign_window` iterates this collection and draws
# from the RNG inside the loop, so the ORDER of iteration decides the order in
# which random numbers are consumed. Set iteration order for strings depends on
# PYTHONHASHSEED, which Python randomises per process. The consequence, measured
# 17 Sep: `synth.generate(seed=0)` produced BYTE-DIFFERENT data in every fresh
# process, and two runs of `sweep_threshold.py` with identical arguments gave
# 12.0% vs 8.8% confirmation precision. Every synthetic figure carried a hidden
# source of variance that no seed controlled and no error bar covered.
#
# A tuple has one order, always. Do not convert these back to sets, and do not
# add a new category by writing `{...}` here.
ROLE_PREPATH = {
    "developer":  ("Browse", "CI_CD", "Cloud_Storage", "Code_Repo_Paste",
                   "Internal", "Messaging_API", "Sync"),
    "office":     ("Browse", "Cloud_Storage", "Internal", "Messaging_API", "Sync"),
    "kiosk":      ("Browse", "Internal"),
    "ot_hmi":     ("Internal",),
    "server":     ("CI_CD", "Internal", "Sync"),
}
ROLES = list(ROLE_PREPATH)
