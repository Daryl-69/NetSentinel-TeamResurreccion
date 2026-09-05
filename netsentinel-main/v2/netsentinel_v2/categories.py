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
ROLE_PREPATH = {
    "developer":  {"Code_Repo_Paste", "CI_CD", "Messaging_API", "Cloud_Storage",
                   "Browse", "Sync", "Internal"},
    "office":     {"Browse", "Sync", "Cloud_Storage", "Messaging_API", "Internal"},
    "kiosk":      {"Browse", "Internal"},
    "ot_hmi":     {"Internal"},
    "server":     {"CI_CD", "Internal", "Sync"},
}
ROLES = list(ROLE_PREPATH)
