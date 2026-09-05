"""End-to-end experiment: does the Sentry route well enough to be worth it?

Evaluation protocol follows arXiv:2608.01454 (provenance-IDS benchmark study):
  * strictly monotonic train -> validate -> test split IN TIME (no random split)
  * every threshold calibrated on VALIDATION only, never on test
  * multi-seed, mean +/- std reported

Three routers are compared at equal escalation budget:
  A  distilled DETECTOR  -- student regresses the teacher's anomaly score,
                            escalate on its own score. This is the ORIGINAL
                            V2 design and the one the distillation literature
                            says degrades on local outliers.
  B  encoder + Mahalanobis -- V2_HARDENING B1: distil only the encoder, keep
                            the local decision exact against a per-host
                            baseline.
  C  deferral head       -- V2_HARDENING G5: predict "would the Inspector
                            flag this window", not "am I unsure".
"""

from __future__ import annotations

import json
import time
import numpy as np
import torch
import torch.nn as nn

from .categories import N_CATEGORIES, N_EDGE_FEATURES
from .models import Inspector, Sentry, DeferralHead, recon_error, _mlp
from .baseline import HostBaseline
from .diagnostics import geometry_report, verdict

DEV = torch.device("cpu")


def set_device(name: str = "cpu"):
    """Switch the compute device.

    Honest expectation: this model is TINY -- 205k parameters, batches of
    64x24x9 through a 96-dim encoder. On that shape a laptop GPU is usually
    NO faster than the CPU and often slower, because per-kernel launch
    overhead and host->device copies dominate the arithmetic. The flag exists
    so you can measure that yourself rather than take my word for it.
    """
    global DEV
    if name.startswith("cuda") and not torch.cuda.is_available():
        print("  [device] CUDA not available; staying on CPU")
        name = "cpu"
    DEV = torch.device(name)
    if name.startswith("cuda"):
        print(f"  [device] {torch.cuda.get_device_name(0)}")
    return DEV


# ---------------------------------------------------------------- utilities
def compute_cohort(E, M):
    """Hop-2 context: mean edge features of OTHER hosts on the same
    (day, window, category). This is the sampled-neighbourhood term that
    E-GraphSAGE contributes over a per-host flat model."""
    s = (E * M[..., None]).sum(axis=0)          # (D,W,C,F)
    n = M.sum(axis=0)[..., None]                # (D,W,C,1)
    own = E * M[..., None]
    cnt = np.maximum(n - M[..., None], 1.0)
    return ((s[None] - own) / cnt).astype(np.float32)


def standardise(E, M, ref_mean=None, ref_std=None):
    flat = E[M > 0]
    if ref_mean is None:
        ref_mean, ref_std = flat.mean(0), flat.std(0) + 1e-6
    out = (E - ref_mean) / ref_std
    return (out * M[..., None]).astype(np.float32), ref_mean, ref_std


def batches(n, bs, shuffle=True, seed=0):
    idx = np.arange(n)
    if shuffle:
        np.random.default_rng(seed).shuffle(idx)
    for i in range(0, n, bs):
        yield idx[i:i + bs]


def t(x):
    return torch.as_tensor(x, dtype=torch.float32, device=DEV)


# ---------------------------------------------------------------- training
def train_inspector(E, M, Co, epochs=14, dim=96, bs=64, lr=2e-3, mask_p=0.25, seed=0):
    torch.manual_seed(seed)
    model = Inspector(dim=dim).to(DEV)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    n = len(E)
    for ep in range(epochs):
        model.train()
        tot = cnt = 0.0
        for b in batches(n, bs, seed=seed * 100 + ep):
            e, m, c = t(E[b]), t(M[b]), t(Co[b])
            # denoising: hide a fraction of present edges from the ENCODER,
            # then ask the decoder to reproduce every present edge.
            drop = (torch.rand_like(m) > mask_p).float() * m
            _, pred = model(e * drop.unsqueeze(-1), drop, c * drop.unsqueeze(-1))
            loss = (((pred - e) ** 2).mean(-1) * m).sum() / m.sum().clamp(min=1)
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
            tot += float(loss.detach()) * len(b); cnt += len(b)
        print(f"  inspector ep{ep:02d} loss {tot / cnt:.4f}", flush=True)
    return model


@torch.no_grad()
def inspector_forward(model, E, M, Co, bs=256):
    model.eval()
    Z, ERR = [], []
    for i in range(0, len(E), bs):
        e, m, c = t(E[i:i + bs]), t(M[i:i + bs]), t(Co[i:i + bs])
        z, pred = model(e, m, c)
        Z.append(z.numpy()); ERR.append(recon_error(pred, e, m).numpy())
    return np.concatenate(Z), np.concatenate(ERR)


def train_sentry(E, M, Zt, ERRt, epochs=16, dim=32, bs=64, lr=2e-3,
                 lam=4.0, seed=0):
    """Distil the ENCODER with an anomaly-weighted loss.

    L = E[(1 + lam * s_teacher) * ||project(f_student) - f_teacher||^2]

    Standard KD minimises mean divergence, which is precisely why rare signals
    wash out. Weighting by the teacher's own normalised anomaly score forces
    student capacity onto the windows the teacher found hardest.
    """
    torch.manual_seed(seed)
    model = Sentry(dim=dim, teacher_dim=Zt.shape[-1]).to(DEV)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    s = ERRt / (np.quantile(ERRt, 0.99) + 1e-9)
    s = np.clip(s, 0, 3.0).astype(np.float32)
    n = len(E)
    for ep in range(epochs):
        model.train(); tot = cnt = 0.0
        for b in batches(n, bs, seed=seed * 200 + ep):
            e, m = t(E[b]), t(M[b])
            zt, w = t(Zt[b]), t(s[b])
            _, proj = model(e, m)
            per = ((proj - zt) ** 2).mean(-1)             # (B,W)
            loss = ((1.0 + lam * w) * per).mean()
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
            tot += float(loss.detach()) * len(b); cnt += len(b)
        print(f"  sentry    ep{ep:02d} loss {tot / cnt:.4f}", flush=True)
    return model


@torch.no_grad()
def sentry_forward(model, E, M, bs=512):
    model.eval(); Z = []
    for i in range(0, len(E), bs):
        z, _ = model(t(E[i:i + bs]), t(M[i:i + bs]))
        Z.append(z.numpy())
    return np.concatenate(Z)


class Head(nn.Module):
    """Shared body for router A (regress teacher score) and C (deferral)."""
    def __init__(self, din, n_extra=0):
        super().__init__(); self.net = _mlp(din + n_extra, 64, 1)

    def forward(self, z, extra=None):
        x = z if extra is None else torch.cat([z, extra], -1)
        return self.net(x).squeeze(-1)


def train_head(Zs, target, extra=None, epochs=30, lr=3e-3, bs=256,
               loss="mse", seed=0):
    torch.manual_seed(seed)
    din, nx = Zs.shape[-1], (0 if extra is None else extra.shape[-1])
    head = Head(din, nx).to(DEV)
    opt = torch.optim.AdamW(head.parameters(), lr=lr, weight_decay=1e-4)
    Zf = Zs.reshape(-1, din)
    yf = target.reshape(-1)
    Ef = None if extra is None else extra.reshape(-1, nx)
    fn = nn.MSELoss() if loss == "mse" else nn.BCEWithLogitsLoss()
    for ep in range(epochs):
        for b in batches(len(Zf), bs, seed=seed * 300 + ep):
            pred = head(t(Zf[b]), None if Ef is None else t(Ef[b]))
            l = fn(pred, t(yf[b]))
            opt.zero_grad(); l.backward(); opt.step()
    return head


@torch.no_grad()
def head_forward(head, Zs, extra=None):
    din = Zs.shape[-1]
    p = head(t(Zs.reshape(-1, din)),
             None if extra is None else t(extra.reshape(-1, extra.shape[-1])))
    return p.numpy().reshape(Zs.shape[:-1])


# ---------------------------------------------------------------- evaluation
def budget_curve(score, teacher_flag, attack, budgets):
    """At each escalation budget, what fraction of teacher-flagged (and of
    true-attack) windows do we recover? Threshold is the budget quantile."""
    out = []
    # Rank-based selection: robust to score ties, which a quantile threshold
    # is not (a mass of identical scores makes `score >= thr` select
    # everything and silently reports 100% recall).
    order = np.argsort(-np.asarray(score, dtype=np.float64), kind="stable")
    n = len(score)
    for b in budgets:
        k = max(1, int(round(b * n)))
        esc = np.zeros(n, dtype=bool)
        esc[order[:k]] = True
        rec_t = float(esc[teacher_flag].mean()) if teacher_flag.any() else float("nan")
        rec_a = float(esc[attack].mean()) if attack.any() else float("nan")
        out.append(dict(budget=float(b), actual=float(esc.mean()),
                        recall_teacher=rec_t, recall_attack=rec_a))
    return out
