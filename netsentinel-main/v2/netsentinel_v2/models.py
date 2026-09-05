"""Inspector (teacher) and Sentry (student) encoders.

Inspector : edge-aware GNN over (host -> service-category) star graphs, with a
            sampled hop-2 cohort context, then a Transformer over the day's
            window sequence, trained as a denoising graph autoencoder.
            This is the GraphIDS-shaped architecture. It is PRIOR ART
            (arXiv:2509.16625) -- it is our Inspector, not our contribution.

Sentry    : same interface, ~10x smaller, NO hop-2, GRU instead of Transformer.
            Trained by distillation from the Inspector's ENCODER, never from
            its decision. That split is the whole point (see V2_HARDENING B1).
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from .categories import N_CATEGORIES, N_EDGE_FEATURES


def _mlp(i, h, o):
    return nn.Sequential(nn.Linear(i, h), nn.GELU(), nn.Linear(h, o))


class EdgeAggregator(nn.Module):
    """E-GraphSAGE-style hop-1 aggregation over a host's category edges.

    message(c) = MLP([edge_features(c) , category_embedding(c) , cohort(c)])
    window     = [ mean_c message , max_c message , presence_mask ]

    The category embedding is what stops the model memorising infrastructure;
    the cohort term is the sampled hop-2 neighbourhood (other hosts touching
    the same category in the same window).
    """

    def __init__(self, dim, use_cohort=True):
        super().__init__()
        self.use_cohort = use_cohort
        self.cat_emb = nn.Embedding(N_CATEGORIES, 16)
        in_dim = N_EDGE_FEATURES + 16 + (N_EDGE_FEATURES if use_cohort else 0)
        self.msg = _mlp(in_dim, dim, dim)
        self.out = _mlp(2 * dim + N_CATEGORIES, dim, dim)

    def forward(self, edges, mask, cohort=None):
        # edges (B,W,C,F)  mask (B,W,C)  cohort (B,W,C,F)
        B, W, C, Fdim = edges.shape
        ce = self.cat_emb.weight.view(1, 1, C, -1).expand(B, W, C, -1)
        parts = [edges, ce]
        if self.use_cohort:
            parts.append(cohort if cohort is not None else torch.zeros_like(edges))
        m = self.msg(torch.cat(parts, dim=-1))              # (B,W,C,d)

        mk = mask.unsqueeze(-1)                             # (B,W,C,1)
        cnt = mk.sum(dim=2)                                 # (B,W,1) TRUE count
        denom = cnt.clamp(min=1.0)
        mean = (m * mk).sum(dim=2) / denom
        # An empty window has no edges to max over. Guarding on `denom` here is
        # wrong -- it is clamped to >=1 and so is never 0, which let the -1e9
        # sentinel escape into the encoder on every empty window (~half of them)
        # and blew the first-epoch loss up to ~1e12. Guard on the true count.
        mx = (m.masked_fill(mk == 0, -1e9)).max(dim=2).values
        mx = torch.where(cnt > 0, mx, torch.zeros_like(mx))
        return self.out(torch.cat([mean, mx, mask], dim=-1))  # (B,W,d)


class Inspector(nn.Module):
    """Expensive teacher. Runs during commissioning and on re-escalation only."""

    def __init__(self, dim=96, heads=4, layers=2):
        super().__init__()
        self.dim = dim
        self.agg = EdgeAggregator(dim, use_cohort=True)
        self.pos = nn.Parameter(torch.randn(1, 24, dim) * 0.02)
        enc = nn.TransformerEncoderLayer(dim, heads, dim * 2, dropout=0.1,
                                         batch_first=True, norm_first=True)
        # norm_first=True makes the nested-tensor fast path inapplicable;
        # disabling it explicitly avoids a warning on every construction.
        self.seq = nn.TransformerEncoder(enc, layers, enable_nested_tensor=False)
        self.dec = _mlp(dim + 16, dim, N_EDGE_FEATURES)
        self.cat_emb = nn.Embedding(N_CATEGORIES, 16)

    def encode(self, edges, mask, cohort):
        h = self.agg(edges, mask, cohort) + self.pos[:, : edges.shape[1]]
        return self.seq(h)                                   # (B,W,d)

    def reconstruct(self, z):
        B, W, d = z.shape
        ce = self.cat_emb.weight.view(1, 1, N_CATEGORIES, 16).expand(B, W, -1, -1)
        zz = z.unsqueeze(2).expand(B, W, N_CATEGORIES, d)
        return self.dec(torch.cat([zz, ce], dim=-1))         # (B,W,C,F)

    def forward(self, edges, mask, cohort):
        z = self.encode(edges, mask, cohort)
        return z, self.reconstruct(z)


class Sentry(nn.Module):
    """Cheap always-on student. No cohort (no hop-2), GRU not Transformer."""

    def __init__(self, dim=32, teacher_dim=96):
        super().__init__()
        self.dim = dim
        self.agg = EdgeAggregator(dim, use_cohort=False)
        self.seq = nn.GRU(dim, dim, batch_first=True, bidirectional=False)
        self.project = nn.Linear(dim, teacher_dim)   # distillation head only

    def encode(self, edges, mask):
        h = self.agg(edges, mask)
        out, _ = self.seq(h)
        return out                                    # (B,W,dim)

    def forward(self, edges, mask):
        z = self.encode(edges, mask)
        return z, self.project(z)


class DeferralHead(nn.Module):
    """G5 fix: predict *"would the Inspector flag this window?"* directly.

    "Sentry escalates when it is unsure" is confidence-based deferral, which is
    provably suboptimal under distribution shift, specialist downstream models
    and label noise (Jitkrittum et al., NeurIPS 2023) -- all three describe an
    IDS. So we do not threshold the Sentry's own score. We train a head on the
    Sentry embedding + the per-host baseline distance to predict the teacher's
    decision. The label is free: during commissioning we ran both models.
    """

    def __init__(self, sentry_dim=32, n_extra=3):
        super().__init__()
        self.net = _mlp(sentry_dim + n_extra, 64, 1)

    def forward(self, z_sentry, extra):
        return self.net(torch.cat([z_sentry, extra], dim=-1)).squeeze(-1)


def recon_error(pred, edges, mask):
    """Per-window mean squared reconstruction error over PRESENT edges."""
    se = ((pred - edges) ** 2).mean(dim=-1)               # (B,W,C)
    mk = mask
    return (se * mk).sum(dim=2) / mk.sum(dim=2).clamp(min=1.0)   # (B,W)
