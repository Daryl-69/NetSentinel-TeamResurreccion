"""
netsentinel_v2.hostnorm -- P0: stop the Inspector ranking "which host is busy".

The problem
-----------
The Inspector's anomaly score is the per-window mean squared reconstruction
error over present edges. That quantity scales with how much there is to
reconstruct. A host with eight active categories and thousands of flows has
more error than a quiet host having a normal day, for reasons that have nothing
to do with whether either is compromised.

On LANL this produced exactly the signature you would predict:

    global AUC, all host-days pooled     0.745 +/- 0.002
    within-host AUC, each host vs itself 0.557 +/- 0.013   (chance)
    live-window density, attacked hosts  0.811
    live-window density, everyone else   0.530

The red team went after busy machines. The model learned to find busy machines.
Pooling hosts together let that leak in as apparent skill.

The fix
-------
Score every window against ITS OWN HOST's commissioning distribution, not
against the global one:

    z_h(x) = (err(x) - median_h) / (1.4826 * MAD_h)

Median and MAD rather than mean and standard deviation because the
commissioning window is not guaranteed clean -- one bad day should move the
threshold slightly, not redefine the scale. 1.4826 makes MAD a consistent
estimator of sigma for Gaussian data, so the output reads like a z-score.

This is the same per-entity logic `baseline.py` already applies in the STUDENT
embedding space for router B. It was simply never applied to the TEACHER's own
score, which is the number every headline figure is computed from.

What it does and does not buy
-----------------------------
It removes a scale confound. It cannot manufacture signal: if the Inspector's
error carries no host-relative information about the attack, normalising it
will leave within-host AUC at chance -- and that is a result worth reporting,
because it says the confound was not the only problem.

Expect the GLOBAL AUC to FALL when this is applied. That is the point. The
global number was inflated by the confound; a lower, honest global AUC beside
an improved within-host AUC is the correct outcome, not a regression.

Fitting rules
-------------
  * Fit on LIVE commissioning windows only. An empty window carries no
    decision, and including empties puts a zero-variance spike at the bottom of
    the distribution which collapses MAD toward zero and blows up every z.
  * A host with too few live commissioning windows falls back to the pooled
    distribution, and says so via `fellback_`. Do not silently fit a scale to
    nine points.
  * MAD can be exactly zero for a host whose error is constant. Floor it.
"""
from __future__ import annotations

import numpy as np

MAD_TO_SIGMA = 1.4826


class HostScoreNormaliser:
    """Per-host robust z-scoring of the Inspector's reconstruction error."""

    def __init__(self, min_live: int = 20, eps: float = 1e-6):
        self.min_live = min_live
        self.eps = eps
        self.med_: dict[int, float] = {}
        self.scale_: dict[int, float] = {}
        self.global_med_ = 0.0
        self.global_scale_ = 1.0
        self.fellback_: set[int] = set()
        self.fitted_ = False

    def fit(self, err: np.ndarray, host_idx: np.ndarray,
            live: np.ndarray | None = None) -> "HostScoreNormaliser":
        """
        err      (N, W) reconstruction error on COMMISSIONING rows
        host_idx (N,)   which host each row belongs to
        live     (N, W) bool, True where the window had at least one edge
        """
        err = np.asarray(err, dtype=np.float64)
        host_idx = np.asarray(host_idx)
        if live is None:
            live = np.ones_like(err, dtype=bool)
        live = np.asarray(live, dtype=bool)

        pooled = err[live]
        if pooled.size == 0:
            pooled = err.reshape(-1)
        self.global_med_ = float(np.median(pooled))
        self.global_scale_ = float(
            np.median(np.abs(pooled - self.global_med_)) * MAD_TO_SIGMA)
        self.global_scale_ = max(self.global_scale_, self.eps)

        for h in np.unique(host_idx):
            rows = np.where(host_idx == h)[0]
            e = err[rows].reshape(-1)
            lv = live[rows].reshape(-1)
            e = e[lv]
            if e.size < self.min_live:
                self.fellback_.add(int(h))
                self.med_[int(h)] = self.global_med_
                self.scale_[int(h)] = self.global_scale_
                continue
            m = float(np.median(e))
            s = float(np.median(np.abs(e - m)) * MAD_TO_SIGMA)
            self.med_[int(h)] = m
            self.scale_[int(h)] = max(s, self.eps)
        self.fitted_ = True
        return self

    def transform(self, err: np.ndarray, host_idx: np.ndarray) -> np.ndarray:
        if not self.fitted_:
            raise RuntimeError("fit() first")
        err = np.asarray(err, dtype=np.float64)
        host_idx = np.asarray(host_idx)
        out = np.empty_like(err)
        for h in np.unique(host_idx):
            rows = np.where(host_idx == h)[0]
            m = self.med_.get(int(h), self.global_med_)
            s = self.scale_.get(int(h), self.global_scale_)
            out[rows] = (err[rows] - m) / s
        return np.nan_to_num(out, nan=0.0, posinf=0.0, neginf=0.0
                             ).astype(np.float32)

    def fit_transform(self, err, host_idx, live=None):
        return self.fit(err, host_idx, live).transform(err, host_idx)

    @property
    def n_fellback(self) -> int:
        return len(self.fellback_)


def within_host_auc(score: np.ndarray, attack: np.ndarray,
                    host_idx: np.ndarray, live: np.ndarray | None = None,
                    min_pos: int = 1, min_neg: int = 5):
    """
    The honest metric: rank each host's windows against that host's OWN
    windows, then average the per-host AUCs. A model that only knows which
    host is busy scores 0.5 here however good its pooled AUC looks.

    Returns (mean, std, n_hosts_scored, n_positives).
    """
    score = np.asarray(score, dtype=np.float64)
    attack = np.asarray(attack, dtype=bool)
    host_idx = np.asarray(host_idx)
    if live is None:
        live = np.ones_like(attack, dtype=bool)
    live = np.asarray(live, dtype=bool)

    aucs, npos = [], 0
    for h in np.unique(host_idx):
        rows = np.where(host_idx == h)[0]
        s = score[rows].reshape(-1)
        a = attack[rows].reshape(-1)
        lv = live[rows].reshape(-1)
        s, a = s[lv], a[lv]
        if a.sum() < min_pos or (~a).sum() < min_neg:
            continue
        npos += int(a.sum())
        aucs.append(_auc(s, a))
    if not aucs:
        return float("nan"), float("nan"), 0, 0
    return float(np.mean(aucs)), float(np.std(aucs)), len(aucs), npos


def _auc(s, y):
    y = np.asarray(y, dtype=bool)
    n1, n0 = int(y.sum()), int((~y).sum())
    if n1 == 0 or n0 == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    ranks[order] = np.arange(1, len(s) + 1)
    uniq = np.unique(s)
    if len(uniq) < len(s):
        for v in uniq:
            m = s == v
            if m.sum() > 1:
                ranks[m] = ranks[m].mean()
    return float((ranks[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))
