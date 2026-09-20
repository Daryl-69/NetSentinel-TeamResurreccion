"""Per-host behavioural baseline in Sentry-embedding space.

This is the part that is deliberately NOT distilled. Distillation degrades
local-outlier detection (20% transfer) and neighbourhood methods (76%
retention) while preserving global structure (78-88%) -- so we distil the
*representation* and keep the *local decision* exact.

Three corrections from V2_HARDENING Part G are implemented here:

  G3  Ledoit-Wolf shrinkage. A 14-day commissioning window gives ~O(d)
      samples, not the >> d^2 a raw sample covariance needs. Without
      shrinkage Sigma is singular and the distance is meaningless.

  G4  Multimodality. One Gaussian cannot cover workday / evening / weekend.
      We fit k components and score against the nearest one.

  Attacker-in-the-baseline. Windows with the highest teacher error are
      trimmed before fitting, so a slow attacker present during commissioning
      contributes less to "normal". This cuts both ways -- it also removes
      legitimate rare behaviour, which is then flagged forever after. That
      trade is real and is reported, not hidden.
"""

from __future__ import annotations

import numpy as np
from sklearn.covariance import LedoitWolf
from sklearn.cluster import KMeans


class HostBaseline:
    def __init__(self, n_components=3, trim_frac=0.05, min_per_component=12):
        self.k = n_components
        self.trim_frac = trim_frac
        self.min_per_component = min_per_component
        self.means_: list[np.ndarray] = []
        self.precisions_: list[np.ndarray] = []
        self.fitted_ = False

    def fit(self, Z: np.ndarray, teacher_err: np.ndarray | None = None):
        """Z (n, d) commissioning embeddings; teacher_err (n,) for trimming."""
        Z = np.asarray(Z, dtype=np.float64)
        if teacher_err is not None and self.trim_frac > 0 and len(Z) > 20:
            keep = np.argsort(teacher_err)[: max(10, int(len(Z) * (1 - self.trim_frac)))]
            Z = Z[keep]

        n, d = Z.shape
        k = max(1, min(self.k, n // max(self.min_per_component, 1)))
        if k == 1:
            labels = np.zeros(n, dtype=int)
        else:
            labels = KMeans(n_clusters=k, n_init=4, random_state=0).fit_predict(Z)

        self.means_, self.precisions_ = [], []
        for c in range(k):
            Zc = Z[labels == c]
            if len(Zc) < 4:
                Zc = Z                       # degenerate cluster -> use all
            lw = LedoitWolf(assume_centered=False).fit(Zc)
            self.means_.append(lw.location_)
            self.precisions_.append(lw.precision_)
        self.fitted_ = True
        return self

    def score(self, Z: np.ndarray) -> np.ndarray:
        """Min Mahalanobis distance over components. Higher = more deviant."""
        if not self.fitted_:
            return np.zeros(len(Z))
        Z = np.asarray(Z, dtype=np.float64)
        best = None
        for mu, P in zip(self.means_, self.precisions_):
            delta = Z - mu
            d2 = np.einsum("ij,jk,ik->i", delta, P, delta)
            d2 = np.sqrt(np.clip(d2, 0, None))
            best = d2 if best is None else np.minimum(best, d2)
        return best


def fit_all(Z_by_host: dict, err_by_host: dict | None = None, **kw):
    out = {}
    for h, Z in Z_by_host.items():
        e = None if err_by_host is None else err_by_host.get(h)
        out[h] = HostBaseline(**kw).fit(Z, e)
    return out
