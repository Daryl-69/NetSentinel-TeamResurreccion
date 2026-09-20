"""G1 go/no-go diagnostic: does the student's embedding space preserve the
teacher's LOCAL geometry?

The whole B1 fix rests on an assumption I flagged as unproven in
V2_HARDENING G1: moving the local decision out of the network only helps if
the distilled ENCODER still preserves local geometry. Compression is exactly
what destroys local structure, so this must be measured, not assumed.

The right test is NOT "do teacher and student scores correlate". It is
whether a point's NEIGHBOURS are the same in both spaces. If host h's nearest
neighbours differ between encoders, then a Mahalanobis test computed in the
student space is being computed in a geometry the teacher would not
recognise, and B1 is unfixed no matter how well the scores correlate.

Reported:
  knn_overlap@k  mean |N_t(x) ∩ N_s(x)| / k        (1.0 = geometry preserved)
  trustworthiness (sklearn)                        standard manifold measure
  spearman(score_t, score_s)                       the WEAKER test, for contrast
"""

from __future__ import annotations

import numpy as np
from scipy.stats import spearmanr
from sklearn.neighbors import NearestNeighbors
from sklearn.manifold import trustworthiness


def knn_overlap(Zt: np.ndarray, Zs: np.ndarray, k: int = 20,
                sample: int = 3000, seed: int = 0) -> float:
    n = len(Zt)
    rng = np.random.default_rng(seed)
    idx = rng.choice(n, size=min(sample, n), replace=False)

    nt = NearestNeighbors(n_neighbors=k + 1).fit(Zt)
    ns = NearestNeighbors(n_neighbors=k + 1).fit(Zs)
    _, it = nt.kneighbors(Zt[idx])
    _, is_ = ns.kneighbors(Zs[idx])

    ov = [len(set(a[1:]) & set(b[1:])) / k for a, b in zip(it, is_)]
    return float(np.mean(ov))


def geometry_report(Zt, Zs, score_t, score_s, k=20, sample=3000):
    Zt, Zs = np.asarray(Zt), np.asarray(Zs)
    n = min(len(Zt), 1500)
    rng = np.random.default_rng(0)
    sub = rng.choice(len(Zt), size=n, replace=False)
    return {
        "knn_overlap@%d" % k: knn_overlap(Zt, Zs, k=k, sample=sample),
        "trustworthiness": float(trustworthiness(Zt[sub], Zs[sub], n_neighbors=min(k, n - 2))),
        "spearman_score": float(spearmanr(score_t, score_s).statistic),
        "n": int(len(Zt)),
    }


# Thresholds are PROVISIONAL. They were asserted before the first run, not
# calibrated. The v1 experiment measured overlap ~0.32 while the Mahalanobis
# router was nonetheless the best of the three -- so partial geometry
# preservation is evidently enough for the baseline test to beat a distilled
# detector. Treat these bands as a monitor for regression, not as physics, and
# recalibrate them against router AUC as more runs accumulate.
GO_BAND, MARGINAL_BAND = 0.50, 0.25


def verdict(report, k=20):
    """Plain-language go/no-go so nobody has to interpret the number."""
    ov = report["knn_overlap@%d" % k]
    if ov >= GO_BAND:
        return ("GO", "Student preserves the teacher's local geometry "
                      "(overlap %.2f). Mahalanobis in student space is well founded." % ov)
    if ov >= MARGINAL_BAND:
        # This text used to add "with ~7x the seed variance of the learned
        # heads". That was true of one 3-seed run and false at 8 seeds, where
        # B has the LOWEST seed spread of the three (0.029 vs A 0.044, C
        # 0.039). A narrative baked into a function that does not measure it
        # will keep asserting it long after the measurement has moved, so the
        # variance claim is gone: this function knows the overlap and nothing
        # else, and now says only what the overlap supports.
        return ("MARGINAL", "Partial geometry preservation (overlap %.2f). The Mahalanobis "
                            "router puts the decision in this geometry, so it is the router "
                            "most exposed to the shortfall. Report the overlap alongside any "
                            "recall claim, and re-check it whenever student capacity or the "
                            "distillation loss changes." % ov)
    return ("NO-GO", "Student does NOT preserve local geometry (overlap %.2f). "
                     "The B1 fix is not established: the local decision has been "
                     "moved into an encoder that destroyed the locality. "
                     "Increase student capacity or distil with a neighbourhood-"
                     "preserving loss before proceeding." % ov)
