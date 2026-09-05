#!/usr/bin/env python3
"""Render the two Grand Finale charts from results.json.

Chart 1 (the money chart): recall of Inspector-flagged windows vs escalation
budget, three routers. This is the claim the panel can check.
Chart 2: the G1 geometry diagnostic, because the go/no-go belongs on a slide
next to the result it qualifies.

Palette: validated categorical slots 1-3 (blue/orange/aqua). Aqua sits below
3:1 on the light surface, so every series carries a direct label (the relief
rule) and identity never rests on colour alone.
"""
from __future__ import annotations

import json, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SERIES = {                       # fixed slot order, never cycled
    "A_distilled_detector":  ("#2a78d6", "A · distilled detector\n(original V2 design)"),
    "B_encoder_mahalanobis": ("#eb6834", "B · encoder + Mahalanobis\n(V2_HARDENING B1)"),
    "C_deferral_head":       ("#1baf7a", "C · deferral head\n(V2_HARDENING G5)"),
}
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#898781", "#e1e0d9", "#fcfcfb"


def style(ax):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#c3c2b7"); ax.spines[s].set_linewidth(1)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)


def chart_budget(res, path):
    agg, budgets = res["aggregate"], np.array(res["budgets"]) * 100
    fig, ax = plt.subplots(figsize=(8.4, 5.0), dpi=200)
    fig.patch.set_facecolor(SURFACE); style(ax)

    ends = {}
    for key, (color, label) in SERIES.items():
        m = np.array([r["recall_teacher_mean"] for r in agg[key]]) * 100
        s = np.array([r["recall_teacher_std"] for r in agg[key]]) * 100
        ax.fill_between(budgets, m - s, m + s, color=color, alpha=0.13, linewidth=0)
        ax.plot(budgets, m, color=color, linewidth=2, zorder=3)
        ax.plot(budgets, m, "o", color=color, markersize=4.5,
                markeredgecolor=SURFACE, markeredgewidth=1.6, zorder=4)
        ends[key] = (m[-1], color, label)

    # de-collide the direct labels: each two-line label needs ~11 y-units
    order = sorted(ends, key=lambda k: -ends[k][0])
    placed: list[float] = []
    for key in order:
        y, color, label = ends[key]
        ly = y
        while any(abs(ly - p) < 11 for p in placed):
            ly -= 1.5
        placed.append(ly)
        ax.annotate(label, (budgets[-1], y), xytext=(9, (ly - y) * 4.6),
                    textcoords="offset points", color=color, fontsize=8.5,
                    va="center", linespacing=1.35, fontweight="medium")

    ax.plot(budgets, budgets, linestyle=(0, (4, 4)), color=MUTED,
            linewidth=1.2, zorder=2)
    ax.annotate("random routing", (budgets[-1], budgets[-1]), xytext=(8, -2),
                textcoords="offset points", color=MUTED, fontsize=8.5, va="center")

    ax.set_xlabel("Escalation budget — % of host-windows sent to the Inspector",
                  color="#52514e", fontsize=10, labelpad=9)
    ax.set_ylabel("Recall of Inspector-flagged windows (%)",
                  color="#52514e", fontsize=10, labelpad=9)
    ax.set_title("Can a cheap Sentry route well enough to keep the Inspector's ceiling?",
                 color=INK, fontsize=12.5, fontweight="semibold", loc="left", pad=14)
    ax.set_xlim(0, budgets[-1] * 1.02); ax.set_ylim(0, 100)
    ax.set_xticks([0, 5, 10, 15, 20, 25, 30])
    fig.text(0.008, 0.015,
             "Mean ±1σ over %d seeds · temporal train→val→test split · "
             "thresholds calibrated on validation only" % len(res["runs"]),
             color=MUTED, fontsize=7.6)
    fig.subplots_adjust(right=0.735, left=0.085, top=0.885, bottom=0.145)
    fig.savefig(path, facecolor=SURFACE)
    print("wrote", path)


def chart_geometry(res, path):
    g = res["geometry_mean"]
    keys = [k for k in g if k != "n"]
    vals = [g[k] for k in keys]
    names = {"knn_overlap@20": "kNN neighbourhood overlap\n(the real test)",
             "trustworthiness": "Trustworthiness",
             "spearman_score": "Score correlation\n(the weak test)"}
    fig, ax = plt.subplots(figsize=(7.6, 3.3), dpi=200)
    fig.patch.set_facecolor(SURFACE); style(ax)
    ypos = np.arange(len(keys))[::-1]
    colors = ["#d03b3b" if (k == "knn_overlap@20" and v < 0.30) else "#2a78d6"
              for k, v in zip(keys, vals)]
    ax.barh(ypos, [abs(v) for v in vals], height=0.42, color=colors, zorder=3)
    for y, v in zip(ypos, vals):
        ax.text(abs(v) + 0.015, y, f"{v:.2f}", va="center", fontsize=10,
                color=INK, fontweight="semibold")
    ax.axvline(0.30, color=MUTED, linestyle=(0, (4, 4)), linewidth=1.2, zorder=2)
    ax.text(0.305, ypos[0] + 0.42, "0.30 = go/no-go", color=MUTED, fontsize=8)
    ax.set_yticks(ypos); ax.set_yticklabels([names[k] for k in keys], fontsize=9,
                                            color="#52514e", linespacing=1.3)
    ax.set_xlim(0, max(1.0, max(abs(v) for v in vals) * 1.25))
    ax.set_title("G1 diagnostic — does the Sentry preserve the Inspector's local geometry?",
                 color=INK, fontsize=11.5, fontweight="semibold", loc="left", pad=12)
    fig.text(0.008, 0.02, "VERDICT: %s — %s" % (res["verdict"][0], res["verdict"][1][:110]),
             color=MUTED, fontsize=7.6, wrap=True)
    fig.subplots_adjust(left=0.285, right=0.97, top=0.83, bottom=0.16)
    fig.savefig(path, facecolor=SURFACE)
    print("wrote", path)


if __name__ == "__main__":
    res = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "results.json"))
    chart_budget(res, "chart_escalation_budget.png")
    chart_geometry(res, "chart_geometry_diagnostic.png")
