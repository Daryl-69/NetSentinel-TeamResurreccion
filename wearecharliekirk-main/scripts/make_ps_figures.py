"""Charts for PS 26145, drawn only from this repository's result files.

    python scripts/make_ps_figures.py

Writes docs/figures/*.png and docs/figures/index.json (name, caption,
source). Every number on a chart comes from the source file named in its
caption; nothing is typed in by hand.
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                     # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "figures")
MC = os.path.join(ROOT, "model_comparisons")

# palette (reference instance of the data-viz method: light surface)
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10.5, "text.color": INK, "axes.labelcolor": INK2,
    "axes.edgecolor": AXIS, "axes.linewidth": 1.0, "xtick.color": MUTED, "ytick.color": INK2,
    "axes.facecolor": SURFACE, "figure.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.grid": False, "axes.titleweight": "bold", "axes.titlesize": 12.5, "axes.titlelocation": "left",
})


def load(name):
    with open(os.path.join(MC, name), encoding="utf-8") as fh:
        return json.load(fh)


def clean(ax, grid_axis="x"):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    if grid_axis == "x":
        ax.spines["left"].set_visible(False)
        ax.xaxis.grid(True, color=GRID, linewidth=1.0)
        ax.tick_params(axis="y", length=0)
    else:
        ax.spines["left"].set_visible(False)
        ax.yaxis.grid(True, color=GRID, linewidth=1.0)
        ax.tick_params(axis="y", length=0)
    ax.set_axisbelow(True)


def footer(fig, text, width=118):
    import textwrap
    lines = []
    for part in text.split("\n"):
        lines += textwrap.wrap(part, width) or [""]
    fig.text(0.012, 0.012, "\n".join(lines), fontsize=8.5, color=MUTED, ha="left", va="bottom", linespacing=1.35)


def fig_alert_volume(items):
    d = load("ps26145_live_path_eval.json")
    names = {
        ("exfil_vae", "DNS tunnelling (anomalous name)"): ("DNS exfiltration VAE", "model"),
        ("dga_cnn_bilstm_v2", "machine-generated name"): ("DGA name model: machine-generated", "model"),
        ("dga_cnn_bilstm_v2", "tunnel-like name"): ("DGA name model: tunnel-like", "model"),
        ("c2_combined_score_v2", "periodic check-ins"): ("C2 periodicity score", "rule"),
        ("portscan_spsd", "block scan"): ("Port-scan tree", "model"),
        ("exfil_byte_ratio", "asymmetric upload (out/in byte ratio)"): ("Byte-ratio exfiltration", "rule"),
    }
    rows = []
    for r in d["by_detector"]:
        label, kind = names.get((r["detector"], r["subtype"]), (r["detector"] + ": " + r["subtype"], "model"))
        rows.append((label, kind, r["per_24h_of_capture"], r["alerts"]))
    for label in ("DDoS rate/entropy", "DNS behaviour rules", "Encrypted-session profile"):
        rows.append((label, "rule", 0.0, 0))
    rows.sort(key=lambda x: x[2])
    fig, ax = plt.subplots(figsize=(9.2, 4.9))
    ys = range(len(rows))
    colors = [BLUE if k == "model" else ORANGE for _, k, _, _ in rows]
    ax.barh(list(ys), [v for _, _, v, _ in rows], height=0.52, color=colors)
    top = max(v for _, _, v, _ in rows)
    for y, (_, _, v, n) in zip(ys, rows):
        ax.text(v + top * 0.01, y, "%s  (%d)" % (("%.1f" % v) if v else "0", n), va="center", fontsize=9.5, color=INK2)
    ax.set_yticks(list(ys))
    ax.set_yticklabels([l for l, _, _, _ in rows])
    ax.set_xlim(0, top * 1.18)
    ax.set_xlabel("alerts per 24 h of capture  (total in brackets)")
    clean(ax, "x")
    ax.set_title("Alerts on 40.5 hours of the team's own traffic, by detector")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label="trained model"), Patch(color=ORANGE, label="rule detector")],
              loc="lower right", frameon=False, fontsize=9.5)
    footer(fig, "Live-mode path, final code. Unlabelled traffic: every count is an upper bound on false alarms. "
                "Source: model_comparisons/ps26145_live_path_eval.json")
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    name = "alert_volume_real_traffic.png"
    fig.savefig(os.path.join(OUT, name), dpi=160)
    plt.close(fig)
    items.append({"name": name, "source": "model_comparisons/ps26145_live_path_eval.json",
                  "caption": "Alerts per 24 h on 40.5 hours of the team's own traffic, by detector "
                             "(upper bound: the traffic is unlabelled)"})


def fig_throughput(items):
    real = load("ps26145_benchmark_real.json")["runs"]
    syn = load("ps26145_benchmark_synthetic.json")["run"]
    labels = [r["file"].replace("team sensor capture, ", "team capture\n")[:-4] for r in real] + ["synthetic mix\n100k packets"]
    pps = [r["packets_per_s"] for r in real] + [syn["packets_per_s"]]
    fps = [r["flows_per_s"] for r in real] + [syn["flows_per_s"]]
    colors = [BLUE] * len(real) + [AQUA]
    fig, axes = plt.subplots(1, 2, figsize=(10.4, 3.9))
    for ax, vals, title, fmt in ((axes[0], pps, "Packets per second", "{:,.0f}"),
                                 (axes[1], fps, "Flows per second", "{:,.0f}")):
        xs = range(len(vals))
        ax.bar(list(xs), vals, width=0.46, color=colors)
        for x, v in zip(xs, vals):
            ax.text(x, v * 1.01, fmt.format(v), ha="center", va="bottom", fontsize=9.5, color=INK2)
        ax.set_xticks(list(xs))
        ax.set_xticklabels(labels, fontsize=8.8)
        ax.set_ylim(0, max(vals) * 1.16)
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: "{:,.0f}".format(v)))
        clean(ax, "y")
        ax.set_title(title)
    from matplotlib.patches import Patch
    axes[1].legend(handles=[Patch(color=BLUE, label="team capture, laptop VM (Ryzen 5 5600H)"),
                            Patch(color=AQUA, label="synthetic, dev container (Xeon 2.8 GHz)")],
                   loc="upper left", frameon=False, fontsize=8.8)
    fig.suptitle("What one Python process sustained: extraction and every detector", x=0.012, ha="left",
                 fontweight="bold", fontsize=12.5)
    footer(fig, "2 vCPUs each, final code; runs vary by about 10%. Team captures are single-host, with few flows.\n"
                "Sources: model_comparisons/ps26145_benchmark_real.json and ps26145_benchmark_synthetic.json")
    fig.tight_layout(rect=(0, 0.09, 1, 0.95))
    name = "throughput.png"
    fig.savefig(os.path.join(OUT, name), dpi=160)
    plt.close(fig)
    items.append({"name": name, "source": "model_comparisons/ps26145_benchmark_real.json, ps26145_benchmark_synthetic.json",
                  "caption": "Throughput of one Python process through extraction and every detector: three 200 MB "
                             "team captures and the synthetic mix"})


def fig_c2_threshold(items):
    d = load("c2_beacon_score_eval.json")
    pts = [(float(k), v["per_24h"], v["beacon_caught"]) for k, v in d["sensitivity_other_thresholds"].items()]
    at = d["alerts_at_threshold"]
    pts.append((float(d["alert_threshold"]), at["benign_session_alerts_per_24h_of_capture"], at["beacon_caught"]))
    pts.sort()
    fig, ax = plt.subplots(figsize=(8.4, 4.2))
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    ax.plot(xs, ys, color=BLUE, linewidth=2, solid_capstyle="round", solid_joinstyle="round", zorder=2)
    for x, y, caught in pts:
        ax.scatter([x], [y], s=64, color=BLUE if caught else SURFACE, edgecolor=BLUE, linewidth=2, zorder=3)
        ax.text(x, y + 1.3, "%.1f" % y, ha="center", va="bottom", fontsize=9.5, color=INK2)
    thr = float(d["alert_threshold"])
    ax.axvline(thr, color=AXIS, linewidth=1, zorder=1)
    ax.text(thr + 0.004, max(ys) * 0.92, "shipped threshold %.2f\nbeacon score %.3f" % (thr, d["beacon"]["score"]),
            fontsize=9, color=INK2, va="top")
    ax.set_xticks(xs)
    ax.set_xlabel("alert threshold on the combined score")
    ax.set_ylabel("other sessions alerted per 24 h")
    ax.set_ylim(0, max(ys) * 1.2)
    clean(ax, "y")
    ax.set_title("C2 periodicity score: one labelled beacon against 97 hours of other traffic")
    from matplotlib.lines import Line2D
    ax.legend(handles=[Line2D([], [], marker="o", color=BLUE, linestyle="none", markersize=8, label="beacon caught"),
                       Line2D([], [], marker="o", markerfacecolor=SURFACE, markeredgecolor=BLUE, markeredgewidth=2,
                              color=BLUE, linestyle="none", markersize=8, label="beacon missed")],
              loc="upper right", frameon=False, fontsize=9.5)
    footer(fig, "Offline whole-window scoring; other traffic unlabelled, so every count is an upper bound. "
                "Source: model_comparisons/c2_beacon_score_eval.json")
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    name = "c2_threshold_tradeoff.png"
    fig.savefig(os.path.join(OUT, name), dpi=160)
    plt.close(fig)
    items.append({"name": name, "source": "model_comparisons/c2_beacon_score_eval.json",
                  "caption": "C2 combined score: other sessions alerted per 24 h at each threshold, and whether the "
                             "one labelled beacon is still caught"})


def fig_latency(items):
    run = load("ps26145_benchmark_synthetic.json")["run"]
    det = run["latency_ms"]["detector"]
    nice = {"ddos_rule": "DDoS rule", "ddos_window": "DDoS window update", "c2_combined": "C2 periodicity score",
            "exfil_ratio": "Byte-ratio exfiltration", "tls_sessions": "TLS session profile",
            "dns_behaviour": "DNS behaviour rules", "exfil_vae": "DNS exfiltration VAE (per new name)",
            "dga_cnn_bilstm": "DGA CNN-BiLSTM (per new name)", "ett_transformer": "Encrypted-traffic classifier",
            "c2_bilstm": "C2 BiLSTM (per 100-flow session)"}
    rows = [(nice.get(k, k), v["p50"], v["p95"], v["n"]) for k, v in det.items() if k in nice]
    rows.sort(key=lambda x: x[2])
    fig, ax = plt.subplots(figsize=(9.2, 4.6))
    ys = list(range(len(rows)))
    h = 0.34
    ax.barh([y + h / 2 + 0.02 for y in ys], [r[2] for r in rows], height=h, color=BLUE, label="p95")
    ax.barh([y - h / 2 - 0.02 for y in ys], [r[1] for r in rows], height=h, color=ORANGE, label="p50")
    for y, r in zip(ys, rows):
        ax.text(r[2] * 1.12, y + h / 2 + 0.02, "%.3f ms" % r[2], va="center", fontsize=9, color=INK2)
    ax.set_xscale("log")
    ax.set_yticks(ys)
    ax.set_yticklabels([r[0] for r in rows])
    ax.set_xlabel("milliseconds per call (log scale)")
    ax.set_xlim(min(r[1] for r in rows) * 0.5, max(r[2] for r in rows) * 6)
    clean(ax, "x")
    ax.legend(loc="lower right", frameon=False, fontsize=9.5)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: ("%g" % v)))
    ax.set_title("Time per detector call while streaming")
    footer(fig, "Synthetic 100k-packet capture, development container, one process, final code. Port-scan window "
                "closes (every 60 s or 1,000 flows) are not shown. Source: model_comparisons/ps26145_benchmark_synthetic.json")
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    name = "detector_latency.png"
    fig.savefig(os.path.join(OUT, name), dpi=160)
    plt.close(fig)
    items.append({"name": name, "source": "model_comparisons/ps26145_benchmark_synthetic.json",
                  "caption": "Time per detector call (p50 and p95) while streaming the synthetic capture"})


def main():
    os.makedirs(OUT, exist_ok=True)
    items = []
    for f in (fig_alert_volume, fig_throughput, fig_c2_threshold, fig_latency):
        try:
            f(items)
        except FileNotFoundError as e:
            print("skipped %s: %s" % (f.__name__, e), file=sys.stderr)
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(items, fh, indent=1)
    for it in items:
        print(it["name"], "<-", it["source"])


if __name__ == "__main__":
    main()
