"""
Covariate Shift Experiment
==========================
Compares CICFlowMeter features (ref.csv) vs our flow_extractor.py (ours.csv)
using the Kolmogorov-Smirnov statistic per feature.

Run:
    python scripts/covariate_shift.py

Outputs:
    ks_results.csv   — per-feature KS stat, p-value, mean/std delta
    ks_summary.txt   — human-readable report
"""
import os
import sys
import pandas as pd
import numpy as np
from scipy.stats import ks_2samp

# ── Path setup ────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

PCAP_PATH  = os.path.join(PROJECT_ROOT, "Friday-WorkingHours.pcap")
REF_CSV    = os.path.join(PROJECT_ROOT, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
OURS_CSV   = os.path.join(PROJECT_ROOT, "ours.csv")
KS_CSV     = os.path.join(PROJECT_ROOT, "ks_results.csv")
KS_SUMMARY = os.path.join(PROJECT_ROOT, "ks_summary.txt")

MAX_FLOWS  = 5000   # Stop after this many flows (enough for statistical comparison)

# ── Step 1: Generate ours.csv from flow_extractor.py ─────────────────────────
def generate_ours_csv():
    if os.path.exists(OURS_CSV):
        print(f"[SKIP] {OURS_CSV} already exists. Delete it to regenerate.")
        return

    print(f"[1/3] Streaming PCAP -> {OURS_CSV}")
    print(f"      Stopping after {MAX_FLOWS} flows...")

    try:
        from netsentinel.extractor.flow_extractor import FlowExtractor
    except ImportError:
        from netsentinel2.extractor.flow_extractor import FlowExtractor
    from scapy.utils import PcapReader

    extractor = FlowExtractor(idle_timeout=120, active_timeout=300)
    rows = []
    packet_count = 0

    with PcapReader(PCAP_PATH) as reader:
        for packet in reader:
            packet_count += 1

            event = extractor.process_packet(packet)
            if event:
                features = event.get("features", {})
                if features:
                    rows.append(features)

            # Periodic flush
            if packet_count % 50000 == 0:
                pkt_time = float(packet.time)
                for evt in extractor.flush_expired(pkt_time):
                    features = evt.get("features", {})
                    if features:
                        rows.append(features)
                print(f"  Packets: {packet_count:,}  |  Flows: {len(rows):,}")

            if len(rows) >= MAX_FLOWS:
                print(f"  Reached {MAX_FLOWS} flows. Stopping.")
                break

    if not rows:
        print("[ERROR] No flow features were extracted! Check PCAP path.")
        return

    df = pd.DataFrame(rows)
    df.to_csv(OURS_CSV, index=False)
    print(f"  Saved {len(df)} flows to {OURS_CSV}")
    print(f"  Our columns ({len(df.columns)}): {list(df.columns)[:5]} ...")


# ── Step 2: Load and align the two CSVs ──────────────────────────────────────
def load_and_align():
    print(f"\n[2/3] Loading CSVs...")

    ref = pd.read_csv(REF_CSV)
    our = pd.read_csv(OURS_CSV)

    # Strip leading/trailing whitespace from CICFlowMeter column names
    ref.columns = [c.strip() for c in ref.columns]

    print(f"  CICFlowMeter ref: {ref.shape[0]} rows x {ref.shape[1]} cols")
    print(f"  Our extractor:    {our.shape[0]} rows x {our.shape[1]} cols")

    # Find common numeric columns (ignore label/metadata)
    exclude = {'Label', 'Flow ID', 'Source IP', 'Destination IP',
               'Source Port', 'Destination Port', 'Protocol', 'Timestamp',
               'source_ip', 'dest_ip', 'src_port', 'dst_port', 'protocol',
               'type', 'flow_id', 'start_time', 'end_time'}

    ref_cols = set(ref.select_dtypes(include=[np.number]).columns) - exclude
    our_cols = set(our.select_dtypes(include=[np.number]).columns) - exclude

    # Normalize names: CICFlowMeter uses "Flow Duration", ours may use "flow_duration"
    def norm(name):
        return name.lower().replace(' ', '_').replace('/', '_per_').replace('.', '')

    ref_norm = {norm(c): c for c in ref_cols}
    our_norm = {norm(c): c for c in our_cols}

    common_norm = set(ref_norm.keys()) & set(our_norm.keys())
    common_pairs = [(ref_norm[n], our_norm[n]) for n in sorted(common_norm)]

    print(f"\n  Common features found: {len(common_pairs)}")
    if len(common_pairs) == 0:
        print("\n  [WARNING] No common features found after name normalization!")
        print(f"  CICFlowMeter cols (sample): {list(ref_cols)[:8]}")
        print(f"  Our cols (sample):          {list(our_cols)[:8]}")

    return ref, our, common_pairs, ref_cols, our_cols


# ── Step 3: Compute KS statistics ────────────────────────────────────────────
def compute_ks(ref, our, common_pairs, ref_cols, our_cols):
    print(f"\n[3/3] Computing KS statistics...")

    results = []

    for ref_col, our_col in common_pairs:
        ref_vals = ref[ref_col].replace([np.inf, -np.inf], np.nan).dropna()
        our_vals = our[our_col].replace([np.inf, -np.inf], np.nan).dropna()

        if len(ref_vals) < 10 or len(our_vals) < 10:
            continue

        ks_stat, p_val = ks_2samp(ref_vals, our_vals)

        results.append({
            "feature_cic":   ref_col,
            "feature_ours":  our_col,
            "ks_stat":       round(ks_stat, 4),
            "p_value":       round(p_val, 6),
            "ref_mean":      round(float(ref_vals.mean()), 4),
            "our_mean":      round(float(our_vals.mean()), 4),
            "mean_delta":    round(abs(float(ref_vals.mean()) - float(our_vals.mean())), 4),
            "ref_std":       round(float(ref_vals.std()), 4),
            "our_std":       round(float(our_vals.std()), 4),
            "shifted":       ks_stat > 0.1,
        })

    if not results:
        write_mismatch_report(ref_cols, our_cols)
        return []

    results.sort(key=lambda x: -x["ks_stat"])

    # Save CSV
    ks_df = pd.DataFrame(results)
    ks_df.to_csv(KS_CSV, index=False)

    # Write summary
    shifted     = [r for r in results if r["shifted"]]
    not_shifted = [r for r in results if not r["shifted"]]

    lines = [
        "=" * 60,
        "NetSentinel -- Covariate Shift Report",
        "=" * 60,
        "",
        f"CICFlowMeter ref:  {REF_CSV}",
        f"Our extractor:     {OURS_CSV}",
        "",
        f"Total common features compared: {len(results)}",
        f"Shifted (KS > 0.1):             {len(shifted)}",
        f"Stable  (KS <= 0.1):            {len(not_shifted)}",
        "",
        "-" * 60,
        "TOP SHIFTED FEATURES (KS > 0.1) -- need investigation:",
        "-" * 60,
    ]

    for r in shifted:
        lines.append(
            f"  {r['feature_cic']:<35} KS={r['ks_stat']:.3f}  "
            f"ref_mean={r['ref_mean']:.2f}  our_mean={r['our_mean']:.2f}"
        )

    lines += [
        "",
        "-" * 60,
        "STABLE FEATURES (KS <= 0.1) -- good alignment:",
        "-" * 60,
    ]
    for r in not_shifted:
        lines.append(f"  {r['feature_cic']:<35} KS={r['ks_stat']:.3f}")

    lines += [
        "",
        "=" * 60,
        f"Shift penalty estimate: {len(shifted)/max(1,len(results))*100:.1f}% of features are shifted",
        "=" * 60,
    ]

    text = "\n".join(lines)
    print(text)

    with open(KS_SUMMARY, "w") as f:
        f.write(text)

    print(f"\nSaved: {KS_CSV}")
    print(f"Saved: {KS_SUMMARY}")
    return results


def write_mismatch_report(ref_cols, our_cols):
    lines = [
        "=" * 60,
        "NetSentinel -- Covariate Shift Report",
        "=" * 60,
        "",
        "WARNING: No common features found between CICFlowMeter and",
        "our flow_extractor.py. This is a column naming mismatch.",
        "",
        "CICFlowMeter columns:",
    ]
    for c in sorted(ref_cols):
        lines.append(f"  {c}")
    lines += ["", "Our extractor columns:"]
    for c in sorted(our_cols):
        lines.append(f"  {c}")

    text = "\n".join(lines)
    print(text)
    with open(KS_SUMMARY, "w") as f:
        f.write(text)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("NetSentinel -- Covariate Shift Experiment")
    print("=" * 60)

    if not os.path.exists(PCAP_PATH):
        print(f"[ERROR] PCAP not found: {PCAP_PATH}")
        sys.exit(1)

    if not os.path.exists(REF_CSV):
        print(f"[ERROR] Reference CSV not found: {REF_CSV}")
        sys.exit(1)

    generate_ours_csv()
    ref, our, common_pairs, ref_cols, our_cols = load_and_align()
    compute_ks(ref, our, common_pairs, ref_cols, our_cols)
