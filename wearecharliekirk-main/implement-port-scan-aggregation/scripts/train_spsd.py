#!/usr/bin/env python3
"""
scripts/train_spsd.py

Offline trainer for the SPSD (Supervised Port Scan Detector) DecisionTree,
per §6 of the port-scan fix plan. Run once (or whenever CIDDS-001 / your
own labeled network-event corpus changes).

CRITICAL: this script imports and reuses
``netsentinel.extractor.network_event_builder.NetworkEventBuilder`` -- the
exact same module used at inference time in
``netsentinel/models/portscan_detector.py``. Do NOT reimplement feature
computation here. Any divergence between train-time and inference-time
features reintroduces the covariate-shift bug that broke the original
per-flow model.

Usage
-----
    python scripts/train_spsd.py \\
        --week1 data/cidds/CIDDS-001-week1.csv \\
        --week2 data/cidds/CIDDS-001-week2.csv \\
        --network-info netsentinel/config/network_info_cidds.json \\
        --out netsentinel/models/weights/portscan_spsd_decisiontree.pkl

CIDDS-001 ("OpenStack" traffic) is unidirectional NetFlow, distributed as
weekly CSVs with columns roughly:
    Date first seen, Duration, Proto, Src IP Addr, Src Pt, Dst IP Addr,
    Dst Pt, Packets, Bytes, Flows, Flags, Tos, class, attackType,
    attackID, attackDescription

Reference: https://www.hs-coburg.de/cidds
Paper: Ring, Landes & Hotho (2018), PLOS ONE, doi:10.1371/journal.pone.0204507

Acceptance criteria (plan §6): >= 90% of labeled scans detected and
<= 5 false alarms on the held-out validation week.
"""

from __future__ import annotations

import argparse
import csv
import logging
import pickle
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

# Allow running as `python scripts/train_spsd.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netsentinel.config.network_info import NetworkInfo, load_network_info
from netsentinel.extractor.network_event_builder import (
    Flow,
    NetworkEvent,
    NetworkEventBuilder,
)

logger = logging.getLogger("train_spsd")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


# ----------------------------------------------------------------------
# CIDDS-001 CSV -> Flow adaptation
# ----------------------------------------------------------------------
def _parse_cidds_timestamp(date_str: str) -> float:
    """CIDDS 'Date first seen' looks like '2017-03-15 00:01:16.632'."""
    import datetime

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(date_str.strip(), fmt).timestamp()
        except ValueError:
            continue
    raise ValueError(f"Unrecognized CIDDS timestamp: {date_str!r}")


def _parse_flags(flags: str) -> Tuple[int, int, int, int]:
    """CIDDS 'Flags' column is a fixed 6-char string, e.g. '.AP.SF' where
    each position is either '.' (not set) or the flag letter
    (U, A, P, R, S, F for URG, ACK, PSH, RST, SYN, FIN)."""
    flags = (flags or "").strip()
    syn = 1 if "S" in flags else 0
    ack = 1 if "A" in flags else 0
    rst = 1 if "R" in flags else 0
    fin = 1 if "F" in flags else 0
    return syn, ack, rst, fin


def load_cidds_flows(csv_path: str) -> Tuple[List[Flow], Dict[Tuple[str, float], bool]]:
    """Parse a CIDDS-001 weekly CSV into Flow objects plus a
    (src_ip, window_start_60s) -> is_attacker label map.

    Labeling rule (plan §6.2): keep normal + portScan-labeled rows; relabel
    'victim' rows to 'normal' (we only identify the attacker's src IP), and
    treat any window containing a 'portScan' attacker flow from a given
    src IP as a positive (attacker) network event for that (src_ip,
    window) key.
    """
    flows: List[Flow] = []
    attacker_windows: Dict[Tuple[str, float], bool] = defaultdict(bool)

    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            proto = (row.get("Proto") or "").strip().upper()
            if proto not in ("TCP", "UDP", "ICMP"):
                continue

            try:
                ts = _parse_cidds_timestamp(row["Date first seen"])
            except (KeyError, ValueError):
                continue

            src_ip = row.get("Src IP Addr", "").strip()
            dst_ip = row.get("Dst IP Addr", "").strip()
            try:
                src_port = int(float(row.get("Src Pt", 0) or 0))
                dst_port = int(float(row.get("Dst Pt", 0) or 0))
                packets = int(float(row.get("Packets", 0) or 0))
            except ValueError:
                continue

            syn, ack, rst, fin = _parse_flags(row.get("Flags", ""))

            flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                timestamp=ts,
                fwd_packets=packets,
                bwd_packets=0,  # CIDDS is unidirectional per-record
                syn_count=syn,
                ack_count=ack,
                rst_count=rst,
                fin_count=fin,
                icmp_type=3 if proto == "ICMP" else None,
                icmp_code=3 if proto == "ICMP" else None,
            )
            flows.append(flow)

            label = (row.get("class") or "").strip().lower()
            attack_type = (row.get("attackType") or "").strip().lower()
            if label == "attacker" and "portscan" in attack_type.replace(" ", ""):
                window_start = (ts // 60) * 60
                attacker_windows[(src_ip, window_start)] = True

    return flows, attacker_windows


# ----------------------------------------------------------------------
# Training
# ----------------------------------------------------------------------
def build_labeled_dataset(
    flows: List[Flow],
    attacker_windows: Dict[Tuple[str, float], bool],
    network_info: NetworkInfo,
) -> Tuple[List[List[float]], List[int], List[NetworkEvent]]:
    builder = NetworkEventBuilder(network_info)
    events = builder.build(flows)

    X: List[List[float]] = []
    y: List[int] = []
    for ev in events:
        key = (ev.src_ip, ev.window_start)
        label = 1 if attacker_windows.get(key, False) else 0
        X.append(ev.feature_vector())
        y.append(label)
    return X, y, events


def evaluate(model, X_val, y_val) -> Tuple[float, int]:
    from sklearn.metrics import confusion_matrix

    y_pred = model.predict(X_val)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred, labels=[0, 1]).ravel()
    total_positive = tp + fn
    detection_rate = (tp / total_positive) if total_positive else 1.0
    false_alarms = int(fp)
    return detection_rate, false_alarms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--week1", required=True, help="CIDDS-001 week 1 CSV path")
    parser.add_argument("--week2", required=True, help="CIDDS-001 week 2 CSV path")
    parser.add_argument(
        "--network-info",
        default="netsentinel/config/network_info.json",
        help="Path to a network_info.json describing the CIDDS environment",
    )
    parser.add_argument(
        "--out",
        default="netsentinel/models/weights/portscan_spsd_decisiontree.pkl",
        help="Output path for the pickled DecisionTreeClassifier",
    )
    parser.add_argument(
        "--swap",
        action="store_true",
        help="Train on week2, validate on week1 (reproduces the paper's "
        "cross-validation in both directions)",
    )
    args = parser.parse_args()

    from sklearn.tree import DecisionTreeClassifier

    network_info = load_network_info(args.network_info)

    logger.info("Loading week1 flows from %s", args.week1)
    week1_flows, week1_labels = load_cidds_flows(args.week1)
    logger.info("Loading week2 flows from %s", args.week2)
    week2_flows, week2_labels = load_cidds_flows(args.week2)

    X1, y1, _ = build_labeled_dataset(week1_flows, week1_labels, network_info)
    X2, y2, _ = build_labeled_dataset(week2_flows, week2_labels, network_info)

    if args.swap:
        X_train, y_train = X2, y2
        X_val, y_val = X1, y1
        train_name, val_name = "week2", "week1"
    else:
        X_train, y_train = X1, y1
        X_val, y_val = X2, y2
        train_name, val_name = "week1", "week2"

    logger.info(
        "Training DecisionTreeClassifier on %s (%d events, %d positive)",
        train_name,
        len(X_train),
        sum(y_train),
    )
    model = DecisionTreeClassifier(criterion="gini", random_state=0)
    model.fit(X_train, y_train)

    detection_rate, false_alarms = evaluate(model, X_val, y_val)
    logger.info(
        "Validation on %s: detection_rate=%.2f%% false_alarms=%d",
        val_name,
        detection_rate * 100,
        false_alarms,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        pickle.dump(model, fh)
    logger.info("Saved model to %s", out_path)

    if detection_rate < 0.90 or false_alarms > 5:
        logger.warning(
            "Acceptance criteria NOT met (need >=90%% detection, <=5 false "
            "alarms). Got detection_rate=%.2f%%, false_alarms=%d. Model was "
            "still saved; review feature quality / network_info before "
            "deploying.",
            detection_rate * 100,
            false_alarms,
        )
        return 1

    logger.info("Acceptance criteria met.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
