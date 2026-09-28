"""CICFlowMeter Wrapper — Zero-drift feature extraction for DDoS & Port Scan.

Uses hieulw/cicflowmeter (pip install cicflowmeter) Python API to extract
the exact same features that the DDoS and Port Scan models were trained on.

Uses the Python API directly (not the CLI), so no tcpdump dependency.
"""
import logging
import os
import tempfile
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# Maps cicflowmeter Python output names → CIC CSV names (what models expect)
CIC_NAME_MAP = {
    "flow_duration":       "Flow Duration",
    "tot_fwd_pkts":        "Total Fwd Packets",
    "tot_bwd_pkts":        "Total Backward Packets",
    "totlen_fwd_pkts":     "Fwd Packets Length Total",
    "totlen_bwd_pkts":     "Bwd Packets Length Total",
    "fwd_pkt_len_max":     "Fwd Packet Length Max",
    "fwd_pkt_len_min":     "Fwd Packet Length Min",
    "fwd_pkt_len_mean":    "Fwd Packet Length Mean",
    "fwd_pkt_len_std":     "Fwd Packet Length Std",
    "bwd_pkt_len_max":     "Bwd Packet Length Max",
    "bwd_pkt_len_min":     "Bwd Packet Length Min",
    "bwd_pkt_len_mean":    "Bwd Packet Length Mean",
    "bwd_pkt_len_std":     "Bwd Packet Length Std",
    "flow_byts_s":         "Flow Bytes/s",
    "flow_pkts_s":         "Flow Packets/s",
    "flow_iat_mean":       "Flow IAT Mean",
    "flow_iat_std":        "Flow IAT Std",
    "flow_iat_max":        "Flow IAT Max",
    "flow_iat_min":        "Flow IAT Min",
    "fwd_iat_tot":         "Fwd IAT Total",
    "fwd_iat_mean":        "Fwd IAT Mean",
    "fwd_iat_std":         "Fwd IAT Std",
    "fwd_iat_max":         "Fwd IAT Max",
    "fwd_iat_min":         "Fwd IAT Min",
    "bwd_iat_tot":         "Bwd IAT Total",
    "bwd_iat_mean":        "Bwd IAT Mean",
    "bwd_iat_std":         "Bwd IAT Std",
    "bwd_iat_max":         "Bwd IAT Max",
    "bwd_iat_min":         "Bwd IAT Min",
    "fwd_psh_flags":       "Fwd PSH Flags",
    "bwd_psh_flags":       "Bwd PSH Flags",
    "fwd_urg_flags":       "Fwd URG Flags",
    "bwd_urg_flags":       "Bwd URG Flags",
    "fwd_header_len":      "Fwd Header Length",
    "bwd_header_len":      "Bwd Header Length",
    "fwd_pkts_s":          "Fwd Packets/s",
    "bwd_pkts_s":          "Bwd Packets/s",
    "pkt_len_max":         "Packet Length Max",
    "pkt_len_min":         "Packet Length Min",
    "pkt_len_mean":        "Packet Length Mean",
    "pkt_len_std":         "Packet Length Std",
    "pkt_len_var":         "Packet Length Variance",
    "fin_flag_cnt":        "FIN Flag Count",
    "syn_flag_cnt":        "SYN Flag Count",
    "rst_flag_cnt":        "RST Flag Count",
    "psh_flag_cnt":        "PSH Flag Count",
    "ack_flag_cnt":        "ACK Flag Count",
    "urg_flag_cnt":        "URG Flag Count",
    "ece_flag_cnt":        "ECE Flag Count",
    "cwr_flag_count":      "CWE Flag Count",
    "down_up_ratio":       "Down/Up Ratio",
    "pkt_size_avg":        "Avg Packet Size",
    "fwd_seg_size_avg":    "Avg Fwd Segment Size",
    "bwd_seg_size_avg":    "Avg Bwd Segment Size",
    "subflow_fwd_pkts":    "Subflow Fwd Packets",
    "subflow_fwd_byts":    "Subflow Fwd Bytes",
    "subflow_bwd_pkts":    "Subflow Bwd Packets",
    "subflow_bwd_byts":    "Subflow Bwd Bytes",
    "init_fwd_win_byts":   "Init Fwd Win Bytes",
    "init_bwd_win_byts":   "Init Bwd Win Bytes",
    "fwd_act_data_pkts":   "Fwd Act Data Packets",
    "fwd_seg_size_min":    "Fwd Seg Size Min",
    "active_mean":         "Active Mean",
    "active_std":          "Active Std",
    "active_max":          "Active Max",
    "active_min":          "Active Min",
    "idle_mean":           "Idle Mean",
    "idle_std":            "Idle Std",
    "idle_max":            "Idle Max",
    "idle_min":            "Idle Min",
    "fwd_byts_b_avg":     "Fwd Bytes/Bulk Avg",
    "fwd_pkts_b_avg":     "Fwd Packets/Bulk Avg",
    "bwd_byts_b_avg":     "Bwd Bytes/Bulk Avg",
    "bwd_pkts_b_avg":     "Bwd Packets/Bulk Avg",
    "fwd_blk_rate_avg":   "Fwd Bulk Rate Avg",
    "bwd_blk_rate_avg":   "Bwd Bulk Rate Avg",
}

# Metadata columns to exclude from features
_META_COLS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
}


def _parse_cic_timestamp(value):
    """Flow start time from a CICFlowMeter CSV row, as epoch seconds.

    python-cicflowmeter writes the start as a naive local-time string
    ("2026-09-21 14:03:11"); other builds write epoch seconds or the CIC-IDS
    "21/09/2026 02:03:11 PM" form. Naive strings are read as local time,
    which inverts what the tool wrote on the same machine. Returns None if
    the value cannot be read (the flow then carries no time, as before).
    """
    if value is None:
        return None
    try:
        f = float(value)
        if f != f:
            return None
        return f / 1000.0 if f > 1e11 else f      # ms epochs -> s
    except (TypeError, ValueError):
        pass
    from datetime import datetime
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %I:%M:%S %p",
                "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class CICFlowMeterExtractor:
    """Extracts CIC-IDS flow features using the reference CICFlowMeter Python API.

    Zero covariate shift by definition — this is the same tool that
    generated the training data for DDoS and Port Scan models.

    Uses the Python API directly (not CLI), no tcpdump required.
    """

    def __init__(self):
        self._verify_installation()

    def _verify_installation(self):
        """Check cicflowmeter is importable."""
        try:
            from cicflowmeter.flow_session import FlowSession  # noqa: F401
            logger.info("[OK] CICFlowMeter Python package available")
        except ImportError:
            raise RuntimeError(
                "cicflowmeter not installed. Run: pip install cicflowmeter"
            )

    def extract_from_pcap(self, pcap_path: str, max_packets: int = 500_000) -> list[dict]:
        """Extract CIC-IDS flow features from a PCAP file.

        Uses the Python API: reads packets with Scapy PcapReader,
        feeds them through FlowSession, and collects flow dicts.

        Memory-safe: periodically garbage-collects completed flows
        and caps total packets to prevent OOM on large captures.

        Args:
            pcap_path: Absolute path to a .pcap/.pcapng file.
            max_packets: Stop after this many packets (default 500K).
                         Set to 0 for no limit (DANGEROUS for large files).

        Returns:
            List of flow event dicts with mapped CIC CSV feature names.
        """
        if not os.path.isfile(pcap_path):
            logger.error(f"PCAP not found: {pcap_path}")
            return []

        try:
            from cicflowmeter.flow_session import FlowSession
            from scapy.utils import PcapReader
        except ImportError as e:
            logger.error(f"Import error: {e}")
            return []

        # Auto-cap based on file size to prevent OOM.
        # CICFlowMeter holds ALL active flows in memory with no way to
        # flush mid-stream. We must limit packets aggressively.
        file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
        if max_packets == 500_000:
            if file_size_mb > 500:
                max_packets = 100_000
            elif file_size_mb > 100:
                max_packets = 200_000
            elif file_size_mb > 50:
                max_packets = 300_000
            logger.info(f"PCAP size: {file_size_mb:.0f} MB → CIC cap: {max_packets} packets")

        # Use a temp CSV as the output target
        tmpdir = tempfile.mkdtemp()
        csv_path = os.path.join(tmpdir, "flows.csv")

        # FlowSession uses class-level attributes set via setattr
        setattr(FlowSession, "output_mode", "csv")
        setattr(FlowSession, "output", csv_path)
        setattr(FlowSession, "fields", None)
        setattr(FlowSession, "verbose", False)

        try:
            session = FlowSession()
        except Exception as e:
            logger.error(f"Failed to create FlowSession: {e}")
            return []

        # Stream packets through the session
        logger.info(f"CICFlowMeter processing: {pcap_path} (max {max_packets} pkts)")
        try:
            reader = PcapReader(pcap_path)
        except Exception as e:
            logger.error(f"Failed to open PCAP: {e}")
            return []

        GC_INTERVAL = 100_000  # Flush completed flows every 100K packets
        pkt_count = 0
        try:
            for pkt in reader:
                pkt_count += 1
                try:
                    session.on_packet_received(pkt)
                except Exception:
                    pass  # Skip malformed packets

                # Periodic garbage collection to prevent OOM
                if pkt_count % GC_INTERVAL == 0:
                    logger.info(f"  CIC: {pkt_count} packets, flushing expired flows...")
                    try:
                        # garbage_collect(None) flushes ALL expired flows to CSV
                        session.garbage_collect(None)
                    except Exception:
                        pass

                if pkt_count % 50000 == 0:
                    logger.info(f"  CIC: {pkt_count} packets processed...")

                if max_packets and pkt_count >= max_packets:
                    logger.info(f"  CIC: Reached packet cap ({max_packets}), stopping")
                    break
        except Exception as e:
            logger.warning(f"CIC packet processing stopped: {e}")
        finally:
            if hasattr(reader, 'close'):
                reader.close()

        # Flush all remaining flows via toPacketList()
        try:
            session.toPacketList()
        except Exception:
            pass

        logger.info(f"CIC: Processed {pkt_count} packets, reading CSV...")

        # Parse the CSV output
        events = self._csv_to_events(csv_path)

        # Cleanup
        try:
            os.remove(csv_path)
            os.rmdir(tmpdir)
        except Exception:
            pass

        return events

    def _csv_to_events(self, csv_path: str) -> list[dict]:
        """Parse CICFlowMeter CSV output into flow event dicts.

        Uses chunked CSV reading to avoid loading millions of rows at once.
        Applies CIC_NAME_MAP to convert snake_case feature names
        to the CIC CSV format expected by the DDoS/PortScan models.
        """
        if not os.path.isfile(csv_path):
            logger.warning("CICFlowMeter CSV not created")
            return []

        events = []
        MAX_EVENTS = 50_000  # Cap events to prevent downstream OOM

        try:
            for chunk in pd.read_csv(csv_path, chunksize=10_000):
                # Normalize column names (strip whitespace)
                chunk.columns = [c.strip() for c in chunk.columns]

                for _, row in chunk.iterrows():
                    if len(events) >= MAX_EVENTS:
                        break
                    try:
                        src_ip = str(row.get("src_ip", "0.0.0.0"))
                        dst_ip = str(row.get("dst_ip", "0.0.0.0"))
                        src_port = int(row.get("src_port", 0))
                        dst_port = int(row.get("dst_port", 0))
                        protocol = int(row.get("protocol", 6))

                        # Build feature dict with mapped names
                        features = {"Protocol": protocol}
                        for col in chunk.columns:
                            if col in _META_COLS:
                                continue
                            val = row[col]
                            try:
                                val = float(val)
                                if val != val or val == float("inf") or val == float("-inf"):
                                    val = 0.0
                            except (ValueError, TypeError):
                                continue

                            # Map to CIC CSV name if known, otherwise keep original
                            mapped_name = CIC_NAME_MAP.get(col, col)
                            features[mapped_name] = val

                        # FIX: the flow's start time was dropped with the
                        # other metadata columns, so every CIC event reached the
                        # analyzer with no timestamp: port-scan windows, the
                        # DDoS rate window and alert times all saw 0.
                        start = _parse_cic_timestamp(row.get("timestamp"))
                        dur_us = features.get("Flow Duration", 0.0) or 0.0
                        events.append({
                            "type": "flow",
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "source_port": src_port,
                            "dest_port": dst_port,
                            "protocol": protocol,
                            "timestamp": start,
                            "last_seen": (start + dur_us / 1e6) if start is not None else None,
                            "features": features,
                            "extractor": "cicflowmeter",
                        })
                    except Exception as e:
                        logger.debug(f"Skipping CIC row: {e}")
                        continue

                if len(events) >= MAX_EVENTS:
                    logger.info(f"CIC: Reached event cap ({MAX_EVENTS}), stopping CSV parse")
                    break

        except Exception as e:
            logger.error(f"Failed to read CICFlowMeter CSV: {e}")
            return events  # Return whatever we got

        logger.info(f"CICFlowMeter extracted {len(events)} flows")
        return events
