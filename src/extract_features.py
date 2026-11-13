#!/usr/bin/env python3
"""
extract_features.py - Bidirectional Flow Feature Extraction Pipeline
=============================================================================
Converts raw .pcap traces into bidirectional flows and computes rich statistical
metadata features for encrypted traffic classification ("sealed parcel" paradigm).

Key Principles:
1. Strict Anonymization: Strips all IP addresses, port numbers, and absolute timestamps
   to prevent shortcut learning (memorizing IP subnets or CDN addresses).
2. Directionality: Separates Forward (client-to-server / uplink) and Backward
   (server-to-client / downlink) traffic.
3. Statistical Invariants: Measures packet length distributions, inter-arrival times (IAT),
   duration, and uplink/downlink ratios.
4. Noise Filtering: Excludes non-application artifacts (multicast, ARP, single-packet probes).
=============================================================================
"""

import os
import sys
import glob
import re
import argparse
import numpy as np
import pandas as pd
import dpkt
import socket


def parse_filename_metadata(pcap_path):
    """
    Extracts class_name, network_env, and run_id from standardized file naming:
    e.g. streaming_wifi_home_run1_20261113_120000.pcap
    or fallback to directory structure: datasets/raw/<class>/<file>.pcap
    """
    basename = os.path.basename(pcap_path)
    parent_dir = os.path.basename(os.path.dirname(pcap_path))
    
    # Try regex match on standardized filename
    match = re.match(r"([a-zA-Z0-9_-]+)_(wifi_home|mobile_hotspot|network[12])_run(\d+)", basename)
    if match:
        class_name = match.group(1)
        network_env = match.group(2)
        run_id = int(match.group(3))
        return class_name, network_env, run_id

    # Fallback to directory name and heuristic
    class_name = parent_dir if parent_dir != "raw" else "unknown"
    network_env = "mobile_hotspot" if "hotspot" in basename.lower() else "wifi_home"
    run_match = re.search(r"run(\d+)", basename.lower()) or re.search(r"_(\d+)", basename)
    run_id = int(run_match.group(1)) if run_match else 1
    return class_name, network_env, run_id


def is_local_or_multicast(ip_str):
    """Checks if an IP address is multicast, broadcast, or link-local."""
    if ip_str.startswith("224.") or ip_str.startswith("239.") or ip_str == "255.255.255.255":
        return True
    if ip_str.startswith("fe80:") or ip_str.startswith("ff02:"):
        return True
    return False


def extract_flows_from_pcap(pcap_path, min_packets=5, flow_timeout=120.0):
    """
    Reads a .pcap file using dpkt and groups IP packets into bidirectional flows.
    
    Flow definition: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
    Bidirectional key is canonicalized such that the initiator (first observed packet)
    sets the Forward direction.
    """
    flows = {}  # key -> list of (timestamp, length, direction)
    
    try:
        with open(pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                # In case it is pcapng format
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                # Ensure it is an IP packet (IPv4 or IPv6)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    ip_len = ip.len
                    proto = ip.p
                elif isinstance(ip, dpkt.ip6.IP6):
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    ip_len = ip.plen + 40
                    proto = ip.nxt
                else:
                    continue

                # Filter out multicast / link-local noise
                if is_local_or_multicast(src_ip) or is_local_or_multicast(dst_ip):
                    continue

                # Extract transport layer ports
                src_port = 0
                dst_port = 0
                if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
                elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
                else:
                    # Ignore non-TCP/UDP flows (IGMP, ICMP, etc.)
                    continue

                # Filter out obvious broadcast ports
                if src_port in (5353, 1900, 5355) or dst_port in (5353, 1900, 5355):
                    continue

                # Determine bidirectional canonical flow key
                fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
                bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)

                if fwd_key in flows:
                    flows[fwd_key].append((ts, ip_len, "fwd"))
                elif bwd_key in flows:
                    flows[bwd_key].append((ts, ip_len, "bwd"))
                else:
                    # First packet establishes Forward direction (Client -> Server)
                    flows[fwd_key] = [(ts, ip_len, "fwd")]

    except Exception as e:
        print(f"[-] Error reading {pcap_path}: {e}", file=sys.stderr)
        return []

    # Filter flows by minimum packet count to discard transient scans/aborted handshakes
    valid_flows = []
    for (src_ip, src_port, dst_ip, dst_port, proto), packets in flows.items():
        if len(packets) >= min_packets:
            valid_flows.append((proto, packets))

    return valid_flows


def compute_statistical_features(proto, packets):
    """
    Computes invariant statistical metadata features for a bidirectional flow.
    DOES NOT store IP addresses, ports, or absolute timestamps.
    """
    timestamps = [p[0] for p in packets]
    lengths = [p[1] for p in packets]
    directions = [p[2] for p in packets]

    # Flow Duration
    duration = max(timestamps[-1] - timestamps[0], 0.0)

    # Direction subsets
    fwd_lens = [l for l, d in zip(lengths, directions) if d == "fwd"]
    bwd_lens = [l for l, d in zip(lengths, directions) if d == "bwd"]

    fwd_ts = [t for t, d in zip(timestamps, directions) if d == "fwd"]
    bwd_ts = [t for t, d in zip(timestamps, directions) if d == "bwd"]

    total_pkts = len(packets)
    fwd_pkts = len(fwd_lens)
    bwd_pkts = len(bwd_lens)

    total_bytes = sum(lengths)
    fwd_bytes = sum(fwd_lens)
    bwd_bytes = sum(bwd_lens)

    # Ratios (safe against zero-division)
    pkt_ratio = fwd_pkts / (bwd_pkts + 1)
    byte_ratio = fwd_bytes / (bwd_bytes + 1)
    fwd_pkt_pct = fwd_pkts / total_pkts if total_pkts > 0 else 0.0
    fwd_byte_pct = fwd_bytes / total_bytes if total_bytes > 0 else 0.0

    # Rates
    effective_dur = max(duration, 0.001)
    pkt_rate = total_pkts / effective_dur
    byte_rate = total_bytes / effective_dur

    # Packet Length Summary Stats (Bi-directional)
    pkt_len_min = float(np.min(lengths))
    pkt_len_max = float(np.max(lengths))
    pkt_len_mean = float(np.mean(lengths))
    pkt_len_std = float(np.std(lengths))
    pkt_len_median = float(np.median(lengths))
    pkt_len_q25 = float(np.percentile(lengths, 25))
    pkt_len_q75 = float(np.percentile(lengths, 75))

    # Forward Packet Length Stats
    fwd_len_min = float(np.min(fwd_lens)) if fwd_lens else 0.0
    fwd_len_max = float(np.max(fwd_lens)) if fwd_lens else 0.0
    fwd_len_mean = float(np.mean(fwd_lens)) if fwd_lens else 0.0
    fwd_len_std = float(np.std(fwd_lens)) if fwd_lens else 0.0

    # Backward Packet Length Stats
    bwd_len_min = float(np.min(bwd_lens)) if bwd_lens else 0.0
    bwd_len_max = float(np.max(bwd_lens)) if bwd_lens else 0.0
    bwd_len_mean = float(np.mean(bwd_lens)) if bwd_lens else 0.0
    bwd_len_std = float(np.std(bwd_lens)) if bwd_lens else 0.0

    # Inter-Arrival Times (IAT)
    def calc_iats(ts_list):
        if len(ts_list) < 2:
            return 0.0, 0.0, 0.0, 0.0
        diffs = np.diff(ts_list)
        return float(np.min(diffs)), float(np.max(diffs)), float(np.mean(diffs)), float(np.std(diffs))

    iat_min, iat_max, iat_mean, iat_std = calc_iats(timestamps)
    fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = calc_iats(fwd_ts)
    bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = calc_iats(bwd_ts)

    # Initial Burst Profile (First 5 packet lengths average)
    init_burst_len_mean = float(np.mean(lengths[:min(5, len(lengths))]))

    features = {
        # Protocol Indicator (1 = UDP, 0 = TCP)
        "is_udp": 1 if proto == dpkt.ip.IP_PROTO_UDP else 0,
        # Duration & Rates
        "duration": duration,
        "pkt_rate": pkt_rate,
        "byte_rate": byte_rate,
        # Volumes & Counts
        "tot_packets": total_pkts,
        "fwd_packets": fwd_pkts,
        "bwd_packets": bwd_pkts,
        "tot_bytes": total_bytes,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        # Directional Ratios
        "pkt_ratio": pkt_ratio,
        "byte_ratio": byte_ratio,
        "fwd_pkt_pct": fwd_pkt_pct,
        "fwd_byte_pct": fwd_byte_pct,
        # Overall Packet Length Statistics
        "pkt_len_min": pkt_len_min,
        "pkt_len_max": pkt_len_max,
        "pkt_len_mean": pkt_len_mean,
        "pkt_len_std": pkt_len_std,
        "pkt_len_median": pkt_len_median,
        "pkt_len_q25": pkt_len_q25,
        "pkt_len_q75": pkt_len_q75,
        # Fwd / Bwd Packet Length Statistics
        "fwd_len_min": fwd_len_min,
        "fwd_len_max": fwd_len_max,
        "fwd_len_mean": fwd_len_mean,
        "fwd_len_std": fwd_len_std,
        "bwd_len_min": bwd_len_min,
        "bwd_len_max": bwd_len_max,
        "bwd_len_mean": bwd_len_mean,
        "bwd_len_std": bwd_len_std,
        # Inter-Arrival Times
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "fwd_iat_min": fwd_iat_min,
        "fwd_iat_max": fwd_iat_max,
        "fwd_iat_mean": fwd_iat_mean,
        "fwd_iat_std": fwd_iat_std,
        "bwd_iat_min": bwd_iat_min,
        "bwd_iat_max": bwd_iat_max,
        "bwd_iat_mean": bwd_iat_mean,
        "bwd_iat_std": bwd_iat_std,
        # Handshake / Initial Burst
        "init_burst_len_mean": init_burst_len_mean
    }

    return features


def process_dataset(raw_dir="datasets/raw", output_csv="datasets/processed/traffic_features.csv", min_packets=5):
    """Walks through raw directory, extracts flows, and saves to CSV."""
    pcap_files = glob.glob(f"{raw_dir}/**/*.pcap", recursive=True)
    if not pcap_files:
        print(f"[!] No .pcap files found in {raw_dir}")
        return None

    print(f"[*] Found {len(pcap_files)} .pcap files. Extracting bidirectional flows...")
    all_rows = []

    for idx, pcap_path in enumerate(pcap_files, 1):
        class_name, net_env, run_id = parse_filename_metadata(pcap_path)
        valid_flows = extract_flows_from_pcap(pcap_path, min_packets=min_packets)
        print(f" [{idx}/{len(pcap_files)}] {os.path.basename(pcap_path)} -> Class: {class_name}, Env: {net_env}, Flows: {len(valid_flows)}")

        for proto, packets in valid_flows:
            row = compute_statistical_features(proto, packets)
            # Add metadata labels
            row["class_label"] = class_name
            row["network_env"] = net_env
            row["run_id"] = run_id
            row["source_file"] = os.path.basename(pcap_path)
            all_rows.append(row)

    if not all_rows:
        print("[!] No valid flows met the threshold filter.")
        return None

    df = pd.DataFrame(all_rows)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"\n[+] Successfully saved {len(df)} flow samples to: {output_csv}")
    print("\nClass distribution in extracted dataset:")
    print(df["class_label"].value_counts())
    print("\nNetwork environment distribution:")
    print(df["network_env"].value_counts())
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract bidirectional flow features from pcap files.")
    parser.add_argument("--raw-dir", default="datasets/raw", help="Directory containing raw .pcap traces")
    parser.add_argument("--output", default="datasets/processed/traffic_features.csv", help="Output CSV path")
    parser.add_argument("--min-packets", type=int, default=5, help="Minimum packets per flow to retain")
    args = parser.parse_args()

    process_dataset(raw_dir=args.raw_dir, output_csv=args.output, min_packets=args.min_packets)
