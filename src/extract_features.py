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


def extract_flows_from_pcap(pcap_path, min_packets=5, flow_timeout=120.0, chunk_size=200):
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

    # Segment each 5-tuple session into analysis flows:
    # - Split on idle gaps > flow_timeout (the previously dead parameter; NIMS-style
    #   flow expiry, e.g. 120s idle means the session continues in a new TCP connection)
    # - Chunk long-lived flows every chunk_size packets so a 20k-packet stream yields
    #   many independent samples instead of one giant row
    valid_flows = []
    for (src_ip, src_port, dst_ip, dst_port, proto), packets in flows.items():
        segments = []
        current = [packets[0]]
        for pkt in packets[1:]:
            if current and pkt[0] - current[-1][0] > flow_timeout:
                segments.append(current)
                current = [pkt]
            else:
                current.append(pkt)
            if len(current) >= chunk_size:
                segments.append(current)
                current = []
        if current:
            segments.append(current)

        for seg in segments:
            if len(seg) >= min_packets:
                valid_flows.append((proto, seg))

    return valid_flows


def compute_statistical_features(proto, packets):
    """
    Computes statistical network traffic features matching the NIMS format.
    Times are measured in microseconds (integer). Packet lengths and counts are integers.
    """
    timestamps = [p[0] for p in packets]
    lengths = [p[1] for p in packets]
    directions = [p[2] for p in packets]

    # Flow Duration in microseconds (int)
    duration_sec = max(timestamps[-1] - timestamps[0], 0.0)
    duration_us = int(round(duration_sec * 1e6))

    # Direction subsets
    fwd_lens = [l for l, d in zip(lengths, directions) if d == "fwd"]
    bwd_lens = [l for l, d in zip(lengths, directions) if d == "bwd"]

    fwd_ts = [t for t, d in zip(timestamps, directions) if d == "fwd"]
    bwd_ts = [t for t, d in zip(timestamps, directions) if d == "bwd"]

    total_fpackets = len(fwd_lens)
    total_bpackets = len(bwd_lens)
    total_fvolume = int(sum(fwd_lens))
    total_bvolume = int(sum(bwd_lens))

    # Forward Packet Length Statistics
    # Forward Packet Length Statistics (0 if 0 packets)
    if fwd_lens:
        min_fpktl = int(np.min(fwd_lens))
        mean_fpktl = int(round(float(np.mean(fwd_lens))))
        max_fpktl = int(np.max(fwd_lens))
        std_fpktl = int(round(float(np.std(fwd_lens))))
    else:
        min_fpktl, mean_fpktl, max_fpktl, std_fpktl = 0, 0, 0, 0

    # Backward Packet Length Statistics (0 if 0 packets)
    if bwd_lens:
        min_bpktl = int(np.min(bwd_lens))
        mean_bpktl = int(round(float(np.mean(bwd_lens))))
        max_bpktl = int(np.max(bwd_lens))
        std_bpktl = int(round(float(np.std(bwd_lens))))
    else:
        min_bpktl, mean_bpktl, max_bpktl, std_bpktl = 0, 0, 0, 0

    # Inter-Arrival Times (IAT) in microseconds (int)
    def calc_iats_us(ts_list):
        if len(ts_list) < 2:
            return 0, 0, 0, 0
        sorted_ts = sorted(ts_list)
        diffs_us = np.maximum(np.diff(sorted_ts) * 1e6, 0.0)
        min_iat = int(round(float(np.min(diffs_us))))
        mean_iat = int(round(float(np.mean(diffs_us))))
        max_iat = int(round(float(np.max(diffs_us))))
        std_iat = int(round(float(np.std(diffs_us))))
        return min_iat, mean_iat, max_iat, std_iat
        return min_iat, mean_iat, max_iat, std_iat

    min_fiat, mean_fiat, max_fiat, std_fiat = calc_iats_us(fwd_ts)
    min_biat, mean_biat, max_biat, std_biat = calc_iats_us(bwd_ts)

    features = {
        "min_fpktl": min_fpktl,
        "mean_fpktl": mean_fpktl,
        "max_fpktl": max_fpktl,
        "std_fpktl": std_fpktl,
        "min_bpktl": min_bpktl,
        "mean_bpktl": mean_bpktl,
        "max_bpktl": max_bpktl,
        "std_bpktl": std_bpktl,
        "min_fiat": min_fiat,
        "mean_fiat": mean_fiat,
        "max_fiat": max_fiat,
        "std_fiat": std_fiat,
        "min_biat": min_biat,
        "mean_biat": mean_biat,
        "max_biat": max_biat,
        "std_biat": std_biat,
        "duration": duration_us,
        "proto": int(proto),
        "total_fpackets": total_fpackets,
        "total_fvolume": total_fvolume,
        "total_bpackets": total_bpackets,
        "total_bvolume": total_bvolume
    }

    return features


def process_dataset(raw_dir="datasets/raw", output_csv="datasets/processed/traffic_features.csv", min_packets=5,
                    flow_timeout=120.0, chunk_size=200):
    """Walks through raw directory, extracts flows, and saves to CSV."""
    pcap_files = glob.glob(f"{raw_dir}/**/*.pcap", recursive=True)
    if not pcap_files:
        print(f"[!] No .pcap files found in {raw_dir}")
        return None

    print(f"[*] Found {len(pcap_files)} .pcap files. Extracting bidirectional flows...")
    all_rows = []
    flow_id = 1

    for idx, pcap_path in enumerate(pcap_files, 1):
        class_name, net_env, run_id = parse_filename_metadata(pcap_path)
        valid_flows = extract_flows_from_pcap(
            pcap_path, min_packets=min_packets, flow_timeout=flow_timeout, chunk_size=chunk_size
        )
        print(f" [{idx}/{len(pcap_files)}] {os.path.basename(pcap_path)} -> Class: {class_name}, Env: {net_env}, Flows: {len(valid_flows)}")

        for proto, packets in valid_flows:
            row = compute_statistical_features(proto, packets)
            row["id"] = flow_id
            row["class"] = class_name
            flow_id += 1
            all_rows.append(row)

    if not all_rows:
        print("[!] No valid flows met the threshold filter.")
        return None

    # Exact column ordering matching NIMS
    nims_columns = [
        "id", "min_fpktl", "mean_fpktl", "max_fpktl", "std_fpktl",
        "min_bpktl", "mean_bpktl", "max_bpktl", "std_bpktl",
        "min_fiat", "mean_fiat", "max_fiat", "std_fiat",
        "min_biat", "mean_biat", "max_biat", "std_biat",
        "duration", "proto", "total_fpackets", "total_fvolume",
        "total_bpackets", "total_bvolume", "class"
    ]

    df = pd.DataFrame(all_rows)[nims_columns]
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"\n[+] Successfully saved {len(df)} flow samples to: {output_csv}")
    print("\nClass distribution in extracted dataset:")
    print(df["class"].value_counts())
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract bidirectional flow features from pcap files.")
    parser.add_argument("--raw-dir", default="datasets/raw", help="Directory containing raw .pcap traces")
    parser.add_argument("--output", default="datasets/processed/traffic_features.csv", help="Output CSV path")
    parser.add_argument("--min-packets", type=int, default=5, help="Minimum packets per flow to retain")
    parser.add_argument("--flow-timeout", type=float, default=120.0, help="Idle gap (s) that splits a session into separate flows")
    parser.add_argument("--chunk-size", type=int, default=200, help="Max packets per flow sample (long flows are chunked into multiple samples)")
    args = parser.parse_args()

    process_dataset(raw_dir=args.raw_dir, output_csv=args.output, min_packets=args.min_packets,
                    flow_timeout=args.flow_timeout, chunk_size=args.chunk_size)
