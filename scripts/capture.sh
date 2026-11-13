#!/usr/bin/env bash
# ==============================================================================
# capture.sh: Controlled Traffic Capture Script for macOS Sequoia
# Usage:
#   ./scripts/capture.sh <class_name> <network_env> <run_number> [duration_seconds]
#
# Examples:
#   ./scripts/capture.sh streaming wifi_home 1 60
#   ./scripts/capture.sh video_call mobile_hotspot 2 60
#   ./scripts/capture.sh file_download wifi_home 1 45
#   ./scripts/capture.sh browsing wifi_home 1 60
# ==============================================================================

set -euo pipefail

CLASS_NAME=${1:-""}
NET_ENV=${2:-""}
RUN_ID=${3:-""}
DURATION=${4:-60}
INTERFACE="en0"

VALID_CLASSES="streaming video_call file_download browsing"

if [[ -z "$CLASS_NAME" || -z "$NET_ENV" || -z "$RUN_ID" ]]; then
    echo "Usage: $0 <class_name> <network_env> <run_id> [duration_seconds]"
    echo "  <class_name>:  streaming | video_call | file_download | browsing"
    echo "  <network_env>: wifi_home | mobile_hotspot"
    echo "  <run_id>:      1, 2, 3, etc."
    echo "  [duration]:    Duration in seconds (default: 60)"
    exit 1
fi

# Check if class is valid
if [[ ! " $VALID_CLASSES " =~ " $CLASS_NAME " ]]; then
    echo "[!] Error: Invalid class '$CLASS_NAME'. Must be one of: $VALID_CLASSES"
    exit 1
fi

OUTPUT_DIR="datasets/raw/${CLASS_NAME}"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="${CLASS_NAME}_${NET_ENV}_run${RUN_ID}_${TIMESTAMP}.pcap"
FILEPATH="${OUTPUT_DIR}/${FILENAME}"

echo "=========================================================="
echo " [!] PRE-CAPTURE CHECKLIST:"
echo " 1. Close all unnecessary browser tabs, Discord, Slack, Steam."
echo " 2. Pause iCloud syncing (System Settings > Apple ID > iCloud Drive)."
echo " 3. Verify active network: $NET_ENV on $INTERFACE"
echo " 4. Target Class: $CLASS_NAME | Run: #$RUN_ID | Duration: ${DURATION}s"
echo " 5. File will be saved to: $FILEPATH"
echo "=========================================================="

# 3-second countdown
for i in 3 2 1; do
    echo -ne "Capture starting in $i seconds... (get your application activity ready)\r"
    sleep 1
done
echo -e "\n[*] >>> CAPTURE STARTED! Start user action now... <<<"

# Capture filter explanation:
# We filter out ARP, STP, mDNS (port 5353), SSDP (port 1900), LLMNR (port 5355), NetBIOS (137-138)
# to keep traces focused on IP application traffic (TCP/UDP).
BPF_FILTER="ip and not (udp port 5353 or udp port 1900 or udp port 5355 or udp port 137 or udp port 138 or port 53)"

# Execute tcpdump with timeout
sudo tcpdump -i "$INTERFACE" \
    -s 0 \
    -w "$FILEPATH" \
    -G "$DURATION" \
    -W 1 \
    "$BPF_FILTER"

echo ""
echo "[*] >>> CAPTURE COMPLETED! <<<"
echo "[*] Saved file: $FILEPATH"
FILE_SIZE=$(ls -lh "$FILEPATH" | awk '{print $5}')
echo "[*] File size: $FILE_SIZE"

# Log entry into metadata/experiment_log.csv
LOG_FILE="metadata/experiment_log.csv"
if [[ ! -f "$LOG_FILE" ]]; then
    echo "timestamp,class_name,network_env,run_id,duration_seconds,file_name,file_size" > "$LOG_FILE"
fi
echo "$TIMESTAMP,$CLASS_NAME,$NET_ENV,$RUN_ID,$DURATION,$FILENAME,$FILE_SIZE" >> "$LOG_FILE"
echo "[*] Recorded run in $LOG_FILE"
