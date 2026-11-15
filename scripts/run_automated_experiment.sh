#!/usr/bin/env bash
# ==============================================================================
# run_automated_experiment.sh: Research-Grade Automated Capture Runner
# ==============================================================================

set -uo pipefail

CLASS_NAME=${1:-""}
NET_ENV=${2:-""}
RUN_ID=${3:-""}
DURATION=${4:-60}
INTERFACE="en0"

VALID_CLASSES="streaming remote_access file_download browsing"

if [[ -z "$CLASS_NAME" || -z "$NET_ENV" || -z "$RUN_ID" ]]; then
    echo "Usage: $0 <class_name> <network_env> <run_id> [duration_seconds]"
    echo "  <class_name>:  streaming | remote_access | file_download | browsing"
    echo "  <network_env>: wifi_home | mobile_hotspot"
    echo "  <run_id>:      1, 2, 3, etc."
    echo "  [duration]:    Duration in seconds (default: 60)"
    exit 1
fi

if [[ ! " $VALID_CLASSES " =~ " $CLASS_NAME " ]]; then
    echo "[!] Error: Invalid class '$CLASS_NAME'. Must be one of: $VALID_CLASSES"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

OUTPUT_DIR="datasets/raw/${CLASS_NAME}"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="${CLASS_NAME}_${NET_ENV}_run${RUN_ID}_${TIMESTAMP}.pcap"
FILEPATH="${OUTPUT_DIR}/${FILENAME}"

echo "===================================================================="
echo "  RESEARCH TESTBED AUTOMATION CONTROLLER"
echo "===================================================================="
echo " Target Class : $CLASS_NAME"
echo " Network Env  : $NET_ENV"
echo " Run Number   : #$RUN_ID"
echo " Duration     : ${DURATION}s"
echo " Output File  : $FILEPATH"
echo "===================================================================="

# Step 1: Pre-authenticate sudo in foreground
echo "[*] Step 1/3: Authenticating administrator privileges..."
sudo -v

# Keep sudo credentials alive in background while script runs
( while true; do sudo -n true; sleep 40; kill -0 "$$" 2>/dev/null || exit; done ) &
SUDO_KEEPALIVE_PID=$!

# BPF filter: capture IP, drop broadcast/multicast and DNS noise
BPF_FILTER="ip and not (udp port 5353 or udp port 1900 or udp port 5355 or udp port 137 or udp port 138 or port 53)"

echo "[*] Step 2/3: Starting packet sniffer on $INTERFACE..."
# Use -G and -W 1 so tcpdump will automatically self-terminate if anything ever hangs
AUTO_TIMEOUT=$((DURATION + 5))
sudo tcpdump -i "$INTERFACE" -s 128 -G "$AUTO_TIMEOUT" -W 1 -w "$FILEPATH" "$BPF_FILTER" > /dev/null 2>&1 &

cleanup() {
    echo -e "\n[!] Stopping capture..."
    sudo pkill -2 -f "$FILENAME" 2>/dev/null || true
    kill -9 "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    exit 1
}
trap cleanup SIGINT SIGTERM

# Give tcpdump a moment to bind
sleep 1.0

echo "[*] Step 3/3: Sniffer active. Launching Playwright Persona..."
echo "--------------------------------------------------------------------"

# Run the Playwright persona
.venv/bin/python scripts/testbed_runner.py --class-name "$CLASS_NAME" --duration "$DURATION"

echo "--------------------------------------------------------------------"
echo "[*] Persona execution finished. Finalizing packet trace..."

# Gracefully terminate tcpdump by file pattern
sudo pkill -2 -f "$FILENAME" 2>/dev/null || true
sleep 1.0
sudo pkill -9 -f "$FILENAME" 2>/dev/null || true
kill -9 "$SUDO_KEEPALIVE_PID" 2>/dev/null || true

if [[ -f "$FILEPATH" ]]; then
    FILE_SIZE=$(ls -lh "$FILEPATH" | awk '{print $5}')
    echo "[+] SUCCESS: PCAP saved -> $FILEPATH ($FILE_SIZE)"

    # Record in experiment log
    LOG_FILE="metadata/experiment_log.csv"
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "timestamp,class_name,network_env,run_id,duration_seconds,file_name,file_size" > "$LOG_FILE"
    fi
    echo "$TIMESTAMP,$CLASS_NAME,$NET_ENV,$RUN_ID,$DURATION,$FILENAME,$FILE_SIZE" >> "$LOG_FILE"
    echo "[+] Recorded run in $LOG_FILE"
    echo "===================================================================="
    echo "  RUN #$RUN_ID COMPLETED SUCCESSFULLY!"
    echo "===================================================================="
else
    echo "[-] Error: Capture file was not generated."
fi
