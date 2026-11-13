#!/usr/bin/env bash
# ==============================================================================
# run_container_experiment.sh: Fully Automated Research Testbed Launcher
# ==============================================================================
# ZERO manual Wi-Fi toggling. ZERO host OS noise. ZERO sudo on your Mac.
#
# Usage:
#   ./scripts/run_container_experiment.sh <class_name> <network_env> <run_id> [duration_seconds]
#
# Examples:
#   ./scripts/run_container_experiment.sh streaming wifi_home 1 45
#   ./scripts/run_container_experiment.sh streaming mobile_hotspot 1 45
#   ./scripts/run_container_experiment.sh video_call mobile_hotspot 1 45
#   ./scripts/run_container_experiment.sh browsing wifi_home 1 30
# ==============================================================================

set -euo pipefail

CLASS_NAME=${1:-""}
NET_ENV=${2:-""}
RUN_ID=${3:-""}
DURATION=${4:-45}

VALID_CLASSES="streaming video_call file_download browsing"
VALID_NETS="wifi_home mobile_hotspot"

if [[ -z "$CLASS_NAME" || -z "$NET_ENV" || -z "$RUN_ID" ]]; then
    echo "Usage: $0 <class_name> <network_env> <run_id> [duration_seconds]"
    echo "  <class_name>:  streaming | video_call | file_download | browsing"
    echo "  <network_env>: wifi_home | mobile_hotspot"
    echo "  <run_id>:      1, 2, 3, etc."
    echo "  [duration]:    Duration in seconds (default: 45)"
    exit 1
fi

if [[ ! " $VALID_CLASSES " =~ " $CLASS_NAME " ]]; then
    echo "[!] Error: Invalid class '$CLASS_NAME'. Must be one of: $VALID_CLASSES"
    exit 1
fi

if [[ ! " $VALID_NETS " =~ " $NET_ENV " ]]; then
    echo "[!] Error: Invalid network environment '$NET_ENV'. Must be one of: $VALID_NETS"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

IMAGE_NAME="traffic-testbed:latest"

# 1. Build testbed image if not already built
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "===================================================================="
    echo "[*] Building contained research testbed image ($IMAGE_NAME)..."
    echo "    (This only happens once)"
    echo "===================================================================="
    docker build -t "$IMAGE_NAME" -f Dockerfile.testbed .
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="${CLASS_NAME}_${NET_ENV}_run${RUN_ID}_${TIMESTAMP}.pcap"
CONTAINER_PCAP="/testbed/datasets/raw/${CLASS_NAME}/${FILENAME}"
HOST_PCAP="datasets/raw/${CLASS_NAME}/${FILENAME}"

mkdir -p "datasets/raw/${CLASS_NAME}"

echo "===================================================================="
echo "  RESEARCH TESTBED: FULLY AUTOMATED ISOLATED EXECUTION"
echo "===================================================================="
echo " Target Class      : $CLASS_NAME"
echo " Virtual Network   : $NET_ENV (emulated via Linux tc-netem on eth0)"
echo " Run Identifier    : #$RUN_ID"
echo " Duration          : ${DURATION}s"
echo " Output Destination: $HOST_PCAP"
echo "===================================================================="

# Run container with:
# - --cap-add=NET_ADMIN: allows tc-netem to manipulate virtual eth0
# - Mount project datasets directory
docker run --rm \
    --cap-add=NET_ADMIN \
    -v "$PROJECT_DIR/datasets:/testbed/datasets" \
    -v "$PROJECT_DIR/scripts/testbed_runner.py:/testbed/scripts/testbed_runner.py:ro" \
    "$IMAGE_NAME" \
    --class-name "$CLASS_NAME" \
    --network "$NET_ENV" \
    --duration "$DURATION" \
    --capture-pcap "$CONTAINER_PCAP"

if [[ -f "$HOST_PCAP" ]]; then
    FILE_SIZE=$(ls -lh "$HOST_PCAP" | awk '{print $5}')
    echo "[+] SUCCESS: Contained PCAP written -> $HOST_PCAP ($FILE_SIZE)"

    LOG_FILE="metadata/experiment_log.csv"
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "timestamp,class_name,network_env,run_id,duration_seconds,file_name,file_size" > "$LOG_FILE"
    fi
    echo "$TIMESTAMP,$CLASS_NAME,$NET_ENV,$RUN_ID,$DURATION,$FILENAME,$FILE_SIZE" >> "$LOG_FILE"
    echo "[+] Logged run in $LOG_FILE"
    echo "===================================================================="
    echo "  RUN #$RUN_ID COMPLETED (ZERO MANUAL TOGGLING NEEDED!)"
    echo "===================================================================="
else
    echo "[-] Error: PCAP trace was not found at $HOST_PCAP"
    exit 1
fi
