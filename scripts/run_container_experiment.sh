#!/usr/bin/env bash
# ==============================================================================
# run_container_experiment.sh: Automated Encrypted Protocol Research Testbed
# ==============================================================================
# Usage:
#   ./scripts/run_container_experiment.sh <class_name> <network_env> <run_id> [duration_seconds]
#
# Supported Modern Encrypted Classes (Option B):
#   HTTPS | DoT | SSH-shell | SCP | SFTP | SSH-localForward |
#   SSH-remoteForward | SSH-x11 | FTPS | TLS-Telnet | Encrypted-P2P
# ==============================================================================

set -euo pipefail

CLASS_NAME=${1:-""}
NET_ENV=${2:-""}
RUN_ID=${3:-""}
DURATION=${4:-30}

VALID_CLASSES="HTTPS DoT SSH-shell SCP SFTP SSH-localForward SSH-remoteForward SSH-x11 FTPS TLS-Telnet Encrypted-P2P"
VALID_NETS="wifi_home mobile_hotspot"

if [[ -z "$CLASS_NAME" || -z "$NET_ENV" || -z "$RUN_ID" ]]; then
    echo "Usage: $0 <class_name> <network_env> <run_id> [duration_seconds]"
    echo "  <class_name>:  $VALID_CLASSES"
    echo "  <network_env>: wifi_home | mobile_hotspot"
    echo "  <run_id>:      1, 2, 3, etc."
    echo "  [duration]:    Duration in seconds (default: 30)"
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
TARGET_IMAGE="traffic-target:latest"
NET_NAME="testbed-net"

# 1. Create Docker bridge network if not exists
if ! docker network inspect "$NET_NAME" > /dev/null 2>&1; then
    docker network create "$NET_NAME" > /dev/null
fi

# 2. Build multi-service target image if not built
if ! docker image inspect "$TARGET_IMAGE" > /dev/null 2>&1; then
    echo "[*] Building multi-protocol encrypted target server image ($TARGET_IMAGE)..."
    docker build -t "$TARGET_IMAGE" -f Dockerfile.ssh_target .
fi

# 3. Ensure target server container is running
TARGET_CONTAINER="research-target-server"
if ! docker ps --format '{{.Names}}' | grep -q "^${TARGET_CONTAINER}$"; then
    docker rm -f "$TARGET_CONTAINER" 2>/dev/null || true
    echo "[*] Launching research target server container on $NET_NAME..."
    docker run -d --rm \
        --name "$TARGET_CONTAINER" \
        --network "$NET_NAME" \
        "$TARGET_IMAGE" > /dev/null
    sleep 2
fi

# 4. Build testbed runner image if needed
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "[*] Building testbed image ($IMAGE_NAME)..."
    docker build -t "$IMAGE_NAME" -f Dockerfile.testbed .
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FILENAME="${CLASS_NAME}_${NET_ENV}_run${RUN_ID}_${TIMESTAMP}.pcap"
CONTAINER_PCAP="/testbed/datasets/raw/${CLASS_NAME}/${FILENAME}"
HOST_PCAP="datasets/raw/${CLASS_NAME}/${FILENAME}"

mkdir -p "datasets/raw/${CLASS_NAME}"

echo "===================================================================="
echo "  RESEARCH TESTBED: ENCRYPTED PROTOCOL CAPTURE"
echo "===================================================================="
echo " Target Class      : $CLASS_NAME"
echo " Virtual Network   : $NET_ENV (emulated via Linux tc-netem on eth0)"
echo " Run Identifier    : #$RUN_ID"
echo " Duration          : ${DURATION}s"
echo " Output Destination: $HOST_PCAP"
echo "===================================================================="

docker run --rm \
    --network "$NET_NAME" \
    --cap-add=NET_ADMIN \
    --dns 8.8.8.8 \
    --dns 1.1.1.1 \
    -v "$PROJECT_DIR/datasets:/testbed/datasets" \
    -v "$PROJECT_DIR/scripts/testbed_runner.py:/testbed/scripts/testbed_runner.py:ro" \
    -e REMOTE_ACCESS_HOST="$TARGET_CONTAINER" \
    -e REMOTE_ACCESS_PORT=22 \
    -e REMOTE_ACCESS_USER=research \
    -e REMOTE_ACCESS_PASSWORD=research \
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
        mkdir -p metadata
        echo "timestamp,class_name,network_env,run_id,duration_seconds,file_name,file_size" > "$LOG_FILE"
    fi
    echo "$TIMESTAMP,$CLASS_NAME,$NET_ENV,$RUN_ID,$DURATION,$FILENAME,$FILE_SIZE" >> "$LOG_FILE"
    echo "[+] Logged run in $LOG_FILE"
else
    echo "[-] Error: PCAP trace was not found at $HOST_PCAP"
    exit 1
fi
