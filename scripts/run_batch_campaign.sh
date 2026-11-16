#!/usr/bin/env bash
# ==============================================================================
# run_batch_campaign.sh: Scale up the 11-class modern encrypted dataset
# ==============================================================================
# Usage:
#   ./scripts/run_batch_campaign.sh [runs_per_cell] [duration_seconds]
#
# Defaults: 5 runs per cell x 11 classes x 2 network envs = 110 captures.
# ==============================================================================

set -uo pipefail

RUNS_PER_CELL=${1:-5}
DURATION=${2:-25}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

CLASSES="HTTPS DoT SSH-shell SCP SFTP SSH-localForward SSH-remoteForward SSH-x11 FTPS TLS-Telnet Encrypted-P2P"
NETS="wifi_home mobile_hotspot"

echo "===================================================================="
echo "  BATCH CAPTURE CAMPAIGN (11 MODERN ENCRYPTED PROTOCOL CLASSES)"
echo "  Target: ${RUNS_PER_CELL} pcaps per (class x network) cell"
echo "  Duration per capture: ${DURATION}s"
echo "===================================================================="

for CLASS_NAME in $CLASSES; do
    for NET_ENV in $NETS; do
        existing=$(ls "datasets/raw/${CLASS_NAME}"/*"${NET_ENV}"*.pcap 2>/dev/null | wc -l | tr -d ' ')
        needed=$((RUNS_PER_CELL - existing))
        echo ""
        echo "[${CLASS_NAME}/${NET_ENV}] existing: ${existing}, to capture: ${needed}"
        for ((i = 1; i <= needed; i++)); do
            RUN_ID=$((existing + i))
            echo "  -> capture ${CLASS_NAME} ${NET_ENV} run${RUN_ID}"
            ./scripts/run_container_experiment.sh "$CLASS_NAME" "$NET_ENV" "$RUN_ID" "$DURATION"
        done
    done
done

echo ""
echo "[*] Re-extracting features from all pcaps..."
.venv/bin/python src/extract_features.py

echo "[*] Done. Row count:"
wc -l datasets/processed/traffic_features.csv
