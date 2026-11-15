#!/usr/bin/env bash
# ==============================================================================
# run_batch_campaign.sh: Scale up the dataset NIMS-style (one row per flow,
# many flows per session, many sessions per class).
#
# Runs the fully automated container testbed in a loop until the requested
# number of pcaps per (class, network_env) cell exists, then re-extracts
# features into datasets/processed/traffic_features.csv.
#
# Usage:
#   ./scripts/run_batch_campaign.sh [runs_per_cell] [duration_seconds]
#
# Defaults: 10 runs per cell x 4 classes x 2 network envs = 80 captures.
# Each run yields roughly 3-15 flows (browsing) up to 60+ (streaming/download,
# thanks to 200-packet chunking), i.e. hundreds-to-thousands of feature rows.
# ==============================================================================

set -uo pipefail

RUNS_PER_CELL=${1:-10}
DURATION=${2:-30}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

CLASSES="streaming remote_access file_download browsing"
NETS="wifi_home mobile_hotspot"

echo "===================================================================="
echo "  BATCH CAPTURE CAMPAIGN"
echo "  Target: ${RUNS_PER_CELL} pcaps per (class x network) cell"
echo "  Duration per capture: ${DURATION}s"
echo "  Estimated wall time: ~$((RUNS_PER_CELL * 4 * 2 * (DURATION + 30)))s"
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
