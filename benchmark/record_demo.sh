#!/usr/bin/env bash
# ARGUS Demo Recorder
#
# One-command pipeline:
#   1. Spin up benchmark Docker containers
#   2. Run the cinematic dashboard
#   3. Capture as asciicast
#   4. Render to GIF
#   5. Update the README's embedded asset
#
# Usage:
#   ./benchmark/record_demo.sh           # default settings
#   ./benchmark/record_demo.sh --keep-up # leave containers running after recording
#
# Requirements:
#   - docker compose
#   - asciinema  (brew install asciinema)
#   - agg        (brew install agg)
#   - ARGUS installed in .venv

set -euo pipefail

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

ASSETS_DIR="${PROJECT_ROOT}/benchmark/assets"
CAST_FILE="${ASSETS_DIR}/argus-action.cast"
GIF_FILE="${ASSETS_DIR}/argus-action.gif"
COMPOSE_FILE="${PROJECT_ROOT}/benchmark/docker-compose.yml"

KEEP_UP=0
for arg in "$@"; do
    case "$arg" in
        --keep-up) KEEP_UP=1 ;;
        --help|-h)
            grep '^# ' "$0" | sed 's/^# //'
            exit 0
            ;;
    esac
done

# ----- Preflight -----
log() { echo -e "\033[1;33m[record_demo]\033[0m $*"; }

for tool in docker asciinema agg; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool not found on PATH. Install it first." >&2
        exit 1
    fi
done

if [[ ! -d "${PROJECT_ROOT}/.venv" ]]; then
    echo "ERROR: .venv not found. Run: python -m venv .venv && pip install -e .[dev]" >&2
    exit 1
fi

mkdir -p "${ASSETS_DIR}"

# ----- Step 1: Containers -----
log "Starting benchmark scenarios..."
docker compose -f "${COMPOSE_FILE}" up -d >/dev/null 2>&1

# Wait for containers to be healthy
log "Waiting for endpoints to come up..."
for port in 8001 8002 8003 8004; do
    for i in {1..15}; do
        if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
done

# ----- Step 2: Record asciicast -----
log "Recording cinematic dashboard (this takes ~10s)..."
asciinema rec \
    --overwrite \
    --headless \
    --window-size 130x40 \
    --command ".venv/bin/python ${PROJECT_ROOT}/benchmark/run_cinematic.py" \
    --idle-time-limit 2 \
    "${CAST_FILE}" >/dev/null 2>&1

CAST_SIZE=$(wc -c < "${CAST_FILE}" | tr -d ' ')
log "Recording captured: ${CAST_FILE} (${CAST_SIZE} bytes)"

# ----- Step 3: Render to GIF -----
log "Rendering GIF (this takes ~30-60s)..."
agg \
    --theme monokai \
    --speed 1.5 \
    --font-size 14 \
    --fps-cap 20 \
    "${CAST_FILE}" \
    "${GIF_FILE}" 2>&1 | tail -1

GIF_SIZE=$(wc -c < "${GIF_FILE}" | tr -d ' ')
GIF_SIZE_MB=$(echo "scale=2; ${GIF_SIZE} / 1024 / 1024" | bc)
log "GIF rendered: ${GIF_FILE} (${GIF_SIZE_MB} MB)"

# ----- Step 4: Teardown (optional) -----
if [[ ${KEEP_UP} -eq 0 ]]; then
    log "Stopping benchmark scenarios..."
    docker compose -f "${COMPOSE_FILE}" down >/dev/null 2>&1
else
    log "Leaving containers running (--keep-up)"
fi

# ----- Step 5: Summary -----
echo
log "Done."
echo
echo "  Asset:    ${GIF_FILE}"
echo "  Size:     ${GIF_SIZE_MB} MB"
echo
echo "  To preview:"
echo "    open ${GIF_FILE}"
echo
echo "  To publish:"
echo "    git add benchmark/assets/argus-action.gif benchmark/assets/argus-action.cast"
echo "    git commit -m 'demo: refresh ARGUS action GIF'"
echo "    git push"
echo
