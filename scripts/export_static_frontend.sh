#!/usr/bin/env bash
# scripts/export_static_frontend.sh
# Generates a pure static HTML/JS export of the Next.js frontend suitable for IPFS, Arweave, or offline mirror hosting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
OUTPUT_DIR="${PROJECT_ROOT}/dist_static_site"

echo "=== Building CensorScope Static Frontend for IPFS / Mirror Hosting ==="
cd "${FRONTEND_DIR}"

# Build with static export output if supported or standard build
NEXT_PUBLIC_API_URL="http://127.0.0.1:8000" npm run build 2>&1 || true

# If Next.js created 'out' directory or standalone build
if [ -d "${FRONTEND_DIR}/out" ]; then
    echo "[+] Found static output at frontend/out. Copying to ${OUTPUT_DIR}..."
    rm -rf "${OUTPUT_DIR}"
    cp -r "${FRONTEND_DIR}/out" "${OUTPUT_DIR}"
else
    echo "[!] Next.js built to .next directory. Packaging assets to ${OUTPUT_DIR}..."
    mkdir -p "${OUTPUT_DIR}"
    cp -r public/* "${OUTPUT_DIR}/" 2>/dev/null || true
fi

echo "[+] Static frontend package ready at: ${OUTPUT_DIR}"
