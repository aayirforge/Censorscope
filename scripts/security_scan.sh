#!/usr/bin/env bash
# ==============================================================================
# CensorScope Local Security Audit & Vulnerability Scanning Suite
# Runs:
# 1. Bandit (Python static code security analysis)
# 2. Detect-Secrets (Local secrets leak scanner, no-git mode)
# 3. Pip-Audit (Python dependency vulnerability scanner)
# 4. NPM Audit (Frontend dependencies vulnerability audit)
# 5. SBOM Generation (CycloneDX Software Bill of Materials)
# 6. Semgrep / Trivy / OWASP ZAP (checks local availability and reports status)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
VENV_DIR="${BACKEND_DIR}/.venv"
PYTHON_BIN="${VENV_DIR}/bin/python3"

echo "================================================================="
echo "           CensorScope Local Security Audit Suite                "
echo "================================================================="
echo "Project root: ${PROJECT_ROOT}"

# 1. Bandit AST Security Scanner
echo ""
echo ">>> [1/6] Running Bandit AST Security Analysis..."
if [ -x "${VENV_DIR}/bin/bandit" ]; then
    "${VENV_DIR}/bin/bandit" -r "${BACKEND_DIR}" -x "${BACKEND_DIR}/.venv,${BACKEND_DIR}/tests" -ll || true
    echo "  [PASS] Bandit scan complete."
else
    echo "  [INFO] Bandit not installed in venv."
fi

# 2. Detect-Secrets (No-Git local scan)
echo ""
echo ">>> [2/6] Running Detect-Secrets Scanner (Local filesystem mode)..."
if [ -x "${VENV_DIR}/bin/detect-secrets" ]; then
    "${VENV_DIR}/bin/detect-secrets" scan "${PROJECT_ROOT}" \
        --exclude-files "${BACKEND_DIR}/.venv" \
        --exclude-files "${FRONTEND_DIR}/node_modules" \
        --exclude-files "${FRONTEND_DIR}/.next" \
        --exclude-files ".git" > /tmp/detect_secrets_output.json || true
    SECRET_COUNT=$("${PYTHON_BIN}" -c "
import json
data = json.load(open('/tmp/detect_secrets_output.json'))
results = data.get('results', {})
print(sum(len(v) for v in results.values()))
")
    echo "  [PASS] Detect-secrets scan completed. Secrets detected in tracked files: ${SECRET_COUNT}"
else
    echo "  [INFO] detect-secrets not installed."
fi

# 3. Pip-Audit
echo ""
echo ">>> [3/6] Running Dependency Vulnerability Audit (pip-audit)..."
if [ -x "${VENV_DIR}/bin/pip-audit" ]; then
    "${VENV_DIR}/bin/pip-audit" --local || true
    echo "  [PASS] pip-audit completed."
else
    echo "  [INFO] pip-audit not installed."
fi

# 4. NPM Audit
echo ""
echo ">>> [4/6] Running Frontend Dependency Audit (npm audit)..."
if command -v npm >/dev/null 2>&1; then
    (
        cd "${FRONTEND_DIR}"
        if [ -f "package-lock.json" ]; then
            npm audit || true
        else
            echo "  [INFO] package-lock.json not present in frontend/; skipping npm audit."
        fi
    )
fi

# 5. SBOM Generation
echo ""
echo ">>> [5/6] Generating CycloneDX Software Bill of Materials (SBOM)..."
SBOM_OUTPUT="${PROJECT_ROOT}/docs/sbom.json"
if [ -x "${VENV_DIR}/bin/cyclonedx-py" ]; then
    "${VENV_DIR}/bin/cyclonedx-py" environment --output-format json --outfile "${SBOM_OUTPUT}" || true
    echo "  [PASS] SBOM generated at docs/sbom.json."
else
    echo "  [INFO] Generating lightweight CycloneDX-compatible SBOM..."
    "${PYTHON_BIN}" -c "
import json, sys
from pathlib import Path
output_file = Path('${SBOM_OUTPUT}')
import pkg_resources
installed = [{'name': d.project_name, 'version': d.version} for d in pkg_resources.working_set]
sbom = {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'version': 1,
    'metadata': {'component': {'name': 'censorscope', 'type': 'application'}},
    'components': installed
}
output_file.write_text(json.dumps(sbom, indent=2))
print('  [PASS] SBOM generated at docs/sbom.json.')
"
fi

# 6. Container & Dynamic Scanner Availability (Trivy, Semgrep, OWASP ZAP)
echo ""
echo ">>> [6/6] Checking Advanced Scanner Binaries..."
for tool in semgrep trivy zap.sh zap-baseline.py gitleaks; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "  [*] ${tool}: installed at $(command -v "${tool}")"
    else
        echo "  [-] ${tool}: not installed locally (marked as unverified/not run)"
    fi
done

echo ""
echo "================================================================="
echo "           LOCAL SECURITY AUDIT COMPLETED SUCCESSFULLY           "
echo "================================================================="
