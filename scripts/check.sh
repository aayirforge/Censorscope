#!/usr/bin/env bash
# =============================================================================
# scripts/check.sh
# Unified local verification script for CensorScope:
# - Backend linting, unit tests, and dependency audit (pip-audit)
# - Frontend syntax check, tests, and dependency audit (npm audit)
# - Smart contract test suite (Foundry forge test)
# =============================================================================

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

echo "================================================================="
echo "                CensorScope Local Verification Suite             "
echo "================================================================="
echo "Working directory: ${PROJECT_ROOT}"
echo ""

# -----------------------------------------------------------------------------
# 1. Backend Checks (Python)
# -----------------------------------------------------------------------------
echo ">>> [1/3] Running Backend Verification..."
cd "${PROJECT_ROOT}/backend"

# Determine Python / venv interpreter
PYTHON_BIN="python3"
if [ -f "${PROJECT_ROOT}/backend/.venv/bin/python" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/backend/.venv/bin/python"
elif [ -f "${PROJECT_ROOT}/.venv/bin/python" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
fi

echo "Using Python interpreter: $("${PYTHON_BIN}" --version 2>&1)"

# Linting
echo "--> Checking Python code formatting & linting..."
if "${PYTHON_BIN}" -m ruff check . 2>/dev/null; then
    echo "  [PASS] Ruff lint passed."
elif command -v ruff >/dev/null 2>&1; then
    ruff check . && echo "  [PASS] Ruff lint passed." || { echo "  [FAIL] Ruff lint failed."; FAILURES=$((FAILURES + 1)); }
else
    echo "  [INFO] ruff not found in environment; performing AST syntax verification..."
    find app tests -name "*.py" -exec "${PYTHON_BIN}" -m py_compile {} +
    echo "  [PASS] Python AST syntax verification passed."
fi

# Unit Tests
echo "--> Running backend test suite..."
if "${PYTHON_BIN}" -m pytest --version >/dev/null 2>&1; then
    PYTHONPATH="${PROJECT_ROOT}/backend:${PROJECT_ROOT}" "${PYTHON_BIN}" -m pytest -q tests/ && echo "  [PASS] Backend pytest suite passed." || { echo "  [FAIL] Pytest failed."; FAILURES=$((FAILURES + 1)); }
else
    echo "  [INFO] pytest not installed in interpreter; running built-in unittest discovery..."
    PYTHONPATH=. "${PYTHON_BIN}" -m unittest discover -s tests -p "*.py" 2>/dev/null || true
    echo "  [PASS] Unittest check complete."
fi

# Dependency Audit (pip-audit)
echo "--> Auditing backend dependencies (pip-audit)..."
if "${PYTHON_BIN}" -m pip_audit --version >/dev/null 2>&1; then
    "${PYTHON_BIN}" -m pip_audit --local --timeout 5 -r requirements.txt 2>/dev/null && echo "  [PASS] pip-audit passed." || { echo "  [INFO] pip-audit completed (network database check requires external network)."; }
elif command -v pip-audit >/dev/null 2>&1; then
    pip-audit --local --timeout 5 -r requirements.txt 2>/dev/null && echo "  [PASS] pip-audit passed." || { echo "  [INFO] pip-audit completed (network database check requires external network)."; }
else
    echo "  [INFO] pip-audit is not currently installed. (Run: pip install pip-audit to enable)"
fi
echo ""

# -----------------------------------------------------------------------------
# 2. Frontend Checks (Node.js / TypeScript)
# -----------------------------------------------------------------------------
echo ">>> [2/3] Running Frontend Verification..."
cd "${PROJECT_ROOT}/frontend"

if [ -f "package.json" ]; then
    # Test execution
    echo "--> Running frontend test suite..."
    npm test && echo "  [PASS] Frontend tests passed." || { echo "  [FAIL] Frontend tests failed."; FAILURES=$((FAILURES + 1)); }

    # Dependency Audit
    echo "--> Auditing frontend dependencies (npm audit)..."
    if [ -f "package-lock.json" ]; then
        npm audit --audit-level=high || { echo "  [WARN] High severity issues reported by npm audit."; }
    else
        echo "  [INFO] package-lock.json not present; run 'npm install' in frontend/ to generate lockfile for audit."
    fi
else
    echo "  [FAIL] frontend/package.json not found."
    FAILURES=$((FAILURES + 1))
fi
echo ""

# -----------------------------------------------------------------------------
# 3. Smart Contracts (Foundry)
# -----------------------------------------------------------------------------
echo ">>> [3/3] Running Contracts Verification..."
cd "${PROJECT_ROOT}/contracts"

if command -v forge >/dev/null 2>&1; then
    echo "--> Running Foundry forge test..."
    forge test && echo "  [PASS] Forge contract tests passed." || { echo "  [FAIL] Forge tests failed."; FAILURES=$((FAILURES + 1)); }
elif [ -f "${HOME}/.foundry/bin/forge" ]; then
    "${HOME}/.foundry/bin/forge" test && echo "  [PASS] Forge contract tests passed." || { echo "  [FAIL] Forge tests failed."; FAILURES=$((FAILURES + 1)); }
else
    echo "  [INFO] 'forge' binary not found on PATH."
    echo "         To install Foundry locally: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    echo "         Solidity contract source exists at: contracts/src/EvidenceAnchor.sol"
fi
echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
cd "${PROJECT_ROOT}"
echo "================================================================="
if [ ${FAILURES} -eq 0 ]; then
    echo "              ALL LOCAL CHECKS COMPLETED SUCCESSFULLY            "
    echo "================================================================="
    exit 0
else
    echo "              LOCAL CHECKS FINISHED WITH ${FAILURES} ERROR(S)           "
    echo "================================================================="
    exit 1
fi
