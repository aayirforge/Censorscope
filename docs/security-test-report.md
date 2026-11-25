# CensorScope Security Testing & Tool Execution Report

**Date**: 2026-11-24  
**Audit Context**: Independent Verification of Security Scanning Tooling

---

## 1. Tool Execution Summary Matrix

| Tool | Target Scope | Execution Environment | Status / Raw Output | Notes / Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **`trivy fs`** | Repository filesystem & secrets | Pinned Binary (`/home/kartik/.local/bin/trivy`) | **PASSED**: 0 secrets found | High fidelity filesystem scan. |
| **`pip-audit`** | Python 3.12.16 dependencies | Virtualenv (`backend/.venv/bin/pip-audit`) | **PASSED**: 0 vulnerabilities found | Audited PyPI packages. |
| **`npm audit`** | Frontend npm dependencies | Host Node.js 20 (`frontend/`) | **PASSED**: 0 vulnerabilities found | Resolved `postcss <=8.5.22` advisory by applying npm `overrides: {"postcss": "^8.5.33"}` without breaking Next.js 15. |
| **`slither`** | Smart contracts (`contracts/`) | Virtualenv (`backend/.venv/bin/slither`) | **PASSED**: 0 High/Critical findings | Reentrancy guard on low-level calls; multi-day coarse timestamp usage. |
| **`forge test`** | Smart contract test suites | Foundry (`bin/forge`) | **PASSED**: 31 passed, 0 failed | Property-based fuzzing (256 runs), reentrancy, monotonic batch IDs, force-send ETH invariants, and slashed pool accounting. |
| **`gitleaks`** | Secret scanning | Docker (`zricethezav/gitleaks:latest`) | **EXECUTED**: 1 finding | Successfully ran against repository. Flagged standard Anvil local development key `0xac09...` in `scripts/demo_evidence.sh` (expected local test fixture). |
| **`OWASP ZAP`** | Web application dynamic baseline | Docker (`ghcr.io/zaproxy/zaproxy:stable`) | **COULD NOT RUN** | Required downloading multi-gigabyte browser/JVM image (>2.5 GB), timing out network downloads. Static and unit test coverage used instead. |
| **`echidna`** | Smart contract property fuzzing | Docker (`trailofbits/echidna:latest`) | **COULD NOT RUN** | Docker image download (>1.8 GB) timed out over connection. Replaced by Foundry built-in property-based fuzz test (`testFuzz_MerkleProofRandom` with 256 runs, and `test_StakeAccounting_UnitAndFuzz`). |

---

## 2. Gitleaks Execution Output

Command run:
```bash
docker run --rm -v "${PWD}":/path zricethezav/gitleaks:latest dir /path --verbose
```

Output:
```
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
Secret:      0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RuleID:      generic-api-key
Entropy:     3.852557
File:        /path/scripts/demo_evidence.sh
Line:        24
Fingerprint: /path/scripts/demo_evidence.sh:generic-api-key:24

scanned ~8454016 bytes (8.45 MB) in 1.16s
leaks found: 1
```

*Auditor Finding*: The single detected leak corresponds to Account #0 from Foundry/Anvil's standard well-known public test mnemonic (`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`). No production secrets, private keys, or API tokens were found.
