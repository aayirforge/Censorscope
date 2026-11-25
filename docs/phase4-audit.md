# Phase 4 Audit Report: Cryptographic Evidence Anchoring & System Isolation

**Date**: 2026-11-24  
**Scope**: Docker fetcher isolation, SSRF mutation coverage, cross-language Merkle verification, Merkle edge cases, browser verification, UI transparency, threat model quorum disclosures, environment dependencies, and cryptographic key auditing.

---

## 1. Docker Fetcher Network Isolation (Enforced vs Documented)

### Isolation Architecture & Enforcement
The measurement probe fetcher (`backend/security/safe_fetch.py`) is designed to run in an isolated Docker container with strictly enforced iptables egress controls:
1. **Public Internet Access**: Outbound connections to external endpoints on port 443/80 are permitted.
2. **Internal Network Block**: Egress to the Docker bridge network (`172.17.0.0/16`), local loopback, PostgreSQL (`port 5435`), Redis (`port 6379`), and the host gateway (`172.17.0.1:22`) are dropped by kernel netfilter rules.

### Verification Run Commands & Actual Output
Inside the containerized fetcher environment (`docker-compose -f docker/docker-compose.fetcher.yml run --rm fetcher-test`):
- **(a) Public Site (`1.1.1.1:443`)**:
  ```bash
  nc -z -w 3 1.1.1.1 443
  # Result: CONNECTED (Exit code 0)
  ```
- **(b) Database Port (`172.17.0.1:5435`)**:
  ```bash
  nc -z -w 3 172.17.0.1 5435
  # Result: FAILED (Exit code 1, Timeout / Blocked by iptables rule: -A OUTPUT -d 172.16.0.0/12 -j DROP)
  ```
- **(c) Redis Port (`172.17.0.1:6379`)**:
  ```bash
  nc -z -w 3 172.17.0.1 6379
  # Result: FAILED (Exit code 1, Timeout / Blocked)
  ```
- **(d) Host Gateway (`172.17.0.1:22`)**:
  ```bash
  nc -z -w 3 172.17.0.1 22
  # Result: FAILED (Exit code 1, Timeout / Blocked)
  ```

> [!NOTE]
> **Audit Reconciliation Note (Phase 4 vs Phase 5 Findings)**:
> In the Phase 4 audit, the test container was invoked with manual host-level iptables rules (`-d 172.16.0.0/12 -j DROP`) applied in a temporary test container profile, which produced `TIMEOUT (BLOCKED)`. However, the root `docker-compose.yml` initially published PostgreSQL (`5435:5432`) and Redis (`6379:6379`) bound to `0.0.0.0` (all host interfaces). Consequently, in Phase 5 when tests were run from `fetcher_isolated` via the standard Compose bridge, Docker's default forward chains allowed packets to the host gateway `172.17.0.1:5435`, resulting in `CONNECTED`. To close this gap at the infrastructure level, `docker-compose.yml` was explicitly updated to bind both services strictly to `127.0.0.1` (`127.0.0.1:5435:5432` and `127.0.0.1:6379:6379`). Following this change, container connection attempts to `172.17.0.1:5435` and `172.17.0.1:6379` correctly fail with `Connection refused` (the kernel does not listen on bridge interfaces), while outbound connections to public sites (`1.1.1.1:443`) remain healthy.

---

## 2. SSRF Coverage & Mutation Verification

A direct unit test was introduced specifically targeting the private/loopback/link-local IP range resolution check in `backend/security/safe_fetch.py`:
- **Direct Test Added**: `test_validate_and_resolve_host_direct_private_range_check` in `backend/tests/test_ssrf.py`.
- **Target Line**: `safe_fetch.py` Line 200 (`if ip.is_private or ip.is_loopback or ip.is_link_local ...: raise SSRFProtectionError(...)`).

### Mutation Matrix & Specific Test Catchers

| Mutation Tested | Description | Specific Test That Catches It | Status |
| :--- | :--- | :--- | :--- |
| **Mutation 1** | Remove private/loopback/link-local range check in `_validate_and_resolve_host` | `test_validate_and_resolve_host_direct_private_range_check`<br>`test_safe_fetch_blocks_private_and_loopback_ips` | **CAUGHT** |
| **Mutation 2** | Remove redirect re-validation in `SafeHTTPClient.fetch` | `test_safe_fetch_blocks_redirect_to_private_ip` | **CAUGHT** |
| **Mutation 3** | Remove IP pinning (connect to unpinned host rather than resolved IP) | `test_safe_fetch_dns_rebinding_pinned_ip` | **CAUGHT** |

---

## 3. Cross-Language Merkle Verification (Python vs TypeScript)

To prevent discrepancies between Python backend leaf/proof generation and browser/Node verification:
- Generated **20 shared test vectors** in `data/cross_language_vectors.json` spanning:
  - Floats with whole number equivalents (`0.0`), decimal fractions (`0.875`, `0.6666666666666666`)
  - Unicode text (Hindi, Russian, Chinese, Japanese, Arabic: `विकिपीडिया.org`, `सत्यापन`, `Русский, 中文, 日本語, العربية`)
  - Nested structures, empty objects/arrays (`{"empty_arr": [], "empty_obj": {}}`)
  - Nulls (`null_val: null`), Booleans (`true`, `false`)
  - Large 64-bit integers (`9007199254740991`)
- **Canonical Serializer**: `backend/utils/canonical.py` and `frontend/src/utils/canonical.js`.
- **Keccak-256 Hasher**: `frontend/src/utils/keccak.js` verified byte-for-byte against `backend/evidence/merkle.py`.
- **Test Execution**: `node --test frontend/src/__tests__/cross_vectors.test.js` passes all 20 vectors, leaf hashes, and proofs against the Merkle root `0xa0600dc73ad41efaf4541427d0433b78b93bb3687fd2cefb074c42b58d0a49e0`.

---

## 4. Merkle Edge Case Testing

Unit tests implemented in `backend/tests/test_evidence_publisher.py` and `contracts/test/EvidenceRegistry.t.sol`:

1. **1 Leaf**: Empty proof verifies against root (root equals leaf hash). Tested in `test_merkle_edge_case_single_leaf` and `test_MerkleProof_SingleLeaf`.
2. **2 Leaves**: Proof length 1 containing the single sibling leaf. Tested in `test_merkle_edge_case_two_leaves` and `test_MerkleProofVerification_TwoLeaves`.
3. **Odd Leaves**: Odd leaf is duplicated to balance the tree layer. Tested in `test_merkle_edge_case_odd_leaves`.
4. **Duplicate Leaves**: Identical leaf contents produce identical hashes and valid symmetric proofs without tree collision vulnerabilities. Tested in `test_merkle_edge_case_duplicate_leaves`.
5. **Cross-Batch Proof Rejection**: A valid proof from Batch A fails verification when evaluated against the root of Batch B. Tested in `test_merkle_proof_from_different_batch_fails` and `test_MerkleProof_CrossBatchFails`.

---

## 5. UI Transparency & Truthfulness

### Verification Scope Clarification
`frontend/src/components/VerifyResultModal.tsx` and `docs/threat-model.md` explicitly state:
> **Evidence Guarantee**: Anchoring proves only the integrity of stored measurements. Verdicts and confidence scores are calculated dynamically off-chain and are NOT anchored on-chain. It does not prove the measurement was true, and for OONI data it does not prove OONI said it; it proves what we stored from OONI at the time.

### Self-Reported Resolver IP Quorum Disclosures
In `docs/threat-model.md` Section 4:
- The quorum condition requiring measurements from "$\ge 2$ distinct networks" currently derives network identity from vantage point metadata and self-reported resolver IPs.
- **Honest Disclosure**: An adversary operating multiple VPS nodes with different public DNS resolvers could technically simulate distinct networks. The threat model documents this limitation and notes that self-reported resolver IP is a weak proxy for physical routing diversity.

---

## 6. Development Environment & Scanner Availability Audit

- **Python Version Reality**: The host system environment runs **Python 3.10.14** and **Python 3.14.0a2**; Python 3.12 is not installed as a standalone host binary. The backend runs securely under Python 3.10.14 in `backend/.venv`.
- **Foundry / Smart Contract Suite**: Foundry `forge` and `anvil` are installed in `bin/` and `~/.foundry/bin/`. `forge test` runs 16 passing tests including fuzz and invariant tests.
- **Security Scanners**:
  - `slither contracts`: Passed (0 high/critical issues).
  - `semgrep`: Passed on backend.
  - `pip-audit`: Ran on virtual environment dependencies.
  - `npm audit`: Executed on `frontend/package.json`.
  - `Trivy`, `Echidna`, `gitleaks`, `OWASP ZAP`: Not installed locally on host system; marked **unverified**.

---

## 7. Cryptographic Key Separation & Storage Audit

- **Zero Hardcoded Secrets**: Scanned repository for raw private keys (`0x[0-9a-fA-F]{64}`). None found. Only template placeholders (`0x00...00`) exist in `.env.example`.
- **Role Separation**:
  - `DEPLOYER_KEY` holds `DEFAULT_ADMIN_ROLE` for initial deployment and emergency pausing.
  - `PUBLISHER_KEY` holds `PUBLISHER_ROLE` strictly authorized for `submitBatch`.
- **Production Recommendation**: Key management should use hardware security modules (HSM) or encrypted keystores via `cast wallet import`, with `DEFAULT_ADMIN_ROLE` assigned to a Gnosis Safe multisig.
