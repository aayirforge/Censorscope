# CensorScope Smart Contract Audit Readiness & L2 Mainnet Checklist

> [!CAUTION]
> **DEPLOYMENT STATUS**: **Not deployed. Current testnet deployment uses single throwaway keys.**
> All multi-sig, timelock, and decentralized role structures described in this document represent a target design plan for future mainnet readiness, not the current active environment.

**Target Protocol**: CensorScope Evidence & Staking Suite  
**Contracts Covered**:
- `EvidenceRegistry.sol` (OpenZeppelin AccessControl, Pausable, MerkleProof)
- `ProbeRegistry.sol` (Staking, Slashing, SlashedPool Accounting, 7-Day Unstaking Delay, ReentrancyGuard)
- `Attestation.sol` (EIP-712 Claims, 3-Day Challenge Windows, Bonds, Arbiter Dispute Resolution)

---

## 1. Static Analysis & Verification Summary

### Tool Coverage & Findings
- **Foundry (`forge test`)**: 31 passing tests (Unit tests, fuzz testing with 256 runs, monotonic batch ID invariants, immutable root invariants, slashed pool accounting, force-send ETH deposit invariants, unstaking challenge checks).
- **Slither Analysis (`slither contracts`)**:
  - **High/Critical**: 0
  - **Medium**: 0
  - **Low / Informational**:
    - Low-level calls in `completeUnstake`, `withdrawSlashedPool`, and `resolveDispute`: Protected by OpenZeppelin `ReentrancyGuard`, zeroed balances before external transfer (checks-effects-interactions).
    - Block timestamp usage: Used for coarse multi-day delays (7-day unstaking, 3-day challenge windows), where minor miner timestamp manipulation ($\pm 15$ seconds) is mathematically negligible.
    - Equality on enum status in `isProbeActive`: Intended state comparison.

---

## 2. Granular Trust Model & Role Compromise Matrix

### A. Role Powers & Compromise Impact (Planned Production Architecture)

| Role Name | Planned Holding Entity | Powers over Users / Funds | Impact if Key Compromised | Mitigation / Constraint |
| :--- | :--- | :--- | :--- | :--- |
| **`DEFAULT_ADMIN_ROLE`** | Multi-sig / TimelockController (planned 3-of-5 Gnosis Safe with 48h delay; currently single throwaway key) | Can pause/unpause all contracts, grant or revoke any role (`PUBLISHER_ROLE`, `SLASHER_ROLE`, `ARBITER_ROLE`). Cannot directly drain probe stakes. Can withdraw accumulated `slashedPool`. | Attacker could pause contracts (Denial of Service) or grant themselves `SLASHER_ROLE` / `ARBITER_ROLE`. | Enforce 48-hour Timelock on all admin calls. Multisig signers must be geographically and organizationally distributed. |
| **`PUBLISHER_ROLE`** | Automated backend publishing worker (planned HSM/AWS KMS signer; currently single throwaway key) | Can invoke `EvidenceRegistry.submitBatch(root, cid, ...)`. Cannot touch ETH balances, cannot slash probes, cannot alter previous batches. | Attacker could anchor fabricated Merkle roots or spam bogus IPFS CIDs to the blockchain registry. | Contract enforces monotonic batch IDs, non-empty CIDs, and non-zero roots. Attacker cannot forge historical roots; DB verifier flags invalid roots against raw probe data. |
| **`SLASHER_ROLE`** | Telemetry Verification Committee (planned multi-sig; currently single throwaway key) | Can invoke `ProbeRegistry.slashProbe(operator, bps, reason)`. Can slash active or unstaking probes and reset reputation to 0. | **Critical Griefing Risk**: A rogue or compromised slasher could burn 100% of honest volunteer probe stakes. | Slashed funds are credited to `slashedPool` in the contract (NOT sent to slasher address, removing direct theft profit incentive). In production, slashing will require multi-sig confirmation or automated fraud proofs. |
| **`ARBITER_ROLE`** | Trusted Dispute Resolution Entity (Academic / Digital Rights Council; currently single throwaway key) | Unilaterally resolves challenged attestations via `Attestation.resolveDispute(claimId, upheld)`. Decides whether bond goes to attestor or challenger. | Attacker can falsely overturn valid censorship claims or falsely uphold bad claims, distributing the 0.1 ETH challenge bond to the wrong party. | **Prototype Limitation**: `Attestation.sol` is explicitly documented as a **prototype with a single trusted arbiter**. In production, it must be replaced with decentralized optimistic oracles (UMA) or multi-party jury systems. |

### B. Challenge Bond Accounting & Destination
- When an attestation is challenged, the challenger deposits `CHALLENGE_BOND` (0.1 ETH).
- **If Upheld (`upheld == true`)**: The original attestor was proven correct. The challenger's forfeited bond is transferred directly to the attestor (`winner = c.attestor`) as compensation for defending the claim.
- **If Overturned (`upheld == false`)**: The attestor's claim was proven false or inaccurate. The bond is refunded back to the challenger (`winner = c.challenger`).
- **No protocol fee or arbiter skim**: 100% of the bond goes to the winning party.

---

## 3. Production Architecture: L2 Deployment & Multisig Administration

### A. Recommended L2 Target
- **Arbitrum One** or **Optimism / Base**:
  - Low gas costs for periodic batch anchoring ($\approx 0.00005$ ETH per batch).
  - High EVM equivalence, native support for EIP-712 and OpenZeppelin contracts.

### B. Timelock & Multisig Architecture
**Never deploy with an EOA (Externally Owned Account) as `DEFAULT_ADMIN_ROLE`.**

```mermaid
flowchart TD
    GnosisSafe["Gnosis Safe (3-of-5 Multisig)"] -->|Proposes Action| TimelockController["OpenZeppelin TimelockController (48h Delay)"]
    TimelockController -->|Administer| EvidenceRegistry["EvidenceRegistry.sol"]
    TimelockController -->|Administer| ProbeRegistry["ProbeRegistry.sol"]
    TimelockController -->|Administer| Attestation["Attestation.sol"]
    PublisherService["Automated Publisher Worker"] -->|submitBatch()| EvidenceRegistry
    SlasherService["Dispute Resolution Committee"] -->|slashProbe()| ProbeRegistry
    ArbiterCommittee["Legal / Academic Arbiter"] -->|resolveDispute()| Attestation
```

---

## 3. L2 Mainnet Deployment Pre-Flight Checklist

- [ ] **Contract Roles & Privileges**:
  - `DEFAULT_ADMIN_ROLE` assigned exclusively to the Timelock Controller.
  - Timelock Delay configured to a minimum of **48 hours**.
  - `PUBLISHER_ROLE` assigned to a dedicated, restricted key with automated gas monitoring.
  - Slasher & Arbiter roles assigned to independent multisig committees.
- [ ] **Cryptographic Key Management**:
  - Deployer EOA key discarded or stripped of all roles post-deployment.
  - Publisher key generated via hardware security module (HSM) or cloud KMS (AWS KMS / GCP Cloud KMS).
- [ ] **Decentralized Storage & Gateway Redundancy**:
  - Pinning service active on dual providers (e.g. Pinata + Web3.Storage / Filecoin).
  - Public gateway fallback URLs configured in client-side applications.
- [ ] **Economic & Attack Protections**:
  - Minimum stake set to economically disincentivize Sybil probes ($0.05$ ETH on L2 or equivalent).
  - 7-day unstake delay enforced to ensure malicious telemetry can be disputed before capital exit.
  - 3-day challenge window for EIP-712 attestations with required bond.
- [ ] **Emergency Operations Plan**:
  - `pause()` procedure documented with incident response keys.
  - Emergency contact registry established for observatory node operators.
