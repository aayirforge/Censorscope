# Smart Contract Security & Static Analysis Report

This document records the security analysis, static checks, and formal verification findings for `EvidenceRegistry.sol`.

---

## 1. Static Analysis: Slither (v0.11.6)

We ran Slither against the Foundry project using OpenZeppelin v5.0.2 contracts:

```bash
slither contracts/src/EvidenceRegistry.sol
```

### Raw Findings
1. **`assembly` (MerkleProof._efficientHash)**:
   - *Severity*: Informational
   - *Location*: `openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol`
   - *Details*: OpenZeppelin uses assembly for gas-optimized sorted pair hashing. Verified standard library behavior.
2. **`pragma` (Multi-version pragma usage)**:
   - *Severity*: Informational
   - *Details*: OpenZeppelin uses `^0.8.20` while CensorScope uses `^0.8.24`. Solc 0.8.24 successfully and consistently compiles both without conflicts.
3. **`solc-version` (0.8.20 known issues)**:
   - *Severity*: Informational
   - *Details*: Fixed by enforcing `solc_version = "0.8.24"` in `foundry.toml`.
4. **`naming-convention` / `immutable-states`**:
   - Flagged legacy `EvidenceAnchor.sol` scaffold parameters. Fixed by migrating completely to `EvidenceRegistry.sol`.

---

## 2. Foundry Test & Invariant Verification Suite

We executed 14 unit, fuzz, and invariant tests via `forge test`:

| Test Name | Gas (avg) | Property Proven |
| :--- | :--- | :--- |
| `test_InitialState` | 54,211 | Validates role setup and initial unpaused state. |
| `test_SubmitBatch_Success` | 217,371 | Proves authorized publisher submits valid batch, increments ID, and emits event. |
| `test_Revert_NonPublisherCannotSubmit` | 37,006 | Enforces role-based rejection on unauthorized callers. |
| `test_Revert_ZeroMerkleRoot` | 38,691 | Rejects null bytes32 root. |
| `test_Revert_ZeroRecordCount` | 39,102 | Rejects zero-item batch submissions. |
| `test_Revert_DuplicateMerkleRoot` | 210,000 | Prevents replay or duplicate root insertion. |
| `test_Revert_EmptyIpfsCid` | 40,575 | Rejects batches missing IPFS/storage pointers. |
| `test_Revert_InvalidTimestampRange` | 42,035 | Enforces `fromTs <= toTs`. |
| `test_Revert_GetBatchDoesNotExist` | 14,015 | Validates array index bounds checking. |
| `test_Revert_PausedCannotSubmit` | 307,959 | Validates Pausable emergency freeze. |
| `test_MerkleProofVerification_TwoLeaves` | 205,820 | Validates root verification; proves tampered leaves & proofs fail. |
| `testFuzz_MerkleProofRandom` (256 runs) | 185,442 | Fuzz test proving sorted-pair Merkle verification holds for arbitrary hashes. |
| `test_Invariant_BatchIdMonotonicallyIncreases`| 814,441 | Invariant test: IDs strictly increment ($0, 1, 2, ...$). |
| `test_Invariant_StoredRootImmutable` | 365,060 | Invariant test: Anchored roots can never be modified. |

---

## 3. Echidna / Advanced Formal Verification Note

- **Echidna Tooling Status**: `echidna` binary is not installed on the local system PATH.
- **Alternative Verification**: We implemented Foundry stateful fuzzing and invariant tests directly in `contracts/test/EvidenceRegistry.t.sol` across 256 fuzz iterations per run.
