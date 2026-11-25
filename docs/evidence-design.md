# Evidence Architecture & Cryptographic Merkle Tree Specification

This document specifies the on-chain evidence registry, Merkle tree construction, and leaf canonicalization standards used by CensorScope.

---

## 1. What Anchoring Proves and Does Not Prove

> [!IMPORTANT]
> **Core Integrity Guarantee**:
> - **Anchoring proves**: that our stored copy of a record has not changed since the batch was published.
> - **Anchoring does not prove**: the measurement was true, and for OONI data it does not prove OONI said it; it proves what we stored from OONI at the time.

---

## 2. Merkle Tree Design & Leaf Specification

### Leaf Canonicalization & Double Hashing
To prevent **second-preimage attacks** where an intermediate branch node (32 bytes) could be misinterpreted as a leaf, CensorScope enforces double-leaf hashing:
$$\text{leaf} = \text{keccak256}(\text{keccak256}(\text{canonical\_json\_bytes}))$$

### Exact Leaf Fields
Each leaf encapsulates 9 strictly normalized fields from the PostgreSQL `measurements` table:
1. `id`: Unique database integer ID.
2. `source`: Measurement origin (`"ooni"` or `"signed_probe"`).
3. `domain`: Fully qualified normalized ASCII domain name.
4. `asn`: Autonomous System Number integer (e.g., `55836`).
5. `measured_at`: ISO 8601 UTC timestamp string (e.g., `"2026-11-20T10:00:00Z"`).
6. `technique`: Detected blocking technique string (e.g. `"dns_tampering"`, `"tls_sni_filtering"`, or `"none"`).
7. `anomaly`: Boolean flag indicating whether network interference was observed.
8. `signals`: Trimmed dictionary of boolean signals (`dns_tampering`, `tcp_reset`, `tls_sni_failure`, `http_failure`).
9. `ingested_at`: ISO 8601 UTC timestamp when CensorScope ingested and saved the telemetry.

### Canonical Serialization
Bytes are generated via `canonical_json_dumps(leaf_dict)`:
- Keys sorted lexicographically by UTF-8 bytes.
- Compact separators (`','`, `':'`).
- Native UTF-8 characters preserved without ASCII escaping.

### Merkle Tree Pair Hashing
Internal node pair hashing matches OpenZeppelin's `MerkleProof.verify` sorted-pair standard:
$$\text{parent} = \text{keccak256}(a < b \ ? \ (a \mathbin{\Vert} b) : (b \mathbin{\Vert} a))$$

---

## 3. EvidenceRegistry Contract Architecture

- **Contract Name**: `EvidenceRegistry.sol` (replaces legacy `EvidenceAnchor.sol`).
- **Access Control**: OpenZeppelin `AccessControl` with:
  - `DEFAULT_ADMIN_ROLE`: Authorized to pause/unpause and assign publisher roles.
  - `PUBLISHER_ROLE`: Authorized to invoke `submitBatch()`.
- **Validation Rules**:
  - Rejects zero root (`0x00...00`).
  - Rejects zero record count (`count == 0`).
  - Rejects duplicate root submissions.
  - Rejects empty IPFS CIDs.
  - Rejects invalid timestamp intervals (`fromTs > toTs`).
- **Pausable**: Administrative kill-switch during security events or private key compromises.
- **Non-upgradeable**: Implemented as an immutable contract without upgrade proxies.

---

## 4. Production Governance: Multisig & Timelock

In local Anvil and Sepolia test environments, administrative and publishing keys are held by standard EOA addresses loaded via environment variables.

In production:
1. `DEFAULT_ADMIN_ROLE` must be transferred to an **OpenZeppelin TimelockController** with a minimum 48-hour delay.
2. The proposer of the Timelock must be a **Safe (Gnosis Safe) 3-of-5 Multisig** whose signers represent independent security auditors and maintainers.
3. Automated publisher bots hold only `PUBLISHER_ROLE` with no ability to grant roles or pause the contract.
