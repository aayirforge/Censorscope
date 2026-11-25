# CensorScope Production Launch Checklist

**Version**: 1.0.0 (Pre-Flight Assessment)

---

## 1. What IS Ready

- [x] **Core Measurement & Ingestion Engine**:
  - Incremental OONI data ingestion with deduplication and normalized domain punycode conversion.
  - Layer-3/4/7 technique classifier (`dns_tampering`, `tcp_reset`, `tls_sni_filtering`, `http_block_page`).
- [x] **Verdict Algorithm**:
  - Requires $\ge 3$ anomalies across $\ge 2$ distinct days with $\ge 60\%$ concentration to declare `Blocked`.
  - Inconclusive categories for scattered failures; separate handling of security malware domains.
- [x] **Smart Contracts (Solidity 0.8.24)**:
  - `EvidenceRegistry.sol`: Monotonic batches, OpenZeppelin sorted-pair Merkle proof verification, double-leaf hashing.
  - `ProbeRegistry.sol`: 0.05 ETH minimum stake, 7-day unstaking delay, slashing during delay, reentrancy protection.
  - `Attestation.sol`: EIP-712 typed data signing, 3-day challenge window, 0.1 ETH challenge bond.
  - 28 passing Foundry tests covering fuzzing, accounting, and reentrancy.
- [x] **Client-Side Proof Verification**:
  - Browser/Node cross-language Merkle verification against 20 comprehensive test vectors.
- [x] **Privacy & Minimization**:
  - Zero-linkage search logging architecture (no client IP or search query parameters written to persistent logs).

---

## 2. What is NOT Ready

> [!CAUTION]
> The following items are **NOT ready** for immediate mainnet or production deployment:

1. **Legal Counsel Review**:
   - `docs/volunteer-safety.md` and `docs/probe-consent.md` have NOT undergone formal legal review under Indian telecommunication laws (IT Act, Telecom Regulatory Framework).
2. **PostCSS / Next.js Dependency Update**:
   - `npm audit` flagged `postcss <=8.5.22` vulnerabilities under `next@15.1.0`. Requires evaluating breaking changes in `next@16`.
3. **Decentralized Arbitration**:
   - `Attestation.sol` uses a centralized `ARBITER_ROLE`. A decentralized oracle (such as UMA) or multi-sig council is required for production mainnet.
4. **Hardware Key Management (HSM / KMS)**:
   - Automated publisher worker currently relies on environment variable private keys in development. Production deployment requires AWS KMS, GCP KMS, or HashiCorp Vault.
5. **Physical Sybil Resistance**:
   - Quorum currently measures distinct networks via reported vantage point metadata and resolver IPs. Physical residential diversity cannot be cryptographically proven without trusted hardware or hardware attestation.
