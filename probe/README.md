# CensorScope Probe Client

> [!WARNING]
> **SAFETY & VOLUNTEER USAGE NOTICE**:
> 1. Run this probe **strictly on your own personal or authorized network infrastructure**. Never run measurements on employer, public institution, or restricted networks without explicit administrative authorization.
> 2. The probe enforces a strict target allowlist (`allowlist.txt`). It will **refuse to execute tests** against any domain not present on this curated list.
> 3. This probe **does not contain any circumvention features**, proxies, VPNs, or censorship bypass tooling. It exclusively performs empirical reachability diagnostics.

## Features
- Strict local allowlist validation
- Non-intrusive DNS, TCP connection, TLS handshake (with and without SNI), and HTTP block page probes
- RFC 8785 canonical JSON serialization
- Cryptographic Ed25519 payload signing with nonce and timestamp protection
