# CensorScope Threat Model (STRIDE) - Final Release

**System**: CensorScope Internet Censorship Telemetry Observatory  
**Version**: 1.0.0 (Phase 3 Final)  
**Methodology**: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. System Overview & Assets
CensorScope tracks and attributes internet censorship telemetry across Indian telecommunication providers.

### Primary Assets:
1. **Measurement Records**: Layer-3/4/7 connectivity measurements.
2. **Analysis Verdicts**: Per-ISP and domain accessibility classifications.
3. **Volunteer Probe Safety**: Protecting volunteer identity, location, and network safety.
4. **User Search Privacy**: Protecting queried domains from user IP linkage.
5. **On-Chain Evidence Merkle Roots**: Tamper-evident anchoring.

---

## 2. Threat Analysis & Mitigations (STRIDE)

| Threat ID | Category | Threat Scenario | Implemented Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | **Spoofing** | Adversary submits forged probe reports pretending to be an authorized probe. | Ed25519 digital signatures required; server verifies against authorized probe public key registry (`POST /api/v1/reports`). | Key theft on a volunteer's compromised local machine. |
| **T-02** | **Tampering** | Man-in-the-middle alters measurement data in transit. | Signatures computed over RFC 8785 canonical JSON; any byte change fails verification. TLS enforced. | None in transit. |
| **T-03** | **Repudiation** | Malicious probe denies submitting corrupt telemetry. | Every report is cryptographically signed with the probe's private key and nonces are permanently logged. | Compromised private key claimed as an excuse. |
| **T-04** | **Info Disclosure** | Adversary intercepts user search queries or links searched domains to user IP. | Zero-linkage logging architecture: client IP is used only in memory for rate-limiting; path is redacted in logs. | Upstream ISP or local network monitoring of the user's browser. |
| **T-05** | **Denial of Service** | Volumetric DoS or payload exhaustion on `/api/v1/reports`. | Sliding-window IP rate limiting (60 req/min), strict 64 KB payload size caps, 10-minute timestamp skew window. | Distributed volumetric bandwidth saturation (DDoS) targeting hosting provider. |
| **T-06** | **Elevation of Privilege** | SSRF: Attacker probes cloud metadata (`169.254.169.254`) or internal services. | `backend/security/safe_fetch.py` validates hostnames, resolves DNS directly, rejects private/cloud metadata IPs, pins resolved IP, and re-validates redirects. Container capabilities dropped (`cap_drop: [ALL]`). | Zero-day in Python `socket` or Linux kernel network stack. |
| **T-07** | **Sybil Attack** | Adversary spins up 100 fake probe keys from one machine to force a `Blocked` verdict. | Quorum rules: `Blocked` verdict strictly requires $\ge 3$ independent probes, from $\ge 2$ distinct networks, across $\ge 2$ distinct days. | An adversary possessing large residential botnets across multiple real Indian ISPs. |

---

## 3. Residual Risks & Non-Protections Table

The following risks are **NOT** protected against by CensorScope design:

| Residual Risk | Why It Is Not Protected | User / Operator Responsibility |
| :--- | :--- | :--- |
| **Sophisticated Distributed Sybil Attacks** | If a state or well-funded actor commands residential botnets across $\ge 2$ major Indian ISPs over $\ge 2$ days, technical quorum will be met. | Rely on multi-source cross-checking (e.g. OONI, IODA, Citizen Lab) before certifying high-impact legal assertions. |
| **Client-Side ISP Eavesdropping** | If an end-user searches CensorScope without HTTPS or over a compromised local network, their local ISP can observe DNS or SNI requests to CensorScope itself. | End users should utilize encrypted DNS (DoH/DoT) and trusted VPNs if local surveillance is suspected. |
| **Volunteer Device Seizure** | If a volunteer probe operator is subjected to physical device seizure, the private Ed25519 key on disk can be acquired. | Volunteers must run probes on dedicated, isolated test hardware with full-disk encryption. |
## 4. Blockchain & Evidence Layer Threat Analysis (Phase 4 Updates)

The evidence layer introduces on-chain Merkle anchoring and decentralized storage interactions. Below is the STRIDE analysis for these threats:

| Threat Scenario | Threat Description | Implemented Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Compromised Publisher Key** | An attacker steals `PUBLISHER_PRIVATE_KEY` and submits arbitrary Merkle roots to `EvidenceRegistry`. | 1. `EvidenceRegistry` is Pausable by `DEFAULT_ADMIN_ROLE`.<br>2. Production contracts require an OpenZeppelin Timelock and multisig.<br>3. Anchored batches are immutable; if revoked, a revoking event or admin pause is triggered. | Roots submitted before admin pause remain on-chain; off-chain DB must discard unrecognized batches. |
| **Malicious Publisher (Insider / Rogue Operator)** | An operator with publisher credentials attempts to anchor fabricated measurement records. | 1. Merkle leaf hashes cryptographically bind database IDs, domains, techniques, and timestamps.<br>2. Full batch JSON must be published to IPFS/storage.<br>3. Independent verifiers can reconstruct the tree from raw records and flag discrepancies. | Bad roots can be published, but cannot be proven to match legitimate OONI/probe telemetry if leaves are challenged. |
| **RPC Lies to Frontend** | A malicious or manipulated Ethereum RPC endpoint returns incorrect roots or fabricated contract state to the client browser. | 1. Frontend verification is decoupled from backend proxies.<br>2. Users can configure custom RPC URLs (e.g. Infura, Alchemy, local node).<br>3. Read-only verification does not require wallet signing or approval. | If the user-selected public RPC is compromised, false verification status could be displayed. |
| **IPFS Data Loss / Unavailability** | The pinned IPFS batch artifact becomes unretrievable due to pin expiry, node downtime, or network censorship of IPFS gateways. | 1. CensorScope maintains complete leaf data in PostgreSQL `measurement_proofs` table.<br>2. Fallback local mock storage (`data/ipfs_mock/`) records exact batch JSON.<br>3. Batches can be re-pinned to alternate decentralized storage (Filecoin, Arweave). | If both CensorScope DB and IPFS nodes discard data, proofs cannot be independently reconstructed from raw leaves. |
| **The Oracle Problem (Anchoring $\neq$ Truth)** | A user assumes that because a measurement root is anchored on Ethereum, the domain is objectively blocked in the physical world. | **Explicit In-UI & Contract Disclaimer**: Anchoring proves only the integrity of stored measurements. Verdicts and confidence scores are calculated dynamically off-chain and are NOT anchored on-chain. It does not prove the measurement was true, and for OONI data it does not prove OONI said it; it proves what we stored from OONI at the time. | User cognitive bias or misinterpretation of blockchain immutability as infallible truth. |
| **Self-Reported Resolver IP Limitation** | Probe quorum requires measurements from "distinct networks". Currently, network diversity is inferred from the resolver IP or vantage point metadata reported in telemetry. | Probes are authenticated with Ed25519 keys, but an adversary running multiple keys across VPS nodes could configure arbitrary recursive resolvers or spoof self-reported IP addresses. Quorum algorithms must treat self-reported resolver IP as a weak signal rather than absolute proof of multi-operator infrastructure diversity. | A single operator controlling multiple probes on a single autonomous system could spoof resolver addresses to appear as multiple distinct networks. |
| **BGP Routing Hijacking & Anycast Poisoning** | An upstream adversary manipulates BGP routes or poison anycast routes to intercept probe traffic intended for public resolvers or control sites. | Outbound requests use TLS SNI validation and verify server certificates against system trust anchors. DNS rebinding and IP pinning prevent dynamic socket redirection. | If a state adversary issues fraudulent certificates via a compromised domestic CA trusted by the system, TLS interception could succeed. |
| **Slasher Governance Griefing** | The entity holding `SLASHER_ROLE` becomes compromised or malicious. | Slashed funds are burned/retained in the contract and cannot be withdrawn by the slasher. Unstaking enforces a 7-day delay. | An attacker with `SLASHER_ROLE` can destroy honest volunteer stakes, inflicting economic damage on probe operators without financial gain for themselves. |
| **Centralized Arbiter in Attestation Prototype** | `Attestation.sol` relies on a trusted `ARBITER_ROLE` to decide challenges. | Prototype contract; challenge bonds (0.1 ETH) are escrowed in contract until resolution. Code explicitly disclaims production mainnet readiness without optimistic oracle integration. | A rogue or compromised arbiter can arbitrarily direct challenge bonds to either party. |


---

## 5. Live Check & On-Demand Probing Threat Analysis (Live-Check System)

Extending CensorScope to accept arbitrary user-supplied domains for live reachability checks and RDAP queries introduces distinct network-layer and operational risks:

| Threat ID | Threat Category | Threat Scenario | Implemented Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **T-08** | **Abuse as an Open Port Scanner** | Attacker inputs domains or subdomains resolving to target victims to scan for open ports. | 1. Ports restricted strictly to **80** and **443**.<br>2. Non-standard ports (e.g. 22, 3306, 8080) are rejected.<br>3. IP literals rejected.<br>4. Per-domain cooldown (10 minutes) prevents rapid-fire port probing. | Probing ports 80/443 on public hosts cannot be fully prevented, but cannot be weaponized for port discovery. |
| **T-09** | **Server-Side Request Forgery (SSRF)** | Attacker inputs a domain resolving to internal infrastructure (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`) or Docker services (`postgres`, `redis`). | 1. Multi-stage hostname validation and direct DNS resolution before connect.<br>2. Hardened private/loopback/link-local/multicast IP address range rejections.<br>3. IP pinning on raw socket.<br>4. Docker fetcher container network isolation blocks host and container inter-communication.<br>5. Redirect targets re-checked from scratch. | Host OS network zero-days or kernel routing table corruption. |
| **T-10** | **Reflection / Amplified Denial of Service** | Attacker automates requests for a victim domain from thousands of proxies to cause CensorScope to flood the victim with HTTP/TLS connections. | 1. Per-domain global cooldown (10 minutes): subsequent queries for the same domain hit Redis cache immediately without sending any outbound packets.<br>2. Worker queue concurrency cap (max 10 jobs).<br>3. IP rate limiting (10 req/min per IP, 50 req/hour).<br>4. Only one single HTTP request sent per check (no recursive asset crawling, images, or JS). | Single HTTP GET sent to victim once every 10 minutes. |
| **T-11** | **User Query Privacy Leakage** | State actor, hostile ISP, or eavesdropper links searched sensitive domains to the querying citizen's IP address. | 1. Client IP address is never logged alongside queried domains (access logs scrubbed).<br>2. Cache keys use HMAC-SHA256 with an environment secret (`CACHE_HMAC_SECRET`).<br>3. Job IDs are non-deterministic random UUIDv4s.<br>4. No query parameters persisted in long-term database tables. | Browser history on user device; local ISP monitoring TLS traffic to CensorScope itself (mitigated by user VPN/DoH). |
| **T-12** | **Remote Code Execution via Malicious HTTP Responses** | Target web server returns oversized payloads, infinite chunked streams, zip bombs, or malformed HTML to compromise the fetcher. | 1. Response bodies are NOT stored.<br>2. Response stream capped at 64 KB and read only for known fingerprint matching, then immediately closed.<br>3. Fetcher runs with `cap_drop: [ALL]`, read-only root filesystem, and no shell binaries. | Flaws in Python HTTP parsing libraries (mitigated by dependency audits). |
| **T-13** | **Emergency Service Abuse / Upstream Ban** | High volume of domain checks triggers blocking or blacklisting of CensorScope server IP by upstream registries (RDAP/IANA/DoH) or ISPs. | 1. Global kill switch (`ENABLE_LIVE_CHECKS=false`) immediately halts all outbound live probing.<br>2. RDAP bootstrap files and TLD lists cached locally for 24 hours.<br>3. Exponential backoff on HTTP 429 from RDAP or DoH resolvers. | Legitimate users experience degraded real-time checks if kill-switch is activated. |
