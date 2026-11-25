# CensorScope Technical Design Document

## 1. Executive Summary & Problem Statement

Internet access in India is mediated by major telecommunications operators and Internet Service Providers (ISPs), including Reliance Jio, Bharti Airtel, Vodafone Idea, BSNL/MTNL, and regional broadband providers. State-directed or court-ordered block orders are delivered to ISPs under statutory frameworks (such as Section 69A of the Information Technology Act). However, blocking implementations remain fragmented and opaque:
1. Different ISPs implement blocks using disparate network enforcement techniques (DNS injection/NXDOMAIN, TCP RST injection, TLS/SNI resets, HTTP block page redirects, or BGP/IP null-routing).
2. Users encountering network timeouts or connection resets cannot readily discern whether an issue stems from official censorship, security filtering (e.g. malware or phishing protection), ISP misconfiguration, or remote origin downtime.
3. Measurement data gathered by researchers is often siloed or difficult for ordinary citizens and civil society observers to interpret.
4. Historical records can be altered, disputed, or lost without verifiable, tamper-evident audit trails.

CensorScope bridges this gap by providing an open, verifiable domain search engine and analytics dashboard tracking censorship telemetry across Indian ISPs, backed by cryptographic Merkle anchoring on Ethereum.

---

## 2. Goals & Non-Goals

### Goals
- **Per-ISP Empirical Verdicts**: Provide transparent accessibility statuses (`Blocked`, `Likely blocked`, `Accessible`, `Insufficient data`) alongside a mathematical confidence score (0-100%).
- **Technical Attribution**: Identify the specific network layer mechanism responsible for failures:
  - DNS tampering (bogus IP, NXDOMAIN synthesis, SERVFAIL, timeout)
  - TCP connection disruption (TCP RST or SYN drop)
  - TLS / SNI interference (handshake reset or certificate manipulation)
  - HTTP block pages (302/307 redirects to ISP warning portals or 403/451 injected bodies)
  - IP routing blocks (null routing or routing drops)
- **Categorization Taxonomy**: Distinguish between:
  - *Censorship-consistent interference* (network anomalies on otherwise healthy origins)
  - *Security-related interventions* (corroborated by malware/phishing feeds)
  - *Infrastructure outages* (correlated with global origin unreachability or broad network partition)
  - *Inconclusive telemetry* (intermittent or noisy probe results)
- **Public Contextual Intelligence**: Display up to five publicly available articles/references (capturing strictly: Title, Source, Publication Date, and Canonical URL; never raw article bodies) annotated with evidence confidence:
  - `Confirmed order` (verified government or court document)
  - `Reported` (credible journalistic reporting)
  - `Unknown` (unverified claims or missing documentation)
- **Verifiable Proof**: Bundle raw signed measurement records into immutable IPFS datasets and commit cryptographic Merkle roots on an Ethereum smart contract for trustless auditability.
- **Cautious & Nuanced Language**: Express findings neutrally and factually (e.g., *"Telemetry is consistent with DNS injection on AS55836"*), never asserting legal culpability or unverified motives.

### Non-Goals
- **No Circumvention Tooling**: CensorScope does not provide proxies, VPNs, DNS relays, or censorship circumvention tools.
- **No Uncurated Scanning**: CensorScope strictly tests domains vetted from trusted repositories (e.g. Citizen Lab test lists); it does not scan unverified user-submitted arbitrary endpoints or illegal content categories.
- **No Raw or Content Storage On-Chain**: Ethereum smart contracts only anchor 32-byte cryptographic Merkle roots and batch metadata. No measurement payloads or article bodies are stored on-chain.
- **No Legal Declarations**: CensorScope reports empirical network observations, not authoritative legal determinations.

---

## 3. System Architecture & Components

```
+---------------------------------------------------------------------------------+
|                                 DATA INGESTION                                  |
|                                                                                 |
|  +----------------+  +-----------------+  +-----------------+  +-------------+  |
|  |   OONI Probe   |  |  Citizen Lab    |  | Censored Planet |  | Threat Feeds|  |
|  |  Measurements  |  |   Test Lists    |  |   & IODA Feeds  |  |  (URLhaus)  |  |
|  +--------+-------+  +--------+--------+  +--------+--------+  +------+------+  |
+-----------|-------------------|--------------------|------------------|---------+
            |                   |                    |                  |
            v                   v                    v                  v
+---------------------------------------------------------------------------------+
|                            INGESTION & PIPELINE WORKERS                         |
|                                                                                 |
|  - Data Normalization & Validation                                              |
|  - Heuristic & Anomaly Classification Engine                                    |
|  - Deduplication & Context Enrichment (News API / Public Notices)               |
+---------------------------------------+-----------------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
+---------------------------------+           +---------------------------------+
|       RELATIONAL STORAGE        |           |       TEMPORAL & TASK CACHE     |
|         (PostgreSQL 16)         |           |           (Redis 7)             |
|                                 |           |                                 |
| - Normalized Measurement Events |           | - Rate limiting & search cache  |
| - ISP Telemetry Aggregate Views |           | - Celery / Task queue states    |
| - Domain Metadata & News Links  |           | - Real-time job pub/sub         |
+----------------+----------------+           +---------------------------------+
                 |
                 +---------------------------------------------+
                 |                                             |
                 v                                             v
+---------------------------------+           +---------------------------------+
|         API BACKEND             |           |       EVIDENCE BATCH ANCHOR     |
|     (Python 3.12 / FastAPI)     |           |        (Background Worker)      |
|                                 |           +----------------+----------------+
| - Domain Query & Stats API      |                            |
| - Cryptographic Proof Verifier  |       +--------------------+--------------------+
| - Health & Telemetry Endpoints  |       |                                         |
+----------------+----------------+       v                                         v
                 |               +------------------+                     +------------------+
                 |               |   IPFS Storage   |                     | Ethereum Sepolia |
                 |               | (Batch Tarballs) |                     | (Anchor Contract)|
                 |               +------------------+                     +------------------+
                 v
+---------------------------------------------------------------------------------+
|                             USER INTERFACE (FRONTEND)                           |
|                            (Next.js 14 / TypeScript)                            |
|                                                                                 |
| - Domain Accessibility Search Bar & Autocomplete                                |
| - ISP Telemetry Cards with Confidence Indicators & Failure Technique Badges     |
| - Curated Contextual Articles (Title, Source, Date, Link) with Confidence Labels|
| - One-Click On-Chain Cryptographic Proof Verification Modal                     |
+---------------------------------------------------------------------------------+
```

---

## 4. Data Sources

1. **OONI (Open Observatory of Network Interference)**
   - *Role*: Primary source for decentralized active measurement tests (`web_connectivity`).
   - *Key Telemetry*: Resolver responses, TCP handshake latency, TLS negotiation certificates, HTTP response status codes and body lengths.
2. **Citizen Lab Test Lists (Global and India Specific)**
   - *Role*: Curated baseline list of domains covering news, civil society, technology, education, and sensitive social topics, excluding non-permissible content.
3. **Censored Planet & Geneva / Hyperquack**
   - *Role*: Server-side and vantage-point measurements identifying middlebox signatures and packet drops.
4. **IODA (Internet Outage Detection and Analysis)**
   - *Role*: Macro-level routing and telescope monitoring to confirm or rule out broad regional Internet outages vs. targeted domain filtering.
5. **Lumen Database**
   - *Role*: Public index of legal takedown demands and copyright/regulatory removal requests.
6. **Threat Intelligence Feeds (e.g. URLhaus, Abuse.ch)**
   - *Role*: Automated tagging of domains blocked primarily due to malicious behavior (phishing, malware distribution, C2 infrastructure) rather than political/speech censorship.
7. **News & Public Reporting APIs**
   - *Role*: Retrieval of top 5 relevant reporting links (metadata only: title, publisher, date, url) linked to target domains.

---

## 5. Analytical Engine & Verdict Heuristics

For each domain across an autonomous system (ASN) in a measurement window:
- **DNS Blocking**: Flagged when probe DNS query returns an unallocated IP, localhost (127.0.0.1), ISP block page landing IP (e.g., standard known Airtel/Jio redirect IPs), NXDOMAIN, or differs markedly from control resolvers (e.g. Cloudflare 1.1.1.1, Google 8.8.8.8).
- **TCP Disruption**: Flagged when initial SYN packets are answered with immediate TCP RST injected by a middlebox or drop indefinitely without SYN-ACK, while control vantage points connect normally.
- **TLS / SNI Disruption**: Flagged when TCP connects successfully but TLS ClientHello containing the target SNI triggers a RST or abrupt timeout before Certificate exchange.
- **HTTP Block Page**: Flagged when an HTTP response returns known block notice text, title tags, or redirects to statutory warning landing pages.
- **Confidence Scoring**: Weighted by sample volume, consistency ratio across distinct probes within the same ASN, and temporal stability over a 24-hour evaluation window.

---

## 6. Smart Contract Anchoring Design

- **Batch Generation**: Daily or hourly measurement summaries are bundled as a canonical JSON format, hashed, and uploaded to IPFS.
- **Merkle Tree Construction**: The individual measurement IDs and hashes form leaves in a binary Merkle tree.
- **Smart Contract (`EvidenceAnchor.sol`)**:
  - Maintains a mapping of `batchId => (merkleRoot, ipfsCid, timestamp, recordCount)`.
  - Accessible via standard Sepolia JSON-RPC for verification by client browsers.
  - Verifier utility allows any user to provide a single measurement record and its Merkle inclusion proof to confirm on-chain authenticity in seconds.

---

## 7. Open Technical Questions

1. **Probe Vantage Point Diversity in Rural vs. Metro Circles**: How should confidence scores weigh telecom circles (e.g., Maharashtra vs. Delhi vs. Karnataka) where ISP filtering policies exhibit intra-AS variations?
2. **Encrypted Client Hello (ECH) Adoption**: As browsers and origins adopt ECH, will middlebox filtering shift predominantly toward IP-level null routing or DNS tampering?
3. **Dynamic IPFS Pinning Lifecycle**: What automated retention strategy balances long-term availability on IPFS with decentralized storage pinning costs?
