# Design Document: Live Domain Check System

## 1. Executive Summary & Objective

CensorScope is extending its analytical capability from static, test-list-bound OONI India evaluations to on-demand, user-initiated domain health and reachability checks.

When a user submits any domain, the platform answers three foundational questions:
1. **Registration Check**: Is the domain registered on public authoritative registries, or does it appear to be unregistered (available / unclaimed)?
2. **Current Reachability Check**: Is the site accessible right now from our vantage point, or does it fail at DNS, TCP, TLS, or HTTP layers?
3. **Global Interference & Context (Country & ISP)**: If inaccessible, in which countries and ISPs is it failing, what blocking techniques are observed, and what legal or regulatory context exists?

---

## 2. Architecture & Execution Flow

```
                      +-----------------------------+
                      |       User Frontend         |
                      +--------------+--------------+
                                     | POST /api/v1/check (domain)
                                     v
                      +-----------------------------+
                      |     FastAPI Edge Gate       |
                      |  - Normalize & Punycode     |
                      |  - IANA TLD validation      |
                      |  - IP/Private/Internal drop |
                      |  - Rate Limits & Cooldown   |
                      |  - Kill-Switch Enforcement  |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                      |                      |
              v                      v                      v
     +-----------------+    +-----------------+   +--------------------+
     |   Task Queue    |    |  Cache (Redis)  |   | Job Store (Redis)  |
     | Concurrency Cap |    | HMAC-SHA256 Key |   |  Progress Status   |
     +--------+--------+    +-----------------+   +---------+----------+
              |                                             ^
              | Worker                                      |
              +----------------------+----------------------+
                                     |
    +--------------------------------+--------------------------------+
    |                                |                                |
    v                                v                                v
+----------------------+  +----------------------+  +---------------------+
| Registration Service |  | Reachability Service |  | Country Data Engine |
| - Resolver NS/SOA/A  |  | - safe_fetch sandbox |  | - OONI Aggregation |
| - DoH Cross-check    |  | - DNS -> TCP (80/443)|  |   API (probe_cc)    |
| - IANA RDAP Bootstrap|  | - TLS SNI Handshake  |  | - India Local DB    |
| - Registry RDAP 404  |  | - 1 HTTP Req + Heads |  |   (ISP verdict)     |
+-----------+----------+  +----------+-----------+  +----------+----------+
            |                        |                         |
            +------------------------+-------------------------+
                                     |
                                     v
                       +---------------------------+
                       |    Explanation Engine     |
                       | - Synthesizes A, B, and C |
                       | - Assigns Confidence      |
                       | - Produces Reason Badges  |
                       +---------------------------+
```

---

## 3. Component Design

### 3.1 Input Normalization & TLD Validation
- **Domain Normalizer**: RFC-3492 Punycode normalization for Internationalized Domain Names (IDNs).
- **IANA TLD Cache**: Downloads `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`. Cached locally and refreshed every 24 hours. Validates whether the domain ends in an authentic registered gTLD/ccTLD.
- **Rejection Rules**:
  - Rejects single-label hostnames (e.g., `localhost`).
  - Rejects IPv4/IPv6 literals.
  - Rejects private, internal, or test TLDs (`.local`, `.internal`, `.test`, `.example`, `.invalid`, `.onion`).
  - Rejects CensorScope's own infrastructure hostnames to prevent recursive loops.

### 3.2 Registration Service (`backend/services/registration.py`)
- **Dual-DNS Resolution**:
  - Local authoritative resolver queries NS, SOA, A, and AAAA records.
  - Cross-checked via DNS-over-HTTPS (DoH) via Cloudflare (`https://cloudflare-dns.com/dns-query`) or Google (`https://dns.google/resolve`) executed via `safe_fetch`.
- **RDAP Discovery & Query**:
  - Downloads and caches IANA RDAP bootstrap registry (`https://data.iana.org/rdap/dns.json`).
  - Matches the TLD to determine the authoritative registry RDAP endpoint.
  - Executes RDAP domain query with strict timeouts and exponential backoff on HTTP 429.
  - **Verdict Logic**:
    - HTTP 404 from Authoritative RDAP + DNS NXDOMAIN (or no NS/SOA) -> `APPEARS_UNREGISTERED`.
    - RDAP 200 with active status (`active`, `clientTransferProhibited`, etc.) -> `REGISTERED`.
    - Domain on `clientHold`, `serverHold`, `redemptionPeriod`, or `pendingDelete` -> `REGISTERED` with specific state note.
    - RDAP server unsupported, timeout, or rate-limited -> `UNKNOWN`.
  - **Evidence**: Explicitly includes NS records, SOA presence, RDAP status codes, expiry dates, and registrar identifiers.
  - **Mandatory Disclaimer**: *"Availability, price and restrictions (premium, reserved or pending-delete names) must be confirmed with a registrar."*

### 3.3 Reachability Service (`backend/services/reachability.py`)
- **Strict Network Sandbox**:
  - Must run via the hardened `safe_fetch` client.
  - Resolves domain IP; enforces that resolved IP is NOT loopback (`127.0.0.0/8`), RFC-1918 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), or multicast (`224.0.0.0/4`).
  - Pins connection to the validated public IP.
  - Allows ports **80** and **443** ONLY.
  - Enforces SNI during TLS handshake.
  - Limits redirects to maximum 3 hops, re-validating the resolved IP on every redirect.
  - **No Response Body Storage**: Response headers and status codes only; body is discarded immediately after reading fingerprint matches.
  - **Identifiable User-Agent**: `User-Agent: CensorScope-ReachabilityBot/1.0 (+https://censorscope.org/bot; research-probe)`
  - **Vantage Point Transparency**: Explicitly tags result: *"Checked from our server at [Hosting Region, e.g., India/Central]"*.

### 3.4 Global Country Data Engine (`backend/services/country_data.py`)
- Queries the public OONI Aggregation API (`https://api.ooni.io/api/v1/aggregation`) for `probe_cc` distribution over the last 30 calendar days for the input domain.
- Requires a minimum sample threshold (e.g., $\ge 5$ measurements) before displaying a country row.
- Extracts anomaly rates, measurement counts, and observed failure types (DNS, TCP, TLS, HTTP).
- Correlates with local CensorScope PostgreSQL India per-ISP verdict if present.
- If no OONI data exists, explicitly states: *"No measurements from other countries are available for this domain. OONI primarily monitors domains on established citizen testing lists."*

### 3.5 Third-Party Multi-Location Services Evaluation (Non-Integrated)
Per instructions, zero third-party multi-vantage probing APIs are integrated. The candidate options, terms, and cost structures are documented below for future evaluation:

| Service | Mechanism | Terms & Privacy | Cost Structure | Feasibility / Verdict |
|---|---|---|---|---|
| **RIPE Atlas** | Global volunteer hardware probe network (DNS, Ping, Traceroute, SSL). | Non-commercial research credit system; probes cannot execute full HTTP GETs to arbitrary sites to prevent probe operator liability. | Credit-based (earned by hosting probes or via academic grant). | Best fit for network-layer latency/DNS; cannot perform full application-level HTTP fetches. |
| **OONI Probe Run API** | Automated triggering of OONI web connectivity tests on volunteer mobile/desktop probes. | CC BY-NC-SA 4.0; public measurement release; probe operator consent explicit. | Free / Public Interest API; strict queue limits. | High alignment with project values; rate-limited and asynchronous (minutes to hours latency). |
| **Catchpoint / ThousandEyes** | Enterprise synthetics with hundreds of global cloud and backbone nodes. | Commercial SaaS; strict API usage terms; requires enterprise contract. | High enterprise cost (\$5,000 - \$50,000+/year). | Incompatible with open-source, non-commercial self-hosting. |
| **BrowserStack / LambdaTest** | Real device cloud in 30+ countries. | Interactive and automated Selenium/Playwright testing; terms prohibit network scanning. | \$29 - \$199/month per parallel thread. | Heavyweight, expensive, and fragile for high-volume domain checks. |

---

## 4. Abuse & Safety Architecture

1. **Concurrency Cap**: Max 10 concurrent reachability/RDAP worker tasks to prevent resource exhaustion.
2. **Per-Domain Cooldown**: When a domain is checked, its verdict is cached in Redis with an HMAC-SHA256 key:
   - Reachability: 10 minutes TTL.
   - RDAP & TLD status: 24 hours TTL.
   - OONI country aggregation: 6 hours TTL.
   Requests for the same domain during cooldown return the cached result immediately without sending outbound packets.
3. **Per-IP Rate Limiting**:
   - 10 checks per minute per IP.
   - 50 checks per hour per IP.
4. **Emergency Kill-Switch**:
   - Environment variable `ENABLE_LIVE_CHECKS=false`.
   - When disabled, live reachability returns HTTP 503 with `"Live reachability checks are currently disabled by administrator."`
5. **No IP-Domain Correlation Logging**:
   - Access logs mask client IPs; query parameters and domain paths are stripped from access logs.
   - Job IDs in Redis are random UUIDs with no reverse pointer to client IP.
6. **CAPTCHA / PoW Hook**:
   - `backend/security/pow_guard.py` provides an extensible validation hook for Cloudflare Turnstile or proof-of-work tokens when bot abuse thresholds are crossed.
