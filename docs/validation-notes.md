# CensorScope Validation Methodology & Empirical Limitations

## 1. Transparency & Audit Notice Regarding Prior Benchmarking

In an earlier preliminary test run of `scripts/validate_verdicts.py`, an offline fallback generator dynamically synthesized measurement signals using `expected_status` as a parameter when the PostgreSQL container was unreachable. This caused `expected_status` to inadvertently dictate the mock measurement features, generating an artificial 100% precision and 100% recall result. 

**That preliminary 100% metric was completely invalid as an empirical measurement of real-world accuracy.**

In this audited revision:
- **Zero Mock Data / Zero Fallback**: The validation script reads strictly from authentic, empirical network telemetry ingested from OONI probes into PostgreSQL.
- **Strict Parameter Isolation**: `expected_status` is never accessed, passed to, or utilized by the measurement retrieval or verdict engine. It is strictly used as an evaluation label to grade predictions after they are independently computed.
- **Separation of Insufficient Data**: Domains with sparse measurements are explicitly classified under **Coverage**, rather than artificially penalized or counted as correct.

---

## 2. Empirical Methodology

The validation pipeline assesses domain reachability through active network telemetry collected across Indian Autonomous Systems (ASNs):
1. **Target Evaluation Set**: 60 curated domains drawn from Citizen Lab Global and India test lists, plus verified security controls (URLhaus).
2. **Measurement Window**: Active telemetry spanning at least the preceding 30 days from OONI `web_connectivity` tests in India (`probe_cc=IN`).
3. **Multi-ISP Verdict Engine**: Evaluates empirical anomaly ratios, multi-day temporal coverage, signal consistency (DNS tampering, TCP RST injection, HTTP block page redirection, TLS handshake resets), and control agreement.
4. **Cross-ISP Aggregation**: Domains experiencing blocking on specific providers while reachable on others are classified explicitly as **`Blocked on some ISPs`**.

---

## 3. Critical Limitations of the 60-Domain Benchmark

Readers and researchers must not interpret benchmark metrics on this 60-domain callset as a generalized measure of internet censorship across all web traffic:

### A. Heavy Selection Bias
The Citizen Lab test lists intentionally curate politically sensitive domains, independent news organizations, human rights portals, circumvention/VPN providers, and copyright-infringing file-sharing networks. They do not represent a random or uniform sample of typical Internet browsing in India.

### B. Vantage Point & Probe Distribution Skew
OONI probe measurements in India rely on volunteer hardware and software probes. Telemetry is heavily concentrated in major metro circles (Karnataka, Maharashtra, Delhi NCR) and major national transit networks (Reliance Jio AS55836, Bharti Airtel AS45609, ACT Fibernet AS24309, and Vodafone Idea AS134106). Tier-2/Tier-3 regional ISPs and state-run enterprise circles often have zero or sporadic observations.

### C. CDN Evasion & Dynamic Blocking Granularity
Many major international domains (e.g. Wikipedia, Reddit, Cloudflare-hosted properties) utilize shared Anycast IP addresses and dynamic CDNs. In India, ISP blocks implemented via DNS tampering (e.g. returning NXDOMAIN or synthetic block page IPs) can be bypassed if the probe uses DNS-over-HTTPS (DoH), whereas SNI-based middlebox filtering drops the TLS ClientHello regardless of DNS resolver. Consequently, probes using custom DNS may report a site as accessible even while standard residential subscribers on default ISP resolvers experience blocking.

### D. Separation of Security Feeds
Security intelligence domains (e.g., `eicar.org`, `phishing-test.org`) are designed to trigger network defenses (antivirus, perimeter firewalls, or browser security warnings). Grouping them into general speech censorship would distort both civil society monitoring and cybersecurity defense telemetry. CensorScope isolates malware controls into a distinct reporting category.

### E. Coverage vs. Accuracy
A system reporting 100% precision on only 5 domains with sufficient data has high fidelity but low coverage. Reporting coverage alongside precision and recall is essential to avoid overstating analytical visibility.
