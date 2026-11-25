# NEEDS LEGAL REVIEW - DO NOT RELY ON THIS DOCUMENT AS LEGAL ADVICE

# CensorScope Volunteer Probe Operator Safety Guide

> [!WARNING]
> **NEEDS LEGAL REVIEW**: This document has NOT been reviewed by legal counsel. Nothing in this guide constitutes legal advice, legal counsel, or an assessment of liability under the laws of India or any other jurisdiction. Before running a network probe or contributing telemetry, **consult a lawyer or a digital rights organisation**.

**Audience**: Individuals and researchers considering operating network telemetry probes.  
**Version**: 1.0.0 (Pre-Review Draft)

---

## 1. Operating Environment & Network Isolation

### Dedicated Hardware
- Run probes on **dedicated hardware** (e.g. Raspberry Pi, spare mini-PC, or isolated virtual machine).
- **Never** run volunteer probes on a primary personal device that stores private emails, banking credentials, or personal files.
- Enable full-disk encryption (LUKS on Linux) on the device running the probe.

### Network Segmentation
- Place the probe on an **isolated guest VLAN** or separate local network segment.
- Prevent the probe from initiating connections to local intranet services, NAS storage, smart home devices, or local router administration portals.
- Use the provided containerized runner (`docker-compose.yml`) which runs as unprivileged user `nobody` (`uid 65534`), drops all Linux capabilities (`cap_drop: [ALL]`), and mounts a read-only root filesystem.

---

## 2. Telemetry Scope & Testing Boundaries

### Scope of Testing
CensorScope probes perform automated network connectivity measurements:
- Standard DNS queries to public recursive resolvers and system resolvers.
- TCP handshake latency and reset detection on port 443.
- TLS Server Name Indication (SNI) negotiation checks.
- HTTP header checks on public, open websites.

### What Probes Do NOT Do
- Probes do **NOT** intercept third-party network traffic.
- Probes do **NOT** attempt to exploit vulnerabilities or conduct denial-of-service tests.
- Probes test only the curated Citizen Lab and OONI standardized public testing lists.

---

## 3. Cryptographic Identity & Data Minimization

- **Ed25519 Signing Key**: Each probe holds a locally generated Ed25519 keypair. The public key is registered with CensorScope.
- **No Personal Identifiers in Telemetry**: Reports contain only:
  - The domain tested
  - Observed Layer 3/4/7 signals (DNS result, TCP handshake status, TLS error)
  - Autonomous System Number (ASN)
  - Nonce and timestamp
- **IP Address Minimization**: The backend observatory discards client IP addresses from storage immediately after rate-limiting checks. The probe's physical IP address is not stored in the persistent measurements database or published on-chain.
