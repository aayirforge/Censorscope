# NEEDS LEGAL REVIEW - DO NOT RELY ON THIS DOCUMENT AS LEGAL ADVICE

# CensorScope Volunteer Probe Operator Consent Agreement

> [!WARNING]
> **NEEDS LEGAL REVIEW**: This consent text has NOT been reviewed by legal counsel. Nothing in this text constitutes legal protection, immunity, or advice. Before participating as a probe operator, **consult a lawyer or a digital rights organisation**.

---

By initializing and running a CensorScope volunteer probe, you acknowledge and agree to the following terms:

### 1. Voluntary Participation
- Your participation as a network probe operator is entirely voluntary.
- You confirm that you have authorization to run network measurements on the internet connection to which the probe is attached.

### 2. Nature of Telemetry
- The probe will periodically perform automated DNS resolution, TCP handshakes, TLS SNI handshakes, and HTTP GET requests to domains included in open censorship testing lists (such as the Citizen Lab test lists).
- Some of the queried domains may be restricted, controversial, or blocked in your local jurisdiction.

### 3. Risk Acknowledgement
- In certain jurisdictions, connecting to blocked or restricted domains may attract surveillance or scrutiny from Internet Service Providers or regulatory bodies.
- You acknowledge that CensorScope does **not** provide legal defense, immunity, or liability coverage. You are advised to **consult a lawyer or a digital rights organisation** if you have concerns regarding network monitoring laws in your jurisdiction.

### 4. Data Handling & Cryptographic Signing
- Telemetry measurements submitted by your probe will be digitally signed using your probe's private Ed25519 key.
- Measurement summaries and cryptographic hashes will be published openly for public interest research and may be anchored to decentralized public ledgers.
- CensorScope does not persistently store or publish your physical IP address.
