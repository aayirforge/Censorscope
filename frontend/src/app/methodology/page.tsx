import React from "react";
import Link from "next/link";

export default function MethodologyPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="border-b border-slate-800 pb-5">
          <Link href="/" className="text-sm text-indigo-400 hover:text-indigo-300 mb-2 inline-block">
            ← Back to CensorScope Observatory
          </Link>
          <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            CensorScope Methodology & Classification Standards
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            How CensorScope ingests, attributes, classifies, checks live reachability, and anchors telemetry.
          </p>
        </div>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">1. Data Sources & Ingestion</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            CensorScope consumes standardized open measurement telemetry from the Open Observatory of Network Interference (OONI) and authorized volunteer probes operating across Indian Autonomous System Numbers (ASNs), including Reliance Jio (AS55836), Bharti Airtel (AS9498), and Vodafone Idea (AS45609).
          </p>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">2. Verdict Classification Rules (Historical India DB)</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            To prevent false positives and transient network noise from creating inaccurate censorship verdicts, CensorScope enforces strict temporal and concentration thresholds:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-slate-300">
            <li>
              <strong className="text-white">Blocked</strong>: Requires $\ge 3$ anomalous measurements, across $\ge 2$ distinct measurement days, with a technique concentration $\ge 60\%$.
            </li>
            <li>
              <strong className="text-white">Likely Blocked</strong>: Anomaly detected with consistent indicators, but spanning fewer than 2 distinct days.
            </li>
            <li>
              <strong className="text-white">Inconclusive</strong>: Sparse or conflicting anomalous signals that fail concentration thresholds.
            </li>
            <li>
              <strong className="text-white">Accessible</strong>: Zero anomalous measurements across valid control checks.
            </li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">3. Universal Live Checks (Any Domain)</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            When any domain is searched, CensorScope executes an asynchronous diagnostic pipeline:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-slate-300">
            <li>
              <strong className="text-white">A. Registration Check</strong>: Authoritative DNS query (NS, SOA, A, AAAA) cross-checked with DNS-over-HTTPS (DoH). Queries authoritative TLD RDAP registries via IANA bootstrap. Reports REGISTERED, APPEARS_UNREGISTERED, or UNKNOWN.
            </li>
            <li>
              <strong className="text-white">B. Live Reachability Diagnosis</strong>: Sandboxed execution through SSRF-hardened client enforcing non-public IP rejection, IP pinning, TCP handshake on ports 80/443, TLS SNI validation, and HTTP response fingerprinting. Response bodies are discarded immediately.
            </li>
            <li>
              <strong className="text-white">C. Global Interference Telemetry</strong>: Queries public OONI aggregation API across all country codes (probe_cc) over the preceding 30 days. Requires $\ge 5$ measurements per country to display.
            </li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">4. Cryptographic Evidence Anchoring</h2>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg text-sm text-slate-300 leading-relaxed">
            Batches of standardized canonical RFC-8785 JSON records are hashed into a SHA-256 Merkle tree and anchored on EVM smart contracts (EvidenceRegistry), providing permanent cryptographic proof of measurement integrity.
          </div>
        </section>
      </div>
    </main>
  );
}
