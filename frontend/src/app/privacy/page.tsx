import React from "react";
import Link from "next/link";

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="border-b border-slate-800 pb-5">
          <Link href="/" className="text-sm text-indigo-400 hover:text-indigo-300 mb-2 inline-block">
            ← Back to CensorScope Observatory
          </Link>
          <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            Privacy & Zero-Linkage Architecture
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            How CensorScope protects user search queries, live check requests, and volunteer probe operators.
          </p>
        </div>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">1. Zero Search Linkage</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            When you search for or check a domain on CensorScope:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-slate-300">
            <li>We do NOT store your client IP address in association with searched or checked domains.</li>
            <li>Client IP addresses are evaluated solely in transient memory for sliding-window abuse prevention and discarded.</li>
            <li>HTTP server access logs redact all `/api/v1/domain/*` and `/api/v1/check/*` query paths.</li>
            <li>Cache keys use privacy-preserving HMAC-SHA256 with an environment secret (`CACHE_HMAC_SECRET`), preventing rainbow-table discovery of checked domains.</li>
            <li>No third-party tracking scripts, advertising trackers, or analytics cookies are embedded.</li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">2. Live Check Safety & Data Retention</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            During on-demand live reachability checks:
          </p>
          <ul className="list-disc pl-5 space-y-2 text-sm text-slate-300">
            <li>We do NOT persist or store remote HTTP response bodies; streams are discarded immediately.</li>
            <li>Connections are restricted strictly to TCP ports 80 and 443 through an isolated network sandbox.</li>
            <li>Per-domain cooldowns (10 minutes) prevent repetitive scanning of target hosts.</li>
          </ul>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-bold text-indigo-300">3. Volunteer Probe Privacy</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            Volunteer network probes submit cryptographically signed telemetry reports using Ed25519 public keys. The physical IP address and personal geolocation of volunteer probes are never exposed in public feeds or stored in on-chain evidence batches.
          </p>
        </section>
      </div>
    </main>
  );
}
