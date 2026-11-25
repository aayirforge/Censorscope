"use client";

import React from "react";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Globe2,
  ExternalLink,
  ShieldAlert,
  Server,
  Lock,
  Search,
  Activity,
  AlertOctagon,
} from "lucide-react";

interface LiveCheckProps {
  checkData: any;
}

const COUNTRY_MAP: Record<string, { name: string; flag: string }> = {
  IN: { name: "India", flag: "🇮🇳" },
  US: { name: "United States", flag: "🇺🇸" },
  RU: { name: "Russia", flag: "🇷🇺" },
  IR: { name: "Iran", flag: "🇮🇷" },
  CN: { name: "China", flag: "🇨🇳" },
  GB: { name: "United Kingdom", flag: "🇬🇧" },
  DE: { name: "Germany", flag: "🇩🇪" },
  FR: { name: "France", flag: "🇫🇷" },
  TR: { name: "Turkey", flag: "🇹🇷" },
  BR: { name: "Brazil", flag: "🇧🇷" },
  ID: { name: "Indonesia", flag: "🇮🇩" },
  PK: { name: "Pakistan", flag: "🇵🇰" },
  BD: { name: "Bangladesh", flag: "🇧🇩" },
  MM: { name: "Myanmar", flag: "🇲🇲" },
  AE: { name: "United Arab Emirates", flag: "🇦🇪" },
  SA: { name: "Saudi Arabia", flag: "🇸🇦" },
  EG: { name: "Egypt", flag: "🇪🇬" },
  CA: { name: "Canada", flag: "🇨🇦" },
  AU: { name: "Australia", flag: "🇦🇺" },
  JP: { name: "Japan", flag: "🇯🇵" },
};

function formatCountry(code: string, name?: string) {
  const upper = (code || "").toUpperCase();
  const info = COUNTRY_MAP[upper];
  if (info) {
    return `${info.flag} ${info.name} (${upper})`;
  }
  return name ? `${name} (${upper})` : upper;
}

export default function LiveCheckResultCard({ checkData }: LiveCheckProps) {
  if (!checkData) return null;

  const {
    domain,
    registration,
    reachability_now,
    countries,
    countries_summary,
    india_isp,
    reasons,
    limitations,
  } = checkData;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "REGISTERED":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" /> Registered
          </span>
        );
      case "APPEARS_UNREGISTERED":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" /> Appears Unregistered
          </span>
        );
      default:
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1.5">
            <HelpCircle className="w-3.5 h-3.5" /> Unknown Registration Status
          </span>
        );
    }
  };

  const getReachabilityBadge = (status: string) => {
    switch (status) {
      case "REACHABLE":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" /> Accessible Right Now
          </span>
        );
      case "BLOCK_PAGE":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" /> ISP Blockpage Intercepted
          </span>
        );
      case "DNS_FAILURE":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5" /> DNS Resolution Failed
          </span>
        );
      case "TCP_FAILURE":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5" /> TCP Connection Failed
          </span>
        );
      case "TLS_FAILURE":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" /> TLS Handshake Failed
          </span>
        );
      case "NON_PUBLIC_IP":
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30 flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5" /> Non-Public / Private IP
          </span>
        );
      default:
        return (
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1.5">
            <HelpCircle className="w-3.5 h-3.5" /> {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* 3 Core Questions Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Card A: Domain Registration Status */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/90 shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                A. Registration Check
              </h3>
            </div>
            {getStatusBadge(registration?.status)}
          </div>

          <div className="space-y-2 text-xs text-slate-300">
            <p className="bg-slate-950/70 p-3 rounded-xl border border-slate-800/80 leading-relaxed">
              {registration?.evidence}
            </p>

            {registration?.registrar_name && (
              <div className="text-slate-400">
                Registrar: <strong className="text-slate-200">{registration.registrar_name}</strong>
              </div>
            )}
            {registration?.expiration_date && (
              <div className="text-slate-400">
                Registry Expiry: <strong className="text-slate-200">{registration.expiration_date}</strong>
              </div>
            )}
            {registration?.ns_records && registration.ns_records.length > 0 && (
              <div className="text-slate-400">
                Authoritative Nameservers:{" "}
                <span className="text-slate-200 font-mono text-[11px]">
                  {registration.ns_records.slice(0, 3).join(", ")}
                </span>
              </div>
            )}

            {/* Outbound Registrar Links for APPEARS_UNREGISTERED */}
            {registration?.status === "APPEARS_UNREGISTERED" && registration?.registrar_links && (
              <div className="pt-2 space-y-2">
                <p className="text-[11px] font-semibold text-amber-400/90">
                  Verify availability directly with independent registrars:
                </p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(registration.registrar_links).map(([name, url]) => (
                    <a
                      key={name}
                      href={url as string}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-700/80 rounded-lg text-[11px] text-indigo-300 inline-flex items-center gap-1 transition-colors"
                    >
                      {name} <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            <p className="text-[11px] text-slate-500 italic pt-1 border-t border-slate-800/60">
              {registration?.disclaimer}
            </p>
          </div>
        </div>

        {/* Card B: Live Reachability Right Now */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/90 shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                B. Live Reachability Now
              </h3>
            </div>
            {getReachabilityBadge(reachability_now?.status)}
          </div>

          <div className="space-y-2 text-xs text-slate-300">
            <p className="bg-slate-950/70 p-3 rounded-xl border border-slate-800/80 leading-relaxed">
              {reachability_now?.evidence}
            </p>

            <div className="grid grid-cols-2 gap-2 pt-1 text-[11px]">
              <div className="p-2 rounded-lg bg-slate-950/40 border border-slate-800/60">
                <span className="text-slate-500 block">Resolved Public IP:</span>
                <span className="font-mono text-slate-200">
                  {reachability_now?.resolved_ip || "None / Blocked"}
                </span>
              </div>
              <div className="p-2 rounded-lg bg-slate-950/40 border border-slate-800/60">
                <span className="text-slate-500 block">Failing Layer:</span>
                <span className="font-semibold text-slate-200">
                  {reachability_now?.failing_layer || "None (Reachable)"}
                </span>
              </div>
              {reachability_now?.tls_version && (
                <div className="p-2 rounded-lg bg-slate-950/40 border border-slate-800/60">
                  <span className="text-slate-500 block">TLS Protocol:</span>
                  <span className="text-slate-200">{reachability_now.tls_version}</span>
                </div>
              )}
              {reachability_now?.http_status && (
                <div className="p-2 rounded-lg bg-slate-950/40 border border-slate-800/60">
                  <span className="text-slate-500 block">HTTP Response Code:</span>
                  <span className="text-slate-200 font-semibold">{reachability_now.http_status}</span>
                </div>
              )}
            </div>

            <p className="text-[11px] text-slate-400 flex items-center gap-1.5 pt-1 border-t border-slate-800/60">
              <Server className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
              <span><strong>Vantage Point:</strong> {reachability_now?.vantage}</span>
            </p>
          </div>
        </div>
      </div>

      {/* Card C: Global Interference & Country Breakdown */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/90 shadow-lg space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              C. Where It Is Not Accessible & Why (Global & Regional Breakdown)
            </h3>
          </div>
          {countries_summary && (
            <span className="text-xs text-slate-400">
              {countries_summary.countries_observed} countries observed ({countries_summary.total_measurements} measurements)
            </span>
          )}
        </div>

        {/* Reasons & Diagnosed Explanation */}
        {reasons && reasons.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Diagnosed Reasons & Technical Findings
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {reasons.map((r: any, idx: number) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-indigo-300 capitalize">
                      {r.label}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        r.confidence === "High"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : r.confidence === "Medium"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                          : "bg-slate-800 text-slate-400 border border-slate-700"
                      }`}
                    >
                      {r.confidence} Confidence
                    </span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {r.description}
                  </p>
                  <p className="text-[10px] text-slate-500 italic">
                    Evidence: {r.evidence}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Country Breakdown Table */}
        {countries && countries.length > 0 ? (
          <div className="space-y-2 pt-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Country-Level OONI Telemetry (Last 30 Days)
            </h4>
            <div className="overflow-x-auto rounded-xl border border-slate-800/80">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950/90 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-4">Country</th>
                    <th className="py-2.5 px-4">Anomaly Rate</th>
                    <th className="py-2.5 px-4">Sample Size</th>
                    <th className="py-2.5 px-4">Observed Techniques</th>
                    <th className="py-2.5 px-4">Confirmed Blocks</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                  {countries.map((c: any) => (
                    <tr key={c.country_code} className="hover:bg-slate-900/40">
                      <td className="py-2 px-4 font-semibold text-slate-200">
                        {formatCountry(c.country_code, c.country_name)}
                      </td>
                      <td className="py-2 px-4">
                        <span
                          className={`font-semibold ${
                            c.anomaly_rate >= 0.5
                              ? "text-rose-400"
                              : c.anomaly_rate > 0.1
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {Math.round(c.anomaly_rate * 100)}% ({c.anomaly_count}/{c.measurement_count})
                        </span>
                      </td>
                      <td className="py-2 px-4 text-slate-400">
                        {c.measurement_count} runs
                      </td>
                      <td className="py-2 px-4">
                        <div className="flex flex-wrap gap-1">
                          {c.failure_types && c.failure_types.length > 0 ? (
                            c.failure_types.map((ft: string) => (
                              <span
                                key={ft}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono"
                              >
                                {ft}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500 text-[11px]">Normal responses</span>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-4 text-slate-400">
                        {c.confirmed_count > 0 ? (
                          <span className="text-rose-400 font-semibold">{c.confirmed_count}</span>
                        ) : (
                          "0"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-xs text-slate-400 italic">
            {countries_summary?.notice ||
              "No measurements from other countries are available for this domain. OONI primarily measures domains on test lists."}
          </div>
        )}

        {/* Local India ISP Breakdown if present */}
        {india_isp && (
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2 pt-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                India Per-ISP Ground Truth Verdict
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                Overall: {india_isp.verdict} (Confidence: {Math.round(india_isp.confidence * 100)}%)
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
              {india_isp.isps?.map((isp: any) => (
                <div key={isp.asn} className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="font-semibold text-slate-200 block">{isp.isp}</span>
                  <span className="text-slate-400 block text-[10px]">{isp.verdict}</span>
                  <span className="text-[10px] text-slate-500">{isp.sample_size} runs &bull; {isp.dominant_technique || "no anomaly"}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Limitations Panel */}
      {limitations && limitations.length > 0 && (
        <div className="p-5 rounded-xl border border-slate-800/80 bg-slate-950/60 text-xs space-y-2">
          <h4 className="font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            Limitations & Transparency Note
          </h4>
          <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px] leading-relaxed">
            {limitations.map((lim: string, idx: number) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
