"use client";

import React from "react";
import { Info, HelpCircle } from "lucide-react";

interface ISPVerdict {
  asn: number;
  isp_name: string;
  country_name?: string;
  country_code?: string;
  verdict: string;
  category?: string;
  confidence: number;
  evidence_count: number;
  primary_technique: string | null;
  technique_labels?: string[];
  explanation: any;
}

interface ISPTableProps {
  ispVerdicts: ISPVerdict[];
  onSelectExplanation: (explanation: any, ispName: string) => void;
}

const KNOWN_ISP_DATA: Record<number, { name: string; country: string; flag: string }> = {
  24560: { name: "Bharti Airtel", country: "India", flag: "🇮🇳" },
  55836: { name: "Reliance Jio", country: "India", flag: "🇮🇳" },
  24309: { name: "ACT Fibernet", country: "India", flag: "🇮🇳" },
  136286: { name: "RailTel", country: "India", flag: "🇮🇳" },
  136311: { name: "Vodafone Idea", country: "India", flag: "🇮🇳" },
  45609: { name: "Bharti Airtel", country: "India", flag: "🇮🇳" },
  9829: { name: "BSNL", country: "India", flag: "🇮🇳" },
  17813: { name: "MTNL", country: "India", flag: "🇮🇳" },
  4755: { name: "Tata Communications", country: "India", flag: "🇮🇳" },
  18101: { name: "Reliance Communications", country: "India", flag: "🇮🇳" },
  24186: { name: "Hathway", country: "India", flag: "🇮🇳" },
};

function getIspDetails(asn: number, rawName: string, rawCountry?: string) {
  const known = KNOWN_ISP_DATA[asn];
  const displayName = known && (!rawName || rawName === `AS${asn}` || rawName.startsWith("ISP-"))
    ? `${known.name} (${rawName})`
    : rawName;
  const country = rawCountry || (known ? known.country : "India");
  const flag = known ? known.flag : (country === "India" ? "🇮🇳" : "🌐");
  return { displayName, country, flag };
}

const TECHNIQUE_DESCRIPTIONS: Record<string, string> = {
  dns_tampering: "DNS Tampering: Resolvers return NXDOMAIN, bogus loopback IPs, or sinkhole records.",
  tcp_reset: "TCP Reset / Disruption: Network middlebox injects TCP RST or drops SYN packets.",
  tls_sni_filtering: "TLS / SNI Disruption: Handshake terminated upon observing Server Name Indication header.",
  http_block_page: "HTTP Block Page: Intercepted and served statutory block notice or ISP landing page.",
  http_injection: "HTTP Injection: Middlebox injects or alters HTTP response packets in transit.",
  ip_blocking: "IP Blocking: All direct connections to target IP addresses time out; DNS resolved cleanly.",
  unknown: "Unknown: Anomalous response pattern without a distinct known censorship signature.",
};

export default function ISPTable({ ispVerdicts, onSelectExplanation }: ISPTableProps) {
  if (!ispVerdicts || ispVerdicts.length === 0) {
    return (
      <div className="p-6 text-center text-sm text-slate-500 border border-slate-800 rounded-xl bg-slate-900/40">
        No per-ISP telemetry records available for this domain.
      </div>
    );
  }

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "Blocked":
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">Blocked</span>;
      case "Likely blocked":
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">Likely blocked</span>;
      case "Accessible":
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Accessible</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">Insufficient data</span>;
    }
  };

  const renderTechniques = (labels?: string[], primary?: string | null) => {
    const list = labels && labels.length > 0 ? labels : (primary ? [primary.toLowerCase().replace(/\s+/g, "_")] : []);
    if (list.length === 0) return <span className="text-slate-500 text-xs">-</span>;

    return (
      <div className="flex flex-wrap gap-1">
        {list.map((tech) => {
          const desc = TECHNIQUE_DESCRIPTIONS[tech] || `Interference mechanism: ${tech}`;
          const formatted = tech.replace(/_/g, " ");
          return (
            <span
              key={tech}
              title={desc}
              className="group relative cursor-help px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-indigo-300 text-xs font-mono inline-flex items-center gap-1"
            >
              <span>{formatted}</span>
              <HelpCircle className="w-2.5 h-2.5 text-slate-400 opacity-60 group-hover:opacity-100" />
            </span>
          );
        })}
      </div>
    );
  };

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50 shadow-md">
      <table className="w-full text-left text-sm text-slate-300">
        <thead className="bg-slate-950/80 text-xs font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800">
          <tr>
            <th className="py-3.5 px-4">ISP / Network</th>
            <th className="py-3.5 px-4">Country</th>
            <th className="py-3.5 px-4">ASN</th>
            <th className="py-3.5 px-4">Verdict</th>
            <th className="py-3.5 px-4">Confidence</th>
            <th className="py-3.5 px-4">Observed Technique</th>
            <th className="py-3.5 px-4 text-right">Evidence Count</th>
            <th className="py-3.5 px-4 text-center">Analysis</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-normal">
          {ispVerdicts.map((isp) => {
            const { displayName, country, flag } = getIspDetails(isp.asn, isp.isp_name, isp.country_name);
            return (
              <tr key={isp.asn} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-4 font-medium text-white">{displayName}</td>
                <td className="py-3 px-4">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800/80 border border-slate-700/60 text-slate-200">
                    <span>{flag}</span>
                    <span>{country}</span>
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-400 font-mono text-xs">AS{isp.asn}</td>
                <td className="py-3 px-4">{getVerdictBadge(isp.verdict)}</td>
              <td className="py-3 px-4">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-slate-200">{Math.round(isp.confidence * 100)}%</span>
                  <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-full ${
                        isp.verdict === "Blocked"
                          ? "bg-rose-500"
                          : isp.verdict === "Likely blocked"
                          ? "bg-amber-500"
                          : isp.verdict === "Accessible"
                          ? "bg-emerald-500"
                          : "bg-slate-600"
                      }`}
                      style={{ width: `${Math.round(isp.confidence * 100)}%` }}
                    />
                  </div>
                </div>
              </td>
              <td className="py-3 px-4">{renderTechniques(isp.technique_labels, isp.primary_technique)}</td>
              <td className="py-3 px-4 text-right font-mono text-xs text-slate-300">{isp.evidence_count}</td>
              <td className="py-3 px-4 text-center">
                <button
                  onClick={() => onSelectExplanation(isp.explanation, isp.isp_name)}
                  className="p-1.5 text-slate-400 hover:text-indigo-400 rounded-lg hover:bg-slate-800/80 transition-colors cursor-pointer"
                  title="View analytical factors"
                >
                  <Info className="w-4 h-4" />
                </button>
              </td>
            </tr>
          );
        })}
        </tbody>
      </table>
    </div>
  );
}
