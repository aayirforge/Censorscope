"use client";

import React from "react";
import { ShieldAlert, ShieldCheck, HelpCircle, AlertTriangle, Tag, Scale } from "lucide-react";
import { VerifyResultModal } from "./VerifyResultModal";

interface VerdictCardProps {
  domain: string;
  verdict: string;
  category?: string;
  confidence: number;
  evidenceCount: number;
  lastUpdated: string;
  onOpenExplanation?: () => void;
}

export default function VerdictCard({
  domain,
  verdict,
  category,
  confidence,
  evidenceCount,
  lastUpdated,
  onOpenExplanation,
}: VerdictCardProps) {
  const getBadgeStyle = (status: string) => {
    switch (status) {
      case "Blocked":
        return {
          bg: "bg-rose-500/10 border-rose-500/30 text-rose-400",
          icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
          title: "Blocked",
          desc: "Measurements are consistent with network-level blocking across all evaluated Indian ISPs.",
        };
      case "Blocked on some ISPs":
        return {
          bg: "bg-orange-500/10 border-orange-500/30 text-orange-400",
          icon: <AlertTriangle className="w-6 h-6 text-orange-400" />,
          title: "Blocked on some ISPs",
          desc: "Measurements indicate blocking on specific ISP networks, while reachable on other providers.",
        };
      case "Likely blocked":
        return {
          bg: "bg-amber-500/10 border-amber-500/30 text-amber-400",
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          title: "Likely blocked",
          desc: "Empirical anomalies indicate probable interference or ISP-specific filtering.",
        };
      case "Accessible":
        return {
          bg: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
          icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
          title: "Accessible",
          desc: "Measurements indicate normal reachability across tested Indian networks.",
        };
      default:
        return {
          bg: "bg-slate-800/40 border-slate-700/60 text-slate-300",
          icon: <HelpCircle className="w-6 h-6 text-slate-400" />,
          title: "Insufficient data",
          desc: "Sample volume is currently too limited to establish a confident verdict.",
        };
    }
  };

  const getCategoryBadge = (cat?: string) => {
    switch (cat) {
      case "censorship_suspected":
        return {
          label: "Censorship Suspected",
          className: "bg-rose-950/60 text-rose-300 border-rose-800/60",
        };
      case "security_related":
        return {
          label: "Security-Related Blocking",
          className: "bg-amber-950/60 text-amber-300 border-amber-800/60",
        };
      case "infrastructure_failure":
        return {
          label: "Infrastructure Failure",
          className: "bg-blue-950/60 text-blue-300 border-blue-800/60",
        };
      default:
        return {
          label: "Inconclusive / Clean",
          className: "bg-slate-800/80 text-slate-300 border-slate-700",
        };
    }
  };

  const badge = getBadgeStyle(verdict);
  const catBadge = getCategoryBadge(category);

  return (
    <div className={`p-6 rounded-2xl border ${badge.bg} backdrop-blur-sm shadow-xl transition-all`}>
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 shrink-0">
            {badge.icon}
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-2xl font-bold tracking-tight text-white">{domain}</h2>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${badge.bg}`}>
                {badge.title}
              </span>
              {category && (
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium border flex items-center gap-1 ${catBadge.className}`}>
                  <Tag className="w-3 h-3" />
                  {catBadge.label}
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-slate-400">{badge.desc}</p>
          </div>
        </div>
      </div>

      <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex items-center gap-4">
          <span>
            Total Evidence Records: <strong className="text-slate-200">{evidenceCount}</strong>
          </span>
          <span>
            Telemetry Window: <strong className="text-slate-200">{lastUpdated.slice(0, 10)}</strong>
          </span>
        </div>

        <div className="flex items-center gap-3">
          {onOpenExplanation && (
            <button
              onClick={onOpenExplanation}
              className="text-indigo-400 hover:text-indigo-300 font-medium hover:underline flex items-center gap-1 cursor-pointer"
            >
              How is this calculated?
            </button>
          )}
          <VerifyResultModal measurementId={1} />
        </div>
      </div>
    </div>
  );
}
