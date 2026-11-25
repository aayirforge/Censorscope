"use client";

import React, { useState } from "react";
import SearchBox from "@/components/SearchBox";
import VerdictCard from "@/components/VerdictCard";
import ISPTable from "@/components/ISPTable";
import TimelineChart from "@/components/TimelineChart";
import ExplanationPanel from "@/components/ExplanationPanel";
import LiveCheckResultCard from "@/components/LiveCheckResultCard";
import {
  Shield,
  Radio,
  CheckCircle2,
  AlertCircle,
  Scale,
  Globe2,
  Newspaper,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  Zap,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

const SAMPLE_DOMAINS = [
  "thepiratebay.org",
  "wikipedia.org",
  "thewire.in",
  "nytimes.com",
  "example.com",
  "1337x.to",
];

export default function Home() {
  const [currentDomain, setCurrentDomain] = useState<string>("");
  const [data, setData] = useState<any | null>(null);
  const [liveCheckData, setLiveCheckData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [progressMsg, setProgressMsg] = useState<string>("Analyzing domain...");
  const [error, setError] = useState<string | null>(null);

  // Explanation modal state
  const [isExpOpen, setIsExpOpen] = useState(false);
  const [expTitle, setExpTitle] = useState("");
  const [activeExp, setActiveExp] = useState<any | null>(null);

  const pollJobStatus = async (jobId: string): Promise<any> => {
    const maxAttempts = 30; // 30 seconds
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const res = await fetch(`${API_BASE}/api/v1/check/${jobId}`);
      if (!res.ok) continue;
      const job = await res.json();

      if (job.status === "completed") {
        return job.result;
      } else if (job.status === "failed") {
        throw new Error(job.error || "Live check job encountered an error.");
      } else {
        setProgressMsg(`Live diagnosis in progress (${job.progress}%)...`);
      }
    }
    throw new Error("Live check timed out. Please try again.");
  };

  const handleDomainSearch = async (domain: string) => {
    setIsLoading(true);
    setError(null);
    setData(null);
    setLiveCheckData(null);
    setCurrentDomain(domain);
    setProgressMsg("Checking registration, reachability, and global interference...");

    try {
      // 1. Submit Live Check Job (Works for ANY domain)
      const checkRes = await fetch(`${API_BASE}/api/v1/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });

      if (!checkRes.ok) {
        const errJson = await checkRes.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server returned HTTP ${checkRes.status}`);
      }

      const initData = await checkRes.json();
      let liveResult: any = null;

      if (initData.status === "completed" && initData.cached) {
        // Immediate cached retrieval
        const pollRes = await fetch(`${API_BASE}/api/v1/check/${initData.job_id}`);
        const job = await pollRes.json();
        liveResult = job.result;
      } else {
        // Poll job queue
        liveResult = await pollJobStatus(initData.job_id);
      }

      setLiveCheckData(liveResult);

      // 2. Also check if local stored India OONI historical data exists
      try {
        const histRes = await fetch(`${API_BASE}/api/v1/domain/${encodeURIComponent(domain)}`);
        if (histRes.ok) {
          const histJson = await histRes.json();
          setData(histJson);
        }
      } catch (e) {
        // Domain is not in historical dataset; live check will handle display
      }
    } catch (err: any) {
      setError(err.message || "Failed to complete domain inspection.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpenOverallExplanation = () => {
    if (!data) return;
    setExpTitle(`Overall Verdict Analysis for ${data.domain}`);
    const totalMeas = data.isp_verdicts.reduce((sum: number, v: any) => sum + v.evidence_count, 0);
    const totalAnom = data.isp_verdicts.reduce((sum: number, v: any) => sum + v.explanation.anomalies_detected, 0);
    setActiveExp({
      total_measurements: totalMeas,
      distinct_days: Math.max(...data.isp_verdicts.map((v: any) => v.explanation.distinct_days), 0),
      anomalies_detected: totalAnom,
      anomaly_ratio: totalMeas > 0 ? totalAnom / totalMeas : 0,
      dns_anomalies: data.isp_verdicts.reduce((sum: number, v: any) => sum + v.explanation.dns_anomalies, 0),
      tcp_failures: data.isp_verdicts.reduce((sum: number, v: any) => sum + v.explanation.tcp_failures, 0),
      http_failures: data.isp_verdicts.reduce((sum: number, v: any) => sum + v.explanation.http_failures, 0),
      tls_failures: data.isp_verdicts.reduce((sum: number, v: any) => sum + v.explanation.tls_failures, 0),
      primary_technique: null,
      has_strong_signature: totalAnom > 0,
      control_agreement_ratio: totalMeas > 0 ? 1 - totalAnom / totalMeas : 1,
      factors: [
        data.summary_explanation?.summary || "Aggregated multi-ISP observation.",
        `Evaluated ${data.isp_verdicts.length} Indian ISP network(s).`,
      ],
    });
    setIsExpOpen(true);
  };

  const handleOpenIspExplanation = (exp: any, ispName: string) => {
    setExpTitle(`Calculation Breakdown: ${ispName} (Domain: ${currentDomain})`);
    setActiveExp(exp);
    setIsExpOpen(true);
  };

  const getConfidenceBadge = (conf: string) => {
    switch (conf) {
      case "Confirmed order":
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Confirmed order</span>;
      case "Reported":
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">Reported</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">Unknown</span>;
    }
  };

  return (
    <main className="min-h-screen flex flex-col justify-between py-10 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
      <div className="space-y-8">
        {/* Header */}
        <div className="text-center space-y-3 pt-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold uppercase tracking-wider">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            Universal Domain Reachability & Censorship Observatory
          </div>
          <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-white">
            Censor<span className="text-indigo-400">Scope</span>
          </h1>
          <p className="max-w-xl mx-auto text-sm sm:text-base text-slate-400">
            Check any domain for public registration, live multi-layer accessibility,
            and empirical censorship telemetry across global jurisdictions and Indian ISPs.
          </p>
        </div>

        {/* Search Component */}
        <div className="space-y-3">
          <SearchBox onSearch={handleDomainSearch} isLoading={isLoading} />

          {/* Quick links */}
          <div className="flex flex-wrap items-center justify-center gap-2 text-xs text-slate-400 pt-1">
            <span className="text-slate-500">Quick inspect:</span>
            {SAMPLE_DOMAINS.map((dom) => (
              <button
                key={dom}
                onClick={() => handleDomainSearch(dom)}
                className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg transition-colors cursor-pointer"
              >
                {dom}
              </button>
            ))}
          </div>
        </div>

        {/* Loading state with progress */}
        {isLoading && (
          <div className="p-12 text-center text-slate-400 space-y-3 animate-pulse bg-slate-900/30 rounded-2xl border border-slate-800/80">
            <div className="w-10 h-10 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-sm font-medium text-slate-300">{progressMsg}</p>
            <p className="text-xs text-slate-500">
              Querying authoritative RDAP registries, performing sandboxed TCP/TLS handshakes, and aggregating OONI data.
            </p>
          </div>
        )}

        {/* Error state */}
        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-sm flex items-start gap-3">
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold">Inspection Error:</strong> {error}
            </div>
          </div>
        )}

        {/* Live Check 3-Question Results (Card A, Card B, Card C) */}
        {liveCheckData && !isLoading && (
          <div className="space-y-6 animate-in fade-in duration-200">
            <LiveCheckResultCard checkData={liveCheckData} />
          </div>
        )}

        {/* Historical Stored Telemetry Results Section (When available) */}
        {data && !isLoading && (
          <div className="space-y-6 animate-in fade-in duration-200 border-t border-slate-800/80 pt-6">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">
                Historical India ISP Multi-Probe Telemetry
              </h3>
            </div>

            {/* Overall Verdict Card */}
            <VerdictCard
              domain={data.domain}
              verdict={data.overall_verdict}
              category={data.category}
              confidence={data.confidence}
              evidenceCount={data.evidence_count}
              lastUpdated={data.last_updated}
              onOpenExplanation={handleOpenOverallExplanation}
            />

            {/* Legal & Reason Context Section */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
                  <Scale className="w-4 h-4 text-indigo-400" />
                  <h3>Why is this domain blocked? (Public Reason & Legal Context)</h3>
                </div>
                {data.legal_context && getConfidenceBadge(data.legal_context.confidence)}
              </div>

              {data.legal_context ? (
                <div className="space-y-2 text-xs text-slate-300">
                  <p className="leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                    {data.legal_context.summary}
                  </p>
                  <div className="flex flex-wrap items-center justify-between text-slate-400 pt-1">
                    <span>Source Type: <strong className="text-slate-200">{data.legal_context.source_type || "Court / Regulatory Notice"}</strong></span>
                    {data.legal_context.source_url && (
                      <a
                        href={data.legal_context.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-indigo-400 hover:underline"
                      >
                        Official Document / Primary Source <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">
                  No public reason found in our sources.
                </p>
              )}
            </div>

            {/* Per-ISP Analysis Table */}
            <div className="space-y-2">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 px-1">
                Per-ISP Accessibility & Technique Diagnostics
              </h3>
              <ISPTable
                ispVerdicts={data.isp_verdicts}
                onSelectExplanation={handleOpenIspExplanation}
              />
            </div>

            {/* Daily Timeline */}
            <TimelineChart timeline={data.timeline} />
          </div>
        )}

        {/* Empty state when no search has been performed */}
        {!data && !liveCheckData && !isLoading && !error && (
          <div className="p-10 border border-slate-800/80 rounded-2xl bg-slate-900/20 text-center space-y-3 max-w-2xl mx-auto">
            <Shield className="w-10 h-10 text-slate-600 mx-auto" />
            <h3 className="text-base font-semibold text-slate-300">Universal Domain Reachability Engine</h3>
            <p className="text-xs text-slate-500 leading-relaxed max-w-md mx-auto">
              Enter any domain above to determine whether it is registered, whether it responds to live TCP/TLS requests right now,
              and whether multi-country telemetry shows censorship in specific jurisdictions.
            </p>
          </div>
        )}
      </div>

      {/* Explanation Modal */}
      <ExplanationPanel
        isOpen={isExpOpen}
        onClose={() => setIsExpOpen(false)}
        title={expTitle}
        explanation={activeExp}
      />

      {/* Cautious Wording Disclaimer Footer */}
      <footer className="mt-16 pt-6 border-t border-slate-800/80 text-center space-y-2">
        <p className="text-xs text-slate-500 max-w-3xl mx-auto leading-relaxed">
          <strong>Cautionary Notice:</strong> Observations presented in CensorScope represent empirical network measurements.
          Live reachability checks are performed from our designated server vantage point. Status classifications indicate whether observed responses are consistent with
          blocking techniques or server downtime. They do not constitute authoritative legal verdicts, court orders, or claims regarding entity intent.
        </p>
        <p className="text-[11px] text-slate-600">
          CensorScope Research Initiative &copy; 2026. Built with Python, Next.js, and Open Telemetry.
        </p>
      </footer>
    </main>
  );
}
