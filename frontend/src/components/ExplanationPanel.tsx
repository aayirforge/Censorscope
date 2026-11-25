"use client";

import React from "react";
import { X, CheckCircle, AlertTriangle } from "lucide-react";

interface ExplanationPanelProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  explanation: {
    total_measurements: number;
    distinct_days: number;
    anomalies_detected: number;
    anomaly_ratio: number;
    dns_anomalies: number;
    tcp_failures: number;
    http_failures: number;
    tls_failures: number;
    primary_technique: string | null;
    has_strong_signature: boolean;
    control_agreement_ratio: number;
    factors: string[];
  } | null;
}

export default function ExplanationPanel({
  isOpen,
  onClose,
  title,
  explanation,
}: ExplanationPanelProps) {
  if (!isOpen || !explanation) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 text-slate-100">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-lg font-bold text-white">How is this calculated?</h3>
            <p className="text-xs text-slate-400">{title}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-4 space-y-4 max-h-[70vh] overflow-y-auto pr-1">
          {/* Metrics grid */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-slate-500">Measurements Analyzed</span>
              <p className="text-base font-bold text-white mt-0.5">{explanation.total_measurements}</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-slate-500">Temporal Coverage</span>
              <p className="text-base font-bold text-white mt-0.5">{explanation.distinct_days} distinct day(s)</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-slate-500">Empirical Anomaly Ratio</span>
              <p className="text-base font-bold text-white mt-0.5">
                {(explanation.anomaly_ratio * 100).toFixed(1)}% ({explanation.anomalies_detected}/{explanation.total_measurements})
              </p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
              <span className="text-slate-500">Control Agreement</span>
              <p className="text-base font-bold text-white mt-0.5">
                {(explanation.control_agreement_ratio * 100).toFixed(1)}%
              </p>
            </div>
          </div>

          {/* Technical signals observed */}
          <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-xl text-xs space-y-2">
            <span className="font-semibold text-slate-300">Technical Signal Breakdown:</span>
            <div className="grid grid-cols-2 gap-2 text-slate-400">
              <div>DNS Inconsistencies: <strong className="text-slate-200">{explanation.dns_anomalies}</strong></div>
              <div>TCP Handshake Drops: <strong className="text-slate-200">{explanation.tcp_failures}</strong></div>
              <div>HTTP Block / Mismatches: <strong className="text-slate-200">{explanation.http_failures}</strong></div>
              <div>TLS / SNI Failures: <strong className="text-slate-200">{explanation.tls_failures}</strong></div>
            </div>
          </div>

          {/* Factors Driving Verdict */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Decision Factors
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300">
              {explanation.factors.map((factor, idx) => (
                <li key={idx} className="flex items-start gap-2 bg-slate-800/40 p-2 rounded-lg">
                  <CheckCircle className="w-3.5 h-3.5 text-indigo-400 shrink-0 mt-0.5" />
                  <span>{factor}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="mt-5 pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
