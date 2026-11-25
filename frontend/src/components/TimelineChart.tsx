"use client";

import React from "react";

interface TimelinePoint {
  date: string;
  total: number;
  anomalies: number;
  accessible: number;
}

interface TimelineChartProps {
  timeline: TimelinePoint[];
}

export default function TimelineChart({ timeline }: TimelineChartProps) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="p-6 text-center text-sm text-slate-500 border border-slate-800 rounded-xl bg-slate-900/40">
        No historical timeline telemetry available for this domain.
      </div>
    );
  }

  // Calculate max scale for SVG visualization
  const maxVal = Math.max(...timeline.map((t) => t.total), 1);

  return (
    <div className="p-5 border border-slate-800 rounded-xl bg-slate-900/50 shadow-md">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
          Daily Telemetry Distribution
        </h3>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-emerald-500/80" />
            <span className="text-slate-400">Accessible Responses</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-rose-500/80" />
            <span className="text-slate-400">Measured Anomalies</span>
          </div>
        </div>
      </div>

      <div className="h-44 flex items-end gap-2 pt-4 px-2 border-b border-slate-800 overflow-x-auto">
        {timeline.map((point) => {
          const accHeight = Math.round((point.accessible / maxVal) * 120);
          const anomHeight = Math.round((point.anomalies / maxVal) * 120);

          return (
            <div key={point.date} className="flex-1 min-w-[36px] flex flex-col items-center gap-1 group">
              <div className="w-full max-w-[28px] flex flex-col items-center justify-end h-[120px]">
                {/* Anomalies bar (top) */}
                {point.anomalies > 0 && (
                  <div
                    style={{ height: `${Math.max(4, anomHeight)}px` }}
                    className="w-full bg-rose-500/80 hover:bg-rose-400 rounded-t-sm transition-all"
                    title={`${point.date}: ${point.anomalies} anomalies`}
                  />
                )}
                {/* Accessible bar (bottom) */}
                {point.accessible > 0 && (
                  <div
                    style={{ height: `${Math.max(4, accHeight)}px` }}
                    className="w-full bg-emerald-500/80 hover:bg-emerald-400 rounded-b-sm transition-all"
                    title={`${point.date}: ${point.accessible} accessible`}
                  />
                )}
              </div>
              <span className="text-[10px] text-slate-500 font-mono rotate-45 md:rotate-0 mt-1 whitespace-nowrap">
                {point.date.slice(5)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
