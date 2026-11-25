"use client";

import React, { useState } from "react";
import { Search, AlertCircle } from "lucide-react";

interface SearchBoxProps {
  onSearch: (domain: string) => void;
  isLoading?: boolean;
}

export function validateDomainInput(raw: string): { isValid: boolean; domain: string; error?: string } {
  if (!raw || !raw.trim()) {
    return { isValid: false, domain: "", error: "Please enter a domain name." };
  }

  let cleaned = raw.trim().toLowerCase();

  // Strip scheme if entered
  if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);
  if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);

  // Strip credentials
  if (cleaned.includes("@")) cleaned = cleaned.split("@")[1];

  // Strip path/query/fragment
  cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0];

  // Strip port
  if (cleaned.includes(":")) cleaned = cleaned.split(":")[0];

  // Strip trailing dot
  cleaned = cleaned.replace(/\.+$/, "");

  if (!cleaned) {
    return { isValid: false, domain: "", error: "Invalid domain format." };
  }

  // Label and structure checks
  const labels = cleaned.split(".");
  if (labels.length < 2) {
    return { isValid: false, domain: cleaned, error: "Please enter a full domain including top-level domain (e.g., example.com)." };
  }

  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!label) {
      return { isValid: false, domain: cleaned, error: "Domain cannot contain empty labels or consecutive dots." };
    }
    if (!labelRegex.test(label)) {
      return { isValid: false, domain: cleaned, error: `Invalid characters in domain segment: '${label}'.` };
    }
  }

  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) {
    return { isValid: false, domain: cleaned, error: "Top-level domain cannot be purely numeric." };
  }

  return { isValid: true, domain: cleaned };
}

export default function SearchBox({ onSearch, isLoading = false }: SearchBoxProps) {
  const [inputVal, setInputVal] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const result = validateDomainInput(inputVal);
    if (!result.isValid) {
      setErrorMsg(result.error || "Invalid domain.");
      return;
    }
    setErrorMsg(null);
    onSearch(result.domain);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="relative flex items-center">
        <div className="relative w-full">
          <div className="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none text-slate-400">
            <Search className="w-5 h-5" />
          </div>
          <input
            type="text"
            value={inputVal}
            onChange={(e) => {
              setInputVal(e.target.value);
              if (errorMsg) setErrorMsg(null);
            }}
            placeholder="Enter a domain to inspect (e.g., thepiratebay.org, wikipedia.org)..."
            className="w-full pl-12 pr-28 py-3.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 shadow-lg text-base transition-all"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !inputVal.trim()}
            className="absolute right-2 top-2 bottom-2 px-5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-medium text-sm rounded-lg transition-colors flex items-center justify-center cursor-pointer disabled:cursor-not-allowed"
          >
            {isLoading ? "Searching..." : "Inspect"}
          </button>
        </div>
      </form>

      {errorMsg && (
        <div className="mt-2.5 flex items-center gap-2 text-rose-400 text-sm px-1">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  );
}
