import React, { useState, useEffect } from "react";
import { Archive, FileText, Calendar, Target, ShieldCheck, ExternalLink, RefreshCw, Download } from "lucide-react";

interface CaseItem {
  id: string;
  target: string;
  target_type: string;
  date: string;
  findings: number;
  confirmed: number;
  verifiability: string;
  size: number;
}

export default function ArchiveList() {
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const [caseContent, setCaseContent] = useState<string>("");
  const [error, setError] = useState("");

  const fetchCases = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/cases?limit=50");
      const data = await res.json();
      setCases(data.cases || []);
    } catch (e: any) {
      setError("Failed to load cases");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const loadCase = async (caseId: string) => {
    if (selectedCase === caseId) {
      setSelectedCase(null);
      setCaseContent("");
      return;
    }
    setSelectedCase(caseId);
    try {
      const res = await fetch(`/api/cases/${caseId}`);
      const text = await res.text();
      setCaseContent(text);
    } catch {
      setCaseContent("Failed to load case.");
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  };

  const getVerifiabilityColor = (v: string) => {
    const pct = parseInt(v);
    if (pct >= 50) return "text-green-400";
    if (pct >= 25) return "text-yellow-400";
    return "text-red-400";
  };

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full overflow-y-auto pb-32 max-w-5xl mx-auto">
      <div className="border-b border-outline-variant/40 pb-4 flex justify-between items-center">
        <div>
          <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">
            Investigation Archives
          </h1>
          <p className="text-on-surface-variant text-sm mt-1">
            Saved OSINT investigation briefs
          </p>
        </div>
        <button
          onClick={fetchCases}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface text-sm transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-error-container/20 border border-error/30 rounded-lg p-4 text-error text-sm">
          {error}
        </div>
      )}

      {loading && cases.length === 0 && (
        <div className="flex items-center justify-center py-12 text-on-surface-variant">
          <RefreshCw size={20} className="animate-spin mr-2" />
          Loading archives...
        </div>
      )}

      {!loading && cases.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-on-surface-variant space-y-3">
          <Archive size={48} className="opacity-30" />
          <p className="text-lg font-headline-md">No cases archived yet</p>
          <p className="text-sm max-w-xs text-center">
            Run an investigation in the <strong>Investigate</strong> tab, then click "Save to Archives" when the brief is ready.
          </p>
        </div>
      )}

      {cases.length > 0 && (
        <div className="space-y-3">
          {cases.map((c) => (
            <div key={c.id}>
              <button
                onClick={() => loadCase(c.id)}
                className={`w-full text-left p-4 rounded-xl border transition-all cursor-pointer ${
                  selectedCase === c.id
                    ? "border-primary bg-primary/5"
                    : "border-outline-variant/30 bg-surface-container hover:border-outline-variant/60 hover:bg-surface-container-high"
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Target size={14} className="text-primary shrink-0" />
                      <span className="font-headline-md text-primary truncate">
                        {c.target || "Unknown target"}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-surface-container-high text-on-surface-variant shrink-0">
                        {c.target_type || "unknown"}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-on-surface-variant mt-2">
                      <span className="flex items-center gap-1">
                        <Calendar size={12} />
                        {c.date || "Unknown date"}
                      </span>
                      <span className="flex items-center gap-1">
                        <FileText size={12} />
                        {c.findings} findings
                        {c.confirmed > 0 && (
                          <span className="text-green-400 ml-1">
                            ({c.confirmed} confirmed)
                          </span>
                        )}
                      </span>
                      {c.verifiability && (
                        <span className={`flex items-center gap-1 ${getVerifiabilityColor(c.verifiability)}`}>
                          <ShieldCheck size={12} />
                          {c.verifiability}
                        </span>
                      )}
                      <span className="text-outline-variant/60">
                        {formatSize(c.size)}
                      </span>
                    </div>
                  </div>
                  <ExternalLink
                    size={16}
                    className={`shrink-0 mt-1 transition-transform ${
                      selectedCase === c.id
                        ? "text-primary rotate-90"
                        : "text-on-surface-variant"
                    }`}
                  />
                </div>
              </button>

              {selectedCase === c.id && caseContent && (
                <div className="mt-2 ml-4 p-4 border-l-2 border-primary/30 bg-surface-container-low rounded-r-lg overflow-x-auto max-h-[60vh] overflow-y-auto">
                  <div className="flex justify-end mb-2">
                    <button
                      onClick={() => {
                        const blob = new Blob([caseContent], { type: "text/markdown" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${c.id}.md`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                      className="flex items-center gap-1 px-2 py-1 text-[10px] font-label-caps bg-primary/10 border border-primary/30 text-primary rounded hover:bg-primary/20 transition-all cursor-pointer"
                    >
                      <Download size={12} /> Export
                    </button>
                  </div>
                  <pre className="text-on-surface text-xs font-mono whitespace-pre-wrap leading-relaxed break-all">
                    {caseContent}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {cases.length > 0 && (
        <div className="text-center text-xs text-on-surface-variant/60 pt-4 border-t border-outline-variant/20">
          {cases.length} case{cases.length !== 1 ? "s" : ""} archived ·{" "}
          {cases.reduce((sum, c) => sum + c.findings, 0)} total findings
        </div>
      )}
    </div>
  );
}
