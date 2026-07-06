import React, { useState } from "react";
import { Clue, OSINTScanResult } from "../types";
import { 
  Terminal, 
  Search, 
  Cpu, 
  Pin, 
  History, 
  ShieldAlert, 
  TrendingUp, 
  RefreshCw,
  Info
} from "lucide-react";

interface OSINTToolkitProps {
  onAddClue: (clue: Clue) => void;
}

export default function OSINTToolkit({ onAddClue }: OSINTToolkitProps) {
  const [queryType, setQueryType] = useState<OSINTScanResult["queryType"]>("ip");
  const [queryValue, setQueryValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [currentResult, setCurrentResult] = useState<OSINTScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<OSINTScanResult[]>([]);
  const [pinnedSuccess, setPinnedSuccess] = useState(false);

  // Suggestions for quick copy/clicking
  const suggestions = [
    { type: "ip" as const, value: "188.42.12.221", label: "Cab spy IP" },
    { type: "domain" as const, value: "merripit-naturalist.net", label: "Merripit domain" },
    { type: "email" as const, value: "lyons.laura@coombetracey.org", label: "Laura Lyons contact" },
    { type: "username" as const, value: "baskerville_heir", label: "Sir Henry alias" },
  ];

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryValue) return;

    setLoading(true);
    setCurrentResult(null);
    setPinnedSuccess(false);

    try {
      const deepseekKey = localStorage.getItem("WATSON_DEEPSEEK_KEY") || "";

      const response = await fetch("/api/osint/scan", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          ...(deepseekKey ? { "x-deepseek-key": deepseekKey } : {})
        },
        body: JSON.stringify({ queryType, queryValue }),
      });

      const data = await response.json();

      if (data.error) {
        // Mock fallback to keep app functional if key is missing
        const fallbackResult: OSINTScanResult = {
          id: "scan_" + Date.now(),
          queryType,
          queryValue,
          timestamp: new Date().toLocaleTimeString(),
          rawOutput: `=== WATSON OFFLINE ===\n\n[DIAGNOSTICS] No LLM API key configured.\n\nWatson needs an LLM API key (DeepSeek, OpenAI, Anthropic, or local) to run investigations.\nConfigure it in Settings → API Vault.`,
          deductions: [
            "Local coordinate shows high correlation to the Grimpen Mire.",
            "Historical tax ledgers indicate active naturalist transactions.",
            "Suspected link to Jack Stapleton's biological records."
          ],
          threatScore: 65,
          associatedEntity: "Stapleton Family Estate"
        };
        setCurrentResult(fallbackResult);
        setScanHistory((prev) => [fallbackResult, ...prev]);
      } else {
        const scanResult: OSINTScanResult = {
          id: "scan_" + Date.now(),
          queryType,
          queryValue,
          timestamp: new Date().toLocaleTimeString(),
          rawOutput: data.rawOutput,
          deductions: data.deductions,
          threatScore: data.threatScore,
          associatedEntity: data.associatedEntity,
        };
        setCurrentResult(scanResult);
        setScanHistory((prev) => [scanResult, ...prev]);
      }
    } catch (err: any) {
      console.error("OSINT trace failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handlePinAsClue = () => {
    if (!currentResult) return;

    const metadata: Record<string, string> = {
      source: "Watson OSINT Scan",
      threat: `${currentResult.threatScore}/100`,
    };
    metadata[currentResult.queryType] = currentResult.queryValue;

    const newClue: Clue = {
      id: "clue_osint_" + Date.now(),
      title: `Scan: ${currentResult.queryValue}`,
      type: "osint",
      description: currentResult.deductions.join(" "),
      exhibitCode: "OSINT-" + Math.floor(100 + Math.random() * 900),
      quote: `Threat score: ${currentResult.threatScore}%. Associated Entity: ${currentResult.associatedEntity}`,
      connections: [],
      metadata,
    };

    onAddClue(newClue);
    setPinnedSuccess(true);
  };

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full overflow-y-auto pb-32">
      {/* Page Header */}
      <div className="border-b border-outline-variant/40 pb-4">
        <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">OSINT Decoder</h1>
        <p className="font-body-sm text-xs text-on-surface-variant italic mt-1">"Execute telegram scans, resolve IP footprints, and trace networks."</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Column: Input Form and Controls */}
        <div className="xl:col-span-4 space-y-6">
          <form onSubmit={handleScan} className="bg-surface-container/60 border border-outline-variant p-5 rounded shadow-lg space-y-4 font-body-md">
            <div className="font-label-caps text-primary text-[10px] tracking-wider uppercase border-b border-outline-variant/30 pb-2 flex items-center gap-2">
              <Cpu size={14} className="text-primary animate-pulse" />
              <span>Enhanced Sweep Configuration</span>
            </div>

            {/* Target Type Selector */}
            <div className="space-y-1">
              <label className="block text-[11px] font-label-caps text-on-surface-variant uppercase tracking-wider">Target Domain</label>
              <div className="grid grid-cols-4 gap-1.5">
                {[
                  { id: "ip", label: "IP" },
                  { id: "domain", label: "Domain" },
                  { id: "email", label: "Email" },
                  { id: "username", label: "Alias" },
                ].map((type) => (
                  <button
                    key={type.id}
                    type="button"
                    onClick={() => setQueryType(type.id as OSINTScanResult["queryType"])}
                    className={`py-1.5 text-[10px] font-label-caps uppercase rounded border cursor-pointer transition-all ${
                      queryType === type.id
                        ? "bg-primary border-primary text-background-dark font-bold"
                        : "bg-surface-container-low border-outline-variant/60 text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface"
                    }`}
                  >
                    {type.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Target Input Field */}
            <div className="space-y-1">
              <label className="block text-[11px] font-label-caps text-on-surface-variant uppercase tracking-wider">Target Identifier</label>
              <div className="relative">
                <input
                  type="text"
                  required
                  placeholder={
                    queryType === "ip" ? "e.g. 188.42.12.221" :
                    queryType === "domain" ? "e.g. merripit-naturalist.net" :
                    queryType === "email" ? "e.g. lyons.laura@coombetracey.org" : "e.g. jstapleton"
                  }
                  value={queryValue}
                  onChange={(e) => setQueryValue(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2.5 pl-8 text-xs font-technical text-primary placeholder-on-surface-variant/40 focus:ring-1 focus:ring-primary focus:border-primary outline-none"
                />
                <Search size={14} className="absolute left-2.5 top-3.5 text-on-surface-variant/50" />
              </div>
            </div>

            {/* Sweep Trigger Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-primary text-background-dark font-label-caps rounded font-bold shadow-md hover:brightness-110 active:scale-[0.98] transition-all cursor-pointer flex items-center justify-center gap-2 text-xs uppercase"
            >
              {loading ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  <span>TRANSMITTING CODES...</span>
                </>
              ) : (
                <>
                  <Terminal size={14} />
                  <span>RUN ENHANCED DECODER</span>
                </>
              )}
            </button>
          </form>

          {/* Quick-Scan Recommendations */}
          <div className="bg-surface-container-low/40 border border-outline-variant/40 p-4 rounded space-y-3">
            <div className="text-[10px] font-label-caps text-on-surface-variant uppercase tracking-widest flex items-center gap-1.5">
              <Info size={12} className="text-primary" />
              <span>Preseeded OSINT Coordinates</span>
            </div>
            <div className="space-y-1.5">
              {suggestions.map((sug, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setQueryType(sug.type);
                    setQueryValue(sug.value);
                  }}
                  className="w-full text-left p-2 bg-surface-container-low hover:bg-surface-container-high border border-outline-variant/40 rounded transition-all flex justify-between items-center group cursor-pointer"
                >
                  <div className="flex flex-col">
                    <span className="text-[11px] font-technical text-primary group-hover:underline">{sug.value}</span>
                    <span className="text-[9px] font-body-sm text-on-surface-variant/70 italic">{sug.label}</span>
                  </div>
                  <span className="text-[9px] font-label-caps bg-primary/10 border border-primary/20 text-primary px-1.5 py-0.5 rounded uppercase">
                    {sug.type}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* History Sidebar */}
          {scanHistory.length > 0 && (
            <div className="bg-surface-container/40 border border-outline-variant/50 p-4 rounded space-y-3">
              <div className="text-[10px] font-label-caps text-on-surface-variant/80 uppercase tracking-widest flex items-center gap-2">
                <History size={14} />
                <span>Recent Scan Sweeps</span>
              </div>
              <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                {scanHistory.map((hist) => (
                  <button
                    key={hist.id}
                    onClick={() => {
                      setCurrentResult(hist);
                      setQueryType(hist.queryType);
                      setQueryValue(hist.queryValue);
                    }}
                    className={`w-full text-left p-2 border rounded transition-all text-xs flex justify-between items-center cursor-pointer ${
                      currentResult?.id === hist.id 
                        ? "bg-surface-container border-primary text-primary" 
                        : "bg-surface-container-low border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:bg-surface-container"
                    }`}
                  >
                    <div className="truncate pr-2">
                      <div className="font-technical text-[10px] truncate">{hist.queryValue}</div>
                      <div className="text-[8px] font-body-sm text-on-surface-variant/60">{hist.timestamp}</div>
                    </div>
                    <span className={`text-[8px] font-technical px-1 rounded uppercase ${
                      hist.threatScore > 75 ? "bg-red-950/55 text-red-400 border border-red-900" :
                      hist.threatScore > 40 ? "bg-yellow-950/40 text-yellow-400 border border-yellow-800" :
                      "bg-emerald-950/40 text-emerald-400 border border-emerald-900"
                    }`}>
                      {hist.threatScore}%
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Scan Result View (Typewriter log and Pinning) */}
        <div className="xl:col-span-8">
          {loading ? (
            <div className="bg-surface-container-low border border-outline-variant h-[500px] flex flex-col items-center justify-center text-center p-6 space-y-4">
              <RefreshCw className="animate-spin text-primary" size={32} />
              <div className="space-y-1">
                <h3 className="font-headline-md text-primary text-lg">Watson Decryptor Running</h3>
                <p className="font-body-sm text-xs text-on-surface-variant italic max-w-sm">
                  Synchronizing high-frequency copper wires through London Post Office nodes to scrape threat data...
                </p>
              </div>
            </div>
          ) : currentResult ? (
            <div className="space-y-6">
              {/* Monospace Typewriter Log Panel */}
              <div className="bg-surface-dark border border-outline-variant rounded p-5 relative overflow-hidden shadow-xl flex flex-col h-[350px]">
                <div className="absolute top-2 right-2 flex gap-1 z-10">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-600 animate-ping absolute" />
                  <div className="w-2.5 h-2.5 rounded-full bg-red-600" />
                </div>
                
                <div className="font-label-caps text-[9px] text-primary mb-3 border-b border-outline-variant/30 pb-2 tracking-widest flex items-center gap-2">
                  <Terminal size={12} />
                  <span>SECURE DIAGNOSTIC WIRE ARCHIVES - {currentResult.timestamp}</span>
                </div>

                <div className="flex-1 overflow-y-auto font-mono text-emerald-400 text-[11px] leading-relaxed p-2 select-text whitespace-pre-wrap select-all">
                  {currentResult.rawOutput}
                </div>
              </div>

              {/* Forensic Details Card */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-stretch">
                {/* Takeaways List */}
                <div className="md:col-span-8 bg-surface-container border border-outline-variant p-5 rounded space-y-3">
                  <div className="font-label-caps text-primary text-[10px] tracking-wider uppercase border-b border-outline-variant/30 pb-1.5">
                    Watson Threat Deductions
                  </div>
                  <ul className="space-y-2 text-xs font-body-sm text-on-surface-variant leading-relaxed">
                    {currentResult.deductions.map((ded, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-primary font-bold">[{i+1}]</span>
                        <span>{ded}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Threat Dial Gauge */}
                <div className="md:col-span-4 bg-surface-container border border-outline-variant p-5 rounded flex flex-col justify-between text-center items-center">
                  <div className="font-label-caps text-on-surface-variant text-[10px] tracking-wider uppercase">
                    Calculated Threat
                  </div>

                  <div className="relative flex items-center justify-center my-3">
                    {/* Circle dial representation */}
                    <svg className="w-24 h-24 transform -rotate-90">
                      <circle 
                        cx="48" cy="48" r="40" 
                        stroke="#20201f" strokeWidth="8" fill="transparent" 
                      />
                      <circle 
                        cx="48" cy="48" r="40" 
                        stroke={currentResult.threatScore > 75 ? "#881e1c" : "#e6c184"} 
                        strokeWidth="8" fill="transparent" 
                        strokeDasharray={251.2}
                        strokeDashoffset={251.2 - (251.2 * currentResult.threatScore) / 100}
                        className="transition-all duration-1000"
                      />
                    </svg>
                    <div className="absolute font-technical text-2xl font-bold text-on-surface">
                      {currentResult.threatScore}%
                    </div>
                  </div>

                  <div className="font-technical text-[10px] text-primary uppercase font-bold truncate max-w-full">
                    {currentResult.associatedEntity}
                  </div>
                </div>
              </div>

              {/* Pin to Corkboard trigger bar */}
              <div className="bg-surface-container border border-outline-variant p-4 rounded flex flex-col sm:flex-row justify-between items-center gap-3 shadow-lg">
                <div className="text-center sm:text-left">
                  <h4 className="font-headline-md text-on-surface text-sm">Synchronize with main ledger?</h4>
                  <p className="font-body-sm text-[11px] text-on-surface-variant italic mt-0.5">
                    "Pinning this threat log adds it directly as interactive clue evidence on the pinboard."
                  </p>
                </div>
                
                <button
                  onClick={handlePinAsClue}
                  disabled={pinnedSuccess}
                  className={`px-4 py-2 text-xs font-label-caps rounded font-bold shadow-md active:scale-95 transition-all flex items-center gap-2 cursor-pointer ${
                    pinnedSuccess 
                      ? "bg-emerald-950 border border-emerald-500 text-emerald-400" 
                      : "bg-primary text-background-dark hover:brightness-110"
                  }`}
                >
                  <Pin size={13} />
                  <span>{pinnedSuccess ? "PINNED SUCCESSFULLY" : "PIN AS ACTIVE CLUE"}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-surface-container-low border border-outline-variant h-[500px] flex flex-col items-center justify-center text-center p-8 shadow-inner">
              <Terminal size={40} className="text-on-surface-variant/30 mb-3 animate-pulse" />
              <h3 className="font-headline-md text-primary text-lg">Telegraphy Node Offline</h3>
              <p className="font-body-sm text-xs text-on-surface-variant italic max-w-md mt-1">
                Configure a target identifier and trigger "Run Enhanced Decoder" to scrap cyber-noir telemetry from Watson mainframes.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
