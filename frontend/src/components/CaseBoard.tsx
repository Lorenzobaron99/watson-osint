import React, { useState } from "react";
import { Clue } from "../types";
import { 
  FileText, 
  Tag, 
  Maximize2, 
  Plus, 
  Link2, 
  Trash2, 
  SearchCode, 
  Sparkles,
  RefreshCw
} from "lucide-react";

interface CaseBoardProps {
  clues: Clue[];
  onAddClue: (clue: Clue) => void;
  onDeleteClue: (id: string) => void;
  onConnectClues: (id1: string, id2: string) => void;
  selectedForTwin?: string[];
  onToggleTwin?: (id: string) => void;
  onTwinInvestigate?: () => void;
  twinLoading?: boolean;
  twinResult?: any;
}

export default function CaseBoard({ 
  clues, 
  onAddClue, 
  onDeleteClue, 
  onConnectClues,
  selectedForTwin = [],
  onToggleTwin,
  onTwinInvestigate,
  twinLoading = false,
  twinResult = null,
}: CaseBoardProps) {
  const [filterType, setFilterType] = useState<string>("all");
  const [showAddModal, setShowAddModal] = useState(false);

  // AI Deep-Dive states
  const [activeDeepDiveId, setActiveDeepDiveId] = useState<string | null>(null);
  const [deepDiveLoading, setDeepDiveLoading] = useState(false);
  const [deepDiveReport, setDeepDiveReport] = useState<string>("");

  // New clue form states
  const [newTitle, setNewTitle] = useState("");
  const [newType, setNewType] = useState<Clue["type"]>("physical");
  const [newDesc, setNewDesc] = useState("");
  const [newExhibit, setNewExhibit] = useState("");
  const [newQuote, setNewQuote] = useState("");
  const [newMetaKey, setNewMetaKey] = useState("ip");
  const [newMetaVal, setNewMetaVal] = useState("");

  const filteredClues = clues.filter(
    (c) => filterType === "all" || c.type === filterType
  );

  // Trigger Watson investigation for a detailed clue analysis
  const handleAIDeepDive = async (clue: Clue) => {
    setActiveDeepDiveId(clue.id);
    setDeepDiveLoading(true);
    setDeepDiveReport("");

    try {
      // Watson API key from settings if present
      const deepseekKey = localStorage.getItem("WATSON_DEEPSEEK_KEY") || "";

      // Re-use our server-side API or fetch general generative helper
      const response = await fetch("/api/osint/scan", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          ...(deepseekKey ? { "x-deepseek-key": deepseekKey } : {})
        },
        body: JSON.stringify({
          queryType: clue.type === "location" ? "domain" : "username",
          queryValue: clue.title,
        }),
      });

      const data = await response.json();
      if (data.error) {
        setDeepDiveReport(
          `WATSON DIAGNOSTICS FAILURE:\n\n${data.error}\n\nEnsure an LLM API key is configured in Settings → API Vault.`
        );
      } else {
        setDeepDiveReport(
          `WATSON FORENSIC DEEP-DIVE REPORT\n` +
          `=================================\n` +
          `TARGET: ${clue.title} (${clue.exhibitCode || "EX-N/A"})\n` +
          `ASSOCIATED FOOTPRINT: ${data.associatedEntity || "Unknown Threat"}\n` +
          `THREAT SCORE: ${data.threatScore} / 100\n\n` +
          `WATSON ANALYSIS:\n` +
          `${data.rawOutput}\n\n` +
          `INTELLIGENCE DEDUCTIONS:\n` +
          data.deductions.map((d: string, i: number) => ` [${i+1}] ${d}`).join("\n")
        );
      }
    } catch (err: any) {
      setDeepDiveReport(
        `CONNECTION ABORTED:\nUnable to synchronize telegraph trace to Watson mainframes. ${err.message}`
      );
    } finally {
      setDeepDiveLoading(false);
    }
  };

  const handleTwineClick = (clueId: string) => {
    if (onToggleTwin) onToggleTwin(clueId);
  };

  const handleCreateClue = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newDesc) return;

    const metadata: Record<string, string> = {};
    if (newMetaVal) {
      metadata[newMetaKey] = newMetaVal;
    }

    const created: Clue = {
      id: "clue_" + Date.now(),
      title: newTitle,
      type: newType,
      description: newDesc,
      exhibitCode: newExhibit || "EX-" + Math.floor(100 + Math.random() * 900),
      quote: newQuote || undefined,
      connections: [],
      metadata,
    };

    onAddClue(created);
    setShowAddModal(false);

    // Reset form
    setNewTitle("");
    setNewDesc("");
    setNewExhibit("");
    setNewQuote("");
    setNewMetaVal("");
  };

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full overflow-y-auto pb-32">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-outline-variant/40 pb-4 gap-4">
        <div>
          <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">Evidence Pinboard</h1>
          <p className="font-body-sm text-xs chat-text-secondary italic mt-1">"Pin clues, trace threads, and draw connections."</p>
        </div>
        
        {/* Actions Row */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onToggleTwin && onToggleTwin("")}
            className={`px-3 py-1.5 text-xs font-label-caps rounded border transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedForTwin.length > 0
                ? "bg-secondary-container border-red-500 text-on-secondary-container animate-pulse"
                : "bg-surface-container border-outline-variant text-primary hover:bg-surface-container-high"
            }`}
          >
            <Link2 size={13} />
            {selectedForTwin.length === 0
              ? "Twin connections"
              : selectedForTwin.length === 1
              ? "Select 2nd finding..."
              : "2 selected — Investigate below"
            }
          </button>
          
          <button
            onClick={() => setShowAddModal(true)}
            className="px-3 py-1.5 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded flex items-center gap-1.5 cursor-pointer transition-all active:scale-95 shadow-md"
          >
            <Plus size={14} />
            <span>Add Clue</span>
          </button>
        </div>
      </div>

      {/* Filters Row */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-outline-variant/20 pb-3">
        {["all", "physical", "digital", "witness", "location", "osint"].map((type) => (
          <button
            key={type}
            onClick={() => setFilterType(type)}
            className={`px-3 py-1 rounded-full text-[10px] font-label-caps uppercase tracking-wider transition-all cursor-pointer ${
              filterType === type
                ? "bg-primary text-background-dark font-bold"
                : "bg-surface-container/40 text-on-surface-variant hover:bg-surface-container hover:text-on-surface"
            }`}
          >
            {type}
          </button>
        ))}
      </div>

      {/* Twin connection panel */}
      {selectedForTwin.length > 0 && (
        <div className="bg-secondary-container/30 border border-red-950 p-3 rounded text-xs font-body-sm text-on-secondary-container flex items-center justify-between">
          <span>
            ⚠️ <span className="font-bold">Twin Mode:</span>{" "}
            {selectedForTwin.length === 1
              ? `Selected: "${clues.find(c => c.id === selectedForTwin[0])?.title}". Click a second finding.`
              : selectedForTwin.length === 2
              ? `Two findings selected. Ready to investigate the connection.`
              : ""}
          </span>
          <div className="flex gap-2">
            {selectedForTwin.length === 2 && (
              <button
                onClick={onTwinInvestigate}
                disabled={twinLoading}
                className="px-3 py-1 bg-primary text-background-dark font-bold rounded text-[10px] uppercase hover:brightness-110 disabled:opacity-50 cursor-pointer"
              >
                {twinLoading ? "Investigating..." : "Deep Investigate"}
              </button>
            )}
            <button
              onClick={() => selectedForTwin.forEach(id => onToggleTwin && onToggleTwin(id))}
              className="underline font-bold text-[10px] uppercase hover:text-white cursor-pointer"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Twin results */}
      {twinResult && (
        <div className="bg-surface-container border border-primary/30 p-3 rounded text-xs">
          <span className="font-bold text-primary">Twin investigation complete</span>
          {" "}
          <span className="text-on-surface-variant">
            {twinResult.findings?.length || 0} new findings added to the board.
          </span>
        </div>
      )}

      {/* Pinboard Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredClues.length === 0 ? (
          <div className="col-span-full py-12 text-center bg-surface-container-low/30 border border-dashed border-outline-variant rounded p-6">
            <FileText size={32} className="mx-auto text-on-surface-variant/35 mb-2" />
            <p className="font-headline-md text-lg text-primary">No clues in ledger category.</p>
            <p className="font-body-sm text-xs chat-text-secondary italic mt-1">Pin new coordinates or execute digital scans to gather evidence.</p>
          </div>
        ) : (
          filteredClues.map((clue) => {
            const isSelected = selectedForTwin.includes(clue.id);
            return (
              <div
                key={clue.id}
                onClick={() => handleTwineClick(clue.id)}
                className={`tactile-paper p-5 flex flex-col justify-between transition-all duration-300 relative group cursor-pointer shadow-lg ${
                  isSelected ? "ring-2 ring-red-500/90 border-red-500" : "hover:-translate-y-1 hover:shadow-xl hover:border-primary/50"
                }`}
              >
                {/* Vintage Pushpin Simulation */}
                <div className="absolute top-1 left-1/2 transform -translate-x-1/2 z-10">
                  <div className="w-3 h-3 bg-red-800 rounded-full shadow border border-red-950 relative flex items-center justify-center">
                    <div className="w-0.5 h-0.5 bg-white rounded-full opacity-60 absolute top-0.5 left-0.5" />
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between items-start border-b border-outline-variant/30 pb-2">
                    <div>
                      <span className="font-technical text-[9px] text-primary uppercase tracking-widest block mb-0.5">
                        {clue.exhibitCode || "LEDGER TRACE"}
                      </span>
                      <h3 className="font-headline-md text-base lg:text-lg text-on-surface leading-tight font-bold group-hover:text-primary transition-colors">
                        {clue.title}
                      </h3>
                    </div>
                    <span className="font-technical text-[9px] px-1.5 py-0.5 rounded uppercase border border-outline-variant bg-surface-container-low text-on-surface-variant">
                      {clue.type}
                    </span>
                  </div>

                  <p className="font-body-sm text-xs chat-text-secondary leading-relaxed line-clamp-4">
                    {clue.description}
                  </p>

                  {clue.quote && (
                    <div className="font-body-sm text-xs italic bg-surface-dark/40 border-l border-primary/30 pl-2.5 py-1 text-on-surface-variant/80">
                      "{clue.quote}"
                    </div>
                  )}

                  {/* Connected clues bullet tags */}
                  {clue.connections.length > 0 && (
                    <div className="pt-2 border-t border-outline-variant/20 flex flex-wrap gap-1 items-center">
                      <span className="font-technical text-[8px] text-on-surface-variant/40 mr-1 uppercase">CONNECTED:</span>
                      {clue.connections.map((targetId) => {
                        const target = clues.find((tc) => tc.id === targetId);
                        if (!target) return null;
                        return (
                          <span 
                            key={targetId}
                            className="bg-red-950/40 border border-red-900 text-[8px] font-technical text-on-secondary-container px-1 rounded hover:brightness-125"
                            title={target.title}
                          >
                            {target.exhibitCode || "EX"}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Card Actions Bottom bar */}
                <div className="pt-4 mt-4 border-t border-outline-variant/30 flex items-center justify-between">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleAIDeepDive(clue);
                    }}
                    className="text-[10px] font-label-caps bg-primary/10 border border-primary/20 text-primary py-1 px-2.5 rounded hover:bg-primary/20 active:scale-95 transition-all flex items-center gap-1 cursor-pointer"
                  >
                    <Sparkles size={11} className="text-primary animate-pulse" />
                    <span>Watson Deep-Dive</span>
                  </button>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteClue(clue.id);
                    }}
                    title="Incinerate Clue"
                    className="text-on-surface-variant/60 hover:text-red-500 p-1 rounded hover:bg-red-500/10 cursor-pointer transition-colors"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* AI Deep-Dive Output Popup */}
      {activeDeepDiveId && (
        <div className="fixed inset-0 bg-black/85 z-50 flex items-center justify-center p-4">
          <div className="bg-surface-container border border-outline-variant max-w-2xl w-full p-6 rounded shadow-2xl space-y-4 flex flex-col max-h-[85vh]">
            <div className="border-b border-outline-variant pb-3 flex justify-between items-start">
              <div>
                <h3 className="font-headline-md text-primary text-xl">Watson Detective Deep-Dive</h3>
                <p className="font-technical text-[10px] text-on-surface-variant uppercase mt-1">
                  SECURE AI INFERENCE TELEGRAPHY
                </p>
              </div>
              <button 
                onClick={() => setActiveDeepDiveId(null)}
                className="text-on-surface-variant hover:text-white font-label-caps text-xs px-2.5 py-1 bg-surface-container-high border border-outline-variant rounded cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto bg-surface-dark border border-outline-variant rounded p-4 font-mono text-xs leading-relaxed text-emerald-400 select-text">
              {deepDiveLoading ? (
                <div className="flex flex-col items-center justify-center py-12 text-center space-y-3">
                  <RefreshCw className="animate-spin text-primary" size={24} />
                  <span className="font-technical text-[10px] text-primary uppercase tracking-widest">
                    Watson is decrypting telegraph packet archives...
                  </span>
                </div>
              ) : (
                <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
                  {deepDiveReport}
                </pre>
              )}
            </div>

            <div className="border-t border-outline-variant pt-3 flex justify-end">
              <button
                onClick={() => setActiveDeepDiveId(null)}
                className="px-4 py-2 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded cursor-pointer transition-all"
              >
                File Report in Ledger
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Clue Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <form 
            onSubmit={handleCreateClue}
            className="bg-surface-container border border-outline-variant max-w-md w-full p-6 rounded shadow-2xl space-y-4 font-body-md"
          >
            <div className="border-b border-outline-variant pb-3">
              <h3 className="font-headline-md text-primary text-xl">Secure New Evidence</h3>
              <p className="font-technical text-[10px] text-on-surface-variant uppercase mt-1">
                Pin hand-logged intelligence to the corkboard
              </p>
            </div>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Clue Title</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Grimpen Mire Boot"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Evidence Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as Clue["type"])}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-label-caps text-primary focus:ring-1 focus:ring-primary outline-none cursor-pointer"
                  >
                    <option value="physical">Physical</option>
                    <option value="digital">Digital</option>
                    <option value="witness">Witness</option>
                    <option value="location">Location</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Evidence Description</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Summarize the core facts, threat significance, and suspect behaviors..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface focus:ring-1 focus:ring-primary outline-none resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Exhibit Ref</label>
                  <input
                    type="text"
                    placeholder="EXHIBIT Z-9"
                    value={newExhibit}
                    onChange={(e) => setNewExhibit(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-technical text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Authentic Quote</label>
                  <input
                    type="text"
                    placeholder="He wants Sir Henry's scent..."
                    value={newQuote}
                    onChange={(e) => setNewQuote(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface-variant focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
              </div>

              {/* Fictional OSINT Footprint Fields */}
              <div className="p-3 bg-surface-container-low border border-outline-variant/60 rounded">
                <div className="text-[9px] font-label-caps text-primary mb-2 uppercase tracking-wider">OSINT Metadata Footprint (Optional)</div>
                <div className="grid grid-cols-3 gap-2">
                  <select
                    value={newMetaKey}
                    onChange={(e) => setNewMetaKey(e.target.value)}
                    className="bg-surface-dark border border-outline-variant rounded p-1.5 text-[10px] font-technical text-on-surface-variant outline-none"
                  >
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="email">Email</option>
                    <option value="source">Source</option>
                  </select>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.1.1"
                    value={newMetaVal}
                    onChange={(e) => setNewMetaVal(e.target.value)}
                    className="col-span-2 bg-surface-dark border border-outline-variant rounded p-1.5 text-xs font-technical text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-outline-variant">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-xs font-label-caps border border-outline-variant text-on-surface-variant hover:text-on-surface rounded cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded cursor-pointer"
              >
                Pin Clue
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
