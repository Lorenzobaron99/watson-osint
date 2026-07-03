import React, { useState, useEffect, useRef } from "react";
import {
  Send, Trash2, Bot, User, RefreshCw, X, Paperclip,
  AlertCircle, Search, FileText,
} from "lucide-react";
import { SSEFinding, SSEBrief, SSETargetProfile, BriefEntity } from "../types";

const SHERLOCK_QUOTES = [
  '"It is a capital mistake to theorize before one has data."',
  '"The world is full of obvious things which nobody by any chance ever observes."',
  '"There is nothing more deceptive than an obvious fact."',
  '"You see, but you do not observe."',
  '"Data! Data! Data! I can\'t make bricks without clay."',
  '"When you have eliminated the impossible, whatever remains, however improbable, must be the truth."',
  '"The little things are infinitely the most important."',
  '"What one man can invent, another can discover."',
];

const getWelcomeText = () => {
  const quote = SHERLOCK_QUOTES[Math.floor(Math.random() * SHERLOCK_QUOTES.length)];
  return `🕵️ Greetings, Detective. I am Watson — your autonomous OSINT investigation engine.

${quote}

**To begin, type a target below.** I investigate people, companies, domains, emails, crypto wallets, and more.

**What happens next:**
1. I run a 7-phase investigation pipeline — from surface collection to deep OSINT.
2. Findings appear in real-time with source URLs and confidence scores.
3. Results flow into your **Case Board**, **Evidence Map**, and **Personnel** tabs.
4. You can connect two findings and I'll investigate their hidden relationship.

**Every finding is evidence-backed.** I never fabricate data.

Try one of the suggested targets below, or type your own.`;
};

interface Message {
  id: string;
  role: "user" | "watson";
  text: string;
  timestamp: string;
  findings?: SSEFinding[];
  brief?: SSEBrief;
  targetProfile?: SSETargetProfile;
  isInvestigation?: boolean;
  caseId?: string;
  saved?: boolean;
  saveError?: string;
}

export default function WatsonChat({ 
  onFindings,
  onBriefEntities,
  twinQuery,
  onTwinComplete,
}: { 
  onFindings?: (findings: SSEFinding[]) => void;
  onBriefEntities?: (entities: BriefEntity[]) => void;
  twinQuery?: string | null;
  onTwinComplete?: () => void;
}) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState("");
  const [loading, setLoading] = useState(false);
  const [watsonError, setWatsonError] = useState<string | null>(null);
  const [progressLog, setProgressLog] = useState<string[]>([]);
  const [clientId, setClientId] = useState<string>("");
  const [steerText, setSteerText] = useState("");
  const [mode, setMode] = useState<string>(() =>
    localStorage.getItem("WATSON_MODE") || "background_check"
  );
  const [publishToGraph, setPublishToGraph] = useState<boolean>(() =>
    localStorage.getItem("WATSON_PUBLISH_GRAPH") === "true"
  );
  const [graphStatus, setGraphStatus] = useState<{
    connected: boolean; configured: boolean; reason: string;
  }>({ connected: false, configured: false, reason: "Checking..." });
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Check graph connection on mount
  useEffect(() => {
    fetch("/api/graph/status")
      .then(r => r.json())
      .then(d => setGraphStatus({
        connected: d.connected ?? d.configured ?? false,
        configured: d.configured ?? false,
        reason: d.reason || "",
      }))
      .catch(() => setGraphStatus({
        connected: false, configured: false, reason: "Cannot reach API",
      }));
  }, []);

  useEffect(() => {
    const savedChat = localStorage.getItem("WATSON_CHAT_HISTORY");
    if (savedChat) {
      setMessages(JSON.parse(savedChat));
    } else {
      setMessages([{
        id: "welcome",
        role: "watson",
        text: getWelcomeText(),
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      }]);
    }
  }, []);

  useEffect(() => {
    if (messages.length > 0) {
      localStorage.setItem("WATSON_CHAT_HISTORY", JSON.stringify(messages.slice(-50)));
    }
  }, [messages]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading, progressLog]);

  // Auto-fire twin investigation when triggered from Case Board
  const twinFiredRef = useRef(false);
  useEffect(() => {
    if (!twinQuery || twinFiredRef.current) return;
    twinFiredRef.current = true;

    const run = async () => {
      setWatsonError(null);
      setProgressLog([]);
      setLoading(true);

      const userMsg: Message = {
        id: "twin_" + Date.now(),
        role: "user",
        text: `🔗 Twin Investigation\n${twinQuery}`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages(prev => [...prev, userMsg]);

      try {
        const response = await fetch("/api/agent/investigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: twinQuery, context: "", depth: 1, mode: "twin_connection" }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const cid = data.client_id;
        setClientId(cid);
        // The existing SSE pipeline handles the rest
      } catch (err: any) {
        setWatsonError(err.message || "Twin investigation failed");
        setLoading(false);
        if (onTwinComplete) onTwinComplete();
      }
    };

    run();
  }, [twinQuery]);

  const handleClearHistory = () => {
    if (window.confirm("Clear entire investigation history?")) {
      setMessages([{
        id: "welcome",
        role: "watson",
        text: "Archive cleared. The slate is clean, Detective. Enter a target to investigate.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      }]);
      localStorage.removeItem("WATSON_CHAT_HISTORY");
    }
  };

  const handleSaveToArchive = async (caseId: string, msgId: string) => {
    setMessages(prev => prev.map(m =>
      m.id === msgId ? { ...m, saveError: undefined } : m
    ));
    try {
      const res = await fetch(`/api/cases/${caseId}/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consent_publish: true }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setMessages(prev => prev.map(m =>
        m.id === msgId ? { ...m, saved: true } : m
      ));
    } catch (err: any) {
      setMessages(prev => prev.map(m =>
        m.id === msgId ? { ...m, saveError: err.message } : m
      ));
    }
  };

  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    setWatsonError(null);
    setProgressLog([]);

    const userMsg: Message = {
      id: "user_" + Date.now(),
      role: "user",
      text: inputText.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };
    setMessages(prev => [...prev, userMsg]);
    const query = inputText.trim();
    setInputText("");
    setLoading(true);

    try {
      // Start investigation
      const response = await fetch("/api/agent/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query, context: "", depth: 2, mode, publish_to_graph: publishToGraph }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      const cid = data.client_id;
      setClientId(cid);

      // Stream SSE events
      const findings: SSEFinding[] = [];
      let brief: SSEBrief | null = null;
      let targetProfile: SSETargetProfile | null = null;
      let markdown = "";

      await new Promise<void>((resolve, reject) => {
        const es = new EventSource(`/api/agent/stream/${cid}`);

        const timeout = setTimeout(() => {
          es.close();
          reject(new Error("Investigation timed out after 600s (10 minutes)"));
        }, 600000);

        es.addEventListener("progress", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            setProgressLog(prev => [...prev, d.message || ""]);
          } catch {}
        });

        es.addEventListener("phase_start", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            setProgressLog(prev => [...prev, `── ${d.label || d.phase} ──`]);
          } catch {}
        });

        es.addEventListener("phase_done", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            if (d.finding_count > 0) {
              setProgressLog(prev => [...prev, `  ✓ ${d.finding_count} findings collected`]);
            }
          } catch {}
        });

        es.addEventListener("target_profile", (ev) => {
          try {
            targetProfile = JSON.parse(ev.data);
          } catch {}
        });

        es.addEventListener("finding", (ev) => {
          try {
            const f = JSON.parse(ev.data);
            findings.push(f);
            // Update the watson message progressively
            setMessages(prev => prev.map(m =>
              m.id === "watson_active" ? { ...m, findings: [...findings] } : m
            ));
          } catch {}
        });

        es.addEventListener("entity_resolution", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            if (d.entities?.length) {
              setProgressLog(prev => [...prev, `  🔗 ${d.total} entities resolved`]);
            }
          } catch {}
        });

        es.addEventListener("cross_reference", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            if (d.patterns?.length) {
              setProgressLog(prev => [...prev, `  🔍 ${d.total} cross-references found`]);
            }
          } catch {}
        });

        es.addEventListener("brief", (ev) => {
          try {
            brief = JSON.parse((ev as MessageEvent).data);
            setMessages(prev => prev.map(m =>
              m.id === "watson_active" ? { ...m, brief: brief! } : m
            ));
            // Feed notable_entities into Personnel tab
            if (onBriefEntities && brief?.notable_entities?.length) {
              onBriefEntities(brief.notable_entities);
            }
          } catch {}
        });

        es.addEventListener("report", (ev) => {
          try {
            const d = JSON.parse(ev.data);
            markdown = d.markdown || "";
            // Update graph status after publish attempt
            if (d.published_to_graph !== undefined) {
              setGraphStatus(prev => ({
                ...prev,
                reason: d.published_to_graph ? "Publishing..." : "",
              }));
            }
          } catch {}
        });

        es.addEventListener("graph_published", (ev: MessageEvent) => {
          try {
            const d = JSON.parse(ev.data);
            setGraphStatus(prev => ({
              ...prev, connected: true, configured: true,
              reason: `✓ Published to graph`,
            }));
            setProgressLog(prev => [...prev, `✓ Published to community graph — ${d.case_id}`]);
          } catch {}
        });

        es.addEventListener("graph_error", (ev: MessageEvent) => {
          try {
            const d = JSON.parse(ev.data);
            setGraphStatus(prev => ({
              ...prev, reason: `✗ ${d.message}`,
            }));
            setProgressLog(prev => [...prev, `✗ Graph publish failed: ${d.message}`]);
          } catch {}
        });

        es.addEventListener("investigation_complete", (ev) => {
          try {
            const d = JSON.parse((ev as MessageEvent).data);
            setProgressLog(prev => [...prev, `✓ Investigation complete: ${d.total_findings} findings, ${d.confirmed} confirmed, ${d.verifiability} verifiability`]);
            // Save case_id so we can offer archive/publish
            setMessages(prev => prev.map(m =>
              m.id === "watson_active" ? { ...m, caseId: d.case_id as string } : m
            ));
          } catch {}
        });

        es.addEventListener("error", (ev) => {
          clearTimeout(timeout);
          es.close();
          try {
            const d = JSON.parse((ev as MessageEvent).data);
            reject(new Error(d.message || "Stream error"));
          } catch {
            reject(new Error("Stream error"));
          }
        });

        es.addEventListener("_close", () => {
          clearTimeout(timeout);
          es.close();
          resolve();
        });
      });

      // Finalize the watson message
      setMessages(prev => prev.map(m =>
        m.id === "watson_active" ? {
          ...m,
          text: brief?.executive_summary || `Investigation complete. ${findings.length} findings collected.`,
          findings,
          brief: brief || undefined,
          targetProfile: targetProfile || undefined,
          isInvestigation: true,
        } : m
      ));

      // Pass findings to parent (CaseBoard)
      if (onFindings && findings.length > 0) {
        onFindings(findings);
      }
    } catch (err: any) {
      console.error("Investigation failed:", err);
      setWatsonError(err.message || "Investigation failed");
      // Remove the placeholder message
      setMessages(prev => prev.filter(m => m.id !== "watson_active"));
      // Clear twin query so Case Board knows investigation is complete
      if (onTwinComplete) onTwinComplete();
    } finally {
      setLoading(false);
      setProgressLog([]);
    }
  };

  // Create the active investigation message when loading starts
  useEffect(() => {
    if (loading && !messages.find(m => m.id === "watson_active")) {
      setMessages(prev => [...prev, {
        id: "watson_active",
        role: "watson",
        text: "Investigating...",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        findings: [],
      }]);
    }
  }, [loading]);

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full flex flex-col pb-32 max-w-5xl mx-auto">
      <div className="border-b border-outline-variant/40 pb-4 flex justify-between items-center">
        <div>
          <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">Watson Investigation</h1>
          <p className="font-body-sm text-xs text-on-surface-variant italic mt-1">
            "Enter a target — person, company, domain, email, crypto wallet. Watson investigates autonomously."
          </p>
        </div>
        <button
          onClick={handleClearHistory}
          className="px-3 py-1.5 text-xs font-label-caps border border-outline-variant text-on-surface-variant hover:text-red-400 hover:bg-red-500/10 rounded flex items-center gap-1.5 transition-all cursor-pointer"
        >
          <Trash2 size={13} />
          <span className="hidden sm:inline">Clear History</span>
        </button>
      </div>

      {/* Mode selector */}
      <div className="flex items-center justify-center gap-0">
        {(["background_check", "due_diligence", "deep_investigation"] as const).map((m) => {
          const labels: Record<string, { icon: string; label: string; desc: string }> = {
            background_check: { icon: "⚡", label: "Quick Check", desc: "30-60s · Identity, sanctions, PEP" },
            due_diligence: { icon: "📋", label: "Due Diligence", desc: "2-5 min · Business, financial, media" },
            deep_investigation: { icon: "🔬", label: "Deep", desc: "5-15 min · Full dossier, all languages" },
          };
          const isActive = mode === m;
          return (
            <button
              key={m}
              onClick={() => {
                setMode(m);
                localStorage.setItem("WATSON_MODE", m);
              }}
              title={labels[m].desc}
              className={`px-3 py-1.5 text-[11px] font-medium border transition-all cursor-pointer
                ${isActive
                  ? "bg-primary/20 border-primary text-primary font-bold"
                  : "bg-transparent border-outline-variant/40 text-on-surface-variant/60 hover:text-on-surface-variant hover:border-outline-variant"}
                ${m === "background_check" ? "rounded-l-md" : ""}
                ${m === "deep_investigation" ? "rounded-r-md" : ""}
              `}
            >
              <span className="hidden sm:inline">{labels[m].icon} </span>{labels[m].label}
            </button>
          );
        })}
      </div>

      {/* Publish consent toggle */}
      <div className="flex items-center justify-center gap-2 mt-1">
        <label className="flex items-center gap-2 text-[10px] text-on-surface-variant cursor-pointer select-none">
          <input
            type="checkbox"
            checked={publishToGraph}
            onChange={(e) => {
              setPublishToGraph(e.target.checked);
              localStorage.setItem("WATSON_PUBLISH_GRAPH", String(e.target.checked));
            }}
            className="w-3 h-3 accent-primary cursor-pointer"
          />
          Publish to community graph
        </label>
        <span className={`inline-block w-2 h-2 rounded-full ${
          graphStatus.connected ? "bg-green-500" :
          graphStatus.configured ? "bg-yellow-500" :
          "bg-red-500/50"
        }`} title={graphStatus.reason} />
        <span className="text-[9px] text-on-surface-variant/60 hidden sm:inline">
          {graphStatus.connected ? "connected" :
           graphStatus.configured ? "local" :
           "not configured"}
        </span>
      </div>

      <div className="flex-1 flex flex-col border border-outline-variant rounded bg-surface-container/40 overflow-hidden shadow-2xl h-[55vh] min-h-[400px]">
        {/* Chat Stream */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6 select-text">
          {messages.map((msg) => {
            const isWatson = msg.role === "watson";
            return (
              <div key={msg.id} className={`flex gap-4 max-w-3xl ${isWatson ? "mr-12" : "ml-auto flex-row-reverse pl-12"}`}>
                <div className={`w-8 h-8 rounded border flex items-center justify-center flex-shrink-0 shadow ${
                  isWatson ? "bg-primary/10 border-primary/30 text-primary" : "bg-surface-container-high border-outline-variant text-on-surface-variant"
                }`}>
                  {isWatson ? <Bot size={15} /> : <User size={15} />}
                </div>

                <div className="space-y-2 flex-1">
                  <div className={`flex items-center gap-1.5 text-[9px] font-technical tracking-wider text-on-surface-variant/50 ${!isWatson && "justify-end"}`}>
                    <span>{isWatson ? "WATSON" : "DETECTIVE"}</span>
                    <span>•</span>
                    <span>{msg.timestamp}</span>
                  </div>

                  <div className={`tactile-paper p-4 rounded text-xs leading-relaxed space-y-3 relative shadow-md ${
                    isWatson ? "bg-surface-container-high border-outline-variant text-on-surface" : "bg-surface-container border-primary/20 text-on-surface"
                  }`}>
                    {isWatson && (
                      <div className="absolute top-1 left-2">
                        <div className="w-1.5 h-1.5 bg-red-800 rounded-full border border-red-950 opacity-40" />
                      </div>
                    )}

                    {/* Target profile */}
                    {msg.targetProfile && (
                      <div className="bg-surface-dark/60 border border-outline-variant/40 rounded p-3 mb-2">
                        <div className="font-label-caps text-[10px] text-primary mb-1">TARGET PROFILE</div>
                        <div className="font-bold text-sm">{msg.targetProfile.target_type.toUpperCase()} — {msg.targetProfile.primary_name}</div>
                        {msg.targetProfile.wikidata_label && (
                          <div className="text-[10px] text-on-surface-variant">{msg.targetProfile.wikidata_label}: {msg.targetProfile.wikidata_description}</div>
                        )}
                        {msg.targetProfile.associated_orgs?.length > 0 && (
                          <div className="text-[10px] text-on-surface-variant">Orgs: {msg.targetProfile.associated_orgs.join(", ")}</div>
                        )}
                      </div>
                    )}

                    {/* Message text */}
                    <div className="whitespace-pre-wrap font-body-sm text-[12px] leading-relaxed">
                      {msg.text}
                    </div>

                    {/* Findings stream */}
                    {msg.findings && msg.findings.length > 0 && (
                      <div className="space-y-2 mt-3 pt-3 border-t border-outline-variant/30">
                        <div className="font-label-caps text-[10px] text-primary">FINDINGS ({msg.findings.length})</div>
                        {msg.findings.slice(-5).map((f, i) => (
                          <div key={i} className="bg-surface-dark/40 border-l-2 border-primary/40 pl-3 py-2">
                            <div className="flex items-center gap-2 mb-1">
                              <span className={`text-[9px] font-bold uppercase ${
                                f.tier === "CONFIRMED" ? "text-emerald-400" :
                                f.tier === "PROBABLE" ? "text-primary" :
                                f.tier === "POSSIBLE" ? "text-yellow-500" : "text-on-surface-variant"
                              }`}>{f.tier}</span>
                              <span className="text-[9px] text-on-surface-variant">{f.source_tier}</span>
                              {f.source_type && f.source_type !== "web_search" && (
                                <span className="text-[9px] text-primary bg-primary/10 px-1 rounded">{f.source_type}</span>
                              )}
                            </div>
                            <div className="text-[11px] font-bold text-on-surface">{f.title}</div>
                            <div className="text-[10px] text-on-surface-variant line-clamp-2">{f.description}</div>
                            {f.source_url && (
                              <a href={f.source_url} target="_blank" rel="noopener noreferrer" className="text-[9px] text-primary hover:underline mt-1 inline-block">
                                {f.source_url.substring(0, 60)}...
                              </a>
                            )}
                          </div>
                        ))}
                        {msg.findings.length > 5 && (
                          <div className="text-[10px] text-on-surface-variant italic">+ {msg.findings.length - 5} more findings...</div>
                        )}
                      </div>
                    )}

                    {/* Intelligence brief */}
                    {msg.brief && (
                      <div className="bg-surface-dark/60 border border-outline-variant/40 rounded p-3 mt-2">
                        <div className="font-label-caps text-[10px] text-primary mb-1">INTELLIGENCE BRIEF</div>
                        {msg.brief.risk_themes?.map((t, i) => (
                          <div key={i} className="flex items-center gap-2 text-[10px] mb-1">
                            <span className={
                              t.severity === "HIGH" ? "text-red-400" :
                              t.severity === "MEDIUM" ? "text-yellow-500" : "text-on-surface-variant"
                            }>●</span>
                            <span className="font-bold">{t.theme}</span>
                            <span className="text-on-surface-variant">— {t.severity}</span>
                          </div>
                        ))}
                        {msg.brief.evidence_gaps?.length > 0 && (
                          <div className="text-[10px] text-on-surface-variant mt-2">
                            <span className="text-primary">Evidence gaps:</span> {msg.brief.evidence_gaps.length}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Save to Archive + MCP Publish */}
                    {msg.isInvestigation && msg.caseId && !msg.saved && (
                      <div className="mt-3 pt-3 border-t border-outline-variant/30">
                        <button
                          onClick={() => handleSaveToArchive(msg.caseId!, msg.id)}
                          className="px-3 py-1.5 bg-primary text-background-dark rounded font-label-caps font-bold text-[10px] hover:brightness-110 transition-all cursor-pointer"
                        >
                          📁 Save to Archive & Publish to MCP
                        </button>
                        {msg.saveError && (
                          <div className="text-[10px] text-red-400 mt-1">Save failed: {msg.saveError}</div>
                        )}
                      </div>
                    )}
                    {msg.saved && (
                      <div className="mt-3 pt-3 border-t border-outline-variant/30">
                        <div className="text-[10px] text-emerald-400 font-label-caps">✅ Archived & Published to MCP Community</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          {/* Loading state with progress log */}
          {loading && (
            <div className="flex gap-4 max-w-3xl mr-12">
              <div className="w-8 h-8 rounded border border-primary/30 bg-primary/10 flex items-center justify-center flex-shrink-0 animate-pulse text-primary">
                <Bot size={15} />
              </div>
              <div className="space-y-1 flex-1">
                <div className="text-[9px] font-technical text-primary uppercase tracking-widest animate-pulse">
                  Watson is investigating...
                </div>
                {progressLog.length > 0 && (
                  <div className="bg-surface-container-high border border-outline-variant/60 rounded p-3 max-h-32 overflow-y-auto">
                    {progressLog.slice(-8).map((line, i) => (
                      <div key={i} className="font-mono text-[10px] text-on-surface-variant leading-relaxed">
                        {line.startsWith("──") ? <span className="text-primary font-bold">{line}</span> : line}
                      </div>
                    ))}
                  </div>
                )}
                <div className="bg-surface-container-high border border-outline-variant/60 rounded p-2 inline-flex items-center gap-2">
                  <RefreshCw className="animate-spin text-primary" size={14} />
                  <span className="font-mono text-[10px] text-on-surface-variant">Running 7-phase OSINT pipeline...</span>
                </div>
              </div>
            </div>
          )}

          {/* Steering input — only during investigation */}
          {loading && clientId && (
            <div className="sticky bottom-2 mx-2">
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!steerText.trim()) return;
                  try {
                    await fetch(`/api/agent/investigate/${clientId}/interrupt`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ action: "context", text: steerText }),
                    });
                    setProgressLog(prev => [...prev, `📝 Steered: ${steerText}`]);
                    setSteerText("");
                  } catch {}
                }}
                className="flex items-center gap-2"
              >
                <input
                  type="text"
                  value={steerText}
                  onChange={(e) => setSteerText(e.target.value)}
                  placeholder="Steer: focus on sanctions, skip dark web, stop..."
                  className="flex-1 bg-surface-dark border border-primary/30 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary outline-none"
                />
                <button
                  type="submit"
                  disabled={!steerText.trim()}
                  className="px-3 py-2 bg-primary/20 border border-primary/50 text-primary rounded text-[10px] font-bold hover:bg-primary/30 disabled:opacity-40 cursor-pointer transition-all"
                >
                  STEER
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await fetch(`/api/agent/investigate/${clientId}/interrupt`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ action: "stop", text: "stop" }),
                      });
                      setProgressLog(prev => [...prev, "⏹ Stop requested..."]);
                    } catch {}
                  }}
                  className="px-3 py-2 bg-red-500/10 border border-red-500/30 text-red-400 rounded text-[10px] font-bold hover:bg-red-500/20 cursor-pointer transition-all"
                >
                  STOP
                </button>
              </form>
            </div>
          )}

          {/* Error notice */}
          {watsonError && (
            <div className="sticky bottom-2 mx-auto max-w-sm bg-red-950/60 border border-red-500/50 p-2.5 rounded flex items-center justify-between text-[11px] font-technical text-red-400 gap-2 backdrop-blur-md">
              <div className="flex items-center gap-1.5">
                <AlertCircle size={14} />
                <span>{watsonError}</span>
              </div>
              <button onClick={() => setWatsonError(null)} className="hover:text-white uppercase font-bold text-[9px] cursor-pointer">Dismiss</button>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <form onSubmit={handleInvestigate} className="p-3 bg-surface-container-low border-t border-outline-variant flex items-center gap-2">
          <Search size={15} className="text-primary ml-2 flex-shrink-0" />
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Investigate: person, company, domain, email, crypto wallet..."
            className="flex-1 bg-surface-dark border border-outline-variant/80 rounded p-2.5 text-xs text-on-surface font-body-sm focus:ring-1 focus:ring-primary focus:border-primary outline-none"
          />
          <button
            type="submit"
            disabled={loading || !inputText.trim()}
            className="px-4 py-2.5 bg-primary text-background-dark rounded font-label-caps font-bold text-xs hover:brightness-110 active:scale-95 disabled:opacity-50 disabled:pointer-events-none transition-all flex items-center gap-1.5 cursor-pointer shadow-md"
          >
            <Send size={12} />
            <span className="hidden sm:inline">INVESTIGATE</span>
          </button>
        </form>
      </div>

      {/* Suggested targets */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { text: "Elon Musk", label: "Person" },
          { text: "stripe.com", label: "Domain" },
          { text: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", label: "Crypto Wallet" },
          { text: "Binance", label: "Company" },
        ].map((sug, i) => (
          <button
            key={i}
            type="button"
            onClick={() => setInputText(sug.text)}
            className="text-left p-2.5 bg-surface-container-low/40 hover:bg-surface-container-high/60 border border-outline-variant/30 rounded transition-all text-xs flex justify-between items-center group cursor-pointer"
          >
            <div className="truncate pr-2">
              <div className="font-technical text-[9px] text-primary uppercase group-hover:underline">{sug.label}</div>
              <div className="text-[11px] font-body-sm text-on-surface-variant truncate italic mt-0.5">{sug.text}</div>
            </div>
            <Search size={11} className="text-primary/40 group-hover:text-primary animate-pulse flex-shrink-0" />
          </button>
        ))}
      </div>
    </div>
  );
}
