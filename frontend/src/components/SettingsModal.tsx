import React, { useState, useEffect } from "react";
import { X, Key, Check, Shield, AlertTriangle } from "lucide-react";

interface ApiKeyInfo {
  slug: string;
  label: string;
  category?: string;
  description: string;
  get_key_url: string;
  env_var: string;
  configured: boolean;
  preview: string;
  tier?: string;
}

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);

  // LLM Provider — read from backend's key registry (dynamic, not hardcoded)
  const [llmProvider, setLlmProvider] = useState<string>(
    localStorage.getItem("WATSON_LLM_PROVIDER") || ""
  );
  const [llmModel, setLlmModel] = useState<string>("");
  const [llmKey, setLlmKey] = useState("");

  // Build LLM provider list from keys with category="llm"
  const llmProviders = keys.filter(k => k.category === "llm");

  useEffect(() => {
    if (!isOpen) return;
    fetch("/api/settings/keys")
      .then(r => r.json())
      .then(data => {
        const allKeys: ApiKeyInfo[] = data.keys || [];
        setKeys(allKeys);
        // Restore saved LLM provider from localStorage, or auto-detect first configured
        const savedProvider = localStorage.getItem("WATSON_LLM_PROVIDER") || "";
        if (savedProvider) {
          setLlmProvider(savedProvider);
        } else {
          // Auto-detect: pick first LLM provider that has a configured key
          const configuredLlm = allKeys.find(
            (k: ApiKeyInfo) => k.category === "llm" && k.configured
          );
          if (configuredLlm) setLlmProvider(configuredLlm.slug);
        }
        const savedKey = localStorage.getItem("WATSON_LLM_KEY") || "";
        setLlmKey(savedKey);
        const v: Record<string, string> = {};
        allKeys.forEach((k: ApiKeyInfo) => { v[k.slug] = ""; });
        setValues(v);
        setLoading(false);
      })
      .catch(() => setLoading(false));
    // Load current model from backend
    fetch("/api/settings/llm")
      .then(r => r.json())
      .then(data => {
        if (data.model) setLlmModel(data.model);
        if (data.provider && !llmProvider) setLlmProvider(data.provider);
      })
      .catch(() => {});
  }, [isOpen]);

  const handleSaveKey = async (slug: string) => {
    const val = values[slug] || "";
    try {
      await fetch("/api/settings/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug, value: val }),
      });
      setSaved(prev => ({ ...prev, [slug]: true }));
      // Refresh key list to get updated preview
      const r = await fetch("/api/settings/keys");
      const data = await r.json();
      setKeys(data.keys || []);
      setTimeout(() => setSaved(prev => ({ ...prev, [slug]: false })), 2000);
    } catch (e) {
      console.error("Failed to save key:", e);
    }
  };

  const handleSaveLLM = async () => {
    localStorage.setItem("WATSON_LLM_PROVIDER", llmProvider);
    localStorage.setItem("WATSON_LLM_KEY", llmKey);
    // Save to server-side key store with the correct slug (provider name, not llm_ prefix)
    try {
      await fetch("/api/settings/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: llmProvider, value: llmKey }),
      });
    } catch {}
    // Save provider + model to persistent backend config
    try {
      await fetch("/api/settings/llm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: llmProvider, model: llmModel }),
      });
    } catch {}
    setSaved(prev => ({ ...prev, llm: true }));
    setTimeout(() => setSaved(prev => ({ ...prev, llm: false })), 2000);
  };

  const handleDeleteKey = async (slug: string) => {
    try {
      await fetch(`/api/settings/keys/${slug}`, { method: "DELETE" });
      setValues(prev => ({ ...prev, [slug]: "" }));
      const r = await fetch("/api/settings/keys");
      const data = await r.json();
      setKeys(data.keys || []);
    } catch (e) {
      console.error("Failed to delete key:", e);
    }
  };

  if (!isOpen) return null;

  const freeTools = keys.filter(k => k.tier === "free");
  const paidTools = keys.filter(k => k.tier === "paid");

  return (
    <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 overflow-y-auto" onClick={onClose}>
      <div onClick={e => e.stopPropagation()}
        className="bg-surface-container border border-outline-variant max-w-lg w-full p-6 rounded shadow-2xl space-y-5 font-body-md max-h-[85vh] overflow-y-auto">
        <div className="border-b border-outline-variant pb-3 flex justify-between items-start">
          <div>
            <h3 className="font-headline-md text-primary text-xl flex items-center gap-2">
              <Key size={18} /> API Vault
            </h3>
            <p className="font-technical text-[10px] text-on-surface-variant uppercase mt-1">
              Keys stored locally in ~/.watson/api_keys.json — never sent to third parties
            </p>
          </div>
          <button type="button" onClick={onClose} className="text-on-surface-variant hover:text-white cursor-pointer">
            <X size={18} />
          </button>
        </div>

        {/* LLM Provider — model-agnostic, required */}
        <div className="bg-surface-dark/30 border border-primary/20 rounded p-3">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-primary text-[9px] font-bold uppercase tracking-wider bg-primary/10 px-1.5 py-0.5 rounded">REQUIRED</span>
            <label className="font-technical text-[10px] text-primary uppercase tracking-wider">LLM Provider — Reasoning Engine</label>
          </div>
          <div className="flex gap-2 mb-2">
            <select value={llmProvider} onChange={e => setLlmProvider(e.target.value)}
              className="bg-surface-dark border border-outline-variant/60 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none cursor-pointer">
              {llmProviders.map(k => (
                <option key={k.slug} value={k.slug}>{k.label}</option>
              ))}
            </select>
            <input type="text" placeholder="Model (e.g. deepseek-chat, gpt-4o-mini)…"
              value={llmModel} onChange={e => setLlmModel(e.target.value)}
              list="model-suggestions"
              className="flex-1 bg-surface-dark border border-outline-variant/60 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
            <datalist id="model-suggestions">
              {(llmProvider === "deepseek" ? ["deepseek-chat", "deepseek-reasoner"] :
                llmProvider === "openai" ? ["gpt-4o-mini", "gpt-4o", "gpt-4.1"] :
                llmProvider === "anthropic" ? ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-3-5-20250514"] :
                llmProvider === "openrouter" ? ["deepseek/deepseek-chat", "openai/gpt-4o-mini", "anthropic/claude-sonnet-4", "google/gemini-2.5-flash"] :
                ["deepseek-chat", "gpt-4o-mini", "claude-sonnet-4-20250514"]
              ).map(m => <option key={m} value={m} />)}
            </datalist>
          </div>
          {/* Quick-pick model chips */}
          <div className="flex flex-wrap gap-1 mb-2">
            {(llmProvider === "deepseek" ? ["deepseek-chat", "deepseek-reasoner"] :
              llmProvider === "openai" ? ["gpt-4o-mini", "gpt-4o", "gpt-4.1"] :
              llmProvider === "anthropic" ? ["claude-sonnet-4-20250514", "claude-opus-4-20250514"] :
              llmProvider === "openrouter" ? ["deepseek/deepseek-chat", "openai/gpt-4o-mini", "google/gemini-2.5-flash"] :
              []
            ).map(m => (
              <button key={m} type="button" onClick={() => setLlmModel(m)}
                className={`px-2 py-0.5 text-[9px] font-technical rounded border cursor-pointer transition-all ${
                  llmModel === m 
                    ? "bg-primary/20 border-primary text-primary" 
                    : "bg-surface-dark border-outline-variant/40 text-on-surface-variant hover:border-primary/50 hover:text-primary"
                }`}>
                {m}
              </button>
            ))}
          </div>
          <div className="flex gap-2 mb-2">
            <input type="password" placeholder="Paste your API key…"
              value={llmKey} onChange={e => setLlmKey(e.target.value)}
              className="flex-1 bg-surface-dark border border-outline-variant/60 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
            <button type="button" onClick={handleSaveLLM}
              className="px-3 py-1 text-[10px] font-bold bg-primary text-background-dark hover:brightness-110 rounded cursor-pointer flex items-center gap-1 transition-all shrink-0">
              {saved.llm ? <><Check size={10} /> SAVED</> : "SAVE"}
            </button>
          </div>
          <p className="text-[9px] text-on-surface-variant">
            Watson is provider-agnostic — choose any. DeepSeek offers a free tier. OpenAI, Anthropic, OpenRouter, or local Hermes all work.
            {llmProviders.find(p => p.slug === llmProvider)?.get_key_url && (
              <> <a href={llmProviders.find(p => p.slug === llmProvider)!.get_key_url} target="_blank" className="text-primary hover:underline">Get a key →</a></>
            )}
          </p>
        </div>

        {loading ? (
          <div className="text-[10px] text-on-surface-variant text-center py-4">Loading available tools…</div>
        ) : (
          <>
            {/* Free tier tools */}
            {freeTools.length > 0 && (
              <div className="space-y-3">
                <label className="block font-technical text-[9px] text-green-400/70 mb-1 uppercase tracking-wider flex items-center gap-1">
                  <Shield size={10} /> Free Tier — Optional keys unlock higher rate limits
                </label>
                {freeTools.map(k => (
                  <div key={k.slug} className="bg-surface-dark/20 border border-outline-variant/30 rounded p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <span className="font-technical text-[10px] text-primary uppercase tracking-wider">{k.label}</span>
                        {k.configured && (
                          <span className="ml-2 text-[9px] text-green-400 bg-green-400/10 px-1.5 py-0.5 rounded">{k.preview}</span>
                        )}
                      </div>
                      {k.configured && (
                        <button onClick={() => handleDeleteKey(k.slug)}
                          className="text-[9px] text-red-400 hover:text-red-300 cursor-pointer">Remove</button>
                      )}
                    </div>
                    <p className="text-[10px] text-on-surface-variant mb-2">{k.description}</p>
                    <div className="flex gap-2">
                      <input type="password" placeholder={k.configured ? "•••••••• (stored)" : "Enter key…"}
                        value={values[k.slug] || ""}
                        onChange={e => setValues(prev => ({ ...prev, [k.slug]: e.target.value }))}
                        className="flex-1 bg-surface-dark border border-outline-variant/60 rounded p-1.5 text-[10px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
                      <button type="button" onClick={() => handleSaveKey(k.slug)}
                        disabled={!values[k.slug]}
                        className="px-3 py-1 text-[10px] font-bold bg-primary text-background-dark hover:brightness-110 rounded cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 transition-all shrink-0">
                        {saved[k.slug] ? <><Check size={10} /> SAVED</> : "SAVE"}
                      </button>
                    </div>
                    <a href={k.get_key_url} target="_blank" className="text-[9px] text-primary hover:underline mt-1 inline-block">
                      Get a key →
                    </a>
                  </div>
                ))}
              </div>
            )}

            {/* Paid tier tools */}
            {paidTools.length > 0 && (
              <div className="space-y-3">
                <label className="block font-technical text-[9px] text-amber-400/70 mb-1 uppercase tracking-wider flex items-center gap-1">
                  <AlertTriangle size={10} /> Paid APIs — Optional premium intelligence sources
                </label>
                {paidTools.map(k => (
                  <div key={k.slug} className="bg-surface-dark/20 border border-outline-variant/30 rounded p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <span className="font-technical text-[10px] text-primary uppercase tracking-wider">{k.label}</span>
                        {k.configured && (
                          <span className="ml-2 text-[9px] text-green-400 bg-green-400/10 px-1.5 py-0.5 rounded">{k.preview}</span>
                        )}
                      </div>
                      {k.configured && (
                        <button onClick={() => handleDeleteKey(k.slug)}
                          className="text-[9px] text-red-400 hover:text-red-300 cursor-pointer">Remove</button>
                      )}
                    </div>
                    <p className="text-[10px] text-on-surface-variant mb-2">{k.description}</p>
                    <div className="flex gap-2">
                      <input type="password" placeholder={k.configured ? "•••••••• (stored)" : "Enter key…"}
                        value={values[k.slug] || ""}
                        onChange={e => setValues(prev => ({ ...prev, [k.slug]: e.target.value }))}
                        className="flex-1 bg-surface-dark border border-outline-variant/60 rounded p-1.5 text-[10px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
                      <button type="button" onClick={() => handleSaveKey(k.slug)}
                        disabled={!values[k.slug]}
                        className="px-3 py-1 text-[10px] font-bold bg-primary text-background-dark hover:brightness-110 rounded cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 transition-all shrink-0">
                        {saved[k.slug] ? <><Check size={10} /> SAVED</> : "SAVE"}
                      </button>
                    </div>
                    <a href={k.get_key_url} target="_blank" className="text-[9px] text-primary hover:underline mt-1 inline-block">
                      Get a key →
                    </a>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* Free tools (no key needed) */}
        <div className="border-t border-outline-variant/30 pt-3">
          <label className="block font-technical text-[9px] text-on-surface-variant mb-1 uppercase tracking-wider">
            Free Tools (No key needed)
          </label>
          <div className="text-[10px] text-on-surface-variant space-y-1 mt-1">
            <div className="flex items-center gap-1.5">
              <span className="text-green-400">●</span>
              <span><strong>Wikidata SPARQL</strong> — Corporate ownership, subsidiaries, key people, sanctions.</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-green-400">●</span>
              <span><strong>DuckDuckGo / Web Search</strong> — Multi-engine search across Google, Yandex, Brave, Startpage.</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-green-400">●</span>
              <span><strong>crt.sh / DNS / Wayback</strong> — Certificate transparency, domain records, web archives.</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-green-400">●</span>
              <span><strong>OpenStreetMap / Overpass</strong> — Geocoding, infrastructure mapping (ports, mines, military).</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-green-400">●</span>
              <span><strong>ransomware.live / RansomWatch</strong> — Dark web ransomware group monitoring.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
