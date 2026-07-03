import React, { useState, useEffect } from "react";
import { X, Key, Check, Shield, AlertTriangle } from "lucide-react";

interface ApiKeyInfo {
  slug: string;
  label: string;
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

  // LLM Provider — model-agnostic, defaults to DeepSeek
  const LLM_PROVIDERS = {
    deepseek: { label: "DeepSeek", placeholder: "sk-...", get_url: "https://platform.deepseek.com/api_keys", env: "DEEPSEEK_API_KEY" },
    openai: { label: "OpenAI", placeholder: "sk-proj-...", get_url: "https://platform.openai.com/api-keys", env: "OPENAI_API_KEY" },
    anthropic: { label: "Anthropic", placeholder: "sk-ant-...", get_url: "https://console.anthropic.com/keys", env: "ANTHROPIC_API_KEY" },
    hermes: { label: "Hermes (local)", placeholder: "local-dev-key", get_url: "", env: "HERMES_API_KEY" },
  } as const;
  type ProviderKey = keyof typeof LLM_PROVIDERS;
  const [llmProvider, setLlmProvider] = useState<ProviderKey>("deepseek");
  const [llmKey, setLlmKey] = useState("");

  useEffect(() => {
    if (!isOpen) return;
    // Load saved LLM provider from localStorage
    const savedProvider = localStorage.getItem("WATSON_LLM_PROVIDER") as ProviderKey | null;
    if (savedProvider && savedProvider in LLM_PROVIDERS) setLlmProvider(savedProvider);
    const savedKey = localStorage.getItem("WATSON_LLM_KEY") || "";
    setLlmKey(savedKey);
    
    fetch("/api/settings/keys")
      .then(r => r.json())
      .then(data => {
        setKeys(data.keys || []);
        const v: Record<string, string> = {};
        (data.keys || []).forEach((k: ApiKeyInfo) => {
          v[k.slug] = "";
        });
        setValues(v);
        setLoading(false);
      })
      .catch(() => setLoading(false));
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
    // Also save to server-side via the API keys endpoint
    const provider = LLM_PROVIDERS[llmProvider];
    try {
      await fetch("/api/settings/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: `llm_${llmProvider}`, value: llmKey }),
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
            <select value={llmProvider} onChange={e => setLlmProvider(e.target.value as ProviderKey)}
              className="bg-surface-dark border border-outline-variant/60 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none cursor-pointer">
              {Object.entries(LLM_PROVIDERS).map(([key, p]) => (
                <option key={key} value={key}>{p.label}</option>
              ))}
            </select>
            <input type="password" placeholder={LLM_PROVIDERS[llmProvider].placeholder}
              value={llmKey} onChange={e => setLlmKey(e.target.value)}
              className="flex-1 bg-surface-dark border border-outline-variant/60 rounded p-2 text-[11px] font-technical text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none" />
            <button type="button" onClick={handleSaveLLM}
              className="px-3 py-1 text-[10px] font-bold bg-primary text-background-dark hover:brightness-110 rounded cursor-pointer flex items-center gap-1 transition-all shrink-0">
              {saved.llm ? <><Check size={10} /> SAVED</> : "SAVE"}
            </button>
          </div>
          <p className="text-[9px] text-on-surface-variant">
            Watson is provider-agnostic. DeepSeek is the default (cheapest). OpenAI, Anthropic, or local Hermes also work.
            {LLM_PROVIDERS[llmProvider].get_url && (
              <>{" "}<a href={LLM_PROVIDERS[llmProvider].get_url} target="_blank" className="text-primary hover:underline">Get a key →</a></>
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
