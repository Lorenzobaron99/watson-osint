import React, { useState, useEffect, useRef } from "react";
import { Users, Key, ChevronDown, Map as MapIcon, LayoutGrid, BookOpen, HelpCircle, FolderOpen, Check, MessageSquare } from "lucide-react";

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  deductionProbability: number;
  onOpenSettings?: () => void;
}

export default function Sidebar({ currentTab, setCurrentTab, deductionProbability, onOpenSettings }: SidebarProps) {
  const [vaultOpen, setVaultOpen] = useState(false);
  const [typedTitle, setTypedTitle] = useState("");
  const [activeModel, setActiveModel] = useState("");

  const SHERLOCK_QUOTES = [
    "It is a capital mistake to theorize before one has data.",
    "The world is full of obvious things which nobody by any chance ever observes.",
    "There is nothing more deceptive than an obvious fact.",
    "You see, but you do not observe.",
    "Data! Data! Data! I can't make bricks without clay.",
    "When you have eliminated the impossible, whatever remains, however improbable, must be the truth.",
    "The little things are infinitely the most important.",
    "What one man can invent, another can discover.",
  ];

  useEffect(() => {
    const quote = SHERLOCK_QUOTES[Math.floor(Math.random() * SHERLOCK_QUOTES.length)];
    setTypedTitle("");
    const timeout = setTimeout(() => {
      const idx = { current: 0 };
      const interval = setInterval(() => {
        if (idx.current < quote.length) {
          setTypedTitle(quote.slice(0, idx.current + 1));
          idx.current++;
        } else {
          clearInterval(interval);
        }
      }, 30);
      return () => clearInterval(interval);
    }, 50);
    return () => clearTimeout(timeout);
  }, []);

  // Fetch active LLM model from backend
  useEffect(() => {
    fetch("/api/settings/llm")
      .then(r => r.json())
      .then(data => {
        if (data.model) {
          const provider = data.provider || "?";
          setActiveModel(`${provider}/${data.model}`);
        }
      })
      .catch(() => {});
  }, []);

  const navItems = [
    { id: "chat", label: "Investigate", icon: MessageSquare },
    { id: "board", label: "Case Board", icon: LayoutGrid },
    { id: "map", label: "Evidence Map", icon: MapIcon },
    { id: "osint", label: "OSINT Decoder", icon: BookOpen },
    { id: "personnel", label: "Personnel", icon: Users },
  ];

  return (
    <aside id="watson-sidebar" className="fixed left-0 top-0 h-screen w-64 bg-surface-container-low border-r border-outline-variant flex flex-col p-4 z-40 pt-24 hidden lg:flex">
      <div className="mb-6 px-2">
        <div className="font-label-caps text-primary text-[11px] mb-1 tracking-wider uppercase">Watson v1</div>
        <div className="font-body-sm text-on-surface-variant italic min-h-[40px] text-xs leading-relaxed">
          {typedTitle}
          <span className="animate-pulse ml-0.5 font-bold text-primary">|</span>
        </div>
        {activeModel && (
          <div className="mt-2 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[9px] font-technical text-emerald-400/70 uppercase tracking-wider">{activeModel}</span>
          </div>
        )}
      </div>

      <nav className="flex-1 space-y-1.5 overflow-y-auto pr-1">
        <div className="text-[10px] font-label-caps text-outline/50 px-3 mb-2 tracking-widest">NAVIGATION</div>
        {navItems.map(item => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button key={item.id} onClick={() => setCurrentTab(item.id)}
              className={`w-full flex items-center gap-3 p-2.5 rounded transition-all font-label-caps text-xs text-left cursor-pointer border ${
                isActive ? "bg-surface-container-high border-primary/40 text-primary" : "bg-transparent border-transparent text-on-surface-variant hover:bg-surface-container hover:text-on-surface"
              }`}>
              <Icon size={16} className={isActive ? "text-primary" : "text-on-surface-variant/70"} />
              {item.label}
            </button>
          );
        })}

        <div className="pt-4 mt-4 border-t border-outline-variant/40">
          <button onClick={() => onOpenSettings ? onOpenSettings() : setVaultOpen(!vaultOpen)}
            className="w-full flex items-center justify-between p-2.5 text-primary font-label-caps text-xs cursor-pointer hover:bg-surface-container rounded">
            <div className="flex items-center gap-3"><Key size={16} /><span>API Vault</span></div>
            <ChevronDown size={14} className={`transition-transform duration-300 ${vaultOpen ? "rotate-180" : ""}`} />
          </button>
        </div>
      </nav>

      <div className="mt-auto pt-4 space-y-3 border-t border-outline-variant/40">
        <div className="px-1 text-[10px] font-technical text-on-surface-variant/50 flex justify-between">
          <span>VERIFIABILITY: {deductionProbability}%</span>
          <span className="animate-pulse text-emerald-500">● ACTIVE</span>
        </div>
        <div className="flex justify-between px-2 pt-1">
          <button title="Archives" onClick={() => setCurrentTab("osint")} className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer">
            <FolderOpen size={18} />
          </button>
          <button title="Help" onClick={() => alert("Watson OSINT:\n\n1. Enter a target in the Investigate tab\n2. Watson runs 7-phase autonomous investigation\n3. Findings stream live into the chat\n4. Switch to Case Board to see evidence cards\n5. Connect clues with red twine\n6. API keys: Settings → API Vault")} className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer">
            <HelpCircle size={18} />
          </button>
        </div>
      </div>
    </aside>
  );
}
