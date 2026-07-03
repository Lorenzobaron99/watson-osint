import React, { useState, useEffect } from "react";
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
  const caseTitle = "Autonomous OSINT Investigation";

  useEffect(() => {
    let index = 0;
    setTypedTitle("");
    const interval = setInterval(() => {
      if (index < caseTitle.length) {
        setTypedTitle(prev => prev + caseTitle.charAt(index));
        index++;
      } else {
        clearInterval(interval);
      }
    }, 40);
    return () => clearInterval(interval);
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
