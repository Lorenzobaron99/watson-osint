import React, { useState } from "react";
import { Suspect } from "../types";
import { Shield, ShieldAlert, BadgeAlert, Sparkles, BookOpen } from "lucide-react";

interface PersonnelProps {
  suspects: Suspect[];
  onAddSuspect: (suspect: Suspect) => void;
}

export default function Personnel({ suspects, onAddSuspect }: PersonnelProps) {
  const [filter, setFilter] = useState<string>("All");
  const [showAddModal, setShowAddModal] = useState(false);

  // Form states for custom suspect creation
  const [newName, setNewName] = useState("");
  const [newRole, setNewRole] = useState<Suspect["status"]>("Suspect");
  const [newThreat, setNewThreat] = useState<Suspect["threatLevel"]>("Medium");
  const [newOccupation, setNewOccupation] = useState("");
  const [newBio, setNewBio] = useState("");
  const [newQuote, setNewQuote] = useState("");

  const filteredSuspects = suspects.filter(
    (s) => filter === "All" || s.status === filter
  );

  const handleCreateSuspect = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName || !newBio) return;

    // Sidney Paget style sketched portrait placeholder url (using existing high quality assets)
    const portraitPlaceholder = "https://lh3.googleusercontent.com/aida-public/AB6AXuBQ8u2qbeHTYvYPXb36MOW1qUR-8LTVkK54d6NmMKZ9V0NnVHwgOqQfrwwe9x3POchDC87DTI1Gl2sC3vjIqTqyinSu2NTNbKE9tpPb0z3DdLSy9IHy9tMlvfGYYYnAIem1ZuWd5WCGKNure9GtbUJhvdsiQgXfqrTm-F7iPiPoz_VMsCwnXTOePnFiaMuC6rBE8OunQ0_w0yZhmt7GrH8vRb5lJcxyVYQzYPvcv2V9ZS4GhW5Te6-oVZJj5xtT5v9QgEgG1pGgF1eF";

    const created: Suspect = {
      id: "sus_" + Date.now(),
      name: newName,
      occupation: newOccupation || "Gentleman of London",
      status: newRole,
      threatLevel: newThreat,
      image: portraitPlaceholder,
      quote: newQuote ? `"${newQuote}"` : '"A mystery cloaked in carbon shadows..."',
      bio: newBio,
      connections: [],
    };

    onAddSuspect(created);
    setShowAddModal(false);

    // Reset form
    setNewName("");
    setNewOccupation("");
    setNewBio("");
    setNewQuote("");
  };

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full overflow-y-auto pb-32">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-outline-variant/40 pb-4 gap-4">
        <div>
          <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">Personnel Dossiers</h1>
          <p className="font-body-sm text-xs text-on-surface-variant italic mt-1">"Identify suspects, document testimonies, and analyze motives."</p>
        </div>
        
        <button
          onClick={() => setShowAddModal(true)}
          className="px-3 py-1.5 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded cursor-pointer active:scale-95 transition-all shadow-md"
        >
          Add Dossier
        </button>
      </div>

      {/* Filter Row */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-outline-variant/20 pb-3">
        {["All", "Suspect", "Informant", "Ally"].map((status) => (
          <button
            key={status}
            onClick={() => setFilter(status)}
            className={`px-3.5 py-1 rounded-full text-[10px] font-label-caps uppercase tracking-wider transition-all cursor-pointer ${
              filter === status
                ? "bg-primary text-background-dark font-bold"
                : "bg-surface-container/40 text-on-surface-variant hover:bg-surface-container hover:text-on-surface"
            }`}
          >
            {status === "All" ? "All Dossiers" : status + "s"}
          </button>
        ))}
      </div>

      {/* Suspect Dossier Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {filteredSuspects.map((sus) => {
          // Dynamic styling for threat level badge
          const threatColors = 
            sus.threatLevel === "Critical" || sus.threatLevel === "High" 
              ? "bg-red-950/45 border-red-900 text-red-400" 
              : sus.threatLevel === "Medium"
              ? "bg-yellow-950/35 border-yellow-800 text-yellow-400"
              : "bg-emerald-950/45 border-emerald-900 text-emerald-400";

          return (
            <div 
              key={sus.id}
              className="tactile-paper p-6 rounded shadow-lg flex flex-col md:flex-row gap-6 relative overflow-hidden transform hover:-rotate-0.5 transition-transform duration-300"
            >
              {/* Pushpin at top */}
              <div className="absolute top-1 left-4 z-10">
                <div className="w-2.5 h-2.5 bg-red-800 rounded-full shadow border border-red-950" />
              </div>

              {/* Portrait Left */}
              <div className="w-full md:w-36 flex-shrink-0">
                <div className="w-full h-44 md:h-48 bg-surface-dark border border-outline-variant rounded overflow-hidden shadow-inner relative group">
                  <img 
                    alt={sus.name} 
                    className="w-full h-full object-cover grayscale contrast-125 hover:contrast-100 transition-all mix-blend-multiply opacity-80 group-hover:opacity-100" 
                    src={sus.image}
                    referrerPolicy="no-referrer"
                  />
                  {/* Fingerprint watermark detail */}
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,0,0,0)_20%,rgba(0,0,0,0.5)_100%)] pointer-events-none" />
                </div>
              </div>

              {/* Bio Details Right */}
              <div className="flex-1 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between items-start gap-2">
                    <div>
                      <h3 className="font-headline-md text-xl text-on-surface leading-tight font-bold">{sus.name}</h3>
                      <p className="font-body-sm text-xs text-primary italic">{sus.occupation}</p>
                    </div>
                    
                    {/* Role Badge */}
                    <span className="font-technical text-[8px] tracking-wider uppercase bg-surface-container-highest/80 border border-outline-variant px-1.5 py-0.5 rounded text-on-surface-variant">
                      {sus.status}
                    </span>
                  </div>

                  <p className="font-body-sm text-[12px] leading-relaxed text-on-surface-variant text-justify">
                    {sus.bio}
                  </p>

                  <div className="font-body-sm text-xs italic text-primary/70 border-l border-primary/20 pl-2 py-0.5">
                    {sus.quote}
                  </div>
                </div>

                {/* Threat Indicators Bottom */}
                <div className="pt-3 border-t border-outline-variant/20 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="font-technical text-[9px] text-on-surface-variant/40 uppercase">Threat Status:</span>
                    <span className={`font-technical text-[9px] font-bold px-2 py-0.5 rounded border uppercase ${threatColors}`}>
                      {sus.threatLevel}
                    </span>
                  </div>
                  
                  {sus.connections.length > 0 && (
                    <span className="font-technical text-[8px] text-on-surface-variant/60 uppercase bg-surface-container-low border border-outline-variant/30 py-0.5 px-1.5 rounded">
                      Linked to {sus.connections.length} leads
                    </span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Add Dossier Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <form 
            onSubmit={handleCreateSuspect}
            className="bg-surface-container border border-outline-variant max-w-md w-full p-6 rounded shadow-2xl space-y-4 font-body-md"
          >
            <div className="border-b border-outline-variant pb-3">
              <h3 className="font-headline-md text-primary text-xl">Compile New Dossier</h3>
              <p className="font-technical text-[10px] text-on-surface-variant uppercase mt-1">
                Document vital intelligence coordinates of key suspects
              </p>
            </div>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Subject Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. John Frankland"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Occupation</label>
                  <input
                    type="text"
                    placeholder="e.g. Amateur Astronomer"
                    value={newOccupation}
                    onChange={(e) => setNewOccupation(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Dossier Status</label>
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as Suspect["status"])}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-label-caps text-primary focus:ring-1 focus:ring-primary outline-none cursor-pointer"
                  >
                    <option value="Suspect">Suspect</option>
                    <option value="Informant">Informant</option>
                    <option value="Ally">Ally</option>
                    <option value="Victim">Victim</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Threat Assessment</label>
                  <select
                    value={newThreat}
                    onChange={(e) => setNewThreat(e.target.value as Suspect["threatLevel"])}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-label-caps text-primary focus:ring-1 focus:ring-primary outline-none cursor-pointer"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Witness Quote / Testimony</label>
                <input
                  type="text"
                  placeholder='e.g. "I saw Barrymore signaling on the moor..."'
                  value={newQuote}
                  onChange={(e) => setNewQuote(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface focus:ring-1 focus:ring-primary outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Forensic Biography & Scrutiny</label>
                <textarea
                  required
                  rows={4}
                  placeholder="Record full details, movements on the moor, family links, and suspicious behaviors..."
                  value={newBio}
                  onChange={(e) => setNewBio(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface focus:ring-1 focus:ring-primary outline-none resize-none"
                />
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
                Compile File
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
