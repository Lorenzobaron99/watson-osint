import React, { useState, useEffect, useRef } from "react";
import { Clue, Suspect } from "../types";
import { Shield, MapPin, Eye, Link2, Plus, Zap } from "lucide-react";

interface InvestigationMapProps {
  clues: Clue[];
  suspects: Suspect[];
  onAddClue: (clue: Clue) => void;
  onDeleteClue?: (id: string) => void;
  deductionProbability: number;
}

export default function InvestigationMap({ 
  clues, 
  suspects, 
  onAddClue,
  onDeleteClue,
  deductionProbability 
}: InvestigationMapProps) {
  const [selectedClueId, setSelectedClueId] = useState<string>("clue_jack_stapleton");
  const [showAddPinModal, setShowAddPinModal] = useState(false);
  const [newPinCoords, setNewPinCoords] = useState<{ x: number; y: number } | null>(null);
  const [newPinTitle, setNewPinTitle] = useState("");
  const [newPinDescription, setNewPinDescription] = useState("");
  const [newPinExhibit, setNewPinExhibit] = useState("");
  const [newPinQuote, setNewPinQuote] = useState("");

  const mapContainerRef = useRef<HTMLDivElement>(null);
  const [svgDimensions, setSvgDimensions] = useState({ width: 0, height: 0 });

  const selectedClue = clues.find((c) => c.id === selectedClueId) || clues[0];
  const associatedSuspect = suspects.find(
    (s) => s.name.toLowerCase().includes(selectedClue?.title.toLowerCase().replace("profile", "").trim()) ||
           s.id === "sus_stapleton" // Fallback fallback for styling
  );

  // Handle map resizing to keep SVG coordinates properly synchronized
  useEffect(() => {
    if (!mapContainerRef.current) return;
    const updateDimensions = () => {
      if (mapContainerRef.current) {
        setSvgDimensions({
          width: mapContainerRef.current.clientWidth,
          height: mapContainerRef.current.clientHeight,
        });
      }
    };
    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    const observer = new ResizeObserver(updateDimensions);
    observer.observe(mapContainerRef.current);
    return () => {
      window.removeEventListener("resize", updateDimensions);
      observer.disconnect();
    };
  }, []);

  // Handle click on map to set coordinate for new custom pins
  const handleMapClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (showAddPinModal) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = Math.round(((e.clientX - rect.left) / rect.width) * 100);
    const y = Math.round(((e.clientY - rect.top) / rect.height) * 100);
    setNewPinCoords({ x, y });
    setNewPinTitle("Custom Coordinate Footprint");
    setNewPinDescription("A localized OSINT trace logged at grid coordinate x:" + x + ", y:" + y);
    setNewPinExhibit("EXHIBIT MAP-" + x + y);
    setNewPinQuote("A fresh link pinned to the web of twine...");
    setShowAddPinModal(true);
  };

  const handleCreatePin = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPinCoords || !newPinTitle) return;

    const newClue: Clue = {
      id: "clue_custom_" + Date.now(),
      title: newPinTitle,
      type: "location",
      description: newPinDescription,
      exhibitCode: newPinExhibit || undefined,
      quote: newPinQuote || undefined,
      coordinates: newPinCoords,
      connections: [selectedClueId], // Automatically twine to the currently selected clue!
      metadata: {
        source: "Manual Map Pin",
        threat: "MEDIUM",
        timestamp: new Date().toISOString().split("T")[0],
      }
    };

    onAddClue(newClue);
    setSelectedClueId(newClue.id);
    setShowAddPinModal(false);
    setNewPinCoords(null);
  };

  return (
    <div className="p-4 lg:p-6 space-y-6 h-full overflow-y-auto pb-32">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-outline-variant/40 pb-4 gap-4">
        <div>
          <h1 className="font-headline-md text-primary text-2xl lg:text-3xl leading-none">Evidence Map</h1>
          <p className="font-body-sm text-xs text-on-surface-variant italic mt-1">"We must map the crimson twine through London and Dartmoor."</p>
        </div>
        <div className="flex items-center gap-2 bg-surface-container-high border border-outline-variant px-3 py-1.5 rounded text-xs font-technical">
          <span className="text-emerald-500 animate-pulse">●</span>
          <span className="text-on-surface-variant">Active Sector:</span>
          <span className="text-primary font-bold">Dartmoor &amp; Districts</span>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Column: Interactive Map Grid */}
        <div className="xl:col-span-8 flex flex-col gap-4">
          <div className="text-xs font-body-sm text-on-surface-variant italic">
            💡 <span className="text-primary font-bold">Tip:</span> Click anywhere on the map to pin custom coordinates and twine them into the network!
          </div>

          <div 
            ref={mapContainerRef}
            onClick={handleMapClick}
            className="relative h-[450px] bg-surface-container-low border border-outline-variant rounded overflow-hidden shadow-2xl cursor-crosshair group select-none"
          >
            {/* Ambient shader/texture overlay mimicking old parchment cartography */}
            <div className="absolute inset-0 bg-radial-[circle_at_center,rgba(0,0,0,0.2)_0%,rgba(0,0,0,0.8)_100%] pointer-events-none z-10" />

            {/* Vintage London/Dartmoor Sketch Map */}
            <img 
              alt="Vintage London Map" 
              className="absolute inset-0 w-full h-full object-cover opacity-35 grayscale contrast-125 mix-blend-luminosity" 
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuC874Rcp9KTx6vonWy1w57JNjJHDeOf2q-7ZqK-t1jnlvwMeYmv7mpT6iqzmSYYR_tsYCSd16RYodGizpZqWZcqO_mkrp5AGxsicZn6sCgooCtvJdKzC80WfqdpqpDoGD1E7O6FSUDWe14GoeIhn_ANtyyWph21_72BRxcNts8z3zPpO5Bxmvk_g0w_7TGNPrJOkMedaiXflrvG7rUYSwQgeRmVIVSOiO5poF0T65LES8auzsrMmkljZRbPd6C5RCd0ydHVbVw-LrcM"
            />

            {/* Dynamic Connections Web - Drawing Crimson Threads */}
            <svg 
              className="absolute inset-0 w-full h-full pointer-events-none z-10"
              style={{ width: svgDimensions.width, height: svgDimensions.height }}
            >
              <g className="connections-group">
                {clues.map((clue) => {
                  if (!clue.coordinates) return null;
                  const fromX = (clue.coordinates.x / 100) * svgDimensions.width;
                  const fromY = (clue.coordinates.y / 100) * svgDimensions.height;

                  return clue.connections.map((targetId) => {
                    const target = clues.find((tc) => tc.id === targetId);
                    if (!target || !target.coordinates) return null;

                    const toX = (target.coordinates.x / 100) * svgDimensions.width;
                    const toY = (target.coordinates.y / 100) * svgDimensions.height;

                    // Draw a lovely bezier curve representing crimon twine
                    const midX = (fromX + toX) / 2;
                    const midY = (fromY + toY) / 2 - 40; // upward arch

                    return (
                      <path 
                        key={`${clue.id}-${targetId}`}
                        className="red-string"
                        d={`M${fromX},${fromY} Q${midX},${midY} ${toX},${toY}`}
                        fill="none"
                      />
                    );
                  });
                })}
              </g>
            </svg>

            {/* Render Map Pin Tacks */}
            {clues.map((clue) => {
              if (!clue.coordinates) return null;
              const isSelected = clue.id === selectedClueId;

              return (
                <div
                  key={clue.id}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedClueId(clue.id);
                  }}
                  style={{ 
                    left: `${clue.coordinates.x}%`, 
                    top: `${clue.coordinates.y}%` 
                  }}
                  className="absolute transform -translate-x-1/2 -translate-y-1/2 z-20 cursor-pointer group"
                >
                  {/* Brass Tack Core */}
                  <div className={`w-3.5 h-3.5 rounded-full relative flex items-center justify-center transition-all ${
                    isSelected 
                      ? "bg-red-600 ring-4 ring-red-800/60 scale-125 shadow-[0_0_12px_#ef4444]" 
                      : "bg-primary hover:bg-red-500 ring-2 ring-primary/30 group-hover:scale-110 shadow-md"
                  }`}>
                    {/* Tiny metal highlight inside the brass tack */}
                    <div className="w-1 h-1 bg-white rounded-full opacity-70 absolute top-0.5 left-0.5" />
                  </div>

                  {/* Delete button — visible on selected pin */}
                  {isSelected && onDeleteClue && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteClue(clue.id);
                        setSelectedClueId("");
                      }}
                      className="absolute -top-1 -right-1 w-4 h-4 bg-red-800 text-white rounded-full text-[8px] flex items-center justify-center hover:bg-red-600 z-40 cursor-pointer"
                      title="Remove pin"
                    >
                      ×
                    </button>
                  )}

                  {/* Tooltip on Hover */}
                  <div className="absolute left-1/2 -translate-x-1/2 top-5 bg-surface-container-highest border border-outline-variant text-[10px] font-technical text-primary py-0.5 px-2 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-30 pointer-events-none">
                    {clue.exhibitCode || "FOOTPRINT"} : {clue.title}
                  </div>
                </div>
              );
            })}

            {/* Grid coordinates overlay */}
            <div className="absolute bottom-2 right-2 z-10 font-technical text-[10px] text-on-surface-variant/40 bg-surface-container-low/80 py-0.5 px-1.5 rounded">
              SECTOR: 50.55°N | 3.91°W
            </div>
          </div>
        </div>

        {/* Right Column: Physical suspect & exhibit cards stacked */}
        <div className="xl:col-span-4 space-y-6">
          {/* Statistical Probability Node */}
          <div className="bg-surface-container/60 backdrop-blur border border-outline-variant/60 p-4 rounded flex flex-col items-center justify-center text-center shadow-lg relative floating-node" style={{ animationDelay: "-2s" }}>
            <div className="text-primary font-technical text-4xl font-bold leading-none mb-0.5">
              {deductionProbability}%
            </div>
            <div className="font-label-caps text-[9px] text-on-surface-variant tracking-wider mb-2.5 uppercase">
              Deduction Probability
            </div>
            <div className="w-full bg-surface-container-highest rounded-full h-1 overflow-hidden">
              <div 
                className="bg-primary h-full transition-all duration-1000"
                style={{ width: `${deductionProbability}%` }}
              />
            </div>
          </div>

          {/* Suspect/Source Card (Tactile Paper) */}
          <div 
            className="tactile-paper p-6 flex flex-col transform -rotate-1 hover:rotate-0 transition-transform duration-500 shadow-2xl relative floating-node"
            style={{ animationDelay: "-4s" }}
          >
            {/* Pushpin simulation at top */}
            <div className="absolute top-0.5 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-30">
              <div className="w-3.5 h-3.5 bg-red-800 rounded-full shadow-inner border border-red-950 relative flex items-center justify-center">
                <div className="w-1 h-1 bg-white rounded-full opacity-60 absolute top-0.5 left-0.5" />
              </div>
            </div>

            <div className="flex justify-between items-start mb-4">
              <div>
                <h2 className="font-headline-md text-on-surface leading-tight text-xl font-bold">
                  {selectedClue?.title}
                </h2>
                <span className="font-technical text-[10px] text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded uppercase mt-1 inline-block">
                  {selectedClue?.type} trace
                </span>
              </div>
              <div className="w-2.5 h-2.5 bg-red-800 rounded-full shadow-md mt-1" />
            </div>

            {/* Display Portrait or Placeholder */}
            {selectedClue?.image ? (
              <div className="w-full h-44 bg-surface-dark mb-4 border border-outline-variant overflow-hidden shadow-inner">
                <img 
                  alt={selectedClue?.title} 
                  className="w-full h-full object-cover grayscale contrast-125 mix-blend-multiply opacity-85 hover:opacity-100 transition-opacity"
                  src={selectedClue.image}
                  referrerPolicy="no-referrer"
                />
              </div>
            ) : (
              <div className="w-full h-24 bg-surface-dark/50 mb-4 border border-dashed border-outline-variant flex flex-col items-center justify-center text-center p-3">
                <Shield size={24} className="text-on-surface-variant/40 mb-1" />
                <span className="font-technical text-[9px] text-on-surface-variant/60 uppercase">Forensic Material Logged</span>
              </div>
            )}

            <div className="space-y-3 font-body-sm text-xs text-on-surface-variant flex-1 leading-relaxed">
              <p className="border-b border-outline-variant/30 pb-1.5">
                <span className="font-bold text-primary">Exhibit Reference:</span> {selectedClue?.exhibitCode || "EX-NONE"}
              </p>
              
              <p className="text-on-surface text-[13px] leading-relaxed">
                {selectedClue?.description}
              </p>

              {selectedClue?.quote && (
                <div className="bg-black/10 border-l-2 border-primary/40 pl-3 py-1 font-body-sm italic text-on-surface-variant/90 text-center my-2">
                  "{selectedClue.quote}"
                </div>
              )}

              {selectedClue?.metadata && (
                <div className="pt-2 border-t border-outline-variant/30 font-technical text-[9px] space-y-1 text-primary/80">
                  {selectedClue.metadata.source && <div>SRC: {selectedClue.metadata.source}</div>}
                  {selectedClue.metadata.threat && <div>THREAT: {selectedClue.metadata.threat}</div>}
                  {selectedClue.metadata.ip && <div>IP: {selectedClue.metadata.ip}</div>}
                  {selectedClue.metadata.domain && <div>DOMAIN: {selectedClue.metadata.domain}</div>}
                  {selectedClue.metadata.email && <div>EMAIL: {selectedClue.metadata.email}</div>}
                </div>
              )}
            </div>
          </div>

          {/* Exhibit Node (Card pinned separately) */}
          <div 
            className="tactile-paper p-5 border border-outline-variant transform rotate-1 hover:rotate-0 transition-transform duration-500 shadow-xl relative floating-node"
            style={{ animationDelay: "-6s" }}
          >
            <div className="font-label-caps text-primary border-b border-outline-variant/40 mb-2 pb-1 text-[10px] tracking-widest uppercase">
              COORDINATES WEB
            </div>
            <p className="font-body-sm italic text-xs leading-relaxed text-on-surface text-center">
              "Every thread on the board points to the Mire. Follow the coordinates, Watson, and you shall locate the hound."
            </p>
          </div>
        </div>
      </div>

      {/* Pin Creation Modal Overlay */}
      {showAddPinModal && newPinCoords && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <form 
            onSubmit={handleCreatePin}
            className="bg-surface-container border border-outline-variant max-w-md w-full p-6 rounded shadow-2xl space-y-4 font-body-md"
          >
            <div className="border-b border-outline-variant pb-3">
              <h3 className="font-headline-md text-primary text-xl">Pin Coordinate trace</h3>
              <p className="font-technical text-[10px] text-on-surface-variant uppercase mt-1">
                LOCATION GRID: X {newPinCoords.x}% | Y {newPinCoords.y}%
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Trace Title</label>
                <input
                  type="text"
                  required
                  value={newPinTitle}
                  onChange={(e) => setNewPinTitle(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-primary focus:ring-1 focus:ring-primary outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Forensic Description</label>
                <textarea
                  required
                  rows={3}
                  value={newPinDescription}
                  onChange={(e) => setNewPinDescription(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface focus:ring-1 focus:ring-primary outline-none resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Exhibit Ref</label>
                  <input
                    type="text"
                    value={newPinExhibit}
                    onChange={(e) => setNewPinExhibit(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-technical text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Quote Key</label>
                  <input
                    type="text"
                    value={newPinQuote}
                    onChange={(e) => setNewPinQuote(e.target.value)}
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-on-surface-variant focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-outline-variant">
              <button
                type="button"
                onClick={() => setShowAddPinModal(false)}
                className="px-4 py-2 text-xs font-label-caps border border-outline-variant text-on-surface-variant hover:text-on-surface rounded cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded cursor-pointer"
              >
                Secure Pin
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
