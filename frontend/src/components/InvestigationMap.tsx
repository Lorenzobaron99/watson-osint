import React, { useState, useEffect, useRef } from "react";
import { Clue, Suspect } from "../types";
import { Shield, MapPin, Eye, Link2, Plus, Zap } from "lucide-react";
import EntityGraph, { GraphEntity, GraphRelation } from "./EntityGraph";

interface InvestigationMapProps {
  clues: Clue[];
  suspects: Suspect[];
  onAddClue: (clue: Clue) => void;
  onDeleteClue?: (id: string) => void;
  deductionProbability: number;
  graphData?: { entities: GraphEntity[]; relations: GraphRelation[] };
}

export default function InvestigationMap({ 
  clues, 
  suspects, 
  onAddClue,
  onDeleteClue,
  deductionProbability,
  graphData,
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
  const hasGraph = graphData && graphData.entities.length > 0;

  // Handle map resizing
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

  // Handle click on map for custom pins
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
      connections: [selectedClueId],
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
          <p className="font-body-sm text-xs text-on-surface-variant italic mt-1">
            {hasGraph 
              ? `Entity graph: ${graphData!.entities.length} nodes, ${graphData!.relations.length} connections`
              : "\"We must map the crimson twine through London and Dartmoor.\""}
          </p>
        </div>
        <div className="flex items-center gap-2 bg-surface-container-high border border-outline-variant px-3 py-1.5 rounded text-xs font-technical">
          <span className={hasGraph ? "text-emerald-500" : "text-emerald-500 animate-pulse"}>●</span>
          <span className="text-on-surface-variant">Active Sector:</span>
          <span className="text-primary font-bold">
            {hasGraph ? "Entity Graph" : "Dartmoor & Districts"}
          </span>
        </div>
      </div>

      {/* ── Entity Graph ── */}
      {hasGraph ? (
        <div className="bg-surface-container border border-outline-variant/60 rounded overflow-hidden">
          <div className="px-4 py-2 border-b border-outline-variant/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-technical text-xs text-primary uppercase tracking-wider">
                🔗 Investigation Entity Graph
              </span>
              <span className="text-[9px] text-amber-400/60 font-technical">LIVE</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="font-technical text-[10px] text-on-surface-variant">
                {graphData!.entities.length} entities · {graphData!.relations.length} relations
              </span>
              <button
                onClick={() => {
                  const data = { entities: graphData!.entities, relations: graphData!.relations, exported_at: new Date().toISOString() };
                  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `watson-graph-${Date.now()}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                className="px-2 py-0.5 text-[9px] font-label-caps bg-primary/10 border border-primary/30 text-primary rounded hover:bg-primary/20 cursor-pointer"
                title="Export graph as JSON"
              >
                Export
              </button>
            </div>
          </div>
          <EntityGraph
            entities={graphData!.entities}
            relations={graphData!.relations}
          />
        </div>
      ) : (
        /* Empty state */
        <div className="bg-surface-container border border-outline-variant/60 rounded overflow-hidden">
          <div className="px-4 py-2 border-b border-outline-variant/40 flex items-center justify-between">
            <span className="font-technical text-xs text-primary uppercase tracking-wider">
              Entity Graph
            </span>
            <span className="font-technical text-[10px] text-on-surface-variant animate-pulse">
              Waiting for graph data…
            </span>
          </div>
          <div className="h-[400px] bg-surface-container-low flex items-center justify-center">
            <div className="text-center space-y-3">
              <div className="text-4xl opacity-30">🕸️</div>
              <p className="font-technical text-xs text-on-surface-variant/60 max-w-xs">
                Start an investigation from the <span className="text-primary">Investigate</span> tab.
                <br />
                Entities will appear here when the graph engine discovers connections.
              </p>
              <div className="flex gap-1.5 justify-center">
                <span className="w-2 h-2 rounded-full bg-primary/40 animate-pulse" style={{animationDelay: "0s"}} />
                <span className="w-2 h-2 rounded-full bg-primary/40 animate-pulse" style={{animationDelay: "0.2s"}} />
                <span className="w-2 h-2 rounded-full bg-primary/40 animate-pulse" style={{animationDelay: "0.4s"}} />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Column: Interactive Case Map */}
        <div className="xl:col-span-8 flex flex-col gap-4">
          <div className="flex items-center gap-3 pt-2 border-t border-outline-variant/30">
            <span className="font-technical text-xs text-primary uppercase tracking-wider">📍 Case Pin Map</span>
            <span className="h-px flex-1 bg-outline-variant/20" />
            <span className="text-[9px] text-on-surface-variant/50 font-technical">MANUAL EVIDENCE PINS</span>
          </div>
          <div className="text-xs font-body-sm text-on-surface-variant italic">
            💡 <span className="text-primary font-bold">Tip:</span> Click anywhere on the map to pin custom coordinates and twine them into the network!
          </div>

          <div 
            ref={mapContainerRef}
            onClick={handleMapClick}
            className={`relative h-[450px] bg-surface-container-low border border-outline-variant rounded overflow-hidden cursor-crosshair group select-none`}
          >
            <div className="absolute inset-0 bg-radial-[circle_at_center,rgba(0,0,0,0.2)_0%,rgba(0,0,0,0.8)_100%] pointer-events-none z-10" />
            <img 
              alt="Vintage London Map" 
              className="absolute inset-0 w-full h-full object-cover opacity-35 grayscale contrast-125 mix-blend-luminosity" 
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuC874Rcp9KTx6vonWy1w57JNjJHDeOf2q-7ZqK-t1jnlvwMeYmv7mpT6iqzmSYYR_tsYCSd16RYodGizpZqWZcqO_mkrp5AGxsicZn6sCgooCtvJdKzC80WfqdpqpDoGD1E7O6FSUDWe14GoeIhn_ANtyyWph21_72BRxcNts8z3zPpO5Bxmvk_g0w_7TGNPrJOkMedaiXflrvG7rUYSwQgeRmVIVSOiO5poF0T65LES8auzsrMmkljZRbPd6C5RCd0ydHVbVw-LrcM"
            />
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
                    const midX = (fromX + toX) / 2;
                    const midY = (fromY + toY) / 2 - 40;
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
            {clues.map((clue) => {
              if (!clue.coordinates) return null;
              const isSelected = clue.id === selectedClueId;
              return (
                <div
                  key={clue.id}
                  onClick={(e) => { e.stopPropagation(); setSelectedClueId(clue.id); }}
                  style={{ left: `${clue.coordinates.x}%`, top: `${clue.coordinates.y}%` }}
                  className="absolute transform -translate-x-1/2 -translate-y-1/2 z-20 cursor-pointer group"
                >
                  <div className={`w-3.5 h-3.5 rounded-full relative flex items-center justify-center transition-all ${
                    isSelected 
                      ? "bg-red-600 ring-2 ring-red-800/40 scale-110 shadow-md" 
                      : "bg-primary hover:bg-red-500 ring-1 ring-primary/20 group-hover:scale-110"
                  }`}>
                    <div className="w-1 h-1 bg-white rounded-full opacity-70 absolute top-0.5 left-0.5" />
                  </div>
                  {isSelected && onDeleteClue && (
                    <button
                      onClick={(e) => { e.stopPropagation(); onDeleteClue(clue.id); setSelectedClueId(""); }}
                      className="absolute -top-1 -right-1 w-4 h-4 bg-red-800 text-white rounded-full text-[8px] flex items-center justify-center hover:bg-red-600 z-40 cursor-pointer"
                      title="Remove pin"
                    >×</button>
                  )}
                  <div className="absolute left-1/2 -translate-x-1/2 top-5 bg-surface-container-highest border border-outline-variant text-[10px] font-technical text-primary py-0.5 px-2 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-30 pointer-events-none">
                    {clue.exhibitCode || "FOOTPRINT"} : {clue.title}
                  </div>
                </div>
              );
            })}
            <div className="absolute bottom-2 right-2 z-10 font-technical text-[10px] text-on-surface-variant/40 bg-surface-container-low/80 py-0.5 px-1.5 rounded">
              SECTOR: 50.55°N | 3.91°W
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div className="xl:col-span-4 space-y-6">
          <div className="bg-surface-container/60 border border-outline-variant/60 p-4 rounded flex flex-col items-center justify-center text-center">
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

          <div 
            className="tactile-paper p-6 flex flex-col relative"
          >
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
            <div className="space-y-3 font-body-sm text-xs chat-text-secondary flex-1 leading-relaxed">
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

          <div 
            className="tactile-paper p-5 border border-outline-variant relative"
          >
            <div className="font-label-caps text-primary border-b border-outline-variant/40 mb-2 pb-1 text-[10px] tracking-widest uppercase">
              COORDINATES WEB
            </div>
            <p className="font-body-sm italic text-xs leading-relaxed text-on-surface text-center">
              {hasGraph
                ? `"The graph reveals ${graphData!.entities.length} connected entities across the digital landscape. Follow the threads, Watson, and you shall uncover the architecture of the network."`
                : "\"Every thread on the board points to the Mire. Follow the coordinates, Watson, and you shall locate the hound.\""}
            </p>
          </div>
        </div>
      </div>

      {/* Pin Creation Modal */}
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
                  type="text" required
                  value={newPinTitle}
                  onChange={(e) => setNewPinTitle(e.target.value)}
                  className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-body-sm text-primary focus:ring-1 focus:ring-primary outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] font-label-caps text-on-surface-variant mb-1">Forensic Description</label>
                <textarea
                  required rows={3}
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
                    className="w-full bg-surface-dark border border-outline-variant rounded p-2 text-xs font-technical text-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2 border-t border-outline-variant/40">
              <button
                type="button"
                onClick={() => setShowAddPinModal(false)}
                className="px-4 py-2 border border-outline-variant text-on-surface-variant text-xs rounded hover:bg-surface-container-high cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 bg-primary text-white text-xs font-bold rounded hover:bg-red-700 cursor-pointer"
              >
                Pin to Map
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
