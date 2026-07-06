import React, { useState, useEffect, useRef, useCallback } from "react";

// ── Types ──

export interface GraphEntity {
  id: string;
  type: string;
  value: string;
  label: string;
  source: string;
  confidence: number;
}

export interface GraphRelation {
  source_id: string;
  target_id: string;
  type: string;
  confidence: number;
}

// ── Watson-themed entity colors (dark, elegant, muted) ──

const ENTITY_COLORS: Record<string, { fill: string; glow: string; ring: string }> = {
  person:       { fill: "#D97706", glow: "rgba(217,119,6,0.3)",  ring: "rgba(217,119,6,0.5)" },
  domain:       { fill: "#60A5FA", glow: "rgba(96,165,250,0.3)",  ring: "rgba(96,165,250,0.5)" },
  ip_address:   { fill: "#34D399", glow: "rgba(52,211,153,0.3)",  ring: "rgba(52,211,153,0.5)" },
  organization: { fill: "#A78BFA", glow: "rgba(167,139,250,0.3)", ring: "rgba(167,139,250,0.5)" },
  email:        { fill: "#F87171", glow: "rgba(248,113,113,0.3)", ring: "rgba(248,113,113,0.5)" },
  location:     { fill: "#FBBF24", glow: "rgba(251,191,36,0.3)",  ring: "rgba(251,191,36,0.5)" },
  website:      { fill: "#22D3EE", glow: "rgba(34,211,238,0.3)",  ring: "rgba(34,211,238,0.5)" },
  document:     { fill: "#9CA3AF", glow: "rgba(156,163,175,0.3)", ring: "rgba(156,163,175,0.5)" },
  unknown:      { fill: "#6B7280", glow: "rgba(107,114,128,0.3)", ring: "rgba(107,114,128,0.5)" },
};

const ENTITY_RADIUS: Record<string, number> = {
  person: 18, domain: 14, ip_address: 11, organization: 15,
  email: 11, location: 13, website: 12, document: 10, unknown: 11,
};

const ENTITY_EMOJI: Record<string, string> = {
  person: "👤", domain: "🌐", ip_address: "🔢", organization: "🏢",
  email: "✉", location: "📍", website: "🖥", document: "📄", unknown: "●",
};

// ── Layout helpers ──

function computeRadialLayout(
  entities: GraphEntity[],
  relations: GraphRelation[],
  cx: number, cy: number,
): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};

  // Primary: highest confidence, or "primary_target" source
  const primary = entities.find(e => e.source === "primary_target")
    || entities.reduce((a, b) => (a.confidence > b.confidence ? a : b), entities[0]);

  // Build adjacency
  const adj: Record<string, string[]> = {};
  for (const r of relations) {
    (adj[r.source_id] ??= []).push(r.target_id);
    (adj[r.target_id] ??= []).push(r.source_id);
  }

  // BFS ring assignment
  const levels: Record<string, number> = { [primary.id]: 0 };
  const queue = [primary.id];
  const visited = new Set([primary.id]);
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const n of adj[cur] || []) {
      if (!visited.has(n)) {
        visited.add(n);
        levels[n] = (levels[cur] || 0) + 1;
        queue.push(n);
      }
    }
  }

  // Group by ring
  const rings: Record<number, string[]> = {};
  for (const e of entities) {
    const lvl = levels[e.id] ?? 99;
    (rings[lvl] ??= []).push(e.id);
  }

  const maxRing = Math.max(...Object.keys(rings).map(Number), 1);
  for (const [lvlStr, ids] of Object.entries(rings)) {
    const lvl = Number(lvlStr);
    const radius = lvl === 0 ? 0 : 12 + lvl * 16;
    ids.forEach((eid, i) => {
      if (lvl === 0) {
        positions[eid] = { x: cx, y: cy };
      } else {
        const angle = (2 * Math.PI * i) / ids.length - Math.PI / 2;
        positions[eid] = {
          x: cx + radius * Math.cos(angle),
          y: cy + radius * Math.sin(angle),
        };
      }
    });
  }

  // Fallback for unpositioned
  for (const e of entities) {
    if (!positions[e.id]) {
      positions[e.id] = { x: cx - 30 + Math.random() * 60, y: cy - 30 + Math.random() * 60 };
    }
  }

  return positions;
}

// ── Component ──

interface EntityGraphProps {
  entities: GraphEntity[];
  relations: GraphRelation[];
  compact?: boolean;
  onEntityClick?: (entity: GraphEntity) => void;
  onEntityDoubleClick?: (entity: GraphEntity) => void;
}

export default function EntityGraph({
  entities,
  relations,
  compact = false,
  onEntityClick,
  onEntityDoubleClick,
}: EntityGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 100, h: 100 });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);
  const [panning, setPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  // Base positions from layout
  const [basePositions, setBasePositions] = useState<Record<string, { x: number; y: number }>>({});
  // User-adjusted offsets
  const [offsets, setOffsets] = useState<Record<string, { x: number; y: number }>>({});

  useEffect(() => {
    if (entities.length === 0) return;
    const cx = 50, cy = 48;
    const pos = computeRadialLayout(entities, relations, cx, cy);
    setBasePositions(pos);
    setOffsets({});
    setSelectedId(null);
    setViewBox({ x: 0, y: 0, w: 100, h: 100 });
  }, [entities, relations]);

  // ── Mouse handlers ──

  const svgToViewCoords = useCallback((clientX: number, clientY: number) => {
    if (!svgRef.current) return { x: 0, y: 0 };
    const rect = svgRef.current.getBoundingClientRect();
    const x = ((clientX - rect.left) / rect.width) * viewBox.w + viewBox.x;
    const y = ((clientY - rect.top) / rect.height) * viewBox.h + viewBox.y;
    return { x, y };
  }, [viewBox]);

  // Zoom on scroll
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.15 : 0.87;
    const { x: mx, y: my } = svgToViewCoords(e.clientX, e.clientY);
    setViewBox(prev => {
      const nw = prev.w * factor;
      const nh = prev.h * factor;
      const nx = mx - (mx - prev.x) * (nw / prev.w);
      const ny = my - (my - prev.y) * (nh / prev.h);
      // Clamp
      return {
        x: Math.max(-20, Math.min(120, nx)),
        y: Math.max(-20, Math.min(120, ny)),
        w: Math.max(20, Math.min(400, nw)),
        h: Math.max(20, Math.min(400, nh)),
      };
    });
  }, [svgToViewCoords]);

  // Pan on background drag
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.target === svgRef.current || (e.target as SVGElement).classList.contains("bg-layer")) {
      setPanning(true);
      setPanStart({ x: e.clientX, y: e.clientY });
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (panning) {
      const dx = (panStart.x - e.clientX) / (svgRef.current?.clientWidth || 1) * viewBox.w;
      const dy = (panStart.y - e.clientY) / (svgRef.current?.clientHeight || 1) * viewBox.h;
      setViewBox(prev => ({
        ...prev,
        x: prev.x + dx,
        y: prev.y + dy,
      }));
      setPanStart({ x: e.clientX, y: e.clientY });
      return;
    }
    if (dragging && svgRef.current) {
      const { x, y } = svgToViewCoords(e.clientX, e.clientY);
      setOffsets(prev => ({
        ...prev,
        [dragging]: { x: x - dragOffset.x, y: y - dragOffset.y },
      }));
    }
  }, [panning, dragging, panStart, dragOffset, svgToViewCoords, viewBox]);

  const handleMouseUp = useCallback(() => {
    setPanning(false);
    setDragging(null);
  }, []);

  // Node drag start
  const handleNodeMouseDown = useCallback((e: React.MouseEvent, entityId: string) => {
    e.stopPropagation();
    const pos = getEntityPos(entityId);
    if (!pos) return;
    setDragging(entityId);
    setDragOffset({ x: pos.x, y: pos.y });
  }, []);

  // ── Helpers ──

  const getEntityPos = (id: string): { x: number; y: number } | null => {
    const base = basePositions[id];
    if (!base) return null;
    const off = offsets[id] || { x: 0, y: 0 };
    return { x: base.x + off.x, y: base.y + off.y };
  };

  const getConnectedIds = (id: string): Set<string> => {
    const ids = new Set<string>();
    for (const r of relations) {
      if (r.source_id === id) ids.add(r.target_id);
      if (r.target_id === id) ids.add(r.source_id);
    }
    return ids;
  };

  const height = compact ? 280 : 420;
  const primaryId = entities.find(e => e.source === "primary_target")?.id
    || entities[0]?.id;

  // ── Render ──

  if (entities.length === 0) return null;

  return (
    <div
      ref={containerRef}
      className="relative bg-surface-container-low border border-outline-variant/40 rounded overflow-hidden select-none"
      style={{ height }}
    >
      <svg
        ref={svgRef}
        className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing"
        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        {/* Background layer for pan detection */}
        <rect
          className="bg-layer"
          x={viewBox.x - 50} y={viewBox.y - 50}
          width={viewBox.w + 100} height={viewBox.h + 100}
          fill="transparent"
        />

        {/* Relations */}
        {relations.map((rel, i) => {
          const from = getEntityPos(rel.source_id);
          const to = getEntityPos(rel.target_id);
          if (!from || !to) return null;
          const isHighlighted = selectedId === rel.source_id || selectedId === rel.target_id
            || hoveredId === rel.source_id || hoveredId === rel.target_id;
          return (
            <line
              key={`rel-${i}`}
              x1={from.x} y1={from.y}
              x2={to.x} y2={to.y}
              stroke={isHighlighted ? "rgba(239,68,68,0.4)" : "rgba(156,163,175,0.2)"}
              strokeWidth={isHighlighted ? 0.5 : 0.25}
            />
          );
        })}

        {/* Entities */}
        {entities.map((entity) => {
          const pos = getEntityPos(entity.id);
          if (!pos) return null;
          const colors = ENTITY_COLORS[entity.type] || ENTITY_COLORS.unknown;
          const radius = (ENTITY_RADIUS[entity.type] || 11) * (compact ? 0.85 : 1);
          const isSelected = selectedId === entity.id;
          const isHovered = hoveredId === entity.id;
          const isPrimary = entity.id === primaryId;
          const connectedToSelected = selectedId ? getConnectedIds(selectedId).has(entity.id) : false;

          return (
            <g
              key={entity.id}
              className="cursor-pointer"
              onMouseDown={(e) => handleNodeMouseDown(e, entity.id)}
              onClick={(e) => {
                e.stopPropagation();
                setSelectedId(entity.id);
                onEntityClick?.(entity);
              }}
              onDoubleClick={(e) => {
                e.stopPropagation();
                onEntityDoubleClick?.(entity);
              }}
              onMouseEnter={() => setHoveredId(entity.id)}
              onMouseLeave={() => setHoveredId(null)}
            >
              {/* Glow ring for primary */}
              {isPrimary && (
                <circle cx={pos.x} cy={pos.y} r={radius + 4}
                  fill="none" stroke={colors.glow} strokeWidth={0.6}
                  opacity={0.4}
                  className="animate-pulse"
                />
              )}
              {/* Selection / hover ring */}
              {(isSelected || isHovered) && (
                <circle cx={pos.x} cy={pos.y} r={radius + 2.5}
                  fill="none"
                  stroke={isSelected ? "#EF4444" : "rgba(255,255,255,0.3)"}
                  strokeWidth={0.5}
                  opacity={0.8}
                />
              )}
              {/* Connected-to-selected indicator */}
              {connectedToSelected && !isSelected && (
                <circle cx={pos.x} cy={pos.y} r={radius + 1.5}
                  fill="none" stroke="rgba(239,68,68,0.3)" strokeWidth={0.3}
                />
              )}
              {/* Entity circle */}
              <circle cx={pos.x} cy={pos.y} r={radius}
                fill={colors.fill}
                opacity={isSelected ? 1 : isHovered ? 0.95 : 0.8}
                className="transition-opacity duration-200"
              />
              {/* Emoji icon */}
              <text x={pos.x} y={pos.y + (compact ? 0 : 0.3)}
                textAnchor="middle" dominantBaseline="middle"
                fill="#fff" fontSize={radius * (compact ? 0.7 : 0.55)}
                className="pointer-events-none"
                style={{ fontFamily: "system-ui" }}
              >
                {ENTITY_EMOJI[entity.type] || "●"}
              </text>
              {/* Label */}
              <text x={pos.x} y={pos.y + radius + (compact ? 2.2 : 3)}
                textAnchor="middle"
                fill="rgba(255,255,255,0.6)"
                fontSize={compact ? 1.8 : 2.2}
                className="pointer-events-none font-technical"
              >
                {entity.label?.length > (compact ? 12 : 18)
                  ? entity.label.slice(0, (compact ? 11 : 17)) + "…"
                  : entity.label}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Zoom controls */}
      <div className="absolute bottom-2 right-2 flex gap-0.5 z-10">
        <button
          onClick={() => setViewBox(p => ({ ...p, w: p.w * 0.8, h: p.h * 0.8 }))}
          className="w-6 h-6 bg-surface-container-highest/80 border border-outline-variant/60 rounded-l text-on-surface-variant text-xs hover:text-primary flex items-center justify-center"
        >+</button>
        <button
          onClick={() => setViewBox(p => ({ ...p, w: p.w * 1.25, h: p.h * 1.25 }))}
          className="w-6 h-6 bg-surface-container-highest/80 border border-outline-variant/60 rounded-r text-on-surface-variant text-xs hover:text-primary flex items-center justify-center"
        >−</button>
        <button
          onClick={() => {
            setViewBox({ x: 0, y: 0, w: 100, h: 100 });
            setOffsets({});
          }}
          className="w-7 h-6 bg-surface-container-highest/80 border border-outline-variant/60 rounded text-on-surface-variant text-[9px] hover:text-primary flex items-center justify-center ml-1"
          title="Reset view"
        >↺</button>
      </div>

      {/* Selected entity tooltip */}
      {selectedId && (() => {
        const entity = entities.find(e => e.id === selectedId);
        if (!entity) return null;
        const colors = ENTITY_COLORS[entity.type] || ENTITY_COLORS.unknown;
        return (
          <div className="absolute bottom-10 left-2 right-16 bg-surface-container-highest/95 backdrop-blur border border-outline-variant/60 rounded p-2.5 z-10 max-w-[220px]">
            <div className="flex items-center gap-1.5 mb-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: colors.fill }} />
              <span className="font-technical text-[9px] text-primary uppercase tracking-wider">{entity.type}</span>
              <button onClick={() => setSelectedId(null)} className="ml-auto text-on-surface-variant/50 hover:text-on-surface text-[10px]">×</button>
            </div>
            <p className="font-body-sm text-[11px] text-on-surface font-medium leading-tight">
              {entity.label || entity.value}
            </p>
            <div className="mt-1 space-y-0.5 font-technical text-[8px] text-on-surface-variant/70">
              <div>Source: {entity.source}</div>
              <div>Confidence: {(entity.confidence * 100).toFixed(0)}%</div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
