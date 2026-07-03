/**
 * Watson Shared Investigation Store
 *
 * Single source of truth for cross-tab state:
 *   - Findings (clues) flow into Case Board, Evidence Map, Personnel
 *   - Twin connection: select two findings → trigger deep re-investigation
 *   - Brief entities auto-populate Personnel suspects
 *
 * Replaces the scattered useState + prop-drilling in App.tsx.
 */

import React, { createContext, useContext, useReducer, useCallback, useEffect, useRef } from "react";
import type { Clue, Suspect, SSEFinding, BriefEntity } from "../types";

// ── State ──────────────────────────────────────────────────────────

export interface WatsonState {
  /** All findings (clues) from investigations — feeds Case Board + Evidence Map */
  clues: Clue[];
  /** Suspects/people — feeds Personnel tab */
  suspects: Suspect[];
  /** Currently selected finding IDs for twin connection (max 2) */
  selectedForTwin: string[];
  /** Active twin investigation in progress */
  twinLoading: boolean;
  /** Twin investigation result */
  twinResult: any | null;
  /** Case ID of the current/last investigation */
  activeCaseId: string | null;
  /** Investigation mode */
  investigationMode: "background_check" | "due_diligence" | "deep_investigation";
  /** Deduction probability (computed from clue connections) */
  deductionProbability: number;
  /** Settings modal */
  settingsOpen: boolean;
  /** DeductionEngine modal */
  deductionOpen: boolean;
  /** Twin investigation query to auto-fire in WatsonChat */
  twinQuery: string | null;
}

const initialState: WatsonState = {
  clues: [],
  suspects: [],
  selectedForTwin: [],
  twinLoading: false,
  twinResult: null,
  activeCaseId: null,
  investigationMode: "deep_investigation",
  deductionProbability: 40,
  settingsOpen: false,
  deductionOpen: false,
  twinQuery: null,
};

// ── Actions ────────────────────────────────────────────────────────

export type WatsonAction =
  | { type: "LOAD_FROM_STORAGE"; clues: Clue[]; suspects: Suspect[] }
  | { type: "ADD_FINDINGS"; findings: SSEFinding[] }
  | { type: "ADD_CLUE"; clue: Clue }
  | { type: "DELETE_CLUE"; id: string }
  | { type: "CONNECT_CLUES"; id1: string; id2: string }
  | { type: "TOGGLE_TWIN_SELECTION"; id: string }
  | { type: "CLEAR_TWIN_SELECTION" }
  | { type: "TWIN_LOADING"; loading: boolean }
  | { type: "TWIN_RESULT"; result: any }
  | { type: "ADD_SUSPECTS_FROM_BRIEF"; entities: BriefEntity[] }
  | { type: "ADD_SUSPECT"; suspect: Suspect }
  | { type: "DELETE_SUSPECT"; id: string }
  | { type: "SET_CASE_ID"; caseId: string | null }
  | { type: "SET_MODE"; mode: WatsonState["investigationMode"] }
  | { type: "SET_SETTINGS_OPEN"; open: boolean }
  | { type: "SET_DEDUCTION_OPEN"; open: boolean }
  | { type: "SET_TWIN_QUERY"; query: string | null }
  | { type: "RECALC_PROBABILITY" };

// ── Reducer ────────────────────────────────────────────────────────

function watsonReducer(state: WatsonState, action: WatsonAction): WatsonState {
  switch (action.type) {
    case "LOAD_FROM_STORAGE":
      return { ...state, clues: action.clues, suspects: action.suspects };

    case "ADD_FINDINGS": {
      const existingIds = new Set(state.clues.map(c => c.id));
      const newClues: Clue[] = action.findings
        .filter(f => f.id && !existingIds.has(f.id))
        .map((f, i) => ({
          id: f.id || `clue_${Date.now()}_${i}`,
          title: f.title || "Untitled finding",
          type: f.source_type && f.source_type !== "web_search" ? "digital" : "osint",
          description: f.description || "",
          exhibitCode: f.phase
            ? `EX-${f.phase.toUpperCase().slice(0, 3)}`
            : `EX-${String(i + 1).padStart(3, "0")}`,
          quote: f.source_url || "",
          metadata: {
            source: f.source_type || "unknown",
            source_url: f.source_url || "",
            confidence: f.confidence || 0.5,
            tier: f.tier || "POSSIBLE",
            phase: f.phase || "",
            threat: f.tier === "CONFIRMED" ? "HIGH"
              : f.tier === "PROBABLE" ? "MEDIUM"
              : "LOW",
            timestamp: f.timestamp || new Date().toISOString(),
          },
          connections: [],
        }));
      if (newClues.length === 0) return state;
      const merged = [...newClues, ...state.clues];
      return { ...state, clues: merged };
    }

    case "ADD_CLUE":
      return { ...state, clues: [action.clue, ...state.clues] };

    case "DELETE_CLUE":
      return {
        ...state,
        clues: state.clues
          .filter(c => c.id !== action.id)
          .map(c => ({
            ...c,
            connections: c.connections.filter(connId => connId !== action.id),
          })),
        selectedForTwin: state.selectedForTwin.filter(id => id !== action.id),
      };

    case "CONNECT_CLUES":
      return {
        ...state,
        clues: state.clues.map(c => {
          if (c.id === action.id1 && !c.connections.includes(action.id2))
            return { ...c, connections: [...c.connections, action.id2] };
          if (c.id === action.id2 && !c.connections.includes(action.id1))
            return { ...c, connections: [...c.connections, action.id1] };
          return c;
        }),
      };

    case "TOGGLE_TWIN_SELECTION": {
      const already = state.selectedForTwin.includes(action.id);
      if (already) {
        return { ...state, selectedForTwin: state.selectedForTwin.filter(id => id !== action.id) };
      }
      if (state.selectedForTwin.length >= 2) {
        // Replace the oldest
        return { ...state, selectedForTwin: [state.selectedForTwin[1], action.id] };
      }
      return { ...state, selectedForTwin: [...state.selectedForTwin, action.id] };
    }

    case "CLEAR_TWIN_SELECTION":
      return { ...state, selectedForTwin: [], twinResult: null };

    case "TWIN_LOADING":
      return { ...state, twinLoading: action.loading };

    case "TWIN_RESULT":
      return {
        ...state,
        twinLoading: false,
        twinResult: action.result,
        // Merge twin findings back as clues
        clues: action.result?.findings
          ? [
              ...action.result.findings.map((f: any, i: number) => ({
                id: f.id || `twin_${Date.now()}_${i}`,
                title: f.title || "Twin finding",
                type: "osint" as const,
                description: f.description || "",
                exhibitCode: `TWIN-${String(i + 1).padStart(3, "0")}`,
                quote: f.source_url || "",
                metadata: {
                  source: "twin_investigation",
                  source_url: f.source_url || "",
                  confidence: f.confidence || 0.5,
                  tier: f.tier || "POSSIBLE",
                  phase: "deep",
                  threat: "MEDIUM" as const,
                  timestamp: new Date().toISOString(),
                },
                connections: [],
              })),
              ...state.clues,
            ]
          : state.clues,
      };

    case "ADD_SUSPECTS_FROM_BRIEF": {
      const existingNames = new Set(state.suspects.map(s => s.name.toLowerCase()));
      const newSuspects: Suspect[] = action.entities
        .filter(e => e.name && !existingNames.has(e.name.toLowerCase()))
        .map(e => ({
          id: `suspect_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          name: e.name,
          role: e.role || "unknown",
          context: e.context || "",
          occupation: e.role || "Unknown",
          status: "Suspect" as const,
          threatLevel: "Medium" as const,
          image: "",
          quote: `"${e.context || 'Entity from synthesis brief'}"`,
          bio: e.context || `Identified as ${e.role || 'entity'} in investigation brief.`,
          connections: [],
        }));
      if (newSuspects.length === 0) return state;
      return { ...state, suspects: [...newSuspects, ...state.suspects] };
    }

    case "ADD_SUSPECT":
      return { ...state, suspects: [action.suspect, ...state.suspects] };

    case "DELETE_SUSPECT":
      return { ...state, suspects: state.suspects.filter(s => s.id !== action.id) };

    case "SET_CASE_ID":
      return { ...state, activeCaseId: action.caseId };

    case "SET_MODE":
      return { ...state, investigationMode: action.mode };

    case "SET_SETTINGS_OPEN":
      return { ...state, settingsOpen: action.open };

    case "SET_DEDUCTION_OPEN":
      return { ...state, deductionOpen: action.open };

    case "SET_TWIN_QUERY":
      return { ...state, twinQuery: action.query, twinLoading: action.query !== null };

    case "RECALC_PROBABILITY": {
      const connectedCount = state.clues.reduce((acc, c) => acc + c.connections.length, 0);
      const prob = Math.min(100, 40 + connectedCount * 4 + state.clues.length * 2);
      return { ...state, deductionProbability: prob };
    }

    default:
      return state;
  }
}

// ── Context ────────────────────────────────────────────────────────

interface WatsonStoreCtx {
  state: WatsonState;
  dispatch: React.Dispatch<WatsonAction>;
  /** Convert and ingest SSE findings */
  handleFindings: (findings: SSEFinding[]) => void;
  /** Ingest brief entities (notable_entities from synthesis) */
  handleBriefEntities: (entities: BriefEntity[]) => void;
  /** Connect two clues and optionally trigger twin investigation */
  handleConnectClues: (id1: string, id2: string) => void;
  /** Select/deselect a clue for twin mode */
  handleToggleTwin: (id: string) => void;
  /** Trigger twin deep investigation on the two selected findings */
  handleTwinInvestigate: () => void;
  /** Delete a clue and its connections */
  handleDeleteClue: (id: string) => void;
  /** Add a suspect manually */
  handleAddSuspect: (suspect: Suspect) => void;
}

const WatsonStoreContext = createContext<WatsonStoreCtx | null>(null);

// ── Provider ───────────────────────────────────────────────────────

export function WatsonStoreProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(watsonReducer, initialState);
  const mountedRef = useRef(false);

  // Hydrate from localStorage on mount
  useEffect(() => {
    if (mountedRef.current) return;
    mountedRef.current = true;

    try {
      const savedClues = localStorage.getItem("WATSON_CLUES_LEDGER");
      const savedSuspects = localStorage.getItem("WATSON_SUSPECTS_LEDGER");
      if (savedClues || savedSuspects) {
        dispatch({
          type: "LOAD_FROM_STORAGE",
          clues: savedClues ? JSON.parse(savedClues) : [],
          suspects: savedSuspects ? JSON.parse(savedSuspects) : [],
        });
      }
    } catch {}
  }, []);

  // Persist to localStorage on changes
  useEffect(() => {
    if (!mountedRef.current) return;
    localStorage.setItem("WATSON_CLUES_LEDGER", JSON.stringify(state.clues.slice(0, 200)));
  }, [state.clues]);

  useEffect(() => {
    if (!mountedRef.current) return;
    localStorage.setItem("WATSON_SUSPECTS_LEDGER", JSON.stringify(state.suspects.slice(0, 100)));
  }, [state.suspects]);

  // Recalculate probability on clue changes
  useEffect(() => {
    dispatch({ type: "RECALC_PROBABILITY" });
  }, [state.clues.length]);

  // ── Action creators ──────────────────────────────────────────────

  const handleFindings = useCallback((findings: SSEFinding[]) => {
    dispatch({ type: "ADD_FINDINGS", findings });
  }, []);

  const handleBriefEntities = useCallback((entities: BriefEntity[]) => {
    dispatch({ type: "ADD_SUSPECTS_FROM_BRIEF", entities });
  }, []);

  const handleConnectClues = useCallback((id1: string, id2: string) => {
    dispatch({ type: "CONNECT_CLUES", id1, id2 });
  }, []);

  const handleToggleTwin = useCallback((id: string) => {
    dispatch({ type: "TOGGLE_TWIN_SELECTION", id });
  }, []);

  const handleTwinInvestigate = useCallback(() => {
    if (state.selectedForTwin.length < 2) return;
    const [id1, id2] = state.selectedForTwin;
    const c1 = state.clues.find(c => c.id === id1);
    const c2 = state.clues.find(c => c.id === id2);

    // Build a rich context string so Watson can actually investigate
    const fmtClue = (c: Clue | undefined, label: string): string => {
      if (!c) return `(${label}) [unknown]`;
      const parts: string[] = [];
      parts.push(`TITLE: ${c.title}`);
      if (c.description) parts.push(`DESCRIPTION: ${c.description}`);
      if (c.exhibitCode) parts.push(`EXHIBIT: ${c.exhibitCode}`);
      if (c.type) parts.push(`TYPE: ${c.type}`);
      if (c.metadata) {
        const meta = c.metadata;
        if (meta.source_url) parts.push(`SOURCE URL: ${meta.source_url}`);
        if (meta.ip) parts.push(`IP: ${meta.ip}`);
        if (meta.domain) parts.push(`DOMAIN: ${meta.domain}`);
        if (meta.email) parts.push(`EMAIL: ${meta.email}`);
        if (meta.source && meta.source !== "unknown") parts.push(`SOURCE: ${meta.source}`);
        if (meta.tier) parts.push(`CONFIDENCE TIER: ${meta.tier}`);
      }
      if (c.quote) parts.push(`QUOTE: "${c.quote}"`);
      return parts.join(" | ");
    };

    const query = [
      "Investigate the hidden connection between these two findings:",
      `[FINDING A] ${fmtClue(c1, "A")}`,
      `[FINDING B] ${fmtClue(c2, "B")}`,
      "Identify overlaps in entities, domains, IPs, people, locations, or patterns. What links them? Report specific evidence with source URLs.",
    ].join("\n\n");

    dispatch({ type: "SET_TWIN_QUERY", query });
  }, [state.selectedForTwin, state.clues]);

  const handleDeleteClue = useCallback((id: string) => {
    dispatch({ type: "DELETE_CLUE", id });
  }, []);

  const handleAddSuspect = useCallback((suspect: Suspect) => {
    dispatch({ type: "ADD_SUSPECT", suspect });
  }, []);

  const value: WatsonStoreCtx = {
    state,
    dispatch,
    handleFindings,
    handleBriefEntities,
    handleConnectClues,
    handleToggleTwin,
    handleTwinInvestigate,
    handleDeleteClue,
    handleAddSuspect,
  };

  return (
    <WatsonStoreContext.Provider value={value}>
      {children}
    </WatsonStoreContext.Provider>
  );
}

// ── Hook ───────────────────────────────────────────────────────────

export function useWatsonStore() {
  const ctx = useContext(WatsonStoreContext);
  if (!ctx) throw new Error("useWatsonStore must be used within WatsonStoreProvider");
  return ctx;
}
