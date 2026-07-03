// Watson OSINT types — matches the Python backend SSE events

export interface Clue {
  id: string;
  title: string;
  type: "physical" | "digital" | "witness" | "location" | "osint";
  description: string;
  exhibitCode?: string;
  quote?: string;
  image?: string;
  metadata?: {
    source?: string;
    threat?: string;
    timestamp?: string;
    ip?: string;
    domain?: string;
    email?: string;
    source_url?: string;
    source_type?: string;
    confidence?: number;
    tier?: string;
    phase?: string;
  };
  coordinates?: { x: number; y: number };
  connections: string[];
}

export interface Suspect {
  id: string;
  name: string;
  /** Role from brief synthesis (regulator, executive, company, court, etc.) */
  role?: string;
  /** Context snippet from brief */
  context?: string;
  occupation: string;
  status: "Suspect" | "Victim" | "Informant" | "Ally";
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  image: string;
  quote: string;
  bio: string;
  connections: string[];
}

/** A single entity from the synthesis brief's notable_entities array */
export interface BriefEntity {
  name: string;
  role: string;
  context: string;
}

export interface OSINTScanResult {
  id: string;
  queryType: "ip" | "domain" | "email" | "username" | "person" | "company" | "wallet";
  queryValue: string;
  timestamp: string;
  rawOutput: string;
  deductions: string[];
  threatScore: number;
  associatedEntity?: string;
}

export interface CaseDeduction {
  probability: number;
  culprit: string;
  motive: string;
  method: string;
  summary: string;
  timeline: { event: string; date: string; relevance: string }[];
}

// SSE event types from Watson backend
export interface SSEFinding {
  id: string;
  title: string;
  description: string;
  source_type: string;
  source_url: string;
  source_tier: string;
  confidence: number;
  tier: string;
  entities: any[];
  phase: string;
  timestamp: string;
}

export interface SSETargetProfile {
  target_type: string;
  primary_name: string;
  confidence: number;
  associated_orgs: string[];
  associated_domains: string[];
  social_handles: string[];
  known_aliases: string[];
  locations: string[];
  wikidata_qid: string | null;
  wikidata_label: string | null;
  wikidata_description: string | null;
  suggested_sources: string[];
  investigation_angles: string[];
  classified_by: string;
}

export interface SSEBrief {
  executive_summary: string;
  risk_themes: { theme: string; severity: string; summary: string; source_titles: string[] }[];
  notable_entities: { name: string; role: string; context: string }[];
  evidence_gaps: string[];
  recommended_next_steps: any[];
  _synthesized: boolean;
}

export interface InvestigationResult {
  case_id: string;
  query: string;
  target_type: string;
  findings_count: number;
  confirmed_count: number;
  verifiability_score: number;
  brief: SSEBrief | null;
  markdown: string;
  phases_completed: string[];
}
