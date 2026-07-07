"""Intelligence synthesis — turn gathered findings into an analyst's brief.

This is the step that separates Watson from a clipping service. The reasoning
loop gathers sources; synthesis READS them and produces:

  - Executive summary (2-3 sentences: what's the bottom line)
  - Key risk themes (grouped: antitrust, labor, tax, data/privacy, sanctions…)
  - Severity per theme (HIGH / MEDIUM / LOW) with the evidence behind it
  - Notable entities (people, orgs, regulators involved)
  - Timeline (chronological events: career, criminal, legal, financial, education)
  - Evidence gaps (what couldn't be verified)
  - Recommended next steps
  - Source list with credibility

Every claim is grounded in a finding — synthesis NEVER invents facts.
"""

from __future__ import annotations

import json
import logging
from typing import Any

# Try to import Finding from wherever it lives
try:
    from watson.agents.protocol import Finding
except ImportError:
    try:
        from watson.engine import Finding
    except ImportError:
        from dataclasses import dataclass

        @dataclass
        class Finding:
            title: str = ""
            description: str = ""
            source_url: str = ""
            source_type: str = ""
            confidence: float = 0.5
            raw_data: dict | None = None

logger = logging.getLogger("watson.synthesis")

_SYNTHESIS_PROMPT = """You are an intelligence analyst writing a due-diligence brief.

TARGET: {query}
TARGET TYPE: {target_type}
FOCUS: {focus}

You have gathered the following raw findings (sources already read). Synthesize
them into a structured intelligence brief. Use ONLY information present in these
findings — do NOT add outside knowledge or invent facts. If something is unclear
or unverified, say so.

{target_specific_guidance}

FINDINGS:
{findings}

{resolved_entities}

{intelligence}

{cross_platform_correlation}

Produce STRICT JSON (no markdown fences) with this shape:
{{
  "executive_summary": "2-3 sentence bottom line for a decision-maker",
  "risk_themes": [
    {{"theme": "Antitrust / Competition", "severity": "HIGH|MEDIUM|LOW",
      "summary": "what the evidence shows", "source_titles": ["..."]}}
  ],
  "notable_entities": [
    {{"name": "...", "role": "regulator|executive|company|court|cybercriminal", "context": "..."}}
  ],
  "timeline": [
    {{"date": "YYYY or YYYY-MM or YYYY-MM-DD", "category": "career|criminal|legal|education|personal|financial",
      "event": "what happened", "source_title": "which finding this came from"}}
  ],
  "evidence_gaps": ["what could not be verified or is missing"],
  "recommended_next_steps": [
    {{"entity": "the specific target (wallet, domain, name, IP, etc.) — NOT the full instruction",
      "action": "what to do with it (trace, investigate, search, etc.)",
      "tool_hint": "best tool category (blockchain, sanctions, corporate, domain, social, web)"}}
  ]
}}

Rules:
- 2-5 risk themes, ordered by severity.
- severity reflects evidence strength + impact, not your opinion.
- notable_entities: real orgs/people/regulators that appear in the findings.
- TIMELINE: extract every date-backed event from findings. Birth dates, employment
  start/end, arrests, convictions, sentencing, sanctions designations, company
  founding, acquisitions, lawsuits filed/resolved. Use partial dates when exact
  unknown (e.g., "2025" or "2025-07"). Order chronologically. Max 15 events.
  Categories: career, criminal, legal, education, personal, financial.
  NEVER invent dates — if a finding says "sentenced in 2023", use "2023", not a guess.
- Be specific: name the regulator, the amount, the year when the finding states it.
- If findings are thin, say so in executive_summary and keep themes minimal.
- CRITICAL: IGNORE findings about unrelated people, organizations, or topics. If a
  finding is about "Lynn Packer", "Mohammad Faisal", "Russian Army", or any person/org
  that has nothing to do with the target, discard it completely. Only synthesize
  findings that are DIRECTLY about the target or the target's industry/domain.
- CRITICAL for recommended_next_steps: do NOT suggest steps that were ALREADY
  executed. The tools listed below already ran — recommending them again is wrong.
  Only suggest genuinely new follow-up vectors that haven't been tried.

TOOLS ALREADY EXECUTED (do NOT re-recommend these):
{executed_tools}
"""

_TARGET_GUIDANCE = {
    "person": (
        "PERSON INVESTIGATION GUIDANCE:\n"
        "- The goal is to IDENTIFY this individual: who they are, what they do, their affiliations,\n"
        "  professional background, and digital footprint.\n"
        "- LinkedIn, ResearchGate, GitHub, Behance, Twitter profiles ARE substantive findings —\n"
        "  they establish identity, career, and expertise. Do NOT dismiss these as 'not intelligence.'\n"
        "- Social media profiles, professional pages, and news mentions are the PRIMARY deliverables\n"
        "  for a person investigation — not a failure or thin result.\n"
        "- Risk themes are OPTIONAL for persons. If no sanctions/criminal findings exist, that's\n"
        "  NORMAL for most people. Don't fabricate risk themes to fill space.\n"
        "- The executive summary should state WHO this person is (role, org, location) based on\n"
        "  available findings, even if partial.\n"
        "- ENTITY DISAMBIGUATION: If findings describe what appear to be MULTIPLE DIFFERENT PEOPLE\n"
        "  sharing the same name (e.g., a wanted fugitive AND an academic researcher), you MUST\n"
        "  flag this ambiguity. In notable_entities, list each distinct identity separately with\n"
        "  'role' indicating what's known about EACH. Add a risk_theme with theme 'Entity Disambiguation'\n"
        "  explaining whether these are likely the same person or different individuals. This is\n"
        "  CRITICAL — conflating two people with the same name is a catastrophic intelligence failure."
    ),
    "email": (
        "EMAIL INVESTIGATION GUIDANCE:\n"
        "- Identify the person behind the email, their affiliations, breach history, and accounts.\n"
        "- Breach data, social profiles, and username pivots are substantive findings."
    ),
    "domain": (
        "DOMAIN INVESTIGATION GUIDANCE:\n"
        "- Focus on infrastructure: WHOIS, DNS, TLS certs, subdomain enumeration, technologies.\n"
        "- Identify the organization behind the domain and assess its legitimacy."
    ),
    "company": (
        "COMPANY INVESTIGATION GUIDANCE:\n"
        "- Focus on corporate structure, ownership, regulatory actions, sanctions, controversies.\n"
        "- Executive leadership, subsidiaries, and legal risks are key.\n"
        "- EMPLOYEE PIVOT FINDINGS: Findings prefixed with 👤 [Name] are key people detected\n"
        "  during the investigation. Cross-reference them in risk themes and notable entities.\n"
        "  If an executive has sanctions, lawsuits, or controversy findings, surface that in\n"
        "  the executive summary — it's often the most actionable intelligence in the report.\n"
        "- Risk themes should include 'Executive / Leadership Risk' when key people have\n"
        "  adverse findings (lawsuits, sanctions, controversies)."
    ),
    "wallet": (
        "WALLET INVESTIGATION GUIDANCE:\n"
        "- Trace transactions, identify counterparties, check sanctions lists, and assess risk.\n"
        "- Exchange interactions and token holdings are substantive."
    ),
}

_PERSON_DEEP_GUIDANCE = (
    "PERSON DEEP INVESTIGATION GUIDANCE:\n"
    "- This is a CRIMINAL/LEGAL investigation. Look for: criminal charges, convictions, sentences,\n"
    "  court cases, arrests, indictments, Interpol notices, sanctions (OFAC/UN/EU), asset freezes,\n"
    "  travel bans, organized crime connections, cartel affiliations, prison records, wanted status.\n"
    "- Wikipedia, sanctions databases, and crime/legal news articles ARE the primary evidence.\n"
    "- Risk themes ARE expected — criminal/legal findings ARE the deliverable. Rank by severity.\n"
    "- The executive summary should state who this person is, their criminal/legal status,\n"
    "  and key charges/sanctions with dates and jurisdictions.\n"
    "- If no criminal findings were found, state that clearly — do not fabricate."
)

_PERSON_DUE_DILIGENCE_GUIDANCE = (
    "PERSON DUE DILIGENCE GUIDANCE:\n"
    "- This is a PROFESSIONAL/BUSINESS investigation. Focus on: employment history, board positions,\n"
    "  business affiliations, corporate connections, professional reputation.\n"
    "- Also check for: lawsuits, regulatory actions, fines, penalties, adverse media,\n"
    "  fraud allegations, ethics violations, professional misconduct.\n"
    "- Risk themes may include regulatory risk, reputational risk, litigation risk.\n"
    "- The executive summary should state who this person is professionally, their role,\n"
    "  and any adverse findings that would concern a business partner or employer."
)


def _format_executed_tools(executed: set[tuple[str, str]] | None) -> str:
    """Format executed tool+target pairs for injection into the synthesis prompt."""
    if not executed:
        return "(no tools were executed — this was a direct analysis)"
    lines = []
    for tool, target in sorted(executed):
        lines.append(f"  • {tool}: {target[:120]}")
    return "\n".join(lines) if lines else "(no tools executed)"


def _format_resolved_entities(resolved: list | None) -> str:
    """Format resolved entities for the synthesis prompt."""
    if not resolved:
        return ""
    lines = ["RESOLVED ENTITIES (cross-referenced, deduplicated):"]
    for e in resolved:
        # ResolvedEntity is a dataclass — use getattr, not .get()
        name = getattr(e, "canonical_name", None) or getattr(e, "canonical", str(e))
        etype = getattr(e, "entity_type", None) or getattr(e, "etype", "unknown")
        confidence = getattr(e, "confidence", 0)
        src_count = getattr(e, "total_sources", None)
        if src_count is None:
            src_findings = getattr(e, "source_findings", None)
            src_count = len(src_findings) if src_findings else len(getattr(e, "finding_ids", []))
        aliases = getattr(e, "aliases", [])
        lines.append(
            f"  • {name} [{etype}] — confidence {confidence:.0%}, "
            f"{src_count} sources"
        )
        if aliases:
            lines.append(f"    aliases: {', '.join(list(aliases)[:5])}")
    return "\n".join(lines)


def _filter_relevant_findings(
    findings: list,
    query: str,
    target_type: str = "",
    min_score: int = 25,
    min_keep: int = 5,
) -> list:
    """Score each finding against the target query and discard noise.
    
    Returns only findings likely relevant to the investigation target.
    Prevents the LLM from drowning in unrelated web-search noise 
    (Obama tan suits, Big Tigger lawsuits, Audi forum posts, etc.).
    
    Scoring is deterministic — no LLM calls.
    """
    import re as _re
    
    query_lower = query.lower().strip()
    query_terms = set(query_lower.split())
    # Also extract the main target domain/name for matching
    query_words = [w for w in query_lower.split() if len(w) > 2]
    
    # Source-type relevance boost by target type
    _SOURCE_RELEVANCE = {
        "organization": {"wikidata": 5, "corporate-finance": 5, "websites-domains": 4,
                         "dns": 5, "crtsh": 5, "sanctions": 4, "scraper": 3},
        "person": {"people-search": 5, "social-media": 4, "wikidata": 4, "sanctions": 5,
                   "criminal-legal": 5, "scraper": 3},
        "domain": {"websites-domains": 5, "dns": 5, "crtsh": 5, "scraper": 3},
    }
    
    # Noise patterns: these are almost certainly irrelevant for any target
    _NOISE_PATTERNS = [
        r'\bdictionary\s+definition\b', r'\bforum\s+post\b', r'\binstagram\s+likes?\b',
        r'\btan\s+suit\b', r'\bcontroversy\b(?!.*(?:fraud|sanction|investigation))',
        r'\bdefamation\s+lawsuit\b', r'\bbreaks?\s+silence\b',
        r'\b7\s*nation\s*army\b', r'\bwhite\s+stripes?\b(?!.*(?:com\b|\.com))',
        r'\bservice\s+due\b', r'\bremove.*(?:warning|stripe)\b',
        r'\btechnical\s+(?:forecast|analysis)\b', r'\bforex\b',
        r'\bfree\s+instagram\b', r'\bhow\s+to\s+(?:get|remove|fix)\b',
        r'\btiktok\b', r'\byoutube\s+(?:summarizer|cover|music)\b',
    ]
    
    # Scoring per finding
    def _score(f) -> int:
        title = (getattr(f, "title", "") or "").lower()
        desc = (getattr(f, "description", "") or "").lower()
        url = (getattr(f, "source_url", "") or "").lower()
        source_type = (getattr(f, "source_type", "") or "").lower()
        source_tier = (getattr(f, "source_tier", "") or "").upper()
        confidence = getattr(f, "confidence", 0.5) or 0.5
        combined = f"{title} {desc}"
        
        score = 0
        
        # ── Strong positive signals ──
        # Target name appears in title
        if any(term in title for term in query_terms if len(term) > 3):
            score += 50
        elif any(term in title for term in query_terms):
            score += 40
        
        # Target terms appear in description
        desc_term_matches = sum(1 for t in query_terms if len(t) > 3 and t in desc)
        score += desc_term_matches * 15
        
        # Source URL contains target domain
        target_domain = None
        for term in query_terms:
            if '.' in term:
                target_domain = term
                break
        if target_domain and target_domain in url:
            score += 60
        
        # Source type relevance boost
        st_relevance = _SOURCE_RELEVANCE.get(target_type, {})
        score += st_relevance.get(source_type, 0) * 5
        
        # Source tier: PRIMARY findings are inherently relevant
        if source_tier == "PRIMARY":
            score += 15
        elif source_tier == "TERTIARY":
            score -= 10
        
        # Confidence: high-confidence findings more likely relevant
        if confidence >= 0.85:
            score += 10
        
        # ── Entity matching ──
        for ent in getattr(f, "entities", []) or []:
            ent_val = (ent.get("value", "") or ent.get("name", "") or str(ent)).lower()
            if any(term in ent_val for term in query_words if len(term) > 2):
                score += 25
                break
        
        # ── Negative signals (noise detection) ──
        # Check noise patterns
        for pattern in _NOISE_PATTERNS:
            if _re.search(pattern, combined):
                score -= 30
                break
        
        # Title contains clearly unrelated capitalized proper names
        # (e.g., "Lynn Packer", "Mohammad Faisal", "Russian Army")
        # that don't overlap with the target query
        proper_names = _re.findall(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b', 
                                   getattr(f, "title", "") or "")
        for name in proper_names:
            name_lower = name.lower()
            name_parts = set(name_lower.split())
            if not (name_parts & query_terms):
                # This proper name doesn't overlap with target at all
                # If description ALSO has zero target mentions, it's almost certainly noise
                desc_has_target = any(t in desc for t in query_terms if len(t) > 3)
                if not desc_has_target:
                    score -= 40  # Double penalty: unrelated name + no target in body
                else:
                    score -= 20
                break  # One strong signal of unrelated content is enough
        
        # Description reads like a search result page, not substantive content
        search_page_signals = ["search results for", "searching corporate records",
                               "results for '", "browse users and their profiles"]
        if any(sig in desc for sig in search_page_signals):
            score -= 15
        
        # ── Cap and return ──
        return max(-50, min(100, score))
    
    # Score all findings
    scored = [(_score(f), i, f) for i, f in enumerate(findings)]
    
    # Stats for logging
    high = sum(1 for s, _, _ in scored if s >= 50)
    medium = sum(1 for s, _, _ in scored if 25 <= s < 50)
    low = sum(1 for s, _, _ in scored if s < 25)
    logger.info(
        "relevance_filter: %d findings → %d high, %d medium, %d noise (query=%s)",
        len(findings), high, medium, low, query[:60]
    )
    
    # Keep findings scoring >= min_score
    relevant = [f for s, _, f in scored if s >= min_score]
    
    # Safety net: if we filtered TOO aggressively (e.g., all findings are
    # low-confidence web searches), keep at least min_keep findings by score
    if len(relevant) < min_keep:
        scored.sort(key=lambda x: x[0], reverse=True)
        relevant = [f for _, _, f in scored[:max(min_keep, len(scored) // 2)]]
        logger.info(
            "relevance_filter: safety net — keeping %d/%d findings (min_keep=%d)",
            len(relevant), len(findings), min_keep
        )
    
    return relevant


def _findings_block(findings, max_chars: int = 6000) -> str:
    """Build a condensed findings block for the synthesis prompt. 
    Caps at max_chars and prioritizes findings with source URLs."""
    # Sort: findings with URLs first (higher quality), then by confidence
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            not (getattr(f, "source_url", "") or ""),
            -(getattr(f, "confidence", 0.5) or 0.5)
        )
    )
    lines = []
    total = 0
    for i, f in enumerate(sorted_findings, 1):
        title = getattr(f, "title", str(f)[:100]) or ""
        desc = getattr(f, "description", "") or ""
        desc = desc.replace("\n", " ").replace("**Extracted text", "").lstrip("(")
        conf = getattr(f, "confidence", 0.5) or 0.5
        tier = getattr(f, "tier", None)
        # tier is a property computed from confidence — call it
        try:
            tier_str = str(tier) if tier else ("CONFIRMED" if conf >= 0.85 else "PROBABLE" if conf >= 0.70 else "POSSIBLE" if conf >= 0.40 else "UNLIKELY" if conf >= 0.10 else "UNSUBSTANTIATED")
        except Exception:
            tier_str = "UNKNOWN"
        chunk = f"[{i}] [{tier_str} | {conf:.0%}] {title}\n    {desc[:400]}\n"
        if total + len(chunk) > max_chars:
            break
        lines.append(chunk)
        total += len(chunk)
    return "\n".join(lines)


def _has_substantive_content(findings: list) -> bool:
    """Check if findings contain more than social media noise.
    
    Returns True if findings include Wikipedia articles, FBI data, criminal/legal
    content — anything the deterministic brief can't handle. Prevents the class of
    bugs where "verified digital footprint with 2 professional profiles" is
    reported for a mafia boss or convicted murderer.
    """
    substantive_keywords = [
        "wikipedia", "fbi", "wanted", "convicted", "sanctions",
        "sentenced", "arrested", "indictment", "mafia", "cartel",
        "money laundering", "fraud ", "racketeering", "murder",
        "assassination", "trafficking", "conspiracy", "wire fraud",
        "life imprisonment", "organized crime", "bratva",
        "opensanctions", "interpol", "bureau of investigation",
        "justice department", "court records", "prison",
    ]
    for f in findings:
        title = (getattr(f, "title", "") or "").lower()
        desc = (getattr(f, "description", "") or "").lower()
        combined = title + " " + desc
        for kw in substantive_keywords:
            if kw in combined:
                return True
    return False


def _deterministic_person_brief(query: str, findings: list) -> dict:
    """Build a person identity brief from findings WITHOUT an LLM.
    
    Extracts: name variants, professional profiles (LinkedIn, GitHub, etc.),
    content mentions (articles, posts), and gaps. Never gaslights.
    """
    import re as _re
    
    profiles: list[dict] = []
    mentions: list[dict] = []
    name_variants = set()
    
    for f in findings:
        title = getattr(f, "title", "") or ""
        desc = getattr(f, "description", "") or ""
        url = getattr(f, "source_url", "") or ""
        combined = f"{title} {desc}"
        
        # Extract name variants — prioritize ones matching the query terms
        query_parts = set(query.lower().split())
        for match in _re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', combined):
            name = match.group(1)
            name_parts = set(name.lower().split())
            if name_parts & query_parts:
                name_variants.add(name)
        
        # Detect professional profiles by URL pattern
        if any(domain in url for domain in [
            'linkedin.com/in/', 'linkedin.com/posts/', 
            'github.com/', 'twitter.com/', 'x.com/',
            'researchgate.net/profile/', 'behance.net/',
        ]):
            followers_match = _re.search(r'([\d,]+)\s*(?:followers|Posts)', combined)
            profiles.append({
                "url": url, "title": title[:120],
                "followers": followers_match.group(1) if followers_match else None,
            })
        
        # Detect content mentions by keyword
        if any(kw in combined.lower() for kw in ['author', 'editor', 'analyst', 'journalist', 
                                                    'founder', 'defense', 'tech', 'security']):
            mentions.append({"url": url, "title": title[:120], "snippet": desc[:200] if desc else ""})
    
    # Determine best name: prefer longest variant matching all query words
    name_str = query
    if name_variants:
        query_words = set(query.lower().split())
        for v in sorted(name_variants, key=len, reverse=True):
            if query_words.issubset(set(v.lower().split())):
                name_str = v
                break
        else:
            name_str = max(name_variants, key=len)
    pc, mc = len(profiles), len(mentions)
    
    if pc >= 2:
        sources = [p['url'].split('/')[2] for p in profiles[:3]]
        topics = set()
        for m in mentions:
            for kw in ['defense', 'security', 'tech', 'startup', 'founder', 'editor', 'analyst']:
                if kw in m['title'].lower() or kw in m['snippet'].lower():
                    topics.add(kw)
        summary = (f"{name_str} has a verified digital footprint with {pc} professional profiles "
                   f"and {mc} content mentions. Sources: {', '.join(sources)}. "
                   + (f"Topics: {', '.join(sorted(topics))}." if topics else ""))
    elif pc == 1:
        summary = (f"{name_str} has a limited digital footprint — one profile found. "
                   f"{mc} content mentions. Further investigation recommended.")
    else:
        # Count actual unique URLs checked (not total findings — those include tool output noise)
        urls_checked = len(set(
            f.source_url for f in findings
            if hasattr(f, 'source_url') and f.source_url
        ))
        sources_text = f"{urls_checked} sources checked" if urls_checked else "sources checked"
        
        # Detect location confusion — if findings look like business/geographic results
        combined_text = " ".join(
            (getattr(f, "title", "") + " " + getattr(f, "description", "")).lower()
            for f in findings
        )
        location_keywords = ["comune", "municipality", "province", "via ", "p.iva",
                             "impresa", "telefono", "orari", "cap ", "business directory"]
        looks_like_location = any(kw in combined_text for kw in location_keywords)
        
        if looks_like_location:
            summary = (f"No person found for '{name_str}'. "
                       f"Results suggest this may be a geographic location or business name, "
                       f"not an individual. {sources_text}. "
                       f"Try re-running with a different query or check for name variants.")
        else:
            summary = (f"No professional profiles found for {name_str}. "
                       f"{sources_text}. Possible private individual, pseudonym, or name collision.")
    
    return {
        "executive_summary": summary[:500],
        "risk_themes": [],
        "notable_entities": [{"name": name_str, "role": "person", 
                              "context": f"Profiles: {pc}, Mentions: {mc}"}],
        "evidence_gaps": [g for g in [
            "No verified employer or organization" if not any(
                'company' in str(m).lower() or 'firm' in str(m).lower() for m in mentions
            ) else None,
            "Limited digital footprint — try alternative spellings" if pc < 2 else None,
        ] if g],
        "recommended_next_steps": (
            [{"entity": p['url'], "action": "View profile", "tool_hint": "social"} for p in profiles[:3]]
            + [{"entity": m['url'], "action": "Read article", "tool_hint": "web"} for m in mentions[:2]]
        ),
        "_synthesized": True, "_deterministic": True,
    }

async def synthesize_brief(
    query: str,
    focus: str,
    findings: list,
    call_llm,
    target_type: str = "",
    executed_tools: set[tuple[str, str]] | None = None,
    resolved_entities: list | None = None,
    investigation_mode: str = "",
    graph_context: dict | None = None,
    correlation: dict | None = None,
    intelligence: Any = None,
) -> dict | None:
    """Produce a structured intelligence brief from findings. Returns dict or None."""
    # Filter out pure fetch-failures
    real = []
    for f in findings:
        title = getattr(f, "title", "")
        if not title.lower().startswith(("could not read",)):
            real.append(f)
    usable = real or findings
    
    if not usable:
        return None

    # ── Inject graph context into findings for cross-case intelligence ──
    if graph_context and graph_context.get("known_entities"):
        from ..core.models import Finding, FindingSeverity, FindingSource
        known = graph_context["known_entities"]
        cases = graph_context.get("relevant_cases", [])
        for ent in known[:5]:
            usable.append(Finding(
                id=f"graph-{ent.get('id', ent.get('value', 'unknown'))[:20]}",
                source=FindingSource.OSINT,
                tool="knowledge_graph",
                title=f"📊 [Graph] Known entity: {ent.get('value', '')[:120]}",
                description=f"Previously found in case(s): {', '.join(cases[:3])}. "
                            f"Type: {ent.get('type', 'unknown')}. "
                            f"Confidence: PRIMARY (community graph — cross-case intelligence).",
                evidence=[],
                confidence=1.0,
                severity=FindingSeverity.INFO,
            ))

    # Person targets: deterministic extraction for background_check and due_diligence.
    # BUT: if findings contain Wikipedia, FBI, criminal, or legal content,
    # the deterministic brief (which only knows LinkedIn/GitHub profiles) will
    # produce garbage like "verified digital footprint with 2 professional profiles"
    # for a mafia boss. Use LLM synthesis when there's substantive content.
    if target_type == "person" and investigation_mode != "deep_investigation":
        if not _has_substantive_content(usable):
            return _deterministic_person_brief(query, usable)
        # Criminal/legal content detected — fall through to LLM synthesis
        logger.debug("synthesis: substantive content detected, using LLM for %s", query[:60])
    
    # Non-person targets: LLM synthesis

    # ── Overlay intelligence layer confidence scores onto findings ──
    # This replaces LLM-assigned "vibes" confidence (0.55, 0.85, etc.) with
    # evidence-based scores from source tiering + corroboration.
    if intelligence is not None:
        usable = _apply_intelligence_scores(usable, intelligence)

    # ── Filter irrelevant findings BEFORE the LLM sees them ──
    # Without this, the LLM drowns in web-search noise (Obama tan suits,
    # Big Tigger lawsuits, Audi forum posts, dictionary definitions, etc.)
    # and concludes "no information related to X" even when real findings exist.
    usable_filtered = _filter_relevant_findings(usable, query, target_type, min_score=35)
    if usable_filtered:
        usable = usable_filtered
    else:
        logger.warning("synthesis: relevance filter removed all findings — using unfiltered")

    target_guidance = _TARGET_GUIDANCE.get(target_type, "") if target_type else ""
    
    # Deep investigation on persons: use criminal/legal guidance, not generic identity
    if target_type == "person" and investigation_mode == "deep_investigation":
        target_guidance = _PERSON_DEEP_GUIDANCE

    prompt = _SYNTHESIS_PROMPT.format(
        query=query,
        target_type=target_type or "unknown",
        focus=focus or "general due diligence",
        target_specific_guidance=target_guidance,
        findings=_findings_block(usable),
        resolved_entities=_format_resolved_entities(resolved_entities),
        intelligence=_format_intelligence(intelligence),
        cross_platform_correlation=_format_correlation(correlation),
        executed_tools=_format_executed_tools(executed_tools),
    )

    try:
        raw = await call_llm(prompt, timeout=180, max_tokens=4096)
        if not raw or not raw.strip():
            logger.info("synthesis: first LLM attempt empty, retrying with higher tokens")
            raw = await call_llm(prompt, timeout=180, max_tokens=8192)
        if not raw or not raw.strip():
            logger.warning("synthesis: both LLM attempts returned empty — using fallback")
            return _fallback_brief(query, usable)
    except TypeError:
        try:
            raw = await call_llm(prompt, timeout=120, max_tokens=4096)
        except TypeError:
            raw = await call_llm(prompt, max_tokens=4096)
    except Exception as e:
        logger.warning("synthesis_llm_failed: %s", e)
        raw = None

    if not raw:
        return _fallback_brief(query, usable)

    brief = _parse_json(raw)
    if not brief or "executive_summary" not in brief:
        return _fallback_brief(query, usable)

    brief["_synthesized"] = True

    # ── Post-process: inject intelligence layer output ──
    # The LLM may have ignored evidence-based confidence, adversarial signals,
    # and entity relationships. Force them into the brief now.
    if intelligence is not None:
        brief = _enrich_brief_with_intelligence(brief, intelligence)

    return brief


def _parse_json(text: str) -> dict | None:
    import re
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _fallback_brief(query: str, findings: list) -> dict:
    """Deterministic structural brief when the LLM is unavailable.
    Extracts real data from findings instead of just giving up."""
    import re as _re
    
    sources = []
    titles = []
    entities_found: dict[str, list[str]] = {}  # type -> [values]
    for f in findings:
        url = getattr(f, "source_url", "") or (getattr(f, "raw_data", {}) or {}).get("url", "")
        if not url:
            m = _re.search(r"https?://\S+", f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}")
            if m:
                url = m.group(0).rstrip(".,)")
        if url and url not in sources:
            sources.append(url)
        title = getattr(f, "title", "")
        if title and not title.lower().startswith(("check_", "could not read")):
            titles.append(title[:150])
        # Extract entity types from graph findings
        ft = getattr(f, "finding_type", "") or ""
        fval = getattr(f, "source_type", "") or ""
        if ft in ("domain", "ip_address", "person", "organization", "email", "location"):
            if ft not in entities_found:
                entities_found[ft] = []
            entities_found[ft].append(title[:80])
        # Employee pivot findings carry embedded entities
        for ent in getattr(f, "entities", []) or []:
            ent_type = ent.get("type", "person") if isinstance(ent, dict) else "person"
            ent_name = ent.get("name", title[:60]) if isinstance(ent, dict) else str(ent)
            if ent_type not in entities_found:
                entities_found[ent_type] = []
            entities_found[ent_type].append(str(ent_name)[:80])
    
    # Build a real summary — strip tool tags like [scraper], [people-search]
    import re as _re2
    confirmed = sum(1 for f in findings if getattr(f, "tier", "") == "CONFIRMED")
    total = len(findings)
    
    # Strip tool tag prefixes from titles for cleaner summaries
    def _clean_title(t: str) -> str:
        return _re2.sub(r'^\[[^\]]+\]\s*', '', t).strip()
    
    # Extract meaningful content from findings
    people = [_clean_title(n) for n in entities_found.get("person", [])]
    orgs = [_clean_title(n) for n in entities_found.get("organization", [])]
    domains = [_clean_title(n) for n in entities_found.get("domain", [])]
    locations = [_clean_title(n) for n in entities_found.get("location", [])]
    
    parts = [f"Investigation of '{query}' gathered {total} findings ({confirmed} confirmed) from {len(sources)} verified sources."]
    
    if people:
        parts.append(f"Key individuals: {', '.join(people[:3])}.")
    if orgs:
        parts.append(f"Connected organizations: {', '.join(orgs[:3])}.")
    if domains:
        parts.append(f"Infrastructure mapped: {len(domains)} domains, {len(entities_found.get('ip_address', []))} IPs across {len(locations)} locations.")
    
    # If no entities found, use titles
    if not any([people, orgs, domains]):
        top = [_clean_title(t) for t in titles[:5] if not t.startswith("🔗")]
        if top:
            parts.append("Notable findings: " + "; ".join(top[:3]) + ".")
    
    # Detect themes from finding content (more thorough)
    theme_keywords = {
        "Regulatory / Legal": ["sanction", "fine", "settlement", "regulator", "sec", "cftc", "doj",
                                "lawsuit", "indictment", "charged", "plead guilty", "convicted",
                                "class action", "arbitration", "court", "ruling", "securities"],
        "Corporate / Leadership": ["ceo", "founder", "executive", "board", "chairman", "director",
                                    "resigned", "appointed", "named", "co-founder"],
        "Financial": ["revenue", "profit", "loss", "billion", "million", "funding", "valuation",
                      "stock", "share", "investor", "ipo", "acquisition"],
        "Crime / Investigation": ["criminal", "arrest", "prison", "jail", "fraud", "money laundering",
                                   "investigation", "probe", "allegation", "misconduct", "wanted", "fugitive",
                                   "fbi", "hacker", "cyber"],
    }
    themes = []
    all_text = " ".join(titles + [getattr(f, "description", "") or "" for f in findings]).lower()
    for theme, keywords in theme_keywords.items():
        matches = [kw for kw in keywords if kw in all_text]
        # Require at least 2 keyword matches to trigger a theme — prevents
        # a single accidental word match (e.g. "legal" in Instagram gossip)
        # from creating a nonsensical "Regulatory/Legal" theme.
        if len(matches) < 2:
            continue
        if matches:
            # Find the best finding for this theme — prefer ones with real descriptions
            best_summary = f"Evidence of {matches[0]} found across multiple sources."
            best_source = ""
            for f in findings:
                desc = (getattr(f, "description", "") or "")
                title_l = (getattr(f, "title", "") or "").lower()
                for kw in matches:
                    if kw in title_l or kw in desc.lower():
                        # Use the description as summary (actual intelligence, not just title)
                        if desc and len(desc) > 20:
                            # Clean: strip tool tags, wiki markup, and normalize whitespace
                            clean_desc = _clean_title(desc[:400])
                            best_summary = ' '.join(clean_desc.split())
                            best_source = getattr(f, "source_url", "") or ""
                        break
                if best_source:
                    break
            # ── Filter LLM meta-commentary from theme summaries ──
            _llm_meta = [
                "first, i need to parse", "i need to parse", "we are asked to",
                "i need to start", "let me parse", "based on the provided",
                "the user provided", "first i need to", "the wikipedia-style",
                "i need to extract", "let me extract", "i will now",
            ]
            if best_summary and any(m in best_summary.lower() for m in _llm_meta):
                # Replace with a clean summary from matching keywords
                clean_parts = [kw.capitalize() for kw in matches[:3]]
                best_summary = f"Evidence of {' and '.join(clean_parts)} found across multiple sources."
                best_source = ""

            themes.append({
                "theme": theme,
                "severity": "HIGH" if theme.startswith("Crime") else "MEDIUM",
                "summary": best_summary,
                "source_titles": [best_source] if best_source else [],
            })
    
    # Deduplicate themes — same summary shouldn't appear for multiple themes
    seen_summaries = set()
    deduped_themes = []
    for t in themes:
        key = t["summary"][:50]
        if key not in seen_summaries:
            seen_summaries.add(key)
            deduped_themes.append(t)
    themes = deduped_themes[:5]
    
    # Extract timeline events from findings (dates in titles/descriptions)
    timeline_events: list[dict] = []
    date_pattern = _re.compile(
        r'\b((?:19|20)\d{2}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\d|3[01]))?)?)\b'
    )
    seen_dates: set[str] = set()
    for f in findings:
        title = getattr(f, "title", "") or ""
        desc = getattr(f, "description", "") or ""
        combined = f"{title} {desc}"
        for m in date_pattern.finditer(combined):
            d = m.group(1)
            if d in seen_dates or len(d) < 4:
                continue
            seen_dates.add(d)
            # Categorize
            cat = "personal"
            lower = combined.lower()
            if any(kw in lower for kw in ("sentenced", "convicted", "arrested", "charged", "murder", "prison")):
                cat = "criminal"
            elif any(kw in lower for kw in ("lawsuit", "court", "trial", "ruling", "indictment")):
                cat = "legal"
            elif any(kw in lower for kw in ("ceo", "founder", "joined", "hired", "appointed", "director", "board")):
                cat = "career"
            elif any(kw in lower for kw in ("graduated", "university", "degree", "phd", "bachelor", "master")):
                cat = "education"
            elif any(kw in lower for kw in ("revenue", "funding", "ipo", "acquired", "valuation", "million", "billion")):
                cat = "financial"
            snippet = (title or desc)[:120]
            timeline_events.append({
                "date": d, "category": cat, "event": snippet,
                "source_title": title[:100] if title else "",
            })
    timeline_events.sort(key=lambda e: e["date"])

    return {
        "executive_summary": " ".join(parts),
        "risk_themes": themes if themes else [],
        "notable_entities": [
            {"name": _clean_title(v)[:80], "type": k, "role": "discovered", "confidence": 0.7}
            for k, vals in entities_found.items() for v in vals[:3]
        ] if entities_found else [
            {"name": _clean_title(t)[:80], "type": "finding", "role": "key finding", "confidence": 0.6}
            for t in titles[:5] if t and not t.lower().startswith(("check_", "could not read"))
        ],
        "timeline": [
            {**e, "event": _clean_title(e["event"])[:150], "source_title": _clean_title(e["source_title"])[:120]}
            for e in timeline_events[:15]
        ],
        "evidence_gaps": [],
        "recommended_next_steps": [{"entity": u, "action": "Review source", "tool_hint": "web"}
                                   for u in sources[:5]],
        "_synthesized": False,
        "_sources": sources[:15],
    }


def _apply_intelligence_scores(findings: list, intelligence) -> list:
    """Overlay evidence-based confidence scores from the intelligence layer
    onto findings. Returns the same list (mutated in place), with each finding's
    .confidence and .tier replaced by the intelligence engine's output.

    Findings without a matching intelligence score are left unchanged.
    """
    if intelligence is None:
        return findings
    scores = getattr(intelligence, 'confidence_scores', {}) or {}
    if not scores:
        return findings

    overlaid = 0
    for f in findings:
        fid = getattr(f, "id", None) or str(f)
        ev = scores.get(fid)
        if ev is None:
            # Try matching by title prefix
            title = getattr(f, "title", "") or ""
            for key, val in scores.items():
                if key[:20] in title or title[:20] in key:
                    ev = val
                    break
        if ev is not None:
            f.confidence = ev.score
            # tier is a computed property from confidence — no need to set it
            overlaid += 1

    if overlaid:
        logger.debug("intelligence_scores_overlaid: %d/%d findings", overlaid, len(findings))
    return findings


def _enrich_brief_with_intelligence(brief: dict, intelligence) -> dict:
    """Post-process the LLM brief to inject intelligence layer output that the
    LLM may have ignored: adversarial signals → risk themes, relationships →
    entity context, entity corroboration → confidence annotations."""
    if intelligence is None:
        return brief

    # ── Adversarial signals → risk themes ──
    signals = getattr(intelligence, 'adversarial_signals', []) or []
    detected = [s for s in signals if s.get("detected")]
    if detected:
        existing_risks = brief.get("risk_themes") or []
        for s in detected:
            risk = f"OPSEC: {s.get('signal', 'unknown')} — {s.get('detail', '')}"
            if risk not in existing_risks:
                existing_risks.append(risk)
        if existing_risks:
            brief["risk_themes"] = existing_risks

    # ── Entity relationships → notable entities ──
    rels = getattr(intelligence, 'relationships', []) or []
    if rels:
        entities = brief.get("notable_entities") or []
        for r in rels[:10]:
            entities.append({
                "name": f"{r.source} → {r.target}",
                "role": r.relationship,
                "context": f"{r.evidence_summary} (confidence: {r.confidence:.0%})"
            })
        if entities:
            brief["notable_entities"] = entities

    # ── Entity corroboration → entity confidence annotation ──
    corroboration = getattr(intelligence, 'entity_corroboration', {}) or {}
    if corroboration:
        entities = brief.get("notable_entities") or []
        for ent in entities:
            name = ent.get("name", "")
            if name in corroboration:
                count = corroboration[name]
                ent["context"] = (ent.get("context", "") + f" [corroborated by {count} sources]").strip()
        if entities:
            brief["notable_entities"] = entities

    return brief


def _format_intelligence(intel) -> str:
    """Format structured intelligence for the synthesis prompt."""
    if intel is None:
        return ""
    
    lines = ["STRUCTURED INTELLIGENCE (evidence-based, not LLM-generated):"]
    
    # Confidence summary
    if hasattr(intel, 'confidence_scores') and intel.confidence_scores:
        scores = intel.confidence_scores
        confirmed = sum(1 for c in scores.values() if c.tier == "CONFIRMED")
        probable = sum(1 for c in scores.values() if c.tier == "PROBABLE")
        score_vals = [c.score for c in scores.values()]
        avg = sum(score_vals) / len(score_vals) if score_vals else 0
        lines.append(f"\nCONFIDENCE: {len(scores)} findings, {confirmed} CONFIRMED, "
                     f"{probable} PROBABLE, avg {avg:.0%}")
        lines.append("(Based on source credibility + corroboration, not LLM estimate)")
    
    # Entity relationships
    if hasattr(intel, 'relationships') and intel.relationships:
        lines.append(f"\nENTITY RELATIONSHIPS ({len(intel.relationships)}):")
        for r in intel.relationships[:15]:
            lines.append(
                f"  • {r.source} [{r.source_type}] —{r.relationship}→ "
                f"{r.target} [{r.target_type}] "
                f"(conf: {r.confidence:.0%})"
            )
    
    # Timeline
    if hasattr(intel, 'timeline') and intel.timeline:
        lines.append(f"\nEXTRACTED TIMELINE ({len(intel.timeline)} events):")
        for t in intel.timeline[:15]:
            lines.append(f"  • {t.date} [{t.category}] {t.event[:100]}")
    
    # Adversarial signals
    if hasattr(intel, 'adversarial_signals') and intel.adversarial_signals:
        lines.append("\nOPSEC / ADVERSARIAL SIGNALS:")
        for s in intel.adversarial_signals:
            detected = "DETECTED" if s.get("detected") else "None"
            lines.append(f"  • {s.get('signal', '?')}: {detected} — {s.get('detail', '')}")
    
    return "\n".join(lines)


def _format_correlation(correlation: dict | None) -> str:
    """Format cross-platform identity correlation for the synthesis prompt."""
    if not correlation or not correlation.get("total_matches"):
        return ""
    lines = ["CROSS-PLATFORM IDENTITY CORRELATION:"]
    lines.append(correlation.get("summary", ""))
    confirmed = correlation.get("confirmed", [])
    if confirmed:
        lines.append("\nConfirmed matches (confidence ≥ 0.9):")
        for m in confirmed[:3]:
            lines.append(f"  • {m['finding_a'][:60]} ↔ {m['finding_b'][:60]}")
            lines.append(f"    Signals: {', '.join(m['signals'])} | Confidence: {m['confidence']}")
    probable = correlation.get("probable", [])
    if probable:
        lines.append("\nProbable matches (confidence ≥ 0.7):")
        for m in probable[:3]:
            lines.append(f"  • {m['finding_a'][:60]} ↔ {m['finding_b'][:60]}")
    return "\n".join(lines)


def brief_to_markdown(brief: dict, query: str) -> str:
    """Render a brief dict as a readable markdown report."""
    out = [f"# Intelligence Brief: {query}", ""]
    out.append(f"**Bottom line:** {brief.get('executive_summary', 'N/A')}")
    out.append("")

    themes = brief.get("risk_themes", [])
    if themes:
        out.append("## Risk Themes")
        for t in themes:
            sev = t.get("severity", "?")
            badge = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
            out.append(f"### {badge} {t.get('theme', 'Theme')} — {sev}")
            out.append(t.get("summary", ""))
            srcs = t.get("source_titles", [])
            if srcs:
                out.append("Sources: " + "; ".join(srcs[:4]))
            out.append("")

    ents = brief.get("notable_entities", [])
    if ents:
        out.append("## Notable Entities")
        for e in ents:
            out.append(f"- **{e.get('name','?')}** ({e.get('role','?')}): {e.get('context','')}")
        out.append("")

    timeline = brief.get("timeline", [])
    if timeline:
        out.append("## Timeline")
        cat_icons = {
            "criminal": "🔴", "legal": "⚖️", "career": "💼",
            "education": "🎓", "personal": "👤", "financial": "💰",
        }
        for event in timeline:
            icon = cat_icons.get(event.get("category", ""), "📌")
            date = event.get("date", "?")
            evt = event.get("event", "")
            src = event.get("source_title", "")
            out.append(f"- {icon} **{date}** — {evt}")
            if src:
                out.append(f"  *Source: {src[:120]}*")
        out.append("")

    gaps = brief.get("evidence_gaps", [])
    if gaps:
        out.append("## Evidence Gaps")
        for g in gaps:
            out.append(f"- 🔍 {g}")
        out.append("")

    nxt = brief.get("recommended_next_steps", [])
    if nxt:
        out.append("## Recommended Next Steps")
        for n in nxt:
            if isinstance(n, dict):
                out.append(f"- **{n.get('entity','?')}**: {n.get('action','?')} [{n.get('tool_hint','?')}]")
            else:
                out.append(f"- {n}")
        out.append("")

    return "\n".join(out)
