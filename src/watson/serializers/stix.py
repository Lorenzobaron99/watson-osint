"""STIX 2.1 Serializer — convert Watson findings to structured threat intelligence.

Produces valid STIX 2.1 bundles with:
  - Report → SDO with object_refs
  - Finding → Indicator (pattern-based) + ObservedData
  - Entity → Identity (individual/organization), Location, DomainName, IPv4Addr
  - Relationships between all objects
  - External references for source URLs
  - Confidence mapping: CONFIRMED→85, PROBABLE→65, POSSIBLE→40, UNLIKELY→15, UNVERIFIED→0

Reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import logging

logger = logging.getLogger("watson.stix")

# ── Confidence mapping ────────────────────────────────────────

_TIER_CONFIDENCE: dict[str, int] = {
    "CONFIRMED": 85,
    "PROBABLE": 65,
    "POSSIBLE": 40,
    "UNLIKELY": 15,
    "UNVERIFIED": 0,
    "UNSUBSTANTIATED": 0,
}

# ── Entity type → STIX identity_class ─────────────────────────

_ENTITY_STIX_CLASS: dict[str, str] = {
    "person": "individual",
    "organization": "organization",
    "company": "organization",
    "government": "organization",
    "unknown": "unknown",
    "": "unknown",
}

# ── STIX ID generation ────────────────────────────────────────

def _stix_id(stix_type: str, value: str = "") -> str:
    """Generate deterministic STIX ID from type + value, or random UUID."""
    if value:
        # Namespace-based UUID for reproducibility
        ns = uuid.uuid5(uuid.NAMESPACE_DNS, f"watson-osint:{stix_type}")
        return f"{stix_type}--{uuid.uuid5(ns, value)}"
    return f"{stix_type}--{uuid.uuid4()}"


# ── IP regex ──────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")


def _is_ip(value: str) -> str | None:
    """Return 'ipv4', 'ipv6', or None."""
    v = value.strip()
    if _IPV4_RE.match(v):
        return "ipv4-addr"
    if _IPV6_RE.match(v):
        return "ipv6-addr"
    return None


def _is_domain(value: str) -> bool:
    """Rough domain detection."""
    v = value.strip().lower()
    if not v or " " in v or len(v) > 253:
        return False
    return "." in v and not v.startswith(("http://", "https://"))


def _is_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value.strip()))


def _is_url(value: str) -> bool:
    return value.strip().startswith(("http://", "https://"))


# ── Main serializer ───────────────────────────────────────────

class STIXSerializer:
    """Convert Watson investigation results to STIX 2.1 bundles."""

    def __init__(self):
        self._objects: list[dict[str, Any]] = []
        self._seen_ids: set[str] = set()
        self._report_refs: list[str] = []
        self._entity_cache: dict[str, str] = {}  # value → stix_id

    def serialize(
        self,
        query: str,
        case_id: str,
        target_type: str,
        findings: list[Any],
        entities: list[dict] | None = None,
        brief: dict | None = None,
    ) -> dict[str, Any]:
        """Produce a STIX 2.1 bundle from investigation results."""
        self._objects = []
        self._seen_ids = set()
        self._report_refs = []
        self._entity_cache = {}

        now = datetime.now(timezone.utc).isoformat()

        # ── 1. Report SDO ──
        report_id = _stix_id("report", case_id)
        report = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"Watson Investigation: {query[:80]}",
            "description": brief.get("executive_summary", "") if brief else f"OSINT investigation of {query}",
            "report_types": ["investigation"],
            "published": now,
            "object_refs": self._report_refs,  # will be filled
            "labels": ["osint", target_type],
            "external_references": [],
        }
        self._add_object(report)

        # ── 2. Target identity ──
        target_id = self._entity_for(query, target_type, brief)
        self._report_refs.append(target_id)
        self._relate(report_id, "investigates", target_id)

        # ── 3. Findings → Indicators & ObservedData ──
        for f in findings:
            self._serialize_finding(f, report_id, target_id)

        # ── 4. Entities → Identities, Locations, SCOs ──
        if entities:
            for ent in entities:
                ent_id = self._serialize_entity(ent)
                if ent_id:
                    self._report_refs.append(ent_id)
                    self._relate(report_id, "references", ent_id)

        # ── 5. Fix up report object_refs ──
        report["object_refs"] = self._report_refs

        bundle = {
            "type": "bundle",
            "id": _stix_id("bundle", case_id),
            "spec_version": "2.1",
            "objects": self._objects,
        }
        return bundle

    def to_json(self, **kwargs) -> str:
        bundle = self.serialize(**kwargs)
        return json.dumps(bundle, indent=2, default=str)

    def to_file(self, path: Path | str, **kwargs) -> Path:
        path = Path(path)
        path.write_text(self.to_json(**kwargs))
        logger.info("stix_exported: %s", path)
        return path

    # ── Internal ──────────────────────────────────────────────

    def _add_object(self, obj: dict) -> None:
        oid = obj.get("id", "")
        if oid and oid not in self._seen_ids:
            self._seen_ids.add(oid)
            self._objects.append(obj)

    def _relate(self, source_id: str, rel_type: str, target_id: str) -> str | None:
        if not source_id or not target_id:
            return None
        rid = _stix_id("relationship", f"{source_id}|{rel_type}|{target_id}")
        rel = {
            "type": "relationship",
            "id": rid,
            "spec_version": "2.1",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "relationship_type": rel_type,
            "source_ref": source_id,
            "target_ref": target_id,
        }
        self._add_object(rel)
        return rid

    def _confidence(self, tier: str) -> int:
        return _TIER_CONFIDENCE.get(tier, 30)

    def _entity_for(self, value: str, etype: str = "unknown", brief: dict | None = None) -> str:
        """Get or create a STIX identity for an entity value."""
        key = f"{value}|{etype}"
        if key in self._entity_cache:
            return self._entity_cache[key]

        identity_class = _ENTITY_STIX_CLASS.get(etype, "unknown")
        eid = _stix_id("identity", value)

        identity = {
            "type": "identity",
            "id": eid,
            "spec_version": "2.1",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": value[:200],
            "identity_class": identity_class,
            "description": f"Target entity of type: {etype}",
        }

        # Add sectors/labels from brief if available
        if brief and identity_class == "organization":
            risk_themes = brief.get("risk_themes", [])
            if risk_themes:
                identity["sectors"] = [t.get("theme", "")[:80] for t in risk_themes[:3]]
                identity["labels"] = ["risk-associated"] + [
                    t.get("severity", "").lower() for t in risk_themes if t.get("severity")
                ]

        self._add_object(identity)
        self._entity_cache[key] = eid
        return eid

    def _serialize_finding(self, finding: Any, report_id: str, target_id: str) -> None:
        """Convert a Watson Finding to STIX Indicator + ObservedData."""
        title = getattr(finding, "title", str(finding))[:200]
        desc = getattr(finding, "description", "")[:500]
        tier = getattr(finding, "tier", "UNVERIFIED")
        source_url = getattr(finding, "source_url", "")
        src_type = getattr(finding, "source_type", "osint")
        confidence_val = self._confidence(tier) if tier else 30
        fid = _stix_id("indicator", getattr(finding, "id", str(uuid.uuid4())))

        # ── Indicator (pattern-based) ──
        # Build a STIX pattern from finding text
        pattern = self._build_pattern(title, desc)
        indicator = {
            "type": "indicator",
            "id": fid,
            "spec_version": "2.1",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": title,
            "description": desc or title,
            "indicator_types": ["osint-report"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "confidence": confidence_val,
            "labels": [src_type, tier.lower() if tier else "unverified"],
        }
        if source_url:
            indicator["external_references"] = [{
                "source_name": "OSINT Source",
                "url": source_url,
                "description": "Original investigation source",
            }]
        self._add_object(indicator)
        self._report_refs.append(fid)
        self._relate(fid, "derived-from", target_id)

        # ── ObservedData (structured facts) ──
        # Extract IPs, domains, emails from the finding text
        observables = self._extract_observables(desc)
        if observables:
            odata_id = _stix_id("observed-data", fid)
            observed = {
                "type": "observed-data",
                "id": odata_id,
                "spec_version": "2.1",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "first_observed": datetime.now(timezone.utc).isoformat(),
                "last_observed": datetime.now(timezone.utc).isoformat(),
                "number_observed": 1,
                "objects": observables,
            }
            self._add_object(observed)
            self._report_refs.append(odata_id)
            self._relate(fid, "based-on", odata_id)

    def _serialize_entity(self, entity: dict | Any) -> str | None:
        """Serialize a Watson entity to STIX."""
        if isinstance(entity, dict):
            val = entity.get("value", entity.get("name", entity.get("canonical", "")))
            etype = entity.get("type", "unknown")
        elif hasattr(entity, "value"):
            val = getattr(entity, "value", "") or ""
            etype = getattr(entity, "type", "unknown")
        else:
            val = str(entity)
            etype = "unknown"

        if not val or not val.strip():
            return None

        v = val.strip()

        # IP address → IPv4Addr / IPv6Addr SCO
        ip_type = _is_ip(v)
        if ip_type:
            ip_id = _stix_id(ip_type, v)
            ip_obj = {
                "type": ip_type,
                "id": ip_id,
                "spec_version": "2.1",
                "value": v,
            }
            self._add_object(ip_obj)
            return ip_id

        # Domain → DomainName SCO
        if _is_domain(v):
            dom_id = _stix_id("domain-name", v)
            domain = {
                "type": "domain-name",
                "id": dom_id,
                "spec_version": "2.1",
                "value": v,
            }
            self._add_object(domain)
            return dom_id

        # Email → EmailAddr SCO
        if _is_email(v):
            email_id = _stix_id("email-addr", v)
            email_obj = {
                "type": "email-addr",
                "id": email_id,
                "spec_version": "2.1",
                "value": v,
            }
            self._add_object(email_obj)
            return email_id

        # URL → URL SCO
        if _is_url(v):
            url_id = _stix_id("url", v)
            url_obj = {
                "type": "url",
                "id": url_id,
                "spec_version": "2.1",
                "value": v,
            }
            self._add_object(url_obj)
            return url_id

        # Default → Identity
        return self._entity_for(v, etype)

    def _build_pattern(self, title: str, desc: str) -> str:
        """Build a STIX pattern string from finding text."""
        # Extract first significant noun phrase
        text = f"{title} {desc}"[:500]
        # Simple: mark as osint-report indicator with description
        return f"[indicator:pattern_type = 'osint-report' AND indicator:description MATCHES '{self._escape_pattern(desc[:100])}']"

    @staticmethod
    def _escape_pattern(text: str) -> str:
        """Escape single quotes for STIX pattern."""
        return text.replace("'", "\\'").replace("\n", " ")[:200]

    def _extract_observables(self, text: str) -> dict[str, dict]:
        """Extract IPs, domains, emails from text as STIX Cyber Observable objects."""
        objects: dict[str, dict] = {}
        if not text:
            return objects

        # Extract IPs
        for ip_match in re.finditer(_IPV4_RE, text):
            ip = ip_match.group(0)
            if ip not in objects:
                objects[f"0"] = {
                    "type": "ipv4-addr",
                    "value": ip,
                }
                break  # just one per finding

        # Extract domains (rough)
        domain_match = re.search(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text)
        if domain_match:
            dom = domain_match.group(0).lower()
            if dom not in objects:
                key = f"{len(objects)}"
                objects[key] = {
                    "type": "domain-name",
                    "value": dom,
                }

        # Extract emails
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if email_match:
            email = email_match.group(0)
            key = f"{len(objects)}"
            objects[key] = {
                "type": "email-addr",
                "value": email,
            }

        return objects


# ── Convenience export function ───────────────────────────────

def export_stix(
    query: str,
    case_id: str,
    target_type: str,
    findings: list[Any],
    entities: list[dict] | None = None,
    brief: dict | None = None,
    output_path: Path | str | None = None,
) -> tuple[dict, Path | None]:
    """Export investigation results as STIX 2.1.

    Returns (bundle_dict, output_path_or_None).
    """
    serializer = STIXSerializer()
    bundle = serializer.serialize(
        query=query,
        case_id=case_id,
        target_type=target_type,
        findings=findings,
        entities=entities,
        brief=brief,
    )
    path = None
    if output_path:
        path = serializer.to_file(
            output_path,
            query=query,
            case_id=case_id,
            target_type=target_type,
            findings=findings,
            entities=entities,
            brief=brief,
        )
    return bundle, path
