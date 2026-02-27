"""
Core data models for the Papaya Kiwi TI toolkit.

Uses Python dataclasses for clean, typed threat intelligence objects
that can be serialized to STIX 2.1, JSON, or plain-text reports.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import hashlib
import uuid


class IOCType(Enum):
    """Standard indicator of compromise types."""
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    FILE_HASH_MD5 = "file:hashes.MD5"
    FILE_HASH_SHA1 = "file:hashes.SHA-1"
    FILE_HASH_SHA256 = "file:hashes.SHA-256"
    EMAIL = "email-addr"
    CVE = "vulnerability"
    USER_AGENT = "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"


class Severity(Enum):
    """Threat severity levels aligned with CVSS qualitative ratings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(Enum):
    """Analytic confidence levels (aligned with IC standards)."""
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class TLPLevel(Enum):
    """Traffic Light Protocol marking for intel sharing."""
    RED = "TLP:RED"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    GREEN = "TLP:GREEN"
    CLEAR = "TLP:CLEAR"


@dataclass
class IOC:
    """
    Indicator of Compromise.

    Represents a single observable artifact (IP, hash, domain, etc.)
    with enrichment metadata and confidence scoring.
    """
    value: str
    ioc_type: IOCType
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MODERATE
    tlp: TLPLevel = TLPLevel.GREEN
    source: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    enrichment: dict = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.utcnow()
        if self.last_seen is None:
            self.last_seen = self.first_seen

    @property
    def fingerprint(self) -> str:
        """Deterministic hash for deduplication."""
        raw = f"{self.ioc_type.value}:{self.value}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_stix_pattern(self) -> str:
        """Convert to STIX 2.1 indicator pattern."""
        return f"[{self.ioc_type.value} = '{self.value}']"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "value": self.value,
            "type": self.ioc_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "tlp": self.tlp.value,
            "source": self.source,
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "enrichment": self.enrichment,
            "mitre_techniques": self.mitre_techniques,
            "stix_pattern": self.to_stix_pattern(),
            "fingerprint": self.fingerprint,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ThreatActor:
    """
    Threat actor profile using the Diamond Model structure.

    Tracks adversary identity, capabilities, infrastructure, and
    victimology with MITRE ATT&CK TTP mappings.
    """
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    motivation: str = ""  # financial, espionage, hacktivism, destruction
    sophistication: str = ""  # nation-state, organized-crime, script-kiddie
    country_of_origin: str = ""
    target_sectors: list[str] = field(default_factory=list)
    target_regions: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    known_tools: list[str] = field(default_factory=list)
    infrastructure: list[IOC] = field(default_factory=list)
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    confidence: Confidence = Confidence.MODERATE
    sources: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "country_of_origin": self.country_of_origin,
            "target_sectors": self.target_sectors,
            "target_regions": self.target_regions,
            "ttps": self.ttps,
            "known_tools": self.known_tools,
            "infrastructure_count": len(self.infrastructure),
            "confidence": self.confidence.value,
            "sources": self.sources,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ThreatReport:
    """
    Structured threat intelligence report.

    Supports dual-layer output: technical details for SOC analysts
    and plain-English summaries for stakeholders.
    """
    title: str
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MODERATE
    tlp: TLPLevel = TLPLevel.GREEN
    iocs: list[IOC] = field(default_factory=list)
    threat_actors: list[ThreatActor] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    affected_platforms: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    created: datetime = field(default_factory=datetime.utcnow)
    author: str = "Papaya Kiwi TI"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def add_ioc(self, ioc: IOC):
        self.iocs.append(ioc)
        for t in ioc.mitre_techniques:
            if t not in self.mitre_techniques:
                self.mitre_techniques.append(t)

    def add_threat_actor(self, actor: ThreatActor):
        self.threat_actors.append(actor)
        for t in actor.ttps:
            if t not in self.mitre_techniques:
                self.mitre_techniques.append(t)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "tlp": self.tlp.value,
            "ioc_count": len(self.iocs),
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "threat_actors": [ta.to_dict() for ta in self.threat_actors],
            "mitre_techniques": self.mitre_techniques,
            "affected_platforms": self.affected_platforms,
            "recommendations": self.recommendations,
            "references": self.references,
            "created": self.created.isoformat(),
            "author": self.author,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
