"""
MITRE ATT&CK Analyzer for Papaya Kiwi TI.

Maps IOCs and threat data to ATT&CK techniques, builds kill chain
visualizations, and generates tactical recommendations.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from papaya_kiwi_ti.models import IOC, IOCType, Severity
import logging

logger = logging.getLogger("papaya_kiwi_ti.analyzers")


# Embedded subset of MITRE ATT&CK for Enterprise (cloud-focused)
# Full integration would use the MITRE STIX data via cti-python-stix2
ATTACK_TECHNIQUES: dict[str, dict] = {
    "T1078": {
        "name": "Valid Accounts",
        "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        "description": "Adversaries may use credentials of existing accounts to gain access.",
        "platforms": ["AWS", "Azure", "GCP", "SaaS", "Windows", "Linux"],
        "detection": "Monitor for anomalous account usage, unusual login locations, impossible travel.",
        "mitigation": "MFA, conditional access policies, credential rotation, PAM.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": ["Persistence", "Privilege Escalation"],
        "description": "Adversaries may manipulate accounts to maintain or elevate access.",
        "platforms": ["AWS", "Azure", "GCP", "SaaS", "Windows"],
        "detection": "Monitor IAM policy changes, role assignments, key creation.",
        "mitigation": "Least privilege, audit IAM changes, alert on policy modifications.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": ["Initial Access"],
        "description": "Adversaries may exploit vulnerabilities in internet-facing applications.",
        "platforms": ["AWS", "Azure", "GCP", "Windows", "Linux"],
        "detection": "WAF alerts, anomalous HTTP requests, application log monitoring.",
        "mitigation": "Patch management, WAF, input validation, network segmentation.",
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": ["Exfiltration"],
        "description": "Adversaries may exfiltrate data to another cloud account they control.",
        "platforms": ["AWS", "Azure", "GCP"],
        "detection": "Monitor cross-account data transfers, S3 bucket policies, blob access.",
        "mitigation": "DLP, bucket policies, cross-account access restrictions.",
    },
    "T1578": {
        "name": "Modify Cloud Compute Infrastructure",
        "tactic": ["Defense Evasion"],
        "description": "Adversaries may modify cloud compute infrastructure to evade detection.",
        "platforms": ["AWS", "Azure", "GCP"],
        "detection": "Monitor EC2/VM creation, snapshot activity, security group changes.",
        "mitigation": "Cloud audit logging, resource tagging policies, approval workflows.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": ["Credential Access"],
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "platforms": ["AWS", "Azure", "GCP", "SaaS", "Windows", "Linux"],
        "detection": "Failed login monitoring, rate limiting, account lockout alerts.",
        "mitigation": "Account lockout policies, MFA, rate limiting, CAPTCHA.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": ["Initial Access"],
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "platforms": ["SaaS", "Windows", "Linux", "macOS"],
        "detection": "Email filtering, URL sandboxing, user reporting mechanisms.",
        "mitigation": "Security awareness training, email authentication (DMARC/DKIM/SPF).",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": ["Execution"],
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "Script execution logging, PowerShell monitoring, bash history.",
        "mitigation": "Constrained language mode, script signing, execution policies.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": ["Command and Control"],
        "description": "Adversaries may communicate using application layer protocols (HTTP, DNS).",
        "platforms": ["Windows", "Linux", "macOS"],
        "detection": "DNS query analysis, HTTP traffic inspection, beacon detection.",
        "mitigation": "DNS filtering, proxy inspection, network segmentation.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": ["Impact"],
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "platforms": ["AWS", "Azure", "GCP", "Windows", "Linux"],
        "detection": "File modification monitoring, entropy analysis, backup integrity checks.",
        "mitigation": "Offline backups, endpoint detection, network segmentation.",
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": ["Reconnaissance"],
        "description": "Adversaries may scan victim infrastructure to gather information.",
        "platforms": ["AWS", "Azure", "GCP"],
        "detection": "Monitor for port scans, unusual API enumeration, rate anomalies.",
        "mitigation": "Firewall rules, rate limiting, honeypots.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": ["Defense Evasion"],
        "description": "Adversaries may disable or modify security tools to avoid detection.",
        "platforms": ["AWS", "Azure", "GCP", "Windows", "Linux"],
        "detection": "Monitor CloudTrail/audit log disabling, security group changes.",
        "mitigation": "Protect audit logs, immutable logging, SCPs.",
    },
}

# IOC type to likely ATT&CK technique mapping heuristics
IOC_TECHNIQUE_MAP: dict[IOCType, list[str]] = {
    IOCType.IPV4: ["T1071", "T1595"],
    IOCType.IPV6: ["T1071", "T1595"],
    IOCType.DOMAIN: ["T1071", "T1566"],
    IOCType.URL: ["T1566", "T1190"],
    IOCType.FILE_HASH_MD5: ["T1059", "T1486"],
    IOCType.FILE_HASH_SHA1: ["T1059", "T1486"],
    IOCType.FILE_HASH_SHA256: ["T1059", "T1486"],
    IOCType.EMAIL: ["T1566"],
    IOCType.CVE: ["T1190"],
}


@dataclass
class AttackMapping:
    """A single ATT&CK technique mapping with context."""
    technique_id: str
    technique_name: str
    tactics: list[str]
    iocs: list[str] = field(default_factory=list)
    confidence: str = "moderate"
    detection: str = ""
    mitigation: str = ""


class MITREMapper:
    """
    Maps IOCs to MITRE ATT&CK techniques and generates tactical analysis.

    Uses heuristic mapping based on IOC type and enrichment data,
    then produces a kill chain analysis with detection recommendations.
    """

    def __init__(self, custom_mappings: dict[str, list[str]] | None = None):
        self.techniques = ATTACK_TECHNIQUES.copy()
        self.custom_mappings = custom_mappings or {}

    def analyze(self, iocs: list[IOC]) -> dict:
        """Analyze IOCs and return ATT&CK-mapped results."""
        mappings: dict[str, AttackMapping] = {}

        for ioc in iocs:
            # Get techniques from IOC's existing mappings
            technique_ids = list(ioc.mitre_techniques)

            # Add heuristic mappings based on IOC type
            heuristic_ids = IOC_TECHNIQUE_MAP.get(ioc.ioc_type, [])
            for tid in heuristic_ids:
                if tid not in technique_ids:
                    technique_ids.append(tid)

            # Add enrichment-based mappings
            technique_ids.extend(self._enrich_based_mapping(ioc))

            # Build mapping objects
            for tid in technique_ids:
                if tid not in self.techniques:
                    continue
                tech = self.techniques[tid]
                if tid not in mappings:
                    mappings[tid] = AttackMapping(
                        technique_id=tid,
                        technique_name=tech["name"],
                        tactics=tech["tactic"],
                        detection=tech.get("detection", ""),
                        mitigation=tech.get("mitigation", ""),
                    )
                mappings[tid].iocs.append(ioc.value)

                # Update IOC with mapping
                if tid not in ioc.mitre_techniques:
                    ioc.mitre_techniques.append(tid)

        # Build kill chain
        kill_chain = self._build_kill_chain(mappings)

        # Generate recommendations
        recommendations = self._generate_recommendations(mappings, iocs)

        return {
            "techniques": list(mappings.keys()),
            "mappings": {k: self._mapping_to_dict(v) for k, v in mappings.items()},
            "kill_chain": kill_chain,
            "recommendations": recommendations,
            "coverage": self._calculate_coverage(mappings),
        }

    def _enrich_based_mapping(self, ioc: IOC) -> list[str]:
        """Derive additional technique mappings from enrichment data."""
        extra = []
        vt = ioc.enrichment.get("virustotal", {})
        if vt.get("malicious", 0) >= 5:
            if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                extra.append("T1071")  # Likely C2
            if ioc.ioc_type == IOCType.URL:
                extra.append("T1566")  # Likely phishing delivery

        abuse = ioc.enrichment.get("abuseipdb", {})
        if abuse.get("is_tor"):
            extra.append("T1090")  # Proxy (not in our subset but flagged)

        shodan = ioc.enrichment.get("shodan", {})
        if shodan.get("vulns"):
            extra.append("T1190")

        return extra

    def _build_kill_chain(self, mappings: dict[str, AttackMapping]) -> dict[str, list[str]]:
        """Organize techniques into kill chain phases."""
        tactic_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]
        chain: dict[str, list[str]] = {t: [] for t in tactic_order}
        for mapping in mappings.values():
            for tactic in mapping.tactics:
                if tactic in chain:
                    entry = f"{mapping.technique_id}: {mapping.technique_name}"
                    if entry not in chain[tactic]:
                        chain[tactic].append(entry)
        return {k: v for k, v in chain.items() if v}

    def _generate_recommendations(self, mappings: dict[str, AttackMapping], iocs: list[IOC]) -> list[str]:
        """Generate prioritized recommendations based on findings."""
        recs = []
        severity_counts = {}
        for ioc in iocs:
            severity_counts[ioc.severity.value] = severity_counts.get(ioc.severity.value, 0) + 1

        if severity_counts.get("critical", 0) > 0:
            recs.append(f"IMMEDIATE: {severity_counts['critical']} critical-severity IOCs detected — initiate incident triage.")

        for tid, mapping in mappings.items():
            if mapping.mitigation:
                recs.append(f"[{tid}] {mapping.technique_name}: {mapping.mitigation}")

        if any("T1078" in m.technique_id for m in mappings.values()):
            recs.append("PRIORITY: Valid Account abuse detected — enforce MFA, rotate credentials, review IAM policies.")

        if any("T1486" in m.technique_id for m in mappings.values()):
            recs.append("PRIORITY: Ransomware indicators — verify backup integrity, isolate affected systems.")

        return recs

    def _calculate_coverage(self, mappings: dict[str, AttackMapping]) -> dict:
        """Calculate ATT&CK coverage statistics."""
        all_tactics = set()
        for m in mappings.values():
            all_tactics.update(m.tactics)
        return {
            "techniques_mapped": len(mappings),
            "tactics_covered": len(all_tactics),
            "tactics": sorted(all_tactics),
        }

    @staticmethod
    def _mapping_to_dict(mapping: AttackMapping) -> dict:
        return {
            "technique_id": mapping.technique_id,
            "technique_name": mapping.technique_name,
            "tactics": mapping.tactics,
            "ioc_count": len(mapping.iocs),
            "sample_iocs": mapping.iocs[:5],
            "detection": mapping.detection,
            "mitigation": mapping.mitigation,
        }


class CorrelationEngine:
    """
    Correlates IOCs to identify relationships and campaigns.

    Groups IOCs by shared infrastructure, timing, and enrichment
    data to identify coordinated threat activity.
    """

    def analyze(self, iocs: list[IOC]) -> dict:
        """Find correlations across IOCs."""
        clusters: dict[str, list[str]] = {}

        # Cluster by source
        for ioc in iocs:
            src = ioc.source or "unknown"
            clusters.setdefault(src, []).append(ioc.value)

        # Cluster by shared enrichment (country, ASN)
        geo_clusters: dict[str, list[str]] = {}
        for ioc in iocs:
            for enricher_data in ioc.enrichment.values():
                if isinstance(enricher_data, dict):
                    country = enricher_data.get("country", "")
                    if country:
                        geo_clusters.setdefault(country, []).append(ioc.value)

        # Cluster by shared tags
        tag_clusters: dict[str, list[str]] = {}
        for ioc in iocs:
            for tag in ioc.tags:
                if tag:
                    tag_clusters.setdefault(tag, []).append(ioc.value)

        # Find IOCs appearing in multiple clusters (high correlation)
        high_corr = []
        ioc_cluster_count: dict[str, int] = {}
        for cluster_group in [clusters, geo_clusters, tag_clusters]:
            for members in cluster_group.values():
                for m in members:
                    ioc_cluster_count[m] = ioc_cluster_count.get(m, 0) + 1
        for ioc_val, count in ioc_cluster_count.items():
            if count >= 3:
                high_corr.append(ioc_val)

        return {
            "source_clusters": {k: v for k, v in clusters.items() if len(v) > 1},
            "geo_clusters": {k: v for k, v in geo_clusters.items() if len(v) > 1},
            "tag_clusters": {k: v for k, v in tag_clusters.items() if len(v) > 1},
            "high_correlation_iocs": high_corr,
            "total_correlations": len(high_corr),
        }
