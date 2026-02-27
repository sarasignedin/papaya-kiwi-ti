"""
Report Generators for Papaya Kiwi TI.

Implements the dual-layer reporting philosophy: technical IOC packages
for SOC analysts, and plain-English summaries for stakeholders.
This is the 'translation layer' -- the core Papaya & Kiwi concept.
"""

from __future__ import annotations
from datetime import datetime
from papaya_kiwi_ti.models import ThreatReport, Severity
import json
import logging

logger = logging.getLogger("papaya_kiwi_ti.reporters")


class PlainEnglishReporter:
    """
    Generates plain-English threat intelligence reports.

    Translates technical findings into clear, actionable language
    that non-technical stakeholders can understand and act on.
    This is the 'Papaya' agent concept in action.
    """

    def generate(self, report: ThreatReport) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append(f"  THREAT INTELLIGENCE REPORT")
        lines.append(f"  {report.title}")
        lines.append("=" * 70)
        lines.append(f"  Generated: {report.created.strftime('%B %d, %Y at %H:%M UTC')}")
        lines.append(f"  Author: {report.author}")
        lines.append(f"  Classification: {report.tlp.value}")
        lines.append(f"  Severity: {report.severity.value.upper()}")
        lines.append(f"  Confidence: {report.confidence.value.upper()}")
        lines.append("")

        # Executive Summary
        lines.append("-" * 70)
        lines.append("  EXECUTIVE SUMMARY")
        lines.append("-" * 70)
        lines.append("")

        crit = sum(1 for i in report.iocs if i.severity == Severity.CRITICAL)
        high = sum(1 for i in report.iocs if i.severity == Severity.HIGH)
        med = sum(1 for i in report.iocs if i.severity == Severity.MEDIUM)
        low = sum(1 for i in report.iocs if i.severity == Severity.LOW)

        lines.append(f"  This report covers {len(report.iocs)} indicators of compromise (IOCs)")
        lines.append(f"  collected from threat intelligence sources.")
        lines.append("")
        lines.append(f"  Severity Breakdown:")
        if crit: lines.append(f"    !!! CRITICAL: {crit} indicators require immediate attention")
        if high: lines.append(f"    !!  HIGH:     {high} indicators need prompt investigation")
        if med:  lines.append(f"    !   MEDIUM:   {med} indicators for awareness")
        if low:  lines.append(f"        LOW:      {low} indicators for monitoring")
        lines.append("")

        if report.threat_actors:
            lines.append(f"  Threat Actors Identified: {len(report.threat_actors)}")
            for ta in report.threat_actors:
                lines.append(f"    - {ta.name} ({ta.motivation or 'unknown motivation'})")
            lines.append("")

        # What This Means (plain English)
        lines.append("-" * 70)
        lines.append("  WHAT THIS MEANS FOR YOUR ORGANIZATION")
        lines.append("-" * 70)
        lines.append("")

        if crit > 0:
            lines.append("  ** IMMEDIATE ACTION REQUIRED **")
            lines.append(f"  We identified {crit} critical threats that indicate active")
            lines.append("  or imminent risk to your environment. These require immediate")
            lines.append("  investigation and containment.")
            lines.append("")

        if report.mitre_techniques:
            lines.append(f"  Adversary Techniques Detected: {len(report.mitre_techniques)}")
            lines.append("  Attackers associated with these indicators use the following methods:")
            for tech in report.mitre_techniques[:10]:
                lines.append(f"    - {tech}")
            lines.append("")

        if report.affected_platforms:
            lines.append(f"  Affected Platforms: {', '.join(report.affected_platforms)}")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("-" * 70)
            lines.append("  RECOMMENDED ACTIONS")
            lines.append("-" * 70)
            lines.append("")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        # IOC Summary (non-technical)
        lines.append("-" * 70)
        lines.append("  KEY INDICATORS (Summary)")
        lines.append("-" * 70)
        lines.append("")

        for ioc in sorted(report.iocs, key=lambda x: x.severity.value)[:20]:
            sev_icon = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   "}.get(ioc.severity.value, "   ")
            lines.append(f"  [{sev_icon}] {ioc.ioc_type.value}: {ioc.value}")
            lines.append(f"        Source: {ioc.source} | Confidence: {ioc.confidence.value}")
            if ioc.enrichment:
                for provider, data in ioc.enrichment.items():
                    if isinstance(data, dict) and data.get("malicious"):
                        lines.append(f"        {provider}: {data['malicious']} vendors flagged as malicious")
            lines.append("")

        lines.append("=" * 70)
        lines.append(f"  Report ID: {report.id}")
        lines.append(f"  Papaya Kiwi TI | papayakiwi.com")
        lines.append("=" * 70)

        return "\n".join(lines)


class TechnicalReporter:
    """
    Generates technical IOC packages for SOC analysts.

    Outputs structured data with STIX patterns, enrichment details,
    and detection recommendations. This is the 'Kiwi' agent concept.
    """

    def generate(self, report: ThreatReport) -> str:
        output = {
            "report_metadata": {
                "id": report.id,
                "title": report.title,
                "created": report.created.isoformat(),
                "author": report.author,
                "tlp": report.tlp.value,
                "severity": report.severity.value,
                "confidence": report.confidence.value,
            },
            "statistics": {
                "total_iocs": len(report.iocs),
                "by_type": self._count_by_type(report),
                "by_severity": self._count_by_severity(report),
                "mitre_techniques": report.mitre_techniques,
            },
            "iocs": [ioc.to_dict() for ioc in report.iocs],
            "stix_patterns": [ioc.to_stix_pattern() for ioc in report.iocs],
            "threat_actors": [ta.to_dict() for ta in report.threat_actors],
            "recommendations": report.recommendations,
        }
        return json.dumps(output, indent=2, default=str)

    @staticmethod
    def _count_by_type(report: ThreatReport) -> dict:
        counts: dict[str, int] = {}
        for ioc in report.iocs:
            t = ioc.ioc_type.value
            counts[t] = counts.get(t, 0) + 1
        return counts

    @staticmethod
    def _count_by_severity(report: ThreatReport) -> dict:
        counts: dict[str, int] = {}
        for ioc in report.iocs:
            s = ioc.severity.value
            counts[s] = counts.get(s, 0) + 1
        return counts


class MarkdownReporter:
    """
    Generates Markdown-formatted reports for documentation and wikis.

    Useful for pasting into Confluence, GitHub, Notion, or any
    Markdown-compatible platform.
    """

    def generate(self, report: ThreatReport) -> str:
        lines = []
        lines.append(f"# {report.title}")
        lines.append("")
        lines.append(f"**Generated:** {report.created.strftime('%B %d, %Y %H:%M UTC')}  ")
        lines.append(f"**Author:** {report.author}  ")
        lines.append(f"**TLP:** `{report.tlp.value}`  ")
        lines.append(f"**Severity:** `{report.severity.value.upper()}`  ")
        lines.append(f"**Confidence:** `{report.confidence.value.upper()}`  ")
        lines.append("")

        # Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(report.summary or f"Analysis of {len(report.iocs)} indicators of compromise.")
        lines.append("")

        # Severity table
        lines.append("## IOC Overview")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        sev_counts = {}
        for ioc in report.iocs:
            sev_counts[ioc.severity.value] = sev_counts.get(ioc.severity.value, 0) + 1
        for sev in ["critical", "high", "medium", "low", "informational"]:
            if sev in sev_counts:
                lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
        lines.append("")

        # ATT&CK
        if report.mitre_techniques:
            lines.append("## MITRE ATT&CK Techniques")
            lines.append("")
            for tech in report.mitre_techniques:
                lines.append(f"- `{tech}`")
            lines.append("")

        # IOC table
        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value | Severity | Source |")
        lines.append("|------|-------|----------|--------|")
        for ioc in sorted(report.iocs, key=lambda x: x.severity.value)[:50]:
            val = ioc.value if len(ioc.value) <= 60 else ioc.value[:57] + "..."
            lines.append(f"| {ioc.ioc_type.value} | `{val}` | {ioc.severity.value} | {ioc.source} |")
        lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("---")
        lines.append(f"*Report ID: {report.id} | Papaya Kiwi TI*")

        return "\n".join(lines)
