"""
Core pipeline orchestrator for Papaya Kiwi TI.

The ThreatIntelPipeline chains collectors, enrichers, analyzers,
and reporters into a configurable, repeatable workflow.
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable
from papaya_kiwi_ti.models import IOC, ThreatReport
import logging

logger = logging.getLogger("papaya_kiwi_ti")


@runtime_checkable
class Collector(Protocol):
    """Protocol for OSINT/feed collectors."""
    def collect(self, query: str | None = None) -> list[IOC]: ...


@runtime_checkable
class Enricher(Protocol):
    """Protocol for IOC enrichment providers."""
    def enrich(self, ioc: IOC) -> IOC: ...


@runtime_checkable
class Analyzer(Protocol):
    """Protocol for analysis engines (ATT&CK mapping, correlation, etc.)."""
    def analyze(self, iocs: list[IOC]) -> dict: ...


@runtime_checkable
class Reporter(Protocol):
    """Protocol for report generators."""
    def generate(self, report: ThreatReport) -> str: ...


class ThreatIntelPipeline:
    """
    Orchestrates the full TI lifecycle: Collect -> Enrich -> Analyze -> Report.

    Usage:
        pipeline = ThreatIntelPipeline()
        pipeline.add_collector(OTXCollector(api_key="..."))
        pipeline.add_enricher(VirusTotalEnricher(api_key="..."))
        pipeline.add_enricher(AbuseIPDBEnricher(api_key="..."))
        pipeline.add_analyzer(MITREMapper())
        pipeline.add_reporter(PlainEnglishReporter())

        report = pipeline.run(query="APT29 cloud targeting")
    """

    def __init__(self, name: str = "Papaya Kiwi TI Pipeline"):
        self.name = name
        self.collectors: list[Collector] = []
        self.enrichers: list[Enricher] = []
        self.analyzers: list[Analyzer] = []
        self.reporters: list[Reporter] = []
        self._ioc_cache: dict[str, IOC] = {}

    def add_collector(self, collector: Collector) -> ThreatIntelPipeline:
        self.collectors.append(collector)
        return self

    def add_enricher(self, enricher: Enricher) -> ThreatIntelPipeline:
        self.enrichers.append(enricher)
        return self

    def add_analyzer(self, analyzer: Analyzer) -> ThreatIntelPipeline:
        self.analyzers.append(analyzer)
        return self

    def add_reporter(self, reporter: Reporter) -> ThreatIntelPipeline:
        self.reporters.append(reporter)
        return self

    def _deduplicate(self, iocs: list[IOC]) -> list[IOC]:
        """Deduplicate IOCs by fingerprint, keeping highest severity."""
        seen: dict[str, IOC] = {}
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        for ioc in iocs:
            fp = ioc.fingerprint
            if fp not in seen:
                seen[fp] = ioc
            else:
                existing = seen[fp]
                if severity_rank.get(ioc.severity.value, 0) > severity_rank.get(existing.severity.value, 0):
                    seen[fp] = ioc
        return list(seen.values())

    def collect(self, query: str | None = None) -> list[IOC]:
        """Run all collectors and deduplicate results."""
        all_iocs: list[IOC] = []
        for collector in self.collectors:
            try:
                iocs = collector.collect(query)
                logger.info(f"[{collector.__class__.__name__}] collected {len(iocs)} IOCs")
                all_iocs.extend(iocs)
            except Exception as e:
                logger.error(f"[{collector.__class__.__name__}] failed: {e}")
        deduped = self._deduplicate(all_iocs)
        logger.info(f"Collected {len(all_iocs)} IOCs, {len(deduped)} unique after dedup")
        return deduped

    def enrich(self, iocs: list[IOC]) -> list[IOC]:
        """Enrich each IOC through all enrichers."""
        enriched = []
        for ioc in iocs:
            for enricher in self.enrichers:
                try:
                    ioc = enricher.enrich(ioc)
                except Exception as e:
                    logger.warning(f"[{enricher.__class__.__name__}] failed on {ioc.value}: {e}")
            enriched.append(ioc)
        logger.info(f"Enriched {len(enriched)} IOCs through {len(self.enrichers)} enrichers")
        return enriched

    def analyze(self, iocs: list[IOC]) -> dict:
        """Run all analyzers and merge results."""
        results = {}
        for analyzer in self.analyzers:
            try:
                result = analyzer.analyze(iocs)
                results[analyzer.__class__.__name__] = result
            except Exception as e:
                logger.error(f"[{analyzer.__class__.__name__}] failed: {e}")
        return results

    def report(self, threat_report: ThreatReport) -> list[str]:
        """Generate reports through all reporters."""
        outputs = []
        for reporter in self.reporters:
            try:
                output = reporter.generate(threat_report)
                outputs.append(output)
            except Exception as e:
                logger.error(f"[{reporter.__class__.__name__}] failed: {e}")
        return outputs

    def run(self, query: str | None = None, title: str = "Threat Intelligence Report") -> ThreatReport:
        """Execute the full pipeline: Collect -> Enrich -> Analyze -> Report."""
        logger.info(f"=== Running pipeline: {self.name} ===")

        # Collect
        iocs = self.collect(query)

        # Enrich
        iocs = self.enrich(iocs)

        # Analyze
        analysis = self.analyze(iocs)

        # Build report
        report = ThreatReport(title=title)
        for ioc in iocs:
            report.add_ioc(ioc)

        # Attach analysis metadata
        report.summary = f"Pipeline '{self.name}' processed {len(iocs)} IOCs from {len(self.collectors)} sources."
        if analysis:
            for analyzer_name, result in analysis.items():
                if isinstance(result, dict):
                    if "techniques" in result:
                        for t in result["techniques"]:
                            if t not in report.mitre_techniques:
                                report.mitre_techniques.append(t)
                    if "recommendations" in result:
                        report.recommendations.extend(result["recommendations"])

        # Generate outputs
        outputs = self.report(report)
        logger.info(f"Generated {len(outputs)} report(s)")

        return report
