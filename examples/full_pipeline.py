"""
Example: Full Papaya Kiwi TI Pipeline

Demonstrates the complete threat intelligence workflow:
1. Collect IOCs from OSINT sources
2. Enrich with reputation and context data
3. Analyze with MITRE ATT&CK mapping
4. Generate dual-layer reports (plain English + technical)

Usage:
    # Set your API keys as environment variables:
    export OTX_API_KEY="your_otx_key"
    export VT_API_KEY="your_virustotal_key"
    export ABUSEIPDB_API_KEY="your_abuseipdb_key"

    python examples/full_pipeline.py
"""

import os
import logging
from papaya_kiwi_ti.core import ThreatIntelPipeline
from papaya_kiwi_ti.collectors.osint import OTXCollector, CISAKEVCollector, AbuseCHCollector
from papaya_kiwi_ti.enrichers.providers import VirusTotalEnricher, AbuseIPDBEnricher
from papaya_kiwi_ti.analyzers.mitre import MITREMapper, CorrelationEngine
from papaya_kiwi_ti.reporters.generators import PlainEnglishReporter, TechnicalReporter, MarkdownReporter

logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")


def main():
    # Initialize pipeline
    pipeline = ThreatIntelPipeline(name="Cloud Threat Hunt")

    # --- Collectors ---
    # CISA KEV (no API key needed)
    pipeline.add_collector(CISAKEVCollector())

    # abuse.ch URLhaus (no API key needed)
    pipeline.add_collector(AbuseCHCollector(feed="urlhaus"))

    # OTX (free API key)
    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        pipeline.add_collector(OTXCollector(api_key=otx_key))
    else:
        print("[!] OTX_API_KEY not set — skipping OTX collector")

    # --- Enrichers ---
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        pipeline.add_enricher(VirusTotalEnricher(api_key=vt_key))
    else:
        print("[!] VT_API_KEY not set — skipping VirusTotal enrichment")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        pipeline.add_enricher(AbuseIPDBEnricher(api_key=abuse_key))
    else:
        print("[!] ABUSEIPDB_API_KEY not set — skipping AbuseIPDB enrichment")

    # --- Analyzers ---
    pipeline.add_analyzer(MITREMapper())
    pipeline.add_analyzer(CorrelationEngine())

    # --- Reporters ---
    pipeline.add_reporter(PlainEnglishReporter())
    pipeline.add_reporter(TechnicalReporter())
    pipeline.add_reporter(MarkdownReporter())

    # --- Run ---
    print("\n" + "=" * 60)
    print("  Papaya Kiwi TI — Running Full Pipeline")
    print("=" * 60 + "\n")

    report = pipeline.run(
        query="ransomware cloud",
        title="Cloud Ransomware Threat Landscape"
    )

    # Output reports
    outputs = pipeline.report(report)

    if len(outputs) >= 1:
        print("\n\n" + outputs[0])  # Plain English report
        with open("report_executive.txt", "w") as f:
            f.write(outputs[0])
        print("\n[+] Executive report saved to report_executive.txt")

    if len(outputs) >= 2:
        with open("report_technical.json", "w") as f:
            f.write(outputs[1])
        print("[+] Technical report saved to report_technical.json")

    if len(outputs) >= 3:
        with open("report.md", "w") as f:
            f.write(outputs[2])
        print("[+] Markdown report saved to report.md")

    print(f"\n[+] Pipeline complete: {len(report.iocs)} IOCs processed")
    print(f"[+] MITRE techniques mapped: {len(report.mitre_techniques)}")
    print(f"[+] Recommendations generated: {len(report.recommendations)}")


if __name__ == "__main__":
    main()
