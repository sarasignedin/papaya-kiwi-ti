"""
Example: Generate full reports to docs/ directory.

Demonstrates the complete reporting pipeline — extracts IOCs from
a simulated threat report, maps to ATT&CK, and generates:
  - docs/report_executive.pdf  (Papaya Kiwi branded PDF)
  - docs/report_technical.json (structured IOC package)
  - docs/report.md             (Markdown for wikis)

No API keys required — uses text extraction and local analysis.

Usage:
    python examples/generate_reports.py
"""

import os
import json
from papaya_kiwi_ti.models import IOC, IOCType, ThreatReport, ThreatActor, Severity, Confidence, TLPLevel
from papaya_kiwi_ti.utils.parser import extract_iocs
from papaya_kiwi_ti.analyzers.mitre import MITREMapper, CorrelationEngine
from papaya_kiwi_ti.reporters.generators import PlainEnglishReporter, TechnicalReporter, MarkdownReporter
from papaya_kiwi_ti.reporters.pdf_report import PDFReporter

# Simulated threat advisory
THREAT_ADVISORY = """
THREAT ADVISORY: Cloud Credential Compromise Campaign — "CLOUDY SERPENT"

Date: February 2026
TLP: AMBER
Severity: HIGH

Summary:
A sophisticated threat actor group tracked as CLOUDY SERPENT has been observed
conducting a targeted credential harvesting campaign against organizations
using AWS and Azure cloud infrastructure. The campaign leverages spear-phishing
emails impersonating cloud provider security notifications.

Indicators of Compromise:

Command & Control Infrastructure:
- 185[.]220[.]101[.]34 (Primary C2 - Netherlands)
- 91[.]219[.]236[.]222 (Backup C2 - Romania)
- 45[.]155[.]205[.]99 (Staging server - Germany)
- 194[.]26[.]135[.]89 (Exfil endpoint - Russia)

Phishing Domains:
- aws-login-verify[.]com
- azure-portal-auth[.]net
- cloud-security-update[.]xyz
- m365-account-review[.]com

Malware Hashes:
- SHA256: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
- SHA256: deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef
- MD5: d41d8cd98f00b204e9800998ecf8427e

Phishing Senders:
- security-team@aws-login-verify[.]com
- no-reply@azure-portal-auth[.]net

Related Vulnerabilities:
- CVE-2024-21887 (Ivanti Connect Secure - used for initial VPN access)
- CVE-2023-46805 (Ivanti Policy Secure - authentication bypass)
- CVE-2024-3400 (Palo Alto PAN-OS GlobalProtect)

The actor uses hxxps://aws-login-verify[.]com/auth/callback to capture
OAuth tokens. Exfiltration observed to 194[.]26[.]135[.]89 over port 443
using encrypted HTTPS tunnels.

MITRE ATT&CK Mapping:
- T1078 (Valid Accounts) - Harvested credentials used for initial access
- T1566 (Phishing) - Spear-phishing emails with credential harvesting links
- T1537 (Transfer Data to Cloud Account) - Data exfiltrated to attacker cloud
- T1098 (Account Manipulation) - New IAM roles and access keys created
- T1562 (Impair Defenses) - CloudTrail logging disabled in compromised accounts
"""


def main():
    output_dir = "docs"
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  Papaya Kiwi TI — Report Generation")
    print("=" * 60)

    # Step 1: Extract IOCs
    print("\n[1] Extracting IOCs from threat advisory...")
    iocs = extract_iocs(THREAT_ADVISORY)
    print(f"    Extracted {len(iocs)} IOCs")
    for ioc in iocs:
        print(f"      [{ioc.ioc_type.value}] {ioc.value}")

    # Step 2: MITRE ATT&CK Analysis
    print("\n[2] Mapping to MITRE ATT&CK...")
    mapper = MITREMapper()
    analysis = mapper.analyze(iocs)
    print(f"    Techniques: {', '.join(analysis['techniques'])}")
    print(f"    Kill chain phases: {', '.join(analysis['kill_chain'].keys())}")

    # Step 3: Correlation
    print("\n[3] Running correlation analysis...")
    correlator = CorrelationEngine()
    correlation = correlator.analyze(iocs)
    print(f"    High-correlation IOCs: {len(correlation.get('high_correlation_iocs', []))}")

    # Step 4: Build threat actor profile
    actor = ThreatActor(
        name="CLOUDY SERPENT",
        aliases=["UNC-CS-2026", "CloudPhisher"],
        description="Sophisticated threat group targeting cloud infrastructure credentials.",
        motivation="espionage",
        sophistication="organized-crime",
        country_of_origin="Eastern Europe (suspected)",
        target_sectors=["technology", "financial-services", "government"],
        target_regions=["North America", "Western Europe"],
        ttps=["T1078", "T1566", "T1537", "T1098", "T1562"],
        known_tools=["Custom OAuth harvester", "CloudTrail disabler", "Encrypted HTTPS tunnel"],
        confidence=Confidence.MODERATE,
        sources=["Internal investigation", "Mandiant TI", "OSINT"],
    )

    # Step 5: Build report
    print("\n[4] Building threat report...")
    report = ThreatReport(
        title="Cloud Credential Compromise Campaign — CLOUDY SERPENT",
        summary=(
            "A targeted credential harvesting campaign by the CLOUDY SERPENT group "
            "is actively targeting AWS and Azure cloud environments. The campaign uses "
            "sophisticated spear-phishing emails impersonating cloud provider security "
            "notifications to capture OAuth tokens and IAM credentials. Once access is "
            "obtained, the actors disable audit logging, create persistence mechanisms "
            "via new IAM roles, and exfiltrate data to attacker-controlled cloud accounts."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        tlp=TLPLevel.AMBER,
        affected_platforms=["AWS", "Azure", "Ivanti Connect Secure", "PAN-OS"],
        recommendations=analysis.get("recommendations", []),
        references=[
            "CISA Advisory: Ivanti Connect Secure Exploitation",
            "Mandiant APT Report: Cloud Credential Campaigns 2025-2026",
            "Papaya Kiwi Consulting Internal Analysis",
        ],
    )

    for ioc in iocs:
        report.add_ioc(ioc)
    report.add_threat_actor(actor)

    # Step 6: Generate reports
    print("\n[5] Generating reports to docs/...")

    # PDF (branded)
    pdf_reporter = PDFReporter(output_dir=output_dir)
    pdf_path = pdf_reporter.generate(report)
    print(f"    [+] PDF:      {pdf_path}")

    # Technical JSON
    tech_reporter = TechnicalReporter()
    tech_output = tech_reporter.generate(report)
    tech_path = os.path.join(output_dir, "report_technical.json")
    with open(tech_path, "w") as f:
        f.write(tech_output)
    print(f"    [+] JSON:     {tech_path}")

    # Markdown
    md_reporter = MarkdownReporter()
    md_output = md_reporter.generate(report)
    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w") as f:
        f.write(md_output)
    print(f"    [+] Markdown: {md_path}")

    # Plain text (for terminal / email)
    pe_reporter = PlainEnglishReporter()
    pe_output = pe_reporter.generate(report)
    pe_path = os.path.join(output_dir, "report_executive.txt")
    with open(pe_path, "w") as f:
        f.write(pe_output)
    print(f"    [+] Text:     {pe_path}")

    # Summary
    print("\n" + "=" * 60)
    print(f"  Reports generated in {output_dir}/")
    print(f"  IOCs: {len(report.iocs)} | Techniques: {len(report.mitre_techniques)} | Recommendations: {len(report.recommendations)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
