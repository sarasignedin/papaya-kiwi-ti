"""
Example: Extract IOCs from a threat report (no API keys needed).

Demonstrates the IOC parser extracting indicators from unstructured
text — handles defanged indicators commonly found in threat advisories.
"""

from papaya_kiwi_ti.utils.parser import extract_iocs
from papaya_kiwi_ti.analyzers.mitre import MITREMapper
from papaya_kiwi_ti.reporters.generators import PlainEnglishReporter
from papaya_kiwi_ti.models import ThreatReport, Severity, Confidence


# Simulated threat report text (with defanged indicators)
SAMPLE_REPORT = """
THREAT ADVISORY: Cloud Credential Compromise Campaign

A new campaign targeting AWS and Azure environments has been observed.
The threat actor uses phishing emails from spoofed domains to harvest
cloud console credentials.

Indicators of Compromise:

Malicious IPs (C2 infrastructure):
- 185[.]220[.]101[.]34
- 91[.]219[.]236[.]222
- 45[.]155[.]205[.]99

Phishing domains:
- aws-login-verify[.]com
- azure-portal-auth[.]net
- cloud-security-update[.]xyz

Malware hashes:
- SHA256: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
- MD5: d41d8cd98f00b204e9800998ecf8427e

Phishing sender:
- security-team@aws-login-verify[.]com

Related CVEs:
- CVE-2024-21887 (Ivanti Connect Secure)
- CVE-2023-46805 (Ivanti Policy Secure)

The actor uses hxxps://aws-login-verify[.]com/auth/callback to capture
OAuth tokens. Exfiltration observed to 185[.]220[.]101[.]34 over port 443.

MITRE ATT&CK: T1078 (Valid Accounts), T1566 (Phishing), T1537 (Transfer
Data to Cloud Account)
"""


def main():
    print("=" * 60)
    print("  Papaya Kiwi TI — IOC Extraction Demo")
    print("  (No API keys required)")
    print("=" * 60)

    # Extract IOCs from text
    print("\n[1] Extracting IOCs from threat report...\n")
    iocs = extract_iocs(SAMPLE_REPORT)

    for ioc in iocs:
        print(f"  [{ioc.ioc_type.value}] {ioc.value}")

    print(f"\n  Total extracted: {len(iocs)} IOCs")

    # Map to MITRE ATT&CK
    print("\n[2] Mapping to MITRE ATT&CK...\n")
    mapper = MITREMapper()
    analysis = mapper.analyze(iocs)

    kill_chain = analysis.get("kill_chain", {})
    for tactic, techniques in kill_chain.items():
        print(f"  {tactic}:")
        for tech in techniques:
            print(f"    - {tech}")

    print(f"\n  Techniques mapped: {len(analysis.get('techniques', []))}")
    print(f"  Tactics covered: {analysis.get('coverage', {}).get('tactics_covered', 0)}")

    # Generate report
    print("\n[3] Generating plain-English report...\n")
    report = ThreatReport(
        title="Cloud Credential Compromise Campaign",
        summary="Active phishing campaign targeting AWS and Azure cloud console credentials.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        affected_platforms=["AWS", "Azure"],
    )
    for ioc in iocs:
        report.add_ioc(ioc)
    report.recommendations = analysis.get("recommendations", [])

    reporter = PlainEnglishReporter()
    output = reporter.generate(report)
    print(output)

    # Save
    with open("demo_report.txt", "w") as f:
        f.write(output)
    print("\n[+] Report saved to demo_report.txt")


if __name__ == "__main__":
    main()
