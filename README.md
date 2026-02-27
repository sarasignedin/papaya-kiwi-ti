# 🍑🥝 Papaya Kiwi TI

**Open-source threat intelligence toolkit for collection, enrichment, ATT&CK mapping, and plain-English reporting.**

Built for MDR teams, SOC analysts, and security consultants who need to turn raw threat data into actionable intelligence — fast.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## Why Papaya Kiwi TI?

Most threat intelligence tools are either enterprise-expensive or require stitching together dozens of scripts. Papaya Kiwi TI gives you a **clean, modular Python library** that chains the full TI lifecycle into a single pipeline:

```
Collect → Enrich → Analyze → Report
```

The "Papaya & Kiwi" philosophy: **Papaya** translates complex findings into plain-English reports for stakeholders. **Kiwi** produces structured technical IOC packages for SOC analysts. Same data, dual audiences.

## Architecture

```
papaya_kiwi_ti/
├── core.py              # Pipeline orchestrator
├── models.py            # IOC, ThreatActor, ThreatReport data models
├── collectors/          # OSINT & feed collection
│   └── osint.py         # OTX, CISA KEV, abuse.ch
├── enrichers/           # IOC enrichment providers
│   └── providers.py     # VirusTotal, AbuseIPDB, Shodan
├── analyzers/           # Analysis engines
│   └── mitre.py         # ATT&CK mapping, correlation
├── reporters/           # Report generators
│   └── generators.py    # Plain English, Technical JSON, Markdown
└── utils/
    └── parser.py        # IOC extraction from unstructured text
```

## Quick Start

### Install

```bash
pip install -e .
```

### Extract IOCs from text (no API keys needed)

```python
from papaya_kiwi_ti.utils.parser import extract_iocs
from papaya_kiwi_ti.analyzers.mitre import MITREMapper

# Extract from a threat report (handles defanged indicators)
text = """
C2 server observed at 185[.]220[.]101[.]34.
Phishing domain: aws-login-verify[.]com
Exploiting CVE-2024-21887 for initial access.
Payload hash: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
"""

iocs = extract_iocs(text)
for ioc in iocs:
    print(f"[{ioc.ioc_type.value}] {ioc.value}")

# Map to MITRE ATT&CK
mapper = MITREMapper()
analysis = mapper.analyze(iocs)
for tactic, techniques in analysis["kill_chain"].items():
    print(f"\n{tactic}:")
    for t in techniques:
        print(f"  - {t}")
```

### Full Pipeline with API enrichment

```python
import os
from papaya_kiwi_ti.core import ThreatIntelPipeline
from papaya_kiwi_ti.collectors.osint import CISAKEVCollector, AbuseCHCollector
from papaya_kiwi_ti.enrichers.providers import VirusTotalEnricher
from papaya_kiwi_ti.analyzers.mitre import MITREMapper
from papaya_kiwi_ti.reporters.generators import PlainEnglishReporter

pipeline = ThreatIntelPipeline(name="Cloud Threat Hunt")

# Add components (chain them)
pipeline.add_collector(CISAKEVCollector())
pipeline.add_collector(AbuseCHCollector(feed="urlhaus"))
pipeline.add_enricher(VirusTotalEnricher(api_key=os.getenv("VT_API_KEY")))
pipeline.add_analyzer(MITREMapper())
pipeline.add_reporter(PlainEnglishReporter())

# Run the full pipeline
report = pipeline.run(query="ransomware", title="Ransomware Threat Report")

# Get the plain-English output
outputs = pipeline.report(report)
print(outputs[0])
```

### Create IOCs programmatically

```python
from papaya_kiwi_ti.models import IOC, IOCType, Severity, ThreatActor

# Create an IOC
ioc = IOC(
    value="185.220.101.34",
    ioc_type=IOCType.IPV4,
    severity=Severity.CRITICAL,
    source="Internal investigation",
    tags=["c2", "apt29"],
    mitre_techniques=["T1071", "T1078"],
)

print(ioc.to_stix_pattern())  # [ipv4-addr = '185.220.101.34']
print(ioc.fingerprint)         # Deterministic hash for dedup

# Create a threat actor profile
actor = ThreatActor(
    name="CLOUDY BEAR",
    motivation="espionage",
    sophistication="nation-state",
    target_sectors=["government", "defense"],
    ttps=["T1078", "T1537", "T1578"],
    known_tools=["Cobalt Strike", "Mimikatz"],
)
```

## Data Sources

### Collectors (OSINT)

| Source | API Key Required | Data Type |
|--------|:---:|-----------|
| **CISA KEV** | No | Actively exploited CVEs |
| **abuse.ch URLhaus** | No | Malicious URLs |
| **abuse.ch Feodo** | No | C2 server IPs |
| **AlienVault OTX** | Free | Community threat pulses |

### Enrichers

| Provider | API Key Required | Enrichment |
|----------|:---:|------------|
| **VirusTotal** | Free | Multi-AV scan results, reputation |
| **AbuseIPDB** | Free | IP abuse reports, ISP, geolocation |
| **Shodan** | Free tier | Open ports, services, vulnerabilities |

### Analyzers

| Engine | Description |
|--------|-------------|
| **MITREMapper** | Maps IOCs to ATT&CK techniques, builds kill chain |
| **CorrelationEngine** | Groups IOCs by infrastructure, geography, tags |

### Reporters

| Format | Audience | Description |
|--------|----------|-------------|
| **PlainEnglishReporter** | Stakeholders | "Papaya" — human-readable threat advisory |
| **TechnicalReporter** | SOC analysts | "Kiwi" — structured JSON with STIX patterns |
| **MarkdownReporter** | Documentation | Wiki/Confluence-ready format |

## Extending

Every component follows a simple protocol. Add your own collector, enricher, analyzer, or reporter:

```python
from papaya_kiwi_ti.models import IOC

class MyCustomEnricher:
    """Just implement the enrich method."""
    def enrich(self, ioc: IOC) -> IOC:
        # Your enrichment logic
        ioc.enrichment["my_source"] = {"custom_data": "value"}
        return ioc

# Plug it in
pipeline.add_enricher(MyCustomEnricher())
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Type checking
mypy papaya_kiwi_ti/

# Linting
ruff check papaya_kiwi_ti/
```

## Roadmap

- [ ] **STIX 2.1 export** — Full STIX bundle generation for TIP integration
- [ ] **TAXII client** — Push/pull from TAXII servers
- [ ] **Mandiant TI integration** — For Google SecOps environments
- [ ] **Chronicle SIEM connector** — Direct IOC ingestion into YARA-L rules
- [ ] **AI-powered analysis** — LLM-based threat report summarization
- [ ] **CLI tool** — `pkti collect --source otx --query "apt29"`
- [ ] **Dashboard** — Streamlit-based visualization

## License

MIT License — see [LICENSE](LICENSE) for details.

## About

Built by **Papaya Kiwi Consulting LLC** — Securing Your Cloud, One Sweet Byte at a Time. 🍑🥝

This toolkit embodies our philosophy: threat intelligence should be accessible, actionable, and automated. Whether you're a solo consultant or an MDR team, good TI shouldn't require a six-figure platform.

---

*"The best threat intelligence is the kind your team actually uses."*
