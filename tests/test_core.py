"""Tests for Papaya Kiwi TI core models and utilities."""

import pytest
from papaya_kiwi_ti.models import IOC, IOCType, Severity, Confidence, TLPLevel, ThreatActor, ThreatReport
from papaya_kiwi_ti.utils.parser import extract_iocs, refang
from papaya_kiwi_ti.analyzers.mitre import MITREMapper


class TestIOC:
    def test_create_ioc(self):
        ioc = IOC(value="192.168.1.1", ioc_type=IOCType.IPV4)
        assert ioc.value == "192.168.1.1"
        assert ioc.ioc_type == IOCType.IPV4
        assert ioc.severity == Severity.MEDIUM
        assert ioc.first_seen is not None

    def test_fingerprint_deterministic(self):
        ioc1 = IOC(value="8.8.8.8", ioc_type=IOCType.IPV4)
        ioc2 = IOC(value="8.8.8.8", ioc_type=IOCType.IPV4)
        assert ioc1.fingerprint == ioc2.fingerprint

    def test_fingerprint_unique_across_types(self):
        ioc1 = IOC(value="example.com", ioc_type=IOCType.DOMAIN)
        ioc2 = IOC(value="example.com", ioc_type=IOCType.URL)
        assert ioc1.fingerprint != ioc2.fingerprint

    def test_stix_pattern(self):
        ioc = IOC(value="10.0.0.1", ioc_type=IOCType.IPV4)
        assert ioc.to_stix_pattern() == "[ipv4-addr = '10.0.0.1']"

    def test_to_dict(self):
        ioc = IOC(value="evil.com", ioc_type=IOCType.DOMAIN, severity=Severity.HIGH)
        d = ioc.to_dict()
        assert d["value"] == "evil.com"
        assert d["type"] == "domain-name"
        assert d["severity"] == "high"
        assert "fingerprint" in d
        assert "stix_pattern" in d

    def test_to_json(self):
        ioc = IOC(value="evil.com", ioc_type=IOCType.DOMAIN)
        j = ioc.to_json()
        assert '"evil.com"' in j


class TestThreatReport:
    def test_add_ioc_propagates_techniques(self):
        report = ThreatReport(title="Test")
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IPV4, mitre_techniques=["T1071"])
        report.add_ioc(ioc)
        assert "T1071" in report.mitre_techniques
        assert len(report.iocs) == 1

    def test_add_threat_actor(self):
        report = ThreatReport(title="Test")
        ta = ThreatActor(name="APT29", ttps=["T1078", "T1566"])
        report.add_threat_actor(ta)
        assert "T1078" in report.mitre_techniques
        assert "T1566" in report.mitre_techniques


class TestParser:
    def test_extract_ipv4(self):
        iocs = extract_iocs("Malicious IP: 185.220.101.34 was observed")
        ips = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        assert len(ips) == 1
        assert ips[0].value == "185.220.101.34"

    def test_extract_defanged_ip(self):
        iocs = extract_iocs("C2 server: 185[.]220[.]101[.]34")
        ips = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        assert len(ips) == 1
        assert ips[0].value == "185.220.101.34"

    def test_extract_domain(self):
        iocs = extract_iocs("Phishing domain: evil-login.com")
        domains = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
        assert any(d.value == "evil-login.com" for d in domains)

    def test_extract_defanged_url(self):
        iocs = extract_iocs("URL: hxxps://evil[.]com/payload")
        urls = [i for i in iocs if i.ioc_type == IOCType.URL]
        assert len(urls) >= 1

    def test_extract_sha256(self):
        h = "a" * 64
        iocs = extract_iocs(f"Hash: {h}")
        hashes = [i for i in iocs if i.ioc_type == IOCType.FILE_HASH_SHA256]
        assert len(hashes) == 1

    def test_extract_cve(self):
        iocs = extract_iocs("Exploiting CVE-2024-21887 in the wild")
        cves = [i for i in iocs if i.ioc_type == IOCType.CVE]
        assert len(cves) == 1
        assert cves[0].value == "CVE-2024-21887"

    def test_extract_email(self):
        iocs = extract_iocs("Sender: phish@evil.com")
        emails = [i for i in iocs if i.ioc_type == IOCType.EMAIL]
        assert len(emails) == 1

    def test_filters_private_ips(self):
        iocs = extract_iocs("Internal: 192.168.1.1 and 10.0.0.1 and external 45.33.32.156")
        ips = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        values = [i.value for i in ips]
        assert "192.168.1.1" not in values
        assert "10.0.0.1" not in values
        assert "45.33.32.156" in values

    def test_refang(self):
        assert refang("hxxps://evil[.]com") == "https://evil.com"
        assert refang("user[at]evil[.]com") == "user@evil.com"


class TestMITREMapper:
    def test_maps_ip_to_techniques(self):
        mapper = MITREMapper()
        iocs = [IOC(value="1.2.3.4", ioc_type=IOCType.IPV4)]
        result = mapper.analyze(iocs)
        assert len(result["techniques"]) > 0
        assert "T1071" in result["techniques"]

    def test_maps_url_to_phishing(self):
        mapper = MITREMapper()
        iocs = [IOC(value="https://evil.com/login", ioc_type=IOCType.URL)]
        result = mapper.analyze(iocs)
        assert "T1566" in result["techniques"]

    def test_maps_cve_to_exploit(self):
        mapper = MITREMapper()
        iocs = [IOC(value="CVE-2024-1234", ioc_type=IOCType.CVE)]
        result = mapper.analyze(iocs)
        assert "T1190" in result["techniques"]

    def test_kill_chain_populated(self):
        mapper = MITREMapper()
        iocs = [
            IOC(value="1.2.3.4", ioc_type=IOCType.IPV4),
            IOC(value="https://evil.com", ioc_type=IOCType.URL),
            IOC(value="CVE-2024-1234", ioc_type=IOCType.CVE),
        ]
        result = mapper.analyze(iocs)
        assert len(result["kill_chain"]) > 0

    def test_generates_recommendations(self):
        mapper = MITREMapper()
        iocs = [IOC(value="1.2.3.4", ioc_type=IOCType.IPV4, severity=Severity.CRITICAL)]
        result = mapper.analyze(iocs)
        assert len(result["recommendations"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
