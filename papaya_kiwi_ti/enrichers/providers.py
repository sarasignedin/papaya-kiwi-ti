"""
IOC Enrichment Providers for Papaya Kiwi TI.

Each enricher takes an IOC, queries an external service, and returns
the IOC with additional context, reputation scores, and metadata.
"""

from __future__ import annotations
import logging

import requests

from papaya_kiwi_ti.models import IOC, IOCType, Severity, Confidence

logger = logging.getLogger("papaya_kiwi_ti.enrichers")


class VirusTotalEnricher:
    """
    Enrich IOCs using VirusTotal API v3.

    Supports: IPs, domains, URLs, file hashes.
    Requires: Free API key from https://www.virustotal.com
    Rate limit: 4 requests/minute on free tier.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def enrich(self, ioc: IOC) -> IOC:
        endpoint = self._get_endpoint(ioc)
        if not endpoint:
            return ioc

        try:
            resp = self.session.get(endpoint, timeout=30)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                ioc.enrichment["virustotal"] = {
                    "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
                    "undetected": data.get("last_analysis_stats", {}).get("undetected", 0),
                    "reputation": data.get("reputation", None),
                    "tags": data.get("tags", []),
                }
                mal_count = data.get("last_analysis_stats", {}).get("malicious", 0)
                ioc = self._update_severity(ioc, mal_count)
            elif resp.status_code == 404:
                ioc.enrichment["virustotal"] = {"status": "not_found"}
            else:
                logger.warning(f"VT returned {resp.status_code} for {ioc.value}")
        except requests.RequestException as e:
            logger.error(f"VT enrichment failed for {ioc.value}: {e}")

        return ioc

    def _get_endpoint(self, ioc: IOC) -> str | None:
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"{self.BASE_URL}/ip_addresses/{ioc.value}"
        elif ioc.ioc_type == IOCType.DOMAIN:
            return f"{self.BASE_URL}/domains/{ioc.value}"
        elif ioc.ioc_type in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256):
            return f"{self.BASE_URL}/files/{ioc.value}"
        elif ioc.ioc_type == IOCType.URL:
            import base64
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
            return f"{self.BASE_URL}/urls/{url_id}"
        return None

    @staticmethod
    def _update_severity(ioc: IOC, malicious_count: int) -> IOC:
        if malicious_count >= 10:
            ioc.severity = Severity.CRITICAL
            ioc.confidence = Confidence.HIGH
        elif malicious_count >= 5:
            ioc.severity = Severity.HIGH
            ioc.confidence = Confidence.HIGH
        elif malicious_count >= 2:
            ioc.severity = Severity.MEDIUM
            ioc.confidence = Confidence.MODERATE
        elif malicious_count >= 1:
            ioc.severity = Severity.LOW
            ioc.confidence = Confidence.LOW
        return ioc


class AbuseIPDBEnricher:
    """
    Enrich IP addresses using AbuseIPDB.

    Provides abuse confidence scores, ISP info, and report counts.
    Requires: Free API key from https://www.abuseipdb.com
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enrich(self, ioc: IOC) -> IOC:
        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            return ioc

        try:
            resp = requests.get(
                self.BASE_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": True},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                ioc.enrichment["abuseipdb"] = {
                    "abuse_confidence": data.get("abuseConfidencePercentage", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "usage_type": data.get("usageType", ""),
                }
                abuse_score = data.get("abuseConfidencePercentage", 0)
                if abuse_score >= 80:
                    ioc.severity = Severity.CRITICAL
                    ioc.confidence = Confidence.HIGH
                elif abuse_score >= 50:
                    ioc.severity = Severity.HIGH
        except requests.RequestException as e:
            logger.error(f"AbuseIPDB enrichment failed for {ioc.value}: {e}")

        return ioc


class ShodanEnricher:
    """
    Enrich IPs using Shodan for infrastructure context.

    Provides open ports, services, OS, geolocation, and vulns.
    Requires: API key from https://shodan.io
    """

    BASE_URL = "https://api.shodan.io/shodan/host"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enrich(self, ioc: IOC) -> IOC:
        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            return ioc

        try:
            resp = requests.get(
                f"{self.BASE_URL}/{ioc.value}",
                params={"key": self.api_key},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                ioc.enrichment["shodan"] = {
                    "ports": data.get("ports", []),
                    "os": data.get("os", None),
                    "organization": data.get("org", ""),
                    "asn": data.get("asn", ""),
                    "country": data.get("country_code", ""),
                    "city": data.get("city", ""),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "last_update": data.get("last_update", ""),
                }
                if data.get("vulns"):
                    ioc.tags.append("has_vulns")
                    ioc.tags.extend(data["vulns"][:5])
        except requests.RequestException as e:
            logger.error(f"Shodan enrichment failed for {ioc.value}: {e}")

        return ioc
