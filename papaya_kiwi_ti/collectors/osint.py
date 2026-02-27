"""
OSINT Collectors for Papaya Kiwi TI.

Each collector implements the Collector protocol and returns
a list of IOC objects from a specific threat intelligence source.
"""

from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Optional

import requests

from papaya_kiwi_ti.models import IOC, IOCType, Severity, Confidence, TLPLevel

logger = logging.getLogger("papaya_kiwi_ti.collectors")


class OTXCollector:
    """
    Collect IOCs from AlienVault Open Threat Exchange (OTX).

    OTX is a free, open threat intelligence community that provides
    community-generated threat data via 'pulses'.

    Requires: Free API key from https://otx.alienvault.com
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": api_key})

    def collect(self, query: str | None = None) -> list[IOC]:
        """Search OTX pulses and extract IOCs."""
        iocs = []

        if query:
            url = f"{self.BASE_URL}/search/pulses"
            params = {"q": query, "limit": 20}
        else:
            url = f"{self.BASE_URL}/pulses/subscribed"
            params = {"limit": 20}

        try:
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", []):
                pulse_name = pulse.get("name", "")
                for indicator in pulse.get("indicators", []):
                    ioc = self._parse_indicator(indicator, pulse_name)
                    if ioc:
                        iocs.append(ioc)

        except requests.RequestException as e:
            logger.error(f"OTX collection failed: {e}")

        return iocs

    def _parse_indicator(self, indicator: dict, source_pulse: str) -> Optional[IOC]:
        """Parse an OTX indicator into an IOC object."""
        type_map = {
            "IPv4": IOCType.IPV4,
            "IPv6": IOCType.IPV6,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "URL": IOCType.URL,
            "FileHash-MD5": IOCType.FILE_HASH_MD5,
            "FileHash-SHA1": IOCType.FILE_HASH_SHA1,
            "FileHash-SHA256": IOCType.FILE_HASH_SHA256,
            "email": IOCType.EMAIL,
            "CVE": IOCType.CVE,
        }

        otx_type = indicator.get("type", "")
        ioc_type = type_map.get(otx_type)
        if not ioc_type:
            return None

        return IOC(
            value=indicator.get("indicator", ""),
            ioc_type=ioc_type,
            source=f"OTX: {source_pulse}",
            tags=indicator.get("tags", []) if isinstance(indicator.get("tags"), list) else [],
            first_seen=_parse_datetime(indicator.get("created")),
            confidence=Confidence.MODERATE,
            tlp=TLPLevel.GREEN,
        )


class CISAKEVCollector:
    """
    Collect from CISA Known Exploited Vulnerabilities (KEV) catalog.

    The KEV catalog is the authoritative list of CVEs being actively
    exploited in the wild. Critical for vulnerability intelligence.

    No API key required — this is a public government resource.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self, query: str | None = None) -> list[IOC]:
        """Fetch and parse the CISA KEV catalog."""
        iocs = []
        try:
            resp = requests.get(self.KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")

                if query and query.lower() not in json.dumps(vuln).lower():
                    continue

                ioc = IOC(
                    value=cve_id,
                    ioc_type=IOCType.CVE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source="CISA KEV",
                    tlp=TLPLevel.CLEAR,
                    tags=[
                        vuln.get("vendorProject", ""),
                        vuln.get("product", ""),
                    ],
                    first_seen=_parse_datetime(vuln.get("dateAdded")),
                    enrichment={
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "description": vuln.get("vulnerabilityName", ""),
                        "action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    },
                )
                iocs.append(ioc)

        except requests.RequestException as e:
            logger.error(f"CISA KEV collection failed: {e}")

        return iocs


class AbuseCHCollector:
    """
    Collect IOCs from abuse.ch threat intelligence feeds.

    Supports URLhaus (malicious URLs) and Feodo Tracker (C2 IPs).
    No API key required — community-driven.
    """

    URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
    FEODO_IPS = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

    def __init__(self, feed: str = "urlhaus"):
        self.feed = feed

    def collect(self, query: str | None = None) -> list[IOC]:
        if self.feed == "urlhaus":
            return self._collect_urlhaus(query)
        elif self.feed == "feodo":
            return self._collect_feodo(query)
        return []

    def _collect_urlhaus(self, query: str | None) -> list[IOC]:
        """Collect malicious URLs from URLhaus."""
        iocs = []
        try:
            resp = requests.post(self.URLHAUS_RECENT, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("urls", []):
                url_val = entry.get("url", "")
                if query and query.lower() not in url_val.lower():
                    continue

                ioc = IOC(
                    value=url_val,
                    ioc_type=IOCType.URL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source="abuse.ch URLhaus",
                    tlp=TLPLevel.GREEN,
                    tags=entry.get("tags", []) if entry.get("tags") else [],
                    first_seen=_parse_datetime(entry.get("date_added")),
                    enrichment={
                        "threat": entry.get("threat", ""),
                        "status": entry.get("url_status", ""),
                        "host": entry.get("host", ""),
                    },
                )
                iocs.append(ioc)

        except requests.RequestException as e:
            logger.error(f"URLhaus collection failed: {e}")
        return iocs

    def _collect_feodo(self, query: str | None) -> list[IOC]:
        """Collect C2 server IPs from Feodo Tracker."""
        iocs = []
        try:
            resp = requests.get(self.FEODO_IPS, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for entry in data if isinstance(data, list) else []:
                ip = entry.get("ip_address", "")
                if query and query.lower() not in json.dumps(entry).lower():
                    continue

                ioc = IOC(
                    value=ip,
                    ioc_type=IOCType.IPV4,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    source="abuse.ch Feodo Tracker",
                    tlp=TLPLevel.GREEN,
                    tags=[entry.get("malware", "")],
                    first_seen=_parse_datetime(entry.get("first_seen")),
                    last_seen=_parse_datetime(entry.get("last_online")),
                    enrichment={
                        "malware": entry.get("malware", ""),
                        "port": entry.get("port", ""),
                        "status": entry.get("status", ""),
                        "as_number": entry.get("as_number", ""),
                        "country": entry.get("country", ""),
                    },
                )
                iocs.append(ioc)

        except requests.RequestException as e:
            logger.error(f"Feodo Tracker collection failed: {e}")
        return iocs


def _parse_datetime(value: str | None) -> Optional[datetime]:
    """Best-effort datetime parsing from various feed formats."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(value[:26], fmt)
        except (ValueError, TypeError):
            continue
    return None
