"""
IOC extraction and parsing utilities.

Automatically extracts indicators of compromise from unstructured
text — useful for parsing threat reports, emails, and log files.
"""

from __future__ import annotations
import re
from papaya_kiwi_ti.models import IOC, IOCType

# Regex patterns for common IOC types
PATTERNS = {
    IOCType.IPV4: re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    IOCType.DOMAIN: re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|gov|mil|edu|info|biz|xyz|top|ru|cn|tk|cc|pw|club)\b'
    ),
    IOCType.URL: re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    ),
    IOCType.FILE_HASH_SHA256: re.compile(
        r'\b[a-fA-F0-9]{64}\b'
    ),
    IOCType.FILE_HASH_SHA1: re.compile(
        r'\b[a-fA-F0-9]{40}\b'
    ),
    IOCType.FILE_HASH_MD5: re.compile(
        r'\b[a-fA-F0-9]{32}\b'
    ),
    IOCType.EMAIL: re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    IOCType.CVE: re.compile(
        r'\bCVE-\d{4}-\d{4,}\b',
        re.IGNORECASE
    ),
}

# Known false positives to filter out
FALSE_POSITIVES = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "10.0.0.0", "172.16.0.0", "192.168.0.0",
    "8.8.8.8", "8.8.4.4",  # Google DNS — usually not malicious
    "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
}


def extract_iocs(text: str, defang: bool = True) -> list[IOC]:
    """
    Extract IOCs from unstructured text.

    Handles defanged indicators (e.g., hxxps://, [.], [at]) commonly
    found in threat reports and security advisories.

    Args:
        text: Raw text to parse for indicators
        defang: Whether to re-fang defanged indicators first

    Returns:
        List of extracted IOC objects
    """
    if defang:
        text = refang(text)

    found: list[IOC] = []
    seen: set[str] = set()

    # Extract in order of specificity (URLs before domains, etc.)
    for ioc_type in [
        IOCType.CVE, IOCType.URL, IOCType.EMAIL,
        IOCType.FILE_HASH_SHA256, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_MD5,
        IOCType.IPV4, IOCType.DOMAIN,
    ]:
        pattern = PATTERNS.get(ioc_type)
        if not pattern:
            continue

        for match in pattern.finditer(text):
            value = match.group().strip().rstrip(".,;:")
            if value in seen or value in FALSE_POSITIVES:
                continue

            # Skip private IPs
            if ioc_type == IOCType.IPV4 and _is_private_ip(value):
                continue

            # Avoid hash collisions (MD5 matches inside SHA1 matches inside SHA256)
            if ioc_type == IOCType.FILE_HASH_MD5 and len(value) != 32:
                continue
            if ioc_type == IOCType.FILE_HASH_SHA1 and len(value) != 40:
                continue

            seen.add(value)
            found.append(IOC(
                value=value,
                ioc_type=ioc_type,
                source="text_extraction",
            ))

    return found


def refang(text: str) -> str:
    """Convert defanged indicators back to their original form."""
    replacements = [
        ("hxxp://", "http://"),
        ("hxxps://", "https://"),
        ("hXXp://", "http://"),
        ("hXXps://", "https://"),
        ("[.]", "."),
        ("(dot)", "."),
        ("[dot]", "."),
        ("[at]", "@"),
        ("(at)", "@"),
        ("[:]", ":"),
        ("[::]", "::"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False

    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False
