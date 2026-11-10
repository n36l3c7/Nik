"""Factory-default detection rules.

These values are copied verbatim from ``frontend/src/config/detectionRules.js`` so the
backend can serve the same factory defaults the frontend historically shipped
with. They are returned by ``GET /api/settings`` when the shared settings row
has never been written.

Keep these in sync with the frontend source of truth if the defaults change.
"""

from __future__ import annotations

from typing import Any

from .iocs import DEFAULT_ALLOWLIST


def enrichment_defaults() -> dict[str, Any]:
    from copy import deepcopy

    from .enrichment.service import DEFAULTS

    return deepcopy(DEFAULTS)


# Mirror of DEFAULT_SUSPICIOUS_KEYWORDS in frontend/src/config/detectionRules.js.
DEFAULT_SUSPICIOUS_KEYWORDS: list[dict[str, Any]] = [
    {
        "id": "pastebin",
        "label": "pastebin",
        "pattern": "pastebin",
        "severity": "medium",
        "description": ("Text sharing service, often used for data exfiltration or payload delivery."),
    },
    {
        "id": "mega-nz",
        "label": "mega.nz",
        "pattern": "mega\\.nz",
        "severity": "medium",
        "description": (
            "Encrypted cloud storage, a frequent channel for exfiltration or downloading unauthorized tools."
        ),
    },
    {
        "id": "onion",
        "label": ".onion / darkweb",
        "pattern": "\\.onion\\b|darkweb|dark[-_ ]web",
        "severity": "high",
        "description": "Tor network domain (hidden service): dark web access.",
    },
    {
        "id": "exploit",
        "label": "exploit",
        "pattern": "exploit",
        "severity": "high",
        "description": ("Searching for or downloading exploits / offensive code (e.g. exploit-db)."),
    },
    {
        "id": "bypass",
        "label": "bypass",
        "pattern": "bypass",
        "severity": "medium",
        "description": "Attempt to evade security controls (AV, UAC, filters…).",
    },
    {
        "id": "tor",
        "label": "tor",
        "pattern": "\\btor\\b|torproject",
        "severity": "medium",
        "description": ("Reference to the Tor network / Tor Browser (traffic anonymization)."),
    },
    {
        "id": "malware",
        "label": "malware",
        "pattern": "malware|ransomware|trojan|keylogger",
        "severity": "high",
        "description": "Explicit reference to malware or malicious families.",
    },
    {
        "id": "cracking",
        "label": "crack/keygen",
        "pattern": "\\bcrack(ed|ing)?\\b|keygen|warez",
        "severity": "medium",
        "description": ("Pirated software: a common infection vector on corporate endpoints."),
    },
    {
        "id": "anon-sharing",
        "label": "anonymous file sharing",
        "pattern": "anonfiles|temp[-_ ]?mail|transfer\\.sh|gofile\\.io",
        "severity": "medium",
        "description": ("Anonymous file sharing / disposable email services, possible exfiltration."),
    },
]

# Mirror of DEFAULT_BUSINESS_HOURS in frontend/src/config/detectionRules.js.
DEFAULT_BUSINESS_HOURS: dict[str, Any] = {
    "startHour": 8,  # start of business hours (inclusive)
    "endHour": 18,  # end of business hours (exclusive)
    "flagWeekends": True,  # if true, weekends are always "outside hours"
}


def default_settings_doc() -> dict[str, Any]:
    """Return a fresh copy of the factory-default settings document."""
    return {
        "keywords": [dict(k) for k in DEFAULT_SUSPICIOUS_KEYWORDS],
        "businessHours": dict(DEFAULT_BUSINESS_HOURS),
        "iocAllowlist": list(DEFAULT_ALLOWLIST),
        # Incident report header: organisation name and logo (a data: URI).
        "report": {"orgName": "", "logo": ""},
        # Mail Analysis: own domains and trusted Authentication-Results servers.
        "mail": {"orgDomains": [], "trustedAuthServers": []},
        # Threat intelligence: automatic lookups per type, cache period,
        # allowed providers (the API keys live in integration_keys).
        "enrichment": enrichment_defaults(),
    }
