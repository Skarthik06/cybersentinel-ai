"""
Threat intelligence source definitions.
Each source has a URL, fetch interval, and parser type.
Add new sources here without touching the scraper logic.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatSource:
    name: str
    url: str
    interval_hours: float
    parser: str          # maps to a parser function in parsers.py
    requires_api_key: bool = False
    api_key_env: Optional[str] = None
    description: str = ""


SOURCES = [
    ThreatSource(
        name="NVD_CVE",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        interval_hours=4,
        parser="nvd_cve",
        requires_api_key=False,
        description="NIST National Vulnerability Database — critical CVEs (CVSS ≥ 9.0)",
    ),
    ThreatSource(
        name="CISA_KEV",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        interval_hours=6,
        parser="cisa_kev",
        requires_api_key=False,
        description="CISA Known Exploited Vulnerabilities — actively exploited in the wild",
    ),
    ThreatSource(
        name="ABUSEIPDB_BLOCKLIST",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        interval_hours=1,
        parser="abuse_ch",
        requires_api_key=False,
        description="Abuse.ch Feodo Tracker — confirmed C2 botnet IPs",
    ),
    ThreatSource(
        name="MITRE_ATTACK",
        url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        interval_hours=24,
        parser="mitre_attack",
        requires_api_key=False,
        description="MITRE ATT&CK Enterprise — full technique catalog",
    ),
    ThreatSource(
        name="ALIENVAULT_OTX",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        interval_hours=2,
        parser="otx_pulses",
        requires_api_key=True,
        api_key_env="OTX_API_KEY",
        description="AlienVault OTX — community threat intelligence pulses",
    ),
]
