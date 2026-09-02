from dataclasses import dataclass
import re

from app.parser.models import ParsedRule


ENTITY_PATTERNS = {
    "Nmap": re.compile(r"\bnmap\b", re.I),
    "AnyDesk": re.compile(r"\banydesk\b", re.I),
    "TeamViewer": re.compile(r"\bteamviewer\b", re.I),
    "Cobalt Strike": re.compile(r"\bcobalt\s*strike\b", re.I),
    "Metasploit": re.compile(r"\bmetasploit\b", re.I),
    "Mimikatz": re.compile(r"\bmimikatz\b", re.I),
    "PowerShell": re.compile(r"\bpowershell\b", re.I),
}

CATEGORY_PREFIXES = {
    "SCAN": "Reconnaissance",
    "MALWARE": "Malware",
    "TROJAN": "Malware",
    "EXPLOIT": "Exploitation",
    "POLICY": "Policy Violation",
    "WEB_SERVER": "Web Attack",
    "WEB_CLIENT": "Web Attack",
    "DNS": "Suspicious DNS",
    "DOS": "Denial of Service",
    "CNC": "Command and Control",
}


@dataclass(frozen=True)
class EnrichmentHints:
    entity_hint: str | None = None
    category_hint: str | None = None
    hint_evidence: tuple[str, ...] = ()


def enrich_rule(rule: ParsedRule) -> EnrichmentHints:
    searchable = " ".join([rule.msg or "", *rule.contents])
    entity = next((name for name, pattern in ENTITY_PATTERNS.items() if pattern.search(searchable)), None)
    prefix_match = re.match(r"^ET\s+([A-Z_]+)\b", rule.msg or "", re.I)
    prefix = prefix_match.group(1).upper() if prefix_match else None
    category = CATEGORY_PREFIXES.get(prefix or "")
    evidence: list[str] = []
    if entity:
        evidence.append(f'{entity} appears directly in the rule message or content')
    if category and prefix:
        evidence.append(f"ET {prefix} prefix suggests {category}")
    return EnrichmentHints(entity, category, tuple(evidence))

