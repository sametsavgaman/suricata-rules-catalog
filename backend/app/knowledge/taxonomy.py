from enum import StrEnum


class Category(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    DISCOVERY = "Discovery"
    MALWARE = "Malware"
    COMMAND_AND_CONTROL = "Command and Control"
    EXPLOITATION = "Exploitation"
    CREDENTIAL_ACCESS = "Credential Access"
    LATERAL_MOVEMENT = "Lateral Movement"
    REMOTE_ACCESS = "Remote Access"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"
    WEB_ATTACK = "Web Attack"
    DENIAL_OF_SERVICE = "Denial of Service"
    SUSPICIOUS_DNS = "Suspicious DNS"
    POLICY_VIOLATION = "Policy Violation"
    NETWORK_ABUSE = "Network Abuse"
    OTHER = "Other"


SUBCATEGORIES: dict[Category, tuple[str, ...]] = {
    Category.RECONNAISSANCE: ("Port Scan", "Service Scan", "Vulnerability Scan", "Web Scan", "Host Discovery", "OS Fingerprinting"),
    Category.REMOTE_ACCESS: ("Remote Desktop", "Remote Access Software"),
    Category.MALWARE: ("Malware Network Activity", "Malware Download", "Malware Beacon", "Payload Delivery", "Exploit Kit"),
    Category.COMMAND_AND_CONTROL: ("C2 Communication", "HTTP C2 Communication", "DNS C2 Communication", "TLS C2 Communication"),
    Category.CREDENTIAL_ACCESS: ("Credential Activity", "Credential Dumping", "Brute Force"),
    Category.EXPLOITATION: ("Exploit Attempt", "Remote Code Execution", "Command Injection", "Buffer Overflow"),
    Category.WEB_ATTACK: ("SQL Injection", "Cross-Site Scripting", "Path Traversal", "Command Injection", "Web Shell"),
    Category.SUSPICIOUS_DNS: ("DNS Tunneling", "DGA-like Domain", "Malicious Domain", "Unusual DNS Query"),
    Category.POLICY_VIOLATION: ("Prohibited Application or Protocol", "Unauthorized Data Transfer"),
    Category.NETWORK_ABUSE: ("Phishing Infrastructure", "Suspicious HTTP Activity", "Suspicious TLS Activity", "Suspicious TCP Activity", "Suspicious SMTP Activity", "Suspicious IP Activity"),
    Category.OTHER: ("Informational Activity",),
}

SUBCATEGORY_ALIASES = {
    "Remote Administration Tool": "Remote Access Software", "Remote Administration Software": "Remote Access Software",
    "RMM": "Remote Access Software", "HTTP C2": "HTTP C2 Communication", "DNS C2": "DNS C2 Communication",
    "DNS": "DNS C2 Communication", "Web Communications": "HTTP C2 Communication", "CnC Activity": "C2 Communication",
    "Scanning": "Web Scan", "Scanner": "Web Scan", "Browser Exploit": "Web Exploit Attempt",
    "WebShell": "Web Shell", "Web Backdoor": "Web Shell", "Phishing": "Phishing Infrastructure",
    "OS Credential Dumping": "Credential Dumping", "Network Service Discovery": "Service Scan",
}

def canonical_subcategory(category: Category | str | None, value: str | None) -> str | None:
    if not category or not value: return None
    try: cat=Category(category)
    except ValueError: return None
    candidate=SUBCATEGORY_ALIASES.get(value,value)
    return candidate if candidate in SUBCATEGORIES.get(cat,()) else None
