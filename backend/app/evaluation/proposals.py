import argparse
import json
import re
from pathlib import Path

from app.enrichment.deterministic_enrichment import enrich_rule
from app.evaluation.golden_dataset import read_jsonl, write_jsonl
from app.evaluation.evidence import generate_evidence
from app.evaluation.schemas import (
    AnnotationProposal, GoldenRecord, ProposalRecord,
)
from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule
from app.parser.suricata_parser import SuricataRuleParser


def _metadata_values(rule: ParsedRule) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for item in rule.metadata:
        key, _, value = item.partition(" ")
        if value:
            values.setdefault(key.casefold(), []).append(value.strip())
    return values


def _clean_name(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("_", " ")).strip()


def _category(rule: ParsedRule, stratum: str) -> str:
    text = (rule.msg or "").casefold()
    if stratum == "SCAN":
        return "Reconnaissance"
    if stratum in {"MALWARE", "TROJAN"}:
        return "Command and Control" if re.search(r"\b(cnc|c2|command and control|checkin|beacon)\b", text) else "Malware"
    if stratum == "EXPLOIT":
        return "Exploitation"
    if stratum == "POLICY":
        return "Policy Violation"
    if stratum == "C2_CNC":
        return "Command and Control"
    if stratum == "REMOTE_ACCESS":
        return "Remote Access"
    if "phish" in text:
        return "Network Abuse"
    if stratum == "CREDENTIAL":
        return "Credential Access"
    if stratum == "DNS":
        return "Command and Control" if re.search(r"\b(cnc|c2|command and control)\b", text) else "Suspicious DNS"
    if stratum in {"WEB", "SUSPICIOUS_HTTP"}:
        if re.search(r"\b(exploit|injection|traversal|webshell|web shell|xss|sql injection|cve[- ]?\d|buffer overflow|path disclosure|backdoor)\b", text):
            return "Web Attack"
        if re.search(r"\b(malware|trojan|payload)\b", text):
            return "Malware"
        return "Network Abuse"
    if stratum == "TLS":
        return "Command and Control" if re.search(r"\b(cnc|c2|malware|trojan|command and control)\b", text) else "Network Abuse"
    if stratum == "SMB":
        return "Exploitation" if "exploit" in text else "Network Abuse"
    if re.search(r"\bet\s+exploit\b", text):
        return "Exploitation"
    if re.search(r"\bet\s+(malware|trojan)\b", text):
        return "Malware"
    if re.search(r"\bet\s+policy\b", text):
        return "Policy Violation"
    return "Other" if stratum == "INFO" else "Network Abuse"


def _subcategory(rule: ParsedRule, category: str) -> str | None:
    text = (rule.msg or "").casefold()
    protocol = rule.protocol.casefold()
    if category == "Reconnaissance":
        if re.search(r"\b(ping|icmp|host discovery)\b", text):
            return "Host Discovery"
        if "mssql" in text or "service scan" in text or "service" in text:
            return "Service Scan"
        if "port scan" in text or re.search(r"\bports?\b", text):
            return "Port Scan"
        return "Service Scan"
    if category == "Command and Control":
        return {"dns": "DNS C2 Communication", "http": "HTTP C2 Communication", "tls": "TLS C2 Communication"}.get(protocol, "C2 Communication")
    if category == "Remote Access":
        return "Remote Administration Tool"
    if category == "Credential Access":
        return "Credential Dumping" if re.search(r"dump|mimikatz", text) else "Credential Activity"
    if category == "Exploitation":
        return "Web Exploit Attempt" if protocol in {"http", "http2"} else "Exploit Attempt"
    if category == "Web Attack":
        for pattern, name in ((r"sql injection|union select", "SQL Injection"), (r"xss|cross.site scripting", "Cross-Site Scripting"), (r"path traversal|\.\./", "Path Traversal"), (r"command injection", "Command Injection"), (r"web.?shell", "Web Shell")):
            if re.search(pattern, text):
                return name
        return "Web Exploit Attempt"
    if category == "Suspicious DNS":
        if "dga" in text:
            return "DGA-like Domain"
        if "domain" in text or "dns" in text:
            return "Malicious Domain"
        return "Unusual DNS Query"
    if category == "Malware":
        if re.search(r"download|payload", text):
            return "Malware Download"
        if re.search(r"beacon|checkin", text):
            return "Malware Beacon"
        return "Malware Network Activity"
    if category == "Policy Violation":
        return "Prohibited Application or Protocol"
    if category == "Network Abuse":
        if "phish" in text:
            return "Phishing Infrastructure"
        return f"Suspicious {protocol.upper()} Activity" if protocol else "Suspicious Network Activity"
    return "Informational Activity" if category == "Other" else None


def _behavior(rule: ParsedRule, category: str, subcategory: str | None) -> str:
    if category == "Reconnaissance":
        return {"Host Discovery": "Network host discovery", "Port Scan": "Network port scanning"}.get(subcategory, "Network service scanning")
    if category == "Command and Control":
        return f"{rule.protocol.upper()} command-and-control communication"
    if category == "Remote Access":
        return "Remote access software communication"
    if category == "Credential Access":
        return "Credential access-related network activity"
    if category == "Exploitation":
        return "Exploit attempt against a network-accessible service"
    if category == "Web Attack":
        return f"Web attack attempt: {subcategory or 'suspicious web request'}"
    if category == "Suspicious DNS":
        return "DNS lookup for suspicious infrastructure"
    if category == "Malware":
        return "Malware-related network activity"
    if category == "Policy Violation":
        return "Policy-violating application or protocol use"
    if category == "Network Abuse":
        return subcategory or "Suspicious network activity"
    return "Informational network activity"


def _entity(rule: ParsedRule, category: str) -> tuple[str | None, str | None, str]:
    hints = enrich_rule(rule)
    if hints.entity_hint:
        entity_type = "Attack Tool" if hints.entity_hint in {"Nmap", "Cobalt Strike", "Metasploit", "Mimikatz"} else "Software"
        if hints.entity_hint in {"AnyDesk", "TeamViewer"}:
            entity_type = "Remote Access Tool"
        return hints.entity_hint, entity_type, "the name appears directly in the rule message/content"
    metadata = _metadata_values(rule)
    known = re.search(r"\b(predator|shelltea|realrat|brunhilda|raspberry robin|lumma stealer|sloppylemming|mmrat|weevely|screenconnect)\b", " ".join([rule.msg or "", *rule.contents]), re.I)
    if known:
        value = known.group(1)
        return value.title() if value.casefold() != "mmrat" else "MMRAT", "Malware" if value.casefold() != "screenconnect" else "Software", "the named malware or product appears directly in rule evidence"
    malware = metadata.get("malware_family", [])
    if malware:
        value = _clean_name(malware[0])
        if value.casefold() not in {"unknown", "generic", "n/a"}:
            return value, "Malware", "ET metadata explicitly supplies malware_family"
    if category in {"Exploitation", "Web Attack"}:
        products = metadata.get("affected_product", [])
        if products:
            value = _clean_name(products[0])
            if value and value.casefold() not in {"linux", "android", "windows", "windows xp vista", "web server applications", "unknown"}:
                return value, "Product", "ET metadata explicitly supplies affected_product"
    return None, None, "no specific tool, product, or malware identity is directly supported"


def _mitre(rule: ParsedRule, category: str, subcategory: str | None, repository: MitreRepository) -> tuple[dict, str, bool]:
    metadata = _metadata_values(rule)
    candidates = metadata.get("mitre_technique_id", [])
    technique = repository.get(candidates[0]) if candidates else None
    source = "ET metadata"
    if technique is None:
        text = (rule.msg or "").casefold()
        heuristic_id = None
        if category == "Reconnaissance" and subcategory in {"Port Scan", "Service Scan"}:
            heuristic_id = "T1046"
        elif category == "Remote Access" and re.search(r"anydesk|teamviewer|remote access|remote admin", text):
            heuristic_id = "T1219"
        elif category in {"Exploitation", "Web Attack"} and rule.protocol.casefold() in {"http", "http2"} and "exploit" in text:
            heuristic_id = "T1190"
        elif category == "Command and Control" and rule.protocol.casefold() == "dns":
            heuristic_id = "T1071.004"
        elif category == "Command and Control" and rule.protocol.casefold() == "http":
            heuristic_id = "T1071.001"
        elif category == "Credential Access" and re.search(r"credential dump|mimikatz", text):
            heuristic_id = "T1003"
        elif "powershell" in text:
            heuristic_id = "T1059.001"
        elif re.search(r"\brdp\b|remote desktop", text):
            heuristic_id = "T1021.001"
        technique = repository.get(heuristic_id) if heuristic_id else None
        source = "direct rule behavior" if technique else "none"
    if not technique:
        return {"mitre_tactic": None, "mitre_technique": None, "mitre_technique_id": None}, "no defensible local MITRE candidate was found", False
    return {
        "mitre_tactic": technique.tactics[0] if technique.tactics else None,
        "mitre_technique": technique.name,
        "mitre_technique_id": technique.technique_id,
    }, f"{source} supports canonical {technique.technique_id} {technique.name}", source == "ET metadata"


def _kill_chain(category: str, subcategory: str | None) -> str | None:
    if category == "Reconnaissance":
        return "Reconnaissance"
    if category in {"Exploitation", "Web Attack"}:
        return "Exploitation"
    if category in {"Command and Control", "Remote Access"}:
        return "Command and Control"
    if category == "Malware" and subcategory == "Malware Download":
        return "Delivery"
    if category == "Network Abuse" and subcategory == "Phishing Infrastructure":
        return "Delivery"
    return None


def propose(rule: ParsedRule, stratum: str, repository: MitreRepository) -> AnnotationProposal:
    category = _category(rule, stratum)
    subcategory = _subcategory(rule, category)
    entity, entity_type, entity_reason = _entity(rule, category)
    mitre, mitre_reason, metadata_mitre = _mitre(rule, category, subcategory, repository)
    kill_chain = _kill_chain(category, subcategory)
    confidence = 0.62
    if stratum not in {"OTHER", "GENERIC_TCP", "GENERIC_UDP", "INFO"}:
        confidence += 0.10
    if entity:
        confidence += 0.07
    if mitre["mitre_technique_id"]:
        confidence += 0.08 if metadata_mitre else 0.04
    if rule.classtype:
        confidence += 0.03
    confidence = min(0.96, confidence)
    evidence = f'msg="{(rule.msg or "")[:180]}", protocol={rule.protocol}, ports=src:{rule.source_port or "any"}->dst:{rule.destination_port or "any"}, content={len(rule.contents)}, pcre={len(rule.pcre)}, app_layer={len(rule.app_layer)}, classtype={rule.classtype or "null"}'
    notes = (
        f"Evidence used: {evidence}. Entity is "
        f"{entity or 'left null'} because {entity_reason}. MITRE: {mitre_reason}. "
        "This is an AI-assisted proposal and requires human confirmation."
    )
    return AnnotationProposal(
        detected_behavior=_behavior(rule, category, subcategory),
        detected_entity=entity,
        entity_type=entity_type,
        category=category,
        subcategory=subcategory,
        **mitre,
        cyber_kill_chain_phase=kill_chain,
        proposal_confidence=round(confidence, 2),
        notes=notes,
    )


def proposal_summary(records: list[ProposalRecord]) -> dict:
    proposals = [record.proposal for record in records]
    return {
        "status": "AI_PROPOSED",
        "total_proposals": len(proposals),
        "high_confidence_proposals": sum(item.proposal_confidence >= 0.90 for item in proposals),
        "medium_confidence_proposals": sum(0.70 <= item.proposal_confidence < 0.90 for item in proposals),
        "low_confidence_proposals": sum(item.proposal_confidence < 0.70 for item in proposals),
        "proposals_with_mitre_mapping": sum(item.mitre_technique_id is not None for item in proposals),
        "proposals_with_null_mitre": sum(item.mitre_technique_id is None for item in proposals),
        "proposals_with_entity": sum(item.detected_entity is not None for item in proposals),
        "proposals_with_null_entity": sum(item.detected_entity is None for item in proposals),
    }


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    cli = argparse.ArgumentParser(description="Generate conservative, non-ground-truth annotation proposals.")
    cli.add_argument("--golden", type=Path, default=root / "data" / "evaluation" / "golden_dataset.jsonl")
    cli.add_argument("--output", type=Path, default=root / "data" / "evaluation" / "annotation_proposals.jsonl")
    cli.add_argument("--summary", type=Path, default=root / "data" / "evaluation" / "proposal_summary.json")
    args = cli.parse_args()
    golden = read_jsonl(args.golden, GoldenRecord)
    parser, repository = SuricataRuleParser(), MitreRepository()
    proposals: list[ProposalRecord] = []
    for record in golden:
        parsed = parser.parse(record.raw_rule)
        record.proposal = propose(parsed, record.stratum, repository)
        record.evidence = generate_evidence(parsed, record.proposal, enrich_rule(parsed))
        # Safety invariant: proposal generation never changes expected or human status.
        proposals.append(ProposalRecord(sid=record.sid, rev=record.rev, msg=record.msg, source_file=record.source_file, proposal=record.proposal))
    write_jsonl(args.golden, golden)
    write_jsonl(args.output, proposals)
    summary = proposal_summary(proposals)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown = args.summary.with_suffix(".md")
    markdown.write_text("# Annotation Proposal Summary\n\n" + "\n".join(f"- {key.replace('_', ' ').title()}: {value}" for key, value in summary.items()), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
