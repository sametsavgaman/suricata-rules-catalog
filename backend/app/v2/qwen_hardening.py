"""Qwen-only semantic hardening helpers.

This module is deliberately not imported by the Gemini provider or its prompt
path.  It turns deterministic parser output into a compact contract for the
8B local model and canonicalizes the model proposal before the shared V2
finalizer is reached.
"""
from __future__ import annotations

import re
from typing import Any

from app.agent.schemas import ClassificationOutput
from app.knowledge.mitre_repository import MitreRepository
from app.knowledge.taxonomy import Category, SUBCATEGORIES, canonical_subcategory
from app.parser.models import ParsedRule
from app.v2.mitre_decision import resolve_selected

QWEN_INPUT_VERSION = "qwen_semantic_input_v2"

QWEN_SYSTEM_PROMPT = """You are a conservative Suricata detection catalog classifier (Qwen V2.2).
Return ONLY the requested structured JSON object; never output reasoning or thinking.
Use evidence before labels and prefer null over unsupported claims.
- Choose category and subcategory only from the supplied controlled taxonomy; the subcategory must belong to the chosen category.
- MITRE is atomic: choose only one supplied canonical technique ID or set all MITRE fields to null. Never place category/subcategory text in ATT&CK fields.
- Preserve protocol, buffer, method, CVE, mechanism and uncertainty words such as possible, likely, reported and associated with.
- A DNS query for a malicious domain is normally DNS lookup/IOC association, not DNS C2, unless DNS is explicitly used as the C2 channel.
- IOC association is not a direct malware/tool fingerprint. Assign an entity only when the supplied evidence candidate is strong.
- Do not infer a Kill Chain phase when evidence is insufficient. Keep behavior concise and specific.
"""


def qwen_entity_candidates(rule: ParsedRule, candidates: list[dict]) -> list[dict]:
    """Mark feed/domain/IP associations without changing the shared candidate generator."""
    text = (rule.msg or "").casefold()
    association = any(x in text for x in ("c2 ip", "c&c ip", "threatview", "listed ip", "associated domain"))
    if not association:
        return candidates
    result = []
    for item in candidates:
        copy = dict(item)
        if copy.get("evidence_type") in {"EXPLICIT_RULE_NAME", "NAMED_ET_TAG"}:
            copy["evidence_type"] = "IOC_ASSOCIATION"
            copy["weak"] = False
        result.append(copy)
    return result


def observation_type(rule: ParsedRule) -> str:
    """Derive a reliable observation label from parsed selectors/evidence."""
    text = " ".join([str(rule.msg or ""), *(str(x) for x in rule.contents),
                      *(str(x) for x in rule.pcre), *(str(x) for x in rule.app_layer)]).casefold()
    app = " ".join(str(x.get("buffer") or x.get("protocol") or "") for x in rule.app_layer).casefold()
    if "dns.query" in app or rule.protocol.casefold() == "dns":
        return "DNS_QUERY_MATCH"
    for needle, value in (("http.host", "HTTP_HOST_MATCH"), ("http.uri", "HTTP_URI_MATCH"),
                          ("http.user_agent", "HTTP_USER_AGENT_MATCH"),
                          ("http.request_body", "HTTP_REQUEST_BODY_MATCH"),
                          ("http.response_body", "HTTP_RESPONSE_BODY_MATCH"),
                          ("tls.sni", "TLS_SNI_MATCH"), ("tls.cert", "TLS_CERTIFICATE_MATCH")):
        if needle in app or needle in text:
            return value
    if "cve-" in text:
        return "CVE_EXPLOIT_PATTERN"
    if any(x in text for x in ("cobalt strike", "sliver", "threatview", "malicious ip", "listed ip")):
        return "IP_REPUTATION_MATCH"
    if rule.destination_port and ("scan" in text or "enumerat" in text):
        return "PORT_SCAN_PATTERN"
    if rule.contents or rule.pcre:
        return "PAYLOAD_CONTENT_MATCH"
    return "UNKNOWN"


def build_semantic_context(rule: ParsedRule, *, hints: Any, entity_candidates: list[dict],
                           mitre_candidates: list[dict], cves: list[dict], similar_rules: list[dict],
                           controlled_subcategories: dict[str, list[str]]) -> dict:
    app = rule.app_layer[0] if rule.app_layer else {}
    return {
        "rule_identity": {"sid": rule.sid, "rev": rule.rev, "source": rule.source},
        "observable": {"network_protocol": rule.protocol, "app_layer_protocol": app.get("protocol"),
                        "buffer": app.get("buffer"), "observation_type": observation_type(rule),
                        "direction": rule.direction},
        "rule_evidence": {"msg": rule.msg, "classtype": rule.classtype,
                          "contents": rule.contents[:12], "pcre": rule.pcre[:6],
                          "metadata": rule.metadata[:20], "references": rule.references[:12], "cves": cves},
        "entity_candidates": entity_candidates[:12],
        "category_candidates": list(Category),
        "subcategory_candidates": controlled_subcategories,
        "source_mitre": next((x for x in rule.metadata if x.casefold().startswith("mitre_technique_id ")), None),
        "mitre_candidates": mitre_candidates[:8],
        "similar_audited_rules": similar_rules[:3],
        "input_version": QWEN_INPUT_VERSION,
    }


def _protocol_contradiction(rule: ParsedRule, subcategory: str | None) -> bool:
    if not subcategory:
        return False
    app = " ".join(str(x.get("buffer") or x.get("protocol") or "") for x in rule.app_layer).casefold()
    if "http.host" in app or "http.uri" in app or "http.user_agent" in app:
        return subcategory == "Unusual DNS Query"
    if "tls.sni" in app:
        return subcategory == "Unusual DNS Query"
    return False


def canonicalize(output: ClassificationOutput, *, rule: ParsedRule,
                 mitre_candidates: list[dict], repository: MitreRepository) -> tuple[ClassificationOutput, list[str]]:
    """Apply Qwen-only deterministic gates; never invent a replacement label."""
    data = output.model_dump()
    reasons: list[str] = []
    sub = canonical_subcategory(output.category, output.subcategory)
    if _protocol_contradiction(rule, sub):
        sub = None
        reasons.append("protocol_subcategory_contradiction")
    data["subcategory"] = sub

    # MITRE ID is the sole creative choice. Resolve the rest from local ATT&CK.
    decision = resolve_selected(output.mitre_technique_id, mitre_candidates, rule, repository)
    if decision.technique_id is None:
        if any((output.mitre_tactic, output.mitre_technique, output.mitre_technique_id)):
            reasons.append("mitre_atomicity_rejected")
        data.update(mitre_tactic=None, mitre_technique=None, mitre_technique_id=None)
    else:
        data.update(mitre_technique_id=decision.technique_id, mitre_technique=decision.technique_name,
                    mitre_tactic=decision.tactic)

    # Keep uncertainty and mechanism visible when the model emits a bare taxonomy label.
    behavior = data.get("detected_behavior") or ""
    if behavior.casefold().strip() in {"web attack", "network activity", "suspicious activity", "informational activity", "command and control"}:
        mechanism = observation_type(rule).replace("_MATCH", "").replace("_", " ").title()
        if mechanism != "Unknown":
            data["detected_behavior"] = f"{mechanism} observed in rule evidence"
            reasons.append("generic_behavior_specificized")
    return ClassificationOutput.model_validate(data), reasons
