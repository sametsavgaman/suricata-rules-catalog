"""Deterministic MITRE decision layer for the Qwen V2.2 path.

The local ATT&CK repository is authoritative.  The LLM may select an ID from
the bounded candidate list, but it never supplies the canonical name or tactic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule
from app.v2.tools import KEYWORDS, source_mitre_mapping

TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
STOP = {"the", "and", "with", "from", "rule", "alert", "traffic", "possible", "observed"}


@dataclass(frozen=True)
class MitreDecision:
    technique_id: str | None
    technique_name: str | None
    tactic: str | None
    method: str
    reason: str
    evidence: list[dict]
    retrieval_score: float | None


def _rule_text(rule: ParsedRule) -> str:
    app = " ".join(str(x) for x in rule.app_layer)
    return " ".join([rule.msg or "", rule.classtype or "", rule.protocol, app,
                      *rule.metadata, *rule.references, *rule.contents, *rule.pcre]).casefold()


def retrieve_candidates(rule: ParsedRule, repository: MitreRepository, limit: int = 8) -> list[dict]:
    """Retrieve candidates using exact metadata, known mappings and local descriptions."""
    text = _rule_text(rule)
    tokens = set(TOKEN_RE.findall(text)) - STOP
    scores: dict[str, float] = {}
    evidence: dict[str, list[dict]] = {}
    source = source_mitre_mapping(rule, repository)
    if source:
        tid = source["technique_id"]
        scores[tid] = 1.0
        evidence.setdefault(tid, []).append({"type": "SOURCE_METADATA", "value": tid})
    for phrase, ids in KEYWORDS.items():
        if phrase in text:
            for tid in ids:
                scores[tid] = max(scores.get(tid, 0.0), 0.72)
                evidence.setdefault(tid, []).append({"type": "BEHAVIOR_KEYWORD", "value": phrase})
    # Match rule vocabulary against canonical technique names/descriptions.
    for technique in repository.all():
        name_tokens = set(TOKEN_RE.findall(technique.name.casefold())) - STOP
        desc_tokens = set(TOKEN_RE.findall(technique.description.casefold())) - STOP
        overlap = len(tokens & name_tokens)
        if overlap:
            score = min(0.68, 0.28 + 0.12 * overlap)
            if score > scores.get(technique.technique_id, 0.0):
                scores[technique.technique_id] = score
            evidence.setdefault(technique.technique_id, []).append({"type": "LOCAL_NAME_MATCH", "value": technique.name})
        # Description matches are deliberately weaker than names/metadata.
        d_overlap = len(tokens & desc_tokens)
        if d_overlap >= 2 and technique.technique_id not in scores:
            scores[technique.technique_id] = min(0.45, 0.18 + 0.05 * d_overlap)
            evidence.setdefault(technique.technique_id, []).append({"type": "LOCAL_DESCRIPTION_MATCH", "value": d_overlap})
    result = []
    for tid, score in sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]:
        technique = repository.get(tid)
        if not technique:
            continue
        result.append({"id": technique.technique_id, "name": technique.name,
                       "tactics": list(technique.tactics), "score": round(min(score, .99), 3),
                       "evidence": evidence.get(tid, [])[:4], "source": "LOCAL_MITRE_REPOSITORY"})
    return result


def resolve_selected(selected_id: str | None, candidates: list[dict], rule: ParsedRule,
                     repository: MitreRepository) -> MitreDecision:
    """Resolve an LLM-selected ID into an atomic canonical tuple."""
    source = source_mitre_mapping(rule, repository)
    source_id = source.get("technique_id") if source else None
    tid = selected_id.upper() if selected_id else None
    candidate = next((x for x in candidates if x.get("id") == tid), None)
    technique = repository.get(tid) if candidate else None
    evidence = list(candidate.get("evidence", [])) if candidate else []
    if not technique:
        method = "NO_SUPPORTED_MAPPING"
        reason = "Selected MITRE ID was absent, non-canonical, or outside the candidate allowlist."
        return MitreDecision(None, None, None, method, reason, evidence, None)
    if source_id and source_id == technique.technique_id:
        method = "EXACT_SOURCE_MAPPING"; reason = "Selected ID exactly matches Suricata MITRE metadata."
    elif source_id and technique.parent_id == source_id:
        method = "DERIVED_SUBTECHNIQUE"; reason = f"Selected ID is a canonical child of source technique {source_id}."
    elif source_id:
        method = "SOURCE_MAPPING_OVERRIDDEN"; reason = f"Selected ID differs from source metadata {source_id}; review is recommended."
    else:
        method = "INFERRED_MAPPING"; reason = "Selected ID was inferred from rule evidence and local MITRE retrieval."
    return MitreDecision(technique.technique_id, technique.name, technique.tactics[0] if technique.tactics else None,
                         method, reason, evidence, float(candidate.get("score", 0.0)))

