"""Explicit best-effort MITRE selection for an otherwise unmapped result."""
from __future__ import annotations

import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.helper_model import HelperProvider, generate_structured
from app.v2.mitre_decision import retrieve_candidates


TechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]


class ForcedMitreProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    technique_id: TechniqueId
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1, max_length=600)
    evidence: list[str] = Field(min_length=1, max_length=5)


INSTRUCTION = """You are performing an explicitly user-forced, best-effort MITRE ATT&CK mapping for a Suricata rule.
The normal classifier abstained. Select exactly one canonical MITRE ATT&CK Enterprise technique using only RULE_EVIDENCE.
LOCAL_CANDIDATES are suggestions, not a closed list: you may choose another canonical technique when the evidence supports it.
Never invent an ID. Confidence is uncertainty-aware, not a guarantee. Evidence must cite short facts present in
RULE_EVIDENCE or LOCAL_CANDIDATES. Return only schema-valid JSON.
"""


def forced_context(rule, classification, candidates: list[dict]) -> dict:
    return {
        "rule_evidence": {
            "sid": rule.sid,
            "message": rule.msg,
            "protocol": rule.protocol,
            "classtype": rule.classtype,
            "metadata": list(rule.rule_metadata or [])[:30],
            "references": list(rule.references or [])[:20],
            "flow": list(rule.flow or [])[:20],
            "flowbits": list(rule.flowbits or [])[:20],
            "contents": [str(item)[:500] for item in (rule.contents or [])[:20]],
            "pcre": [str(item)[:500] for item in (rule.pcre or [])[:10]],
            "app_layer": list(rule.app_layer or [])[:20],
            "normal_classification": {
                "detected_behavior": classification.detected_behavior,
                "detected_entity": classification.detected_entity,
                "entity_type": classification.entity_type,
                "category": classification.category,
                "subcategory": classification.subcategory,
                "evidence": list(classification.evidence or [])[:10],
                "explanation": (classification.explanation or "")[:1200],
            },
        },
        "local_candidates": candidates,
    }


async def propose_forced_mitre(
    rule,
    classification,
    settings,
    provider: HelperProvider | None = None,
):
    parsed = SuricataRuleParser().parse(rule.raw_rule)
    repository = MitreRepository()
    candidates = retrieve_candidates(parsed, repository, limit=12)
    payload = json.dumps(forced_context(rule, classification, candidates), ensure_ascii=False)
    proposal, used_provider, model = await generate_structured(
        settings,
        instruction=INSTRUCTION,
        payload=payload,
        schema=ForcedMitreProposal,
        max_output_tokens=900,
        timeout_seconds=35,
        provider=provider,
    )
    technique_id = proposal.technique_id.upper()
    technique = repository.get(technique_id)
    if technique is None:
        raise ValueError("The helper model selected an ID that is not present in the local ATT&CK repository.")
    selected = next((candidate for candidate in candidates if candidate["id"] == technique_id), None)
    return proposal, technique, candidates, selected, used_provider, model
