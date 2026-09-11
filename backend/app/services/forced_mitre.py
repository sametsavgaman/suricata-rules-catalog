"""Explicit best-effort MITRE selection for an otherwise unmapped result."""
from __future__ import annotations

import asyncio
import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.v2.mitre_decision import retrieve_candidates


TechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]


class ForcedMitreProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    technique_id: TechniqueId
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1, max_length=600)
    evidence: list[str] = Field(min_length=1, max_length=5)


INSTRUCTION = """You are performing an explicitly user-forced, best-effort MITRE ATT&CK mapping for a Suricata rule.
The normal classifier abstained. Select exactly one technique_id from ALLOWED_CANDIDATES using only RULE_EVIDENCE.
Do not invent an ID and do not use outside IDs. Confidence is uncertainty-aware, not a guarantee.
Evidence must cite short facts present in RULE_EVIDENCE or the selected candidate evidence. Return only schema-valid JSON.
"""


def _clean_schema(value):
    if isinstance(value, dict):
        return {key: _clean_schema(item) for key, item in value.items() if key != "additionalProperties"}
    if isinstance(value, list):
        return [_clean_schema(item) for item in value]
    return value


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
        "allowed_candidates": candidates,
    }


async def propose_forced_mitre(rule, classification, settings, client=None):
    parsed = SuricataRuleParser().parse(rule.raw_rule)
    repository = MitreRepository()
    candidates = retrieve_candidates(parsed, repository, limit=12)
    if not candidates:
        raise ValueError("No defensible MITRE candidates were found in the local ATT&CK repository.")
    owns_client = client is None
    if client is None:
        if not settings.gemini_api_key or not settings.gemini_model:
            raise RuntimeError("Gemini API key and model must be configured in Model Lab.")
        from google import genai
        client = genai.Client(
            api_key=settings.gemini_api_key,
            http_options={"timeout": 25000, "retry_options": {"attempts": 1}},
        )
    try:
        payload = json.dumps(forced_context(rule, classification, candidates), ensure_ascii=False)
        async with asyncio.timeout(35):
            response = await client.aio.models.generate_content(
                model=settings.gemini_model,
                contents=payload,
                config={
                    "system_instruction": INSTRUCTION,
                    "temperature": 0,
                    "max_output_tokens": 900,
                    "response_mime_type": "application/json",
                    "response_schema": _clean_schema(ForcedMitreProposal.model_json_schema()),
                },
            )
        raw = getattr(response, "parsed", None)
        proposal = ForcedMitreProposal.model_validate(raw) if raw is not None else ForcedMitreProposal.model_validate_json(response.text or "")
        allowed = {candidate["id"]: candidate for candidate in candidates}
        selected = allowed.get(proposal.technique_id.upper())
        technique = repository.get(proposal.technique_id.upper()) if selected else None
        if technique is None:
            raise ValueError("Gemini selected a technique outside the server-approved candidate list.")
        return proposal, technique, candidates, selected
    finally:
        if owns_client:
            await client.aio.aclose()
            client.close()
