"""Evidence-first customer-scenario analysis.

Gemini extracts a small, validated plan.  The local catalogue remains the
source of truth for MITRE IDs, rule matches and coverage status.
"""
import asyncio
import json
from typing import Annotated, Literal

import httpx
from openai import AsyncOpenAI

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from sqlalchemy.orm import Session

from app.knowledge.mitre_repository import MitreRepository
from app.services.catalog_assistant import CatalogAnswer, CatalogItem, CatalogSearch, CatalogFilters, query_catalog

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=180)]
Protocol = Literal["tcp", "udp", "ip", "icmp", "http", "dns", "tls", "ftp", "smtp", "smb", "ssh", "rdp"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScenarioQuestion(StrictModel):
    question: str = Field(min_length=10, max_length=3000)
    provider: Literal["gemini", "claude", "openai"] = "gemini"


class ScenarioPlanStep(StrictModel):
    title: Text
    technique_id: Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")] | None = None
    keywords: list[Text] = Field(default_factory=list, max_length=5)
    protocols: list[Protocol] = Field(default_factory=list, max_length=3)
    rationale: str = Field(default="", max_length=360)
    confidence: float = Field(default=0.0, ge=0, le=1)


class ScenarioPlan(StrictModel):
    summary: str = Field(min_length=1, max_length=600)
    # Keep the evidence pass bounded. A long narrative does not become more
    # useful when it is split into many near-duplicate steps; each step also
    # triggers local catalogue work.
    steps: list[ScenarioPlanStep] = Field(min_length=1, max_length=6)
    assumptions: list[str] = Field(default_factory=list, max_length=8)


class ScenarioRule(CatalogItem):
    match_type: Literal["MITRE", "KEYWORD", "PROTOCOL"]
    step_index: int = Field(ge=1, le=10)
    why: str = Field(max_length=260)


class ScenarioStepResult(StrictModel):
    index: int = Field(ge=1, le=10)
    title: str
    technique_id: str | None = None
    technique_name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    status: Literal["COVERED", "PARTIAL", "GAP"]
    confidence: float = Field(ge=0, le=1)
    matched_rule_count: int = Field(ge=0)
    evidence: list[str] = Field(default_factory=list, max_length=5)
    rules: list[ScenarioRule] = Field(default_factory=list, max_length=12)


class ScenarioAnalysis(StrictModel):
    status: Literal["COVERED", "PARTIAL", "GAP"]
    summary: str
    steps: list[ScenarioStepResult]
    recommendations: list[ScenarioRule] = Field(default_factory=list, max_length=24)
    assumptions: list[str] = Field(default_factory=list)
    signals_extracted: int = Field(ge=0)
    planner_model: str
    provider: Literal["gemini", "claude", "openai"]
    source: Literal["PROVIDER_PLAN_LOCAL_EVIDENCE"] = "PROVIDER_PLAN_LOCAL_EVIDENCE"


SCENARIO_INSTRUCTION = """You are a cybersecurity detection analyst. Convert the customer scenario into ScenarioPlan JSON.
Return only JSON matching the schema. Decompose the narrative into 1-6 distinct observable attack steps.
Use a MITRE ATT&CK technique ID only when the behavior clearly supports it; otherwise use null.
Use short literal product/tool/behavior keywords that could occur in a Suricata rule message or classification.
Use only the protocol enum values from the schema. Do not claim that a rule detects an attack, do not invent SIDs,
coverage, alerts, false-positive rates or deployed-sensor facts. The server will verify all technique IDs and rules.
"""


def _clean_schema(value):
    if isinstance(value, dict):
        return {k: _clean_schema(v) for k, v in value.items() if k != "additionalProperties"}
    if isinstance(value, list):
        return [_clean_schema(v) for v in value]
    return value


def _normalize_plan(raw: str) -> ScenarioPlan:
    value = json.loads(raw or "{}")
    if isinstance(value, dict) and isinstance(value.get("steps"), list):
        value["steps"] = value["steps"][:6]
    for step in value.get("steps", []) if isinstance(value, dict) else []:
        if isinstance(step, dict):
            if isinstance(step.get("technique_id"), str):
                step["technique_id"] = step["technique_id"].upper()
            if isinstance(step.get("protocols"), list):
                step["protocols"] = [str(item).lower() for item in step["protocols"]]
    return ScenarioPlan.model_validate(value)


async def plan_scenario(question: str, settings, provider: Literal["gemini", "claude", "openai"] = "gemini") -> ScenarioPlan:
    payload = json.dumps({"scenario": question}, ensure_ascii=False)
    if provider == "gemini":
        from google import genai
        client = genai.Client(api_key=settings.gemini_api_key, http_options={"timeout": 25000, "retry_options": {"attempts": 1}})
        try:
            async with asyncio.timeout(35):
                response = await client.aio.models.generate_content(
                    model=settings.gemini_model, contents=payload,
                    config={"system_instruction": SCENARIO_INSTRUCTION, "temperature": 0, "max_output_tokens": 2200,
                            "response_mime_type": "application/json", "response_schema": _clean_schema(ScenarioPlan.model_json_schema())},
                )
            return _normalize_plan(response.text or "")
        finally:
            await client.aio.aclose(); client.close()
    if provider == "openai":
        client = AsyncOpenAI(api_key=settings.openai_api_key, base_url=settings.openai_base_url or None)
        try:
            async with asyncio.timeout(35):
                response = await client.responses.parse(model=settings.openai_model, instructions=SCENARIO_INSTRUCTION,
                    input=payload, text_format=ScenarioPlan, store=False)
            if response.output_parsed is None:
                raise ValueError("empty structured response")
            return ScenarioPlan.model_validate(response.output_parsed)
        finally:
            await client.close()
    base_url = settings.claude_base_url.rstrip("/")
    url = base_url if base_url.endswith("/messages") else f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"
    async with httpx.AsyncClient(timeout=35, trust_env=False) as client:
        response = await client.post(url, headers={"x-api-key": settings.claude_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": settings.claude_model, "max_tokens": 2200, "temperature": 0,
                  "system": SCENARIO_INSTRUCTION + " Return only JSON.", "messages": [{"role": "user", "content": payload}]})
        response.raise_for_status()
        data = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text").strip()
        if text.startswith("```"):
            text = text.removeprefix("```").removeprefix("json").removesuffix("```").strip()
        return _normalize_plan(text)


def _search(db: Session, filters: CatalogFilters, limit: int) -> CatalogAnswer:
    return query_catalog(db, CatalogSearch(filters=filters, limit=limit, offset=0), count_total=False)


def evaluate_scenario(db: Session, plan: ScenarioPlan, model_name: str, provider: Literal["gemini", "claude", "openai"] = "gemini") -> ScenarioAnalysis:
    repo = MitreRepository()
    step_results: list[ScenarioStepResult] = []
    recommended: dict[tuple[int, int], ScenarioRule] = {}
    signal_count = 0

    for index, step in enumerate(plan.steps, start=1):
        technique = repo.get(step.technique_id) if step.technique_id else None
        exact: dict[tuple[int, int], CatalogItem] = {}
        keyword: dict[tuple[int, int], CatalogItem] = {}
        protocol: dict[tuple[int, int], CatalogItem] = {}
        if technique:
            signal_count += 1
            answer = _search(db, CatalogFilters(mitre_technique_id=technique.technique_id), 12)
            exact.update({(item.sid, item.rev): item for item in answer.items})
        if not exact:
            for word in step.keywords[:5]:
                signal_count += 1
                answer = _search(db, CatalogFilters(search=word), 6)
                keyword.update({(item.sid, item.rev): item for item in answer.items})
        if not exact and not keyword and step.protocols:
            signal_count += 1
            for proto in step.protocols[:3]:
                answer = _search(db, CatalogFilters(protocol=proto), 6)
                protocol.update({(item.sid, item.rev): item for item in answer.items})

        # Exact MITRE evidence is authoritative for a step.  Broad keyword or
        # protocol matches are used only when an exact mapping is unavailable;
        # otherwise generic terms (for example "lateral-movement") can pollute
        # the recommendation list with unrelated signatures.
        merged: dict[tuple[int, int], tuple[CatalogItem, str]] = {}
        if exact:
            merged.update({key: (item, "MITRE") for key, item in exact.items()})
        elif keyword:
            merged.update({key: (item, "KEYWORD") for key, item in keyword.items()})
        else:
            merged.update({key: (item, "PROTOCOL") for key, item in protocol.items()})

        if exact:
            status: Literal["COVERED", "PARTIAL", "GAP"] = "COVERED"
        elif merged:
            status = "PARTIAL"
        else:
            status = "GAP"
        evidence = []
        if exact:
            evidence.append(f"{len(exact)} rule(s) have an exact local MITRE mapping.")
        if keyword and not exact:
            evidence.append(f"{len(keyword)} rule(s) matched the extracted behavior keywords.")
        elif keyword and exact:
            evidence.append(f"{len(keyword)} secondary keyword match(es) were not promoted over exact MITRE evidence.")
        if protocol and not keyword and not exact:
            evidence.append(f"{len(protocol)} rule(s) matched the extracted protocol.")
        if not evidence:
            evidence.append("No matching local catalogue evidence was found.")

        rules: list[ScenarioRule] = []
        for item, match_type in list(merged.values())[:12]:
            rule = ScenarioRule(
                **item.model_dump(),
                match_type=match_type,
                step_index=index,
                why=("Exact MITRE mapping in the local catalogue." if match_type == "MITRE" else
                     "Matched an analyst signal extracted from the scenario." if match_type == "KEYWORD" else
                     "Matched the protocol extracted from the scenario."),
            )
            rules.append(rule)
            existing = recommended.get((rule.sid, rule.rev))
            if existing is None or (existing.match_type != "MITRE" and match_type == "MITRE"):
                recommended[(rule.sid, rule.rev)] = rule
        step_results.append(ScenarioStepResult(
            index=index,
            title=step.title,
            technique_id=technique.technique_id if technique else None,
            technique_name=technique.name if technique else None,
            tactics=list(technique.tactics) if technique else [],
            keywords=list(step.keywords),
            status=status,
            confidence=step.confidence,
            matched_rule_count=len(merged),
            evidence=evidence[:5],
            rules=rules,
        ))

    statuses = {step.status for step in step_results}
    overall: Literal["COVERED", "PARTIAL", "GAP"] = "COVERED" if statuses == {"COVERED"} else "GAP" if statuses == {"GAP"} else "PARTIAL"
    return ScenarioAnalysis(
        status=overall,
        summary=plan.summary,
        steps=step_results,
        recommendations=list(recommended.values())[:24],
        assumptions=list(plan.assumptions),
        signals_extracted=signal_count,
        planner_model=model_name,
        provider=provider,
    )
