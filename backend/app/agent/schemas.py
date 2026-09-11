from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.knowledge.kill_chain import KillChainPhase
from app.knowledge.taxonomy import Category


class EntityType(StrEnum):
    ATTACK_TOOL = "Attack Tool"
    MALWARE = "Malware"
    REMOTE_ACCESS_TOOL = "Remote Access Tool"
    PRODUCT = "Product"
    SOFTWARE = "Software"
    PROTOCOL = "Protocol"
    OTHER = "Other"
    UNKNOWN = "Unknown"


class ClassificationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_behavior: str | None
    detected_entity: str | None
    entity_type: EntityType | None
    category: Category | None
    subcategory: str | None
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_technique_id: str | None
    cyber_kill_chain_phase: KillChainPhase | None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(max_length=10)
    explanation: str = Field(max_length=800)


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class ProviderResult(BaseModel):
    output: ClassificationOutput
    usage: TokenUsage = Field(default_factory=TokenUsage)


class ClassificationContext(BaseModel):
    sid: int
    msg: str | None
    protocol: str
    classtype: str | None
    metadata: list[str]
    references: list[str]
    flow: list[str]
    flowbits: list[str]
    content: list[str]
    pcre: list[str]
    app_layer: list[dict[str, str | None]]
    entity_hint: str | None
    category_hint: str | None
    mitre_candidates: list[dict]
    controlled_subcategories: dict[str, list[str]] = Field(default_factory=dict)
    entity_candidates: list[dict] = Field(default_factory=list)
    cve_context: list[dict] = Field(default_factory=list)
    similar_rules: list[dict] = Field(default_factory=list)
    classifier_version: str = "v1"
