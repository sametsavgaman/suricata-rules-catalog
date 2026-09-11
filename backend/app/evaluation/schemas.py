from enum import StrEnum
from typing import Any, Literal
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.agent.schemas import ProviderResult, TokenUsage


EVALUATED_FIELDS = (
    "detected_behavior",
    "detected_entity",
    "entity_type",
    "category",
    "subcategory",
    "mitre_tactic",
    "mitre_technique",
    "mitre_technique_id",
    "cyber_kill_chain_phase",
)


class AnnotationStatus(StrEnum):
    UNREVIEWED = "UNREVIEWED"
    REVIEWED = "REVIEWED"
    DISPUTED = "DISPUTED"


class VerificationVerdict(StrEnum):
    AGREE = "AGREE"
    PARTIAL = "PARTIAL"
    DISAGREE = "DISAGREE"


class AgreementStatus(StrEnum):
    HIGH_CONFIDENCE_AGREEMENT = "HIGH_CONFIDENCE_AGREEMENT"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    DISAGREEMENT = "DISAGREEMENT"


class ExpectedClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_behavior: str | None = None
    detected_entity: str | None = None
    entity_type: str | None = None
    category: str | None = None
    subcategory: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_id: str | None = None
    cyber_kill_chain_phase: str | None = None


class AnnotationProposal(ExpectedClassification):
    proposal_status: Literal["AI_PROPOSED"] = "AI_PROPOSED"
    proposal_confidence: float = Field(ge=0.0, le=1.0)
    notes: str


class Annotation(BaseModel):
    status: AnnotationStatus = AnnotationStatus.UNREVIEWED
    annotator: str | None = None
    notes: str | None = None
    review_method: str | None = None
    reviewed_at: datetime | None = None


class EvidenceItem(BaseModel):
    field: str
    source: str
    value: str


class VerificationIssue(BaseModel):
    field: str
    reason: str


class Verification(BaseModel):
    verdict: VerificationVerdict
    field_verdicts: dict[str, VerificationVerdict] = Field(default_factory=dict)
    issues: list[VerificationIssue] = Field(default_factory=list)
    verifier_confidence: float = Field(ge=0.0, le=1.0)


class RuleSample(BaseModel):
    sid: int
    rev: int
    msg: str | None
    source_file: str
    raw_rule: str
    stratum: str


class GoldenRecord(RuleSample):
    expected: ExpectedClassification = Field(default_factory=ExpectedClassification)
    proposal: AnnotationProposal | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    verification: Verification | None = None
    agreement_status: AgreementStatus | None = None
    provenance: dict[str, str] = Field(default_factory=lambda: {
        "raw_rule_source": "ET_OPEN", "parser": "deterministic",
        "enrichment": "deterministic", "proposal_source": "LLM",
        "verification_source": "independent_critic",
    })
    benchmark_audit: dict[str, Any] | None = None
    annotation: Annotation = Field(default_factory=Annotation)


class ProposalRecord(BaseModel):
    sid: int
    rev: int
    msg: str | None
    source_file: str
    proposal: AnnotationProposal


class ParserSummary(BaseModel):
    data_status: str
    source_directory: str
    total_rules: int
    parsed_successfully: int
    failed_parsing: int
    parser_success_rate: float
    rule_files: int
    failures: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationResult(BaseModel):
    sid: int
    rev: int
    msg: str | None
    source_file: str
    expected: dict[str, Any]
    actual: dict[str, Any] | None
    matches: dict[str, bool]
    normalized_matches: dict[str, bool]
    errors: list[str]
    confidence: float
    status: str
    cache_hit: bool = False
    usage: TokenUsage = Field(default_factory=TokenUsage)
    classifier_version: str = "v1"
    agent_activity: dict[str, Any] = Field(default_factory=dict)
