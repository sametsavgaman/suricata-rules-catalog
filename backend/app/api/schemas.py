from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.database.models import ClassificationStatus, ProductStatus
from app.v2.state import canonical_state, confidence_summary


class ClassificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detected_behavior: str | None
    detected_entity: str | None
    entity_type: str | None
    category: str | None
    subcategory: str | None
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_technique_id: str | None
    cyber_kill_chain_phase: str | None
    confidence: float
    evidence: list[str]
    explanation: str
    model_name: str
    classifier_version: str
    agent_activity: dict
    inspection_batch: str | None = None
    source_mitre_mapping: dict | None = None
    final_mitre_mapping: dict | None = None
    mitre_mapping_method: str | None = None
    mapping_reason: str | None = None
    mitre_retrieval_score: float | None = None
    evidence_strength: str | None = None
    model_confidence: float | None = None
    validator_mitre_status: str | None = None
    classification_status: ClassificationStatus
    validation_issues: list[str]
    created_at: datetime
    provider: str | None = None
    model_display_name: str | None = None
    inference_mode: str | None = None
    run_id: str | None = None
    classification_run_id: int | None = None
    inference_duration_ms: float | None = None
    field_decisions: dict = Field(default_factory=dict)
    abstained_fields: list[str] = Field(default_factory=list)
    validation: dict | None = None
    consistency_warnings: list[str] = Field(default_factory=list)
    confidence_semantics: str = "MODEL_SELF_REPORTED_UNCALIBRATED"
    confidence_band: str = "LOW"
    confidence_band_definition: str | None = None
    field_coverage: dict = Field(default_factory=dict)
    manual_review: dict | None = None


class RuleRead(BaseModel):
    id: int
    sid: int
    rev: int
    raw_rule: str
    msg: str | None
    action: str
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str
    classtype: str | None
    metadata: list[str]
    references: list[str]
    flow: list[str]
    flowbits: list[str]
    contents: list[str]
    pcre: list[str]
    app_layer: list[dict]
    source_file: str | None
    created_at: datetime
    classification: ClassificationRead | None = None
    manual_review: dict | None = None
    classification_options: list[dict] = Field(default_factory=list)


class RuleListResponse(BaseModel):
    items: list[RuleRead]
    total: int
    offset: int
    limit: int
    page: int = 1
    total_pages: int = 1


class ProductDecisionRequest(BaseModel):
    status: ProductStatus
    note: str | None = None


class ProductDecisionRead(BaseModel):
    status: ProductStatus
    note: str | None = None
    updated_at: datetime


class ProductHistoryItem(BaseModel):
    from_status: str | None
    to_status: str
    note: str | None = None
    created_at: datetime


class RuleNeighbors(BaseModel):
    previous_sid: int | None = None
    next_sid: int | None = None


class ImportFileResult(BaseModel):
    filename: str
    discovered: int
    imported: int
    skipped: int
    errors: list[str] = Field(default_factory=list)


class ImportResponse(BaseModel):
    files: list[ImportFileResult]
    imported: int
    skipped: int
    failed: int


class BatchClassificationResponse(BaseModel):
    requested: int
    auto_classified: int
    review_required: int
    failed: int


class StatsResponse(BaseModel):
    total_rules: int
    classified_rules: int
    review_required: int
    failed: int
    category_distribution: dict[str, int]
    top_detected_entities: list[dict]
    top_mitre_techniques: list[dict]
    average_confidence: float
    manual_review: dict[str, int] = Field(default_factory=dict)


def classification_to_read(item, reviews=()) -> ClassificationRead:
    value = ClassificationRead.model_validate(item)
    decisions, abstained, validation, strength, warnings = canonical_state(item)
    confidence = confidence_summary(item, decisions)
    matching_reviews = [r for r in reviews if r.classification_id == item.id]
    current = matching_reviews[-1] if matching_reviews else None
    return value.model_copy(update={
        "field_decisions": decisions, "abstained_fields": abstained,
        "validation": validation, "evidence_strength": strength, "consistency_warnings": warnings,
        "confidence_semantics": confidence['semantics'], "confidence_band": confidence['band'],
        "confidence_band_definition": confidence['band_definition'], "field_coverage": confidence['field_coverage'],
        "manual_review": {"status": current.status, "note": current.note,
            "reviewer_type": current.reviewer_type, "reviewed_at": current.created_at} if current else None,
    })


def rule_to_read(rule, classification=None) -> RuleRead:
    if classification is None and getattr(rule, "classifications", None):
        non_failed = [item for item in rule.classifications if item.classification_status != ClassificationStatus.FAILED]
        classification = non_failed[-1] if non_failed else None
    fields = RuleRead.model_fields.keys() - {"classification", "metadata", "manual_review", "classification_options"}
    data = {field: getattr(rule, field) for field in fields}
    data["metadata"] = rule.rule_metadata
    reviews = getattr(rule, "manual_reviews", [])
    current = reviews[-1] if reviews else None
    review = {"status": current.status, "note": current.note, "reviewer_type": current.reviewer_type, "reviewed_at": current.created_at} if current else None
    normalized = classification_to_read(classification, reviews) if classification else None
    options = [classification_to_read(item, reviews).model_dump(mode='json')
        for item in sorted(getattr(rule, "classifications", []), key=lambda x: (x.created_at, x.id), reverse=True)]
    return RuleRead(**data, classification=normalized, manual_review=review, classification_options=options)


class ManualReviewRequest(BaseModel):
    status: str
    note: str | None = None
    classification_id: int | None = None


class ManualReviewResponse(BaseModel):
    status: str
    note: str | None = None
    reviewer_type: str
    reviewed_at: datetime


class ManualReviewHistoryResponse(BaseModel):
    items: list[ManualReviewResponse]
