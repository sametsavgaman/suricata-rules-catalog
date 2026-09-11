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
    families: list[dict] = Field(default_factory=list)
    product_decision: dict | None = None


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


class ExistingRulesetPreviewFile(BaseModel):
    filename: str
    discovered: int
    exact_matches: int
    new_catalog_rules: int
    revision_updates: int
    reusable_classifications: int
    gemini_candidates: int
    duplicates: int
    errors: list[str] = Field(default_factory=list)


class ExistingRulesetPreviewResponse(BaseModel):
    files: list[ExistingRulesetPreviewFile]
    discovered: int
    exact_matches: int
    new_catalog_rules: int
    revision_updates: int
    reusable_classifications: int
    gemini_candidates: int
    duplicates: int
    failed: int


class ExistingRulesetImportFile(BaseModel):
    filename: str
    discovered: int
    matched_existing: int
    imported: int
    marked_existing: int
    already_marked: int
    duplicates: int
    errors: list[str] = Field(default_factory=list)


class ExistingRulesetImportResponse(BaseModel):
    files: list[ExistingRulesetImportFile]
    discovered: int
    matched_existing: int
    imported: int
    marked_existing: int
    already_marked: int
    duplicates: int
    failed: int
    reused_classifications: int = 0
    queued_for_gemini: int = 0
    classification_batch_id: str | None = None


class ProductRulesetBatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    batch_id: str
    filenames: list[str]
    status: str
    provider: str
    model_name: str | None = None
    classifier_version: str
    discovered: int
    reused_classifications: int
    queued: int
    processed: int
    auto_classified: int
    review_required: int
    failed: int
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


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
    pending_classification: int = 0
    category_distribution: dict[str, int]
    top_detected_entities: list[dict]
    top_mitre_techniques: list[dict]
    average_confidence: float
    manual_review: dict[str, int] = Field(default_factory=dict)


def classification_to_read(item, reviews=(), overrides=()) -> ClassificationRead:
    value = ClassificationRead.model_validate(item)
    corrected = {
        override.field_name: override.corrected_value
        for override in overrides
        if override.active and (override.classification_id is None or override.classification_id == item.id)
    }
    if corrected:
        value = value.model_copy(update=corrected)
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


def rule_to_read(rule, classification=None, product_decision=None, *, include_classification_options: bool = True) -> RuleRead:
    if classification is None and include_classification_options and getattr(rule, "classifications", None):
        non_failed = [item for item in rule.classifications if item.classification_status != ClassificationStatus.FAILED]
        classification = non_failed[-1] if non_failed else None
    fields = RuleRead.model_fields.keys() - {"classification", "metadata", "manual_review", "classification_options", "families", "product_decision"}
    data = {field: getattr(rule, field) for field in fields}
    data["metadata"] = rule.rule_metadata
    reviews = getattr(rule, "manual_reviews", [])
    current = reviews[-1] if reviews else None
    review = {"status": current.status, "note": current.note, "reviewer_type": current.reviewer_type, "reviewed_at": current.created_at} if current else None
    overrides = getattr(rule, "classification_overrides", [])
    normalized = classification_to_read(classification, reviews, overrides) if classification else None
    options = ([classification_to_read(item, reviews, overrides).model_dump(mode='json')
        for item in sorted(getattr(rule, "classifications", []), key=lambda x: (x.created_at, x.id), reverse=True)]
        if include_classification_options else [])
    data["families"] = [{"slug": a.family.slug, "name": a.family.name, "family_type": getattr(a.family.family_type, "value", a.family.family_type)}
                        for a in getattr(rule, "family_assignments", []) if getattr(a, "family", None)]
    data["product_decision"] = ({"status": getattr(product_decision.status, "value", product_decision.status),
                                  "note": product_decision.note, "updated_at": product_decision.updated_at}
                                 if product_decision is not None else None)
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

class ClassificationOverrideRequest(BaseModel):
    classification_id: int | None = None
    corrections: dict[str, str | None] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=3, max_length=2000)


class ForcedMitreRequest(BaseModel):
    classification_id: int
    acknowledge_risk: bool


class ForcedMitreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    classification_id: int
    technique_id: str
    technique_name: str
    tactic: str | None
    confidence: float
    evidence: list[dict]
    explanation: str
    provider: str
    model_name: str
    created_at: datetime
    forced: bool = True
    warning: str = "This MITRE mapping was forced at the user's request and may be misleading."


class ForcedMitreState(BaseModel):
    eligible: bool
    reason: str | None = None
    mapping: ForcedMitreRead | None = None
