from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ClassificationStatus(StrEnum):
    AUTO_CLASSIFIED = "AUTO_CLASSIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAILED = "FAILED"


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("sid", "rev", name="uq_rules_sid_rev"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    sid: Mapped[int] = mapped_column(Integer, index=True)
    rev: Mapped[int] = mapped_column(Integer, default=1)
    raw_rule: Mapped[str] = mapped_column(Text)
    msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(Text)
    source_port: Mapped[str] = mapped_column(Text)
    direction: Mapped[str] = mapped_column(String(8))
    destination: Mapped[str] = mapped_column(Text)
    destination_port: Mapped[str] = mapped_column(Text)
    classtype: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    rule_metadata: Mapped[list] = mapped_column("metadata", MutableList.as_mutable(JSON), default=list)
    references: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    flow: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    flowbits: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    contents: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    pcre: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    app_layer: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    source_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    classifications: Mapped[list["Classification"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", order_by="Classification.created_at"
    )
    manual_reviews: Mapped[list["ManualReview"]] = relationship(back_populates="rule", cascade="all, delete-orphan", order_by="ManualReview.created_at")
    classification_runs: Mapped[list["ClassificationRun"]] = relationship(back_populates="rule", cascade="all, delete-orphan")
    classification_overrides: Mapped[list["ClassificationOverride"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", order_by="ClassificationOverride.created_at"
    )
    forced_mitre_mappings: Mapped[list["ForcedMitreMapping"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", order_by="ForcedMitreMapping.created_at"
    )
    family_assignments: Mapped[list["RuleFamilyAssignment"]] = relationship(back_populates="rule", cascade="all, delete-orphan")


class ClassificationRun(Base):
    __tablename__ = "classification_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(32))
    model_name: Mapped[str] = mapped_column(String(128))
    model_display_name: Mapped[str] = mapped_column(String(160))
    classifier_version: Mapped[str] = mapped_column(String(16))
    inference_mode: Mapped[str] = mapped_column(String(16))
    dataset_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sample_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    configuration_json: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_rules: Mapped[int] = mapped_column(Integer, default=0)
    successful_rules: Mapped[int] = mapped_column(Integer, default=0)
    failed_rules: Mapped[int] = mapped_column(Integer, default=0)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), nullable=True, index=True)
    rule: Mapped[Rule | None] = relationship(back_populates="classification_runs")


class Classification(Base):
    __tablename__ = "classifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    detected_behavior: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_entity: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    subcategory: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cyber_kill_chain_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    model_name: Mapped[str] = mapped_column(String(128))
    classifier_version: Mapped[str] = mapped_column(String(16), default="v1", index=True)
    agent_activity: Mapped[dict] = mapped_column(JSON, default=dict)
    inspection_batch: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_mitre_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    final_mitre_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    mitre_mapping_method: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    mapping_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_retrieval_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_strength: Mapped[str | None] = mapped_column(String(16), nullable=True)
    model_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    validator_mitre_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    classification_run_id: Mapped[int | None] = mapped_column(ForeignKey("classification_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    model_display_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    inference_mode: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    model_config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    inference_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification_status: Mapped[ClassificationStatus] = mapped_column(
        SAEnum(ClassificationStatus), default=ClassificationStatus.AUTO_CLASSIFIED, index=True
    )
    validation_issues: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[Rule] = relationship(back_populates="classifications")


class ManualReview(Base):
    __tablename__ = "manual_reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    classification_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="UNREVIEWED", index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_type: Mapped[str] = mapped_column(String(32), default="HUMAN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rule: Mapped[Rule] = relationship(back_populates="manual_reviews")

class ClassificationOverride(Base):
    """Auditable admin correction; original model output remains immutable."""
    __tablename__ = "classification_overrides"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    classification_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True, index=True)
    field_name: Mapped[str] = mapped_column(String(64), index=True)
    original_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    corrected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    # Retained for backwards-compatible storage; new writes never contain an
    # operator identity and API responses deliberately omit this legacy field.
    admin_id: Mapped[str] = mapped_column(String(128), default="not_recorded")
    active: Mapped[bool] = mapped_column(default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rule: Mapped[Rule] = relationship(back_populates="classification_overrides")


class ForcedMitreMapping(Base):
    """Append-only, user-requested Gemini mapping kept separate from model output."""
    __tablename__ = "forced_mitre_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    classification_id: Mapped[int] = mapped_column(ForeignKey("classifications.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    technique_name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str | None] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    provider: Mapped[str] = mapped_column(String(32), default="gemini")
    model_name: Mapped[str] = mapped_column(String(128))
    candidate_snapshot: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[Rule] = relationship(back_populates="forced_mitre_mappings")

class ApplicationSetting(Base):
    __tablename__ = "application_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_secret: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class ComparisonReview(Base):
    __tablename__ = "comparison_reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    classification_a_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True)
    classification_b_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True)
    preference: Mapped[str] = mapped_column(String(24))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProductStatus(StrEnum):
    NOT_EVALUATED = "NOT_EVALUATED"
    CANDIDATE = "CANDIDATE"
    # Retained for backwards compatibility with older product-decision rows.
    # New analyst review is organized exclusively through Rule Packs.
    SHORTLISTED = "SHORTLISTED"
    APPROVED_FOR_PRODUCT = "APPROVED_FOR_PRODUCT"
    REJECTED_FOR_PRODUCT = "REJECTED_FOR_PRODUCT"
    ALREADY_INTEGRATED = "ALREADY_INTEGRATED"


class DetectionFamilyType(StrEnum):
    TOOL = "TOOL"
    MALWARE = "MALWARE"
    PRODUCT = "PRODUCT"
    BEHAVIOR = "BEHAVIOR"
    VULNERABILITY = "VULNERABILITY"


class FamilyAssignmentProvenance(StrEnum):
    EXPLICIT_ENTITY = "EXPLICIT_ENTITY"
    EXPLICIT_RULE_NAME = "EXPLICIT_RULE_NAME"
    KNOWN_TOOL = "KNOWN_TOOL"
    KNOWN_MALWARE = "KNOWN_MALWARE"
    CVE_FAMILY = "CVE_FAMILY"
    BEHAVIOR_PATTERN = "BEHAVIOR_PATTERN"
    MANUAL = "MANUAL"
    UNASSIGNED = "UNASSIGNED"


class FamilyEvaluationStatus(StrEnum):
    ASSIGNED = "ASSIGNED"
    UNASSIGNED = "UNASSIGNED"


class DetectionFamily(Base):
    __tablename__ = "detection_families"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(140), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    family_type: Mapped[DetectionFamilyType] = mapped_column(SAEnum(DetectionFamilyType), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RuleFamilyAssignment(Base):
    __tablename__ = "rule_family_assignments"
    __table_args__ = (UniqueConstraint("rule_id", name="uq_rule_primary_family"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[int] = mapped_column(ForeignKey("detection_families.id", ondelete="CASCADE"), index=True)
    source_classification_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True, index=True)
    provenance: Mapped[FamilyAssignmentProvenance] = mapped_column(SAEnum(FamilyAssignmentProvenance), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    algorithm_version: Mapped[str] = mapped_column(String(32), default="family-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    rule: Mapped[Rule] = relationship(back_populates="family_assignments")
    family: Mapped[DetectionFamily] = relationship()


class RuleFamilyEvaluation(Base):
    __tablename__ = "rule_family_evaluations"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), unique=True, index=True)
    source_classification_id: Mapped[int | None] = mapped_column(ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[FamilyEvaluationStatus] = mapped_column(SAEnum(FamilyEvaluationStatus), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    algorithm_version: Mapped[str] = mapped_column(String(32), default="family-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RuleProductDecision(Base):
    __tablename__ = "rule_product_decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), unique=True, index=True)
    status: Mapped[ProductStatus] = mapped_column(SAEnum(ProductStatus), default=ProductStatus.NOT_EVALUATED, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    rule: Mapped[Rule] = relationship()


class RuleProductDecisionHistory(Base):
    __tablename__ = "rule_product_decision_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str] = mapped_column(String(32))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProductRulesetImportBatch(Base):
    __tablename__ = "product_ruleset_import_batches"

    batch_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    filenames: Mapped[list] = mapped_column(MutableList.as_mutable(JSON), default=list)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    provider: Mapped[str] = mapped_column(String(32), default="gemini")
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    classifier_version: Mapped[str] = mapped_column(String(32), default="v2.1")
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    reused_classifications: Mapped[int] = mapped_column(Integer, default=0)
    queued: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    auto_classified: Mapped[int] = mapped_column(Integer, default=0)
    review_required: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProductRulesetImportItem(Base):
    __tablename__ = "product_ruleset_import_items"
    __table_args__ = (UniqueConstraint("batch_id", "rule_id", name="uq_product_ruleset_batch_rule"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("product_ruleset_import_batches.batch_id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    classification_id: Mapped[int | None] = mapped_column(
        ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudBatchStatus(StrEnum):
    PREPARING = "PREPARING"
    ACTIVE = "ACTIVE"
    PARTIALLY_IMPORTED = "PARTIALLY_IMPORTED"
    COMPLETED = "COMPLETED"
    RELEASED = "RELEASED"


class CloudReservationStatus(StrEnum):
    RESERVED = "RESERVED"
    IMPORTED = "IMPORTED"
    RELEASED = "RELEASED"
    FAILED = "FAILED"


class CloudBatch(Base):
    __tablename__ = "cloud_batches"

    batch_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    worker: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[CloudBatchStatus] = mapped_column(
        SAEnum(CloudBatchStatus), default=CloudBatchStatus.PREPARING, index=True
    )
    target_provider: Mapped[str] = mapped_column(String(32))
    target_model: Mapped[str] = mapped_column(String(128))
    target_model_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    classifier_version: Mapped[str] = mapped_column(String(32))
    rule_count: Mapped[int] = mapped_column(Integer, default=0)
    imported_count: Mapped[int] = mapped_column(Integer, default=0)
    contract_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    export_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    reservations: Mapped[list["CloudBatchReservation"]] = relationship(
        back_populates="batch", cascade="all, delete-orphan", order_by="CloudBatchReservation.id"
    )


class CloudBatchReservation(Base):
    __tablename__ = "cloud_batch_reservations"
    __table_args__ = (
        UniqueConstraint("batch_id", "rule_id", name="uq_cloud_batch_rule"),
        # Preserve reservation history while allowing only one live owner.
        Index(
            "uq_cloud_active_reservation_rule",
            "rule_id",
            unique=True,
            sqlite_where=text("status = 'RESERVED'"),
            postgresql_where=text("status = 'RESERVED'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("cloud_batches.batch_id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), index=True)
    sid: Mapped[int] = mapped_column(Integer)
    rev: Mapped[int] = mapped_column(Integer)
    raw_sha256: Mapped[str] = mapped_column(String(64))
    context_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[CloudReservationStatus] = mapped_column(
        SAEnum(CloudReservationStatus), default=CloudReservationStatus.RESERVED, index=True
    )
    classification_id: Mapped[int | None] = mapped_column(
        ForeignKey("classifications.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    batch: Mapped[CloudBatch] = relationship(back_populates="reservations")


class LocalClassificationClaim(Base):
    """Short-lived local ownership used only to close export/inference races."""

    __tablename__ = "local_classification_claims"

    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True)
    claim_id: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    target_provider: Mapped[str] = mapped_column(String(32))
    target_model: Mapped[str] = mapped_column(String(128))
    classifier_version: Mapped[str] = mapped_column(String(32))
    owner_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
