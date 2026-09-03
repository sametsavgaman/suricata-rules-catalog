from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
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
