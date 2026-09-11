from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from app.database.models import (
    Classification,
    ClassificationStatus,
    CloudBatch,
    CloudBatchReservation,
    CloudReservationStatus,
    Rule,
)
from app.parser.models import ParsedRule


class RuleRepository:
    def __init__(self, db: Session):
        self.db = db

    def upsert(self, parsed: ParsedRule, source_file: str | None) -> tuple[Rule, bool]:
        existing = self.db.scalar(select(Rule).where(Rule.sid == parsed.sid, Rule.rev == parsed.rev))
        if existing:
            return existing, False
        payload = parsed.model_dump(exclude={"options", "flowbits", "metadata"})
        rule = Rule(
            **payload,
            rule_metadata=parsed.metadata,
            flowbits=parsed.flowbits,
            source_file=source_file,
        )
        self.db.add(rule)
        self.db.flush()
        return rule, True

    def by_sid(self, sid: int) -> Rule | None:
        return self.db.scalar(
            select(Rule).options(selectinload(Rule.classifications)).where(Rule.sid == sid).order_by(Rule.rev.desc())
        )

    def by_id(self, rule_id: int) -> Rule | None:
        return self.db.get(Rule, rule_id)

    def unclassified(
        self,
        limit: int,
        *,
        target_provider: str | None = None,
        target_model: str | None = None,
        classifier_version: str | None = None,
    ) -> list[Rule]:
        latest_exists = select(Classification.id).where(
            Classification.rule_id == Rule.id,
            Classification.classification_status != ClassificationStatus.FAILED,
        ).exists()
        reservation_query = select(CloudBatchReservation.id).join(
            CloudBatch, CloudBatch.batch_id == CloudBatchReservation.batch_id
        ).where(
            CloudBatchReservation.rule_id == Rule.id,
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )
        if target_provider is not None:
            reservation_query = reservation_query.where(CloudBatch.target_provider == target_provider)
        if target_model is not None:
            reservation_query = reservation_query.where(CloudBatch.target_model == target_model)
        if classifier_version is not None:
            reservation_query = reservation_query.where(CloudBatch.classifier_version == classifier_version)
        cloud_reserved = reservation_query.exists()
        return list(
            self.db.scalars(select(Rule).where(~latest_exists, ~cloud_reserved).order_by(Rule.id).limit(limit))
        )

    def list_query(self) -> Select:
        return select(Rule).options(selectinload(Rule.classifications)).order_by(Rule.sid.desc())
