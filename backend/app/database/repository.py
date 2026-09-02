from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from app.database.models import Classification, ClassificationStatus, Rule
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

    def unclassified(self, limit: int) -> list[Rule]:
        latest_exists = select(Classification.id).where(
            Classification.rule_id == Rule.id,
            Classification.classification_status != ClassificationStatus.FAILED,
        ).exists()
        return list(self.db.scalars(select(Rule).where(~latest_exists).order_by(Rule.id).limit(limit)))

    def list_query(self) -> Select:
        return select(Rule).options(selectinload(Rule.classifications)).order_by(Rule.sid.desc())
