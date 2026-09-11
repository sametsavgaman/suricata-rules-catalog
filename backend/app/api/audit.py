from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import Integer, String, Text, DateTime, func, literal, select, union_all
from sqlalchemy.orm import Session

from app.database.models import ClassificationOverride, ForcedMitreMapping, ManualReview, Rule, RuleProductDecisionHistory
from app.database.session import get_db


router = APIRouter(prefix="/audit-log", tags=["audit"])
AuditAction = Literal["MANUAL_REVIEW", "FIELD_CORRECTION", "PRODUCT_DECISION", "FORCED_MITRE"]


class AuditLogItem(BaseModel):
    event_id: str
    sid: int
    action: str
    classification_id: int | None = None
    field_name: str | None = None
    from_value: str | None = None
    to_value: str | None = None
    detail: str | None = None
    created_at: datetime


class AuditLogResponse(BaseModel):
    items: list[AuditLogItem]
    total: int
    offset: int
    limit: int


@router.get("", response_model=AuditLogResponse)
def list_audit_log(
    action: AuditAction | None = Query(None),
    sid: int | None = Query(None, ge=1),
    date_from: datetime | None = Query(None),
    date_to: datetime | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    null_int = literal(None, type_=Integer())
    null_str = literal(None, type_=String(2048))
    manual = select(
        literal("MANUAL_REVIEW").label("action"), ManualReview.id.label("source_id"),
        ManualReview.rule_id.label("rule_id"), ManualReview.classification_id.label("classification_id"),
        null_str.label("field_name"), null_str.label("from_value"),
        ManualReview.status.label("to_value"), ManualReview.note.label("detail"),
        ManualReview.created_at.label("created_at"),
    )
    correction = select(
        literal("FIELD_CORRECTION").label("action"), ClassificationOverride.id.label("source_id"),
        ClassificationOverride.rule_id.label("rule_id"), ClassificationOverride.classification_id.label("classification_id"),
        ClassificationOverride.field_name.label("field_name"), ClassificationOverride.original_value.label("from_value"),
        ClassificationOverride.corrected_value.label("to_value"), ClassificationOverride.reason.label("detail"),
        ClassificationOverride.created_at.label("created_at"),
    )
    product = select(
        literal("PRODUCT_DECISION").label("action"), RuleProductDecisionHistory.id.label("source_id"),
        RuleProductDecisionHistory.rule_id.label("rule_id"), null_int.label("classification_id"),
        null_str.label("field_name"), RuleProductDecisionHistory.from_status.label("from_value"),
        RuleProductDecisionHistory.to_status.label("to_value"), RuleProductDecisionHistory.note.label("detail"),
        RuleProductDecisionHistory.created_at.label("created_at"),
    )
    forced_mitre = select(
        literal("FORCED_MITRE").label("action"), ForcedMitreMapping.id.label("source_id"),
        ForcedMitreMapping.rule_id.label("rule_id"), ForcedMitreMapping.classification_id.label("classification_id"),
        literal("mitre_technique_id", type_=String(2048)).label("field_name"), null_str.label("from_value"),
        ForcedMitreMapping.technique_id.label("to_value"), ForcedMitreMapping.explanation.label("detail"),
        ForcedMitreMapping.created_at.label("created_at"),
    )
    events = union_all(manual, correction, product, forced_mitre).subquery("audit_events")
    stmt = select(events, Rule.sid).join(Rule, Rule.id == events.c.rule_id)
    if action:
        stmt = stmt.where(events.c.action == action)
    if sid:
        stmt = stmt.where(Rule.sid == sid)
    if date_from:
        stmt = stmt.where(events.c.created_at >= date_from.replace(tzinfo=None))
    if date_to:
        stmt = stmt.where(events.c.created_at <= date_to.replace(tzinfo=None))
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.execute(
        stmt.order_by(events.c.created_at.desc(), events.c.source_id.desc()).offset(offset).limit(limit)
    ).mappings().all()
    items = [AuditLogItem(
        event_id=f"{row['action'].lower()}:{row['source_id']}", sid=row["sid"],
        action=row["action"], classification_id=row["classification_id"], field_name=row["field_name"],
        from_value=row["from_value"], to_value=row["to_value"], detail=row["detail"], created_at=row["created_at"],
    ) for row in rows]
    return AuditLogResponse(items=items, total=total, offset=offset, limit=limit)
