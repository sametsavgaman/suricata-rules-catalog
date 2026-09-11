"""Read-only catalog aggregates and product candidate views."""
import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import rule_to_read
from app.database.models import Classification, ClassificationStatus, ProductStatus, Rule, RuleProductDecision
from app.database.repository import RuleRepository
from app.database.session import get_db

router = APIRouter(prefix="/catalog", tags=["catalog"])

def _latest(db: Session):
    ids = select(func.max(Classification.id).label("id")).where(Classification.classification_status != ClassificationStatus.FAILED).group_by(Classification.rule_id).subquery()
    return Classification, ids

@router.get("/stats")
def catalog_stats(db: Session = Depends(get_db)):
    latest_ids = select(func.max(Classification.id).label("id")).where(Classification.classification_status != ClassificationStatus.FAILED).group_by(Classification.rule_id).subquery()
    latest = select(Classification).join(latest_ids, Classification.id == latest_ids.c.id).subquery()
    total = db.scalar(select(func.count(Rule.id))) or 0
    classified = db.scalar(select(func.count()).select_from(latest)) or 0
    mapped = db.scalar(select(func.count()).select_from(latest).where(latest.c.mitre_technique_id.is_not(None))) or 0
    classification_records = db.scalar(select(func.count()).select_from(Classification).where(Classification.classification_status != ClassificationStatus.FAILED)) or 0
    products = {s.value: db.scalar(select(func.count()).select_from(RuleProductDecision).where(RuleProductDecision.status == s)) or 0 for s in ProductStatus}
    # NOT_EVALUATED is the implicit default for rules without a decision row.
    products[ProductStatus.NOT_EVALUATED.value] += max(0, total - sum(products.values()))
    return {"total_rules": total, "classified_rules": classified, "mitre_mapped": mapped, "classification_records": classification_records, "product_status": products}

@router.get("/facets")
def catalog_facets(db: Session = Depends(get_db)):
    latest_ids = select(func.max(Classification.id).label("id")).where(Classification.classification_status != ClassificationStatus.FAILED).group_by(Classification.rule_id).subquery()
    latest = select(Classification).join(latest_ids, Classification.id == latest_ids.c.id).subquery()
    def counts(column, source):
        return [{"value": v, "count": n} for v,n in db.execute(select(column, func.count()).select_from(source).where(column.is_not(None)).group_by(column).order_by(func.count().desc())).all()]
    return {"categories": counts(latest.c.category, latest), "subcategories": counts(latest.c.subcategory, latest),
            "entities": counts(latest.c.detected_entity, latest), "mitre_tactics": counts(latest.c.mitre_tactic, latest),
            "mitre_techniques": counts(latest.c.mitre_technique_id, latest), "protocols": counts(Rule.protocol, Rule),
            "product_statuses": [{"value": s.value, "count": n} for s,n in db.execute(select(RuleProductDecision.status, func.count()).group_by(RuleProductDecision.status)).all()]}

@router.get("/candidates")
def candidates(status: ProductStatus | None = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    stmt = select(Rule).join(RuleProductDecision, RuleProductDecision.rule_id == Rule.id)
    if status: stmt = stmt.where(RuleProductDecision.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rules = db.scalars(stmt.order_by(Rule.sid.desc()).offset(offset).limit(limit)).all()
    return {"items": [rule_to_read(rule) for rule in rules], "total": total, "offset": offset, "limit": limit}

@router.get("/export.csv")
def export_catalog_csv(search: str | None = None, category: str | None = None, mitre_tactic: str | None = None, product_status: ProductStatus | None = None, db: Session = Depends(get_db)):
    stmt = select(Rule, Classification).outerjoin(Classification, Classification.rule_id == Rule.id)
    if category: stmt = stmt.where(Classification.category == category)
    if mitre_tactic: stmt = stmt.where(Classification.mitre_tactic == mitre_tactic)
    if product_status: stmt = stmt.join(RuleProductDecision, RuleProductDecision.rule_id == Rule.id).where(RuleProductDecision.status == product_status)
    if search:
        pattern=f"%{search}%"; stmt=stmt.where(Rule.msg.ilike(pattern) | Rule.raw_rule.ilike(pattern) | Classification.mitre_technique_id.ilike(pattern))
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["SID","REV","MSG","SOURCE_FILE","PROTOCOL","BEHAVIOR","ENTITY","CATEGORY","SUBCATEGORY","MITRE_ID","MODEL","MODEL_CONFIDENCE"])
    for rule,c in db.execute(stmt.order_by(Rule.sid.desc())).all():
        writer.writerow([rule.sid,rule.rev,rule.msg,rule.source_file,rule.protocol,c.detected_behavior if c else None,c.detected_entity if c else None,c.category if c else None,c.subcategory if c else None,c.mitre_technique_id if c else None,c.model_name if c else None,c.model_confidence if c else None])
    return StreamingResponse(iter(["\ufeff"+output.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=suricata-catalog.csv"})
