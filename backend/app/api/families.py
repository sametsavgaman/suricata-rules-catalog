"""Read-only Detection Families catalogue API."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import rule_to_read
from app.database.models import (
    DetectionFamily, FamilyEvaluationStatus, Rule, RuleFamilyAssignment,
    RuleFamilyEvaluation,
)
from app.database.session import get_db
from app.services.detection_families import FamilyFilters, FamilySearch, family_rules, family_summaries
from app.services.mitre_intelligence import family_mitre_profile

router = APIRouter(prefix="/families", tags=["detection families"])


def filters(search=None, category=None, mitre_tactic=None, mitre_technique_id=None,
            protocol=None, entity_type=None, product_status=None):
    try:
        return FamilyFilters(search=search, category=category, mitre_tactic=mitre_tactic,
                             mitre_technique_id=mitre_technique_id, protocol=protocol,
                             entity_type=entity_type, product_status=product_status)
    except Exception:
        raise HTTPException(422, "Geçersiz detection family filtresi.") from None


@router.get("")
def list_families(
    search: str | None = Query(None, max_length=120), category: str | None = Query(None, max_length=120),
    mitre_tactic: str | None = Query(None, max_length=120),
    mitre_technique_id: str | None = Query(None, pattern=r"^T\d{4}(\.\d{3})?$"),
    protocol: str | None = Query(None, max_length=32), entity_type: str | None = Query(None, max_length=64),
    product_status: str | None = Query(None, max_length=32), offset: int = Query(0, ge=0),
    limit: int = Query(24, ge=1, le=50), db: Session = Depends(get_db),
):
    request = FamilySearch(filters=filters(search, category, mitre_tactic, mitre_technique_id,
                                           protocol, entity_type, product_status), offset=offset, limit=limit)
    items, total = family_summaries(db, request)
    return {"items": items, "total": total, "offset": offset, "limit": limit,
            "page": offset // limit + 1, "total_pages": max(1, (total + limit - 1) // limit)}


@router.get("/stats")
def family_stats(db: Session = Depends(get_db)):
    families = db.scalar(select(func.count()).select_from(DetectionFamily)) or 0
    assigned = db.scalar(select(func.count()).select_from(RuleFamilyAssignment)) or 0
    rules = db.scalar(select(func.count()).select_from(Rule)) or 0
    evaluated = db.scalar(select(func.count()).select_from(RuleFamilyEvaluation)) or 0
    unassigned = db.scalar(select(func.count()).select_from(RuleFamilyEvaluation).where(
        RuleFamilyEvaluation.status == FamilyEvaluationStatus.UNASSIGNED)) or 0
    return {"families": families, "assigned_rules": assigned, "evaluated_rules": evaluated,
            "unassigned_rules": unassigned, "pending_evaluation_rules": max(0, rules - evaluated),
            "assignment_coverage": round(assigned / rules, 4) if rules else 0}


@router.get("/{slug}")
def family_detail(slug: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100),
                  db: Session = Depends(get_db)):
    if len(slug) > 140:
        raise HTTPException(404, "Detection family bulunamadı.")
    family = db.scalar(select(DetectionFamily).where(DetectionFamily.slug == slug))
    if not family:
        raise HTTPException(404, "Detection family bulunamadı.")
    summary_items, _ = family_summaries(db, FamilySearch(filters=FamilyFilters(search=family.name), limit=50))
    summary = next((item for item in summary_items if item["id"] == family.id), None)
    rows, total = family_rules(db, family.id, offset, limit)
    mitre = family_mitre_profile(db, family.id)
    provenance = {str(getattr(value, "value", value)): count for value, count in db.execute(
        select(RuleFamilyAssignment.provenance, func.count()).where(RuleFamilyAssignment.family_id == family.id)
        .group_by(RuleFamilyAssignment.provenance))}
    rules = []
    for rule, classification, assignment in rows:
        item = rule_to_read(rule, classification).model_dump(mode="json")
        item["family_assignment"] = {
            "provenance": str(getattr(assignment.provenance, "value", assignment.provenance)),
            "evidence": assignment.evidence, "algorithm_version": assignment.algorithm_version,
            "source_classification_id": assignment.source_classification_id,
        }
        rules.append(item)
    return {"family": summary or {"id": family.id, "slug": family.slug, "name": family.name,
                                   "family_type": family.family_type.value, "rule_count": total,
                                   "protocols": [], "categories": [], "mitre_ids": [], "entity_types": [],
                                   "mitre_count": 0, "product_status": {}},
            "provenance": provenance, "mitre": mitre, "rules": rules, "total": total, "offset": offset, "limit": limit,
            "page": offset // limit + 1, "total_pages": max(1, (total + limit - 1) // limit)}
