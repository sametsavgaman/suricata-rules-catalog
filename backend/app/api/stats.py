from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import StatsResponse
from app.database.models import Classification, ClassificationStatus, Rule, ManualReview
from app.database.session import get_db


router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    # Provider failures are diagnostic attempts, not reviewable classifications.
    # Report the latest successful/reviewable result per rule; rules with no such
    # result are counted as failed below.
    latest_ids = select(func.max(Classification.id).label("id")).where(
        Classification.classification_status != ClassificationStatus.FAILED
    ).group_by(Classification.rule_id).subquery()
    latest = select(Classification).join(latest_ids, Classification.id == latest_ids.c.id).subquery()

    total_rules = db.scalar(select(func.count(Rule.id))) or 0
    classified = db.scalar(select(func.count()).select_from(latest).where(latest.c.classification_status == ClassificationStatus.AUTO_CLASSIFIED)) or 0
    review = db.scalar(select(func.count()).select_from(latest).where(latest.c.classification_status == ClassificationStatus.REVIEW_REQUIRED)) or 0
    failed = max(0, total_rules - classified - review)

    def distribution(column, limit: int | None = None):
        stmt = select(column, func.count().label("count")).select_from(latest).where(column.is_not(None)).group_by(column).order_by(func.count().desc())
        if limit:
            stmt = stmt.limit(limit)
        return db.execute(stmt).all()

    categories = {name: count for name, count in distribution(latest.c.category)}
    entities = [{"name": name, "count": count} for name, count in distribution(latest.c.detected_entity, 10)]
    techniques = [{"id": technique_id, "name": name, "count": count} for technique_id, name, count in db.execute(
        select(latest.c.mitre_technique_id, latest.c.mitre_technique, func.count())
        .select_from(latest).where(latest.c.mitre_technique_id.is_not(None))
        .group_by(latest.c.mitre_technique_id, latest.c.mitre_technique).order_by(func.count().desc()).limit(10)
    ).all()]
    avg_confidence = db.scalar(select(func.avg(latest.c.confidence)).select_from(latest).where(latest.c.classification_status != ClassificationStatus.FAILED)) or 0.0
    # Human-review counters must be scoped to rules that actually have a
    # successful classification.  Previously the remainder of *all* rules
    # was added to UNREVIEWED, which made every unclassified/failed rule look
    # like it was waiting for a human decision.
    review_ids = select(func.max(ManualReview.id).label("id")).group_by(ManualReview.rule_id).subquery()
    latest_reviews = select(ManualReview).join(review_ids, ManualReview.id == review_ids.c.id).subquery()
    manual = {}
    for name in ("APPROVED", "REJECTED", "NEEDS_REVIEW"):
        manual[name] = db.scalar(
            select(func.count()).select_from(latest)
            .join(latest_reviews, latest_reviews.c.rule_id == latest.c.rule_id)
            .where(latest_reviews.c.status == name)
        ) or 0
    reviewed_classified = sum(manual.values())
    # The dashboard's Manual Unreviewed queue is the set of rules that still
    # have no usable AI classification.  Keep the narrower classified-but-not
    # human-reviewed count separately for clients that need that distinction.
    manual["UNREVIEWED"] = max(0, total_rules - classified)
    manual["CLASSIFIED_UNREVIEWED"] = max(0, classified + review - reviewed_classified)
    manual["NOT_CLASSIFIED"] = manual["UNREVIEWED"]
    return StatsResponse(
        total_rules=total_rules,
        classified_rules=classified,
        review_required=review,
        failed=failed,
        category_distribution=categories,
        top_detected_entities=entities,
        top_mitre_techniques=techniques,
        average_confidence=round(float(avg_confidence), 4),
        manual_review=manual,
    )
