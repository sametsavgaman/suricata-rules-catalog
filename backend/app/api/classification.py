from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_classification_service
from app.api.schemas import BatchClassificationResponse, ClassificationRead
from app.database.models import ClassificationStatus
from app.database.repository import RuleRepository
from app.database.session import get_db
from app.services.classification_service import ClassificationService


router = APIRouter(tags=["classification"])


@router.post("/rules/{sid}/classify", response_model=ClassificationRead)
async def classify_rule(
    sid: int,
    force: bool = False,
    db: Session = Depends(get_db),
    service: ClassificationService = Depends(get_classification_service),
):
    rule = RuleRepository(db).by_sid(sid)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return await service.classify(rule, force=force)


@router.post("/classify/all", response_model=BatchClassificationResponse)
async def classify_all(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    service: ClassificationService = Depends(get_classification_service),
):
    provider_name = (
        getattr(service.provider, "provider_name", None)
        or service.provider.__class__.__name__.replace("ClassificationProvider", "").lower()
        or "unknown"
    )
    rules = RuleRepository(db).unclassified(
        limit,
        target_provider=provider_name,
        target_model=service.provider.model_name,
        classifier_version=service.settings.classifier_version,
    )
    counts = {status: 0 for status in ClassificationStatus}
    for rule in rules:
        result = await service.classify(rule)
        counts[result.classification_status] += 1
    return BatchClassificationResponse(
        requested=len(rules),
        auto_classified=counts[ClassificationStatus.AUTO_CLASSIFIED],
        review_required=counts[ClassificationStatus.REVIEW_REQUIRED],
        failed=counts[ClassificationStatus.FAILED],
    )
