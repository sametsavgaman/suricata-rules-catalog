from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.schemas import ClassificationRead, ImportFileResult, ImportResponse, RuleListResponse, RuleRead, RuleNeighbors, rule_to_read, ManualReviewRequest, ManualReviewResponse, ManualReviewHistoryResponse
from app.database.models import Classification, ClassificationStatus, Rule, ManualReview
from app.database.repository import RuleRepository
from app.database.session import get_db
from app.ingestion.rule_loader import RuleLoader
from app.parser.suricata_parser import SuricataRuleParser


router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=RuleListResponse)
def list_rules(
    category: str | None = None,
    subcategory: str | None = None,
    detected_entity: str | None = None,
    mitre_technique_id: str | None = None,
    entity_type: str | None = None,
    status: ClassificationStatus | None = None,
    protocol: str | None = None,
    classtype: str | None = None,
    confidence: float | None = Query(None, ge=0, le=1),
    confidence_min: float | None = Query(None, ge=0, le=1),
    confidence_max: float | None = Query(None, ge=0, le=1),
    entity_status: str | None = Query(None, pattern="^(has|none)$"),
    mitre_status: str | None = Query(None, pattern="^(has|none)$"),
    mitre_tactic: str | None = None,
    kill_chain_phase: str | None = None,
    has_cve: str | None = Query(None, pattern="^(has|none)$"),
    inspection_batch: str | None = None,
    provider: str | None = None,
    model_name: str | None = None,
    classifier_version: str | None = None,
    inference_mode: str | None = None,
    run_id: str | None = None,
    mitre_mapping_method: str | None = None,
    manual_review_status: str | None = Query(None, pattern="^(UNREVIEWED|APPROVED|REJECTED|NEEDS_REVIEW)$"),
    sort: str = Query("sid_desc"),
    search: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    # Failed provider attempts are historical diagnostics, not the current
    # user-facing classification. Prefer the latest non-failed result so an
    # old 404 does not mask a later successful classification.
    selection = [column == value for column, value in (
        (Classification.provider, provider), (Classification.model_name, model_name),
        (Classification.classifier_version, classifier_version),
        (Classification.inference_mode, inference_mode), (Classification.run_id, run_id),
    ) if value is not None]
    latest_id = select(func.max(Classification.id)).where(
        Classification.rule_id == Rule.id,
        Classification.classification_status != ClassificationStatus.FAILED,
        *selection,
    ).correlate(Rule).scalar_subquery()
    stmt = select(Rule, Classification).outerjoin(Classification, Classification.id == latest_id)
    filters = []
    mapping = {
        "category": (Classification.category, category),
        "subcategory": (Classification.subcategory, subcategory),
        "detected_entity": (Classification.detected_entity, detected_entity),
        "mitre_technique_id": (Classification.mitre_technique_id, mitre_technique_id),
        "entity_type": (Classification.entity_type, entity_type),
        "classification_status": (Classification.classification_status, status),
        "mitre_tactic": (Classification.mitre_tactic, mitre_tactic),
        "kill_chain_phase": (Classification.cyber_kill_chain_phase, kill_chain_phase),
        "inspection_batch": (Classification.inspection_batch, inspection_batch),
        "mitre_mapping_method": (Classification.mitre_mapping_method, mitre_mapping_method),
        "provider": (Classification.provider, provider), "model_name": (Classification.model_name, model_name),
        "classifier_version": (Classification.classifier_version, classifier_version),
        "inference_mode": (Classification.inference_mode, inference_mode), "run_id": (Classification.run_id, run_id),
        "protocol": (Rule.protocol, protocol),
        "classtype": (Rule.classtype, classtype),
    }
    filters.extend(column == value for column, value in mapping.values() if value is not None)
    if manual_review_status:
        review_scope = (ManualReview.rule_id == Rule.id, ManualReview.classification_id == Classification.id)
        latest_review = select(func.max(ManualReview.id)).where(*review_scope).correlate(Rule, Classification).scalar_subquery()
        review_exists = select(ManualReview.id).where(ManualReview.id == latest_review, ManualReview.status == manual_review_status).exists()
        filters.append(or_(~select(ManualReview.id).where(*review_scope).exists(), review_exists) if manual_review_status == "UNREVIEWED" else review_exists)
    if confidence is not None: filters.append(Classification.confidence >= confidence)
    if confidence_min is not None: filters.append(Classification.confidence >= confidence_min)
    if confidence_max is not None: filters.append(Classification.confidence <= confidence_max)
    if entity_status == "has": filters.append(Classification.detected_entity.is_not(None))
    if entity_status == "none": filters.append(Classification.detected_entity.is_(None))
    if mitre_status == "has": filters.append(Classification.mitre_technique_id.is_not(None))
    if mitre_status == "none": filters.append(Classification.mitre_technique_id.is_(None))
    if has_cve == "has": filters.append(Rule.raw_rule.ilike("%cve-%"))
    if has_cve == "none": filters.append(~Rule.raw_rule.ilike("%cve-%"))
    if search:
        pattern = f"%{search}%"
        sid_filter = Rule.sid == int(search) if search.isdigit() else False
        filters.append(or_(sid_filter, Rule.msg.ilike(pattern), Rule.raw_rule.ilike(pattern),
                           Classification.detected_entity.ilike(pattern), Classification.category.ilike(pattern),
                           Classification.subcategory.ilike(pattern), Classification.mitre_technique_id.ilike(pattern),
                           Classification.mitre_technique.ilike(pattern), Classification.mitre_tactic.ilike(pattern),
                           Classification.cyber_kill_chain_phase.ilike(pattern)))
    if filters:
        stmt = stmt.where(and_(*filters))
    count = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    ordering = {"sid_asc": Rule.sid.asc(), "confidence_desc": Classification.confidence.desc(),
                "confidence_asc": Classification.confidence.asc(), "category": Classification.category.asc(),
                "recent": Classification.created_at.desc()}.get(sort, Rule.sid.desc())
    rows = db.execute(stmt.order_by(ordering, Rule.sid.desc()).offset(offset).limit(limit)).all()
    pages = max(1, (count + limit - 1) // limit)
    return RuleListResponse(
        items=[rule_to_read(rule, classification) for rule, classification in rows],
        total=count,
        offset=offset,
        limit=limit,
        page=(offset // limit) + 1,
        total_pages=pages,
    )


@router.get("/{sid}/neighbors", response_model=RuleNeighbors)
def rule_neighbors(sid: int, db: Session = Depends(get_db)):
    previous = db.scalar(select(Rule.sid).where(Rule.sid < sid).order_by(Rule.sid.desc()).limit(1))
    next_sid = db.scalar(select(Rule.sid).where(Rule.sid > sid).order_by(Rule.sid.asc()).limit(1))
    return RuleNeighbors(previous_sid=previous, next_sid=next_sid)

@router.get("/{sid}/classifications")
def list_classifications(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    return {"rule": {"sid": rule.sid, "rev": rule.rev}, "classifications": [ClassificationRead.model_validate(c).model_dump(mode="json") for c in sorted(rule.classifications, key=lambda x: (x.created_at, x.id), reverse=True)]}

@router.get("/filters")
def classification_filters(db: Session = Depends(get_db)):
    # Only current provider-owned identities belong in the interactive model
    # selector. Legacy imports encoded model names such as ``v2.1:...`` and
    # had no provider; retaining them made empty filter choices look valid.
    active = and_(Classification.provider.in_(["gemini", "ollama"]),
                  ~Classification.model_name.like("v%:%"))
    return {"models": [x for (x,) in db.execute(select(Classification.model_name).where(Classification.model_name.is_not(None), active).distinct()).all()],
            "providers": [x for (x,) in db.execute(select(Classification.provider).where(Classification.provider.is_not(None), active).distinct()).all()],
            "classifier_versions": [x for (x,) in db.execute(select(Classification.classifier_version).distinct()).all()],
            "inference_modes": [x for (x,) in db.execute(select(Classification.inference_mode).where(Classification.inference_mode.is_not(None)).distinct()).all()],
            "runs": [x for (x,) in db.execute(select(Classification.run_id).where(Classification.run_id.is_not(None)).distinct()).all()]}


@router.get("/{sid}", response_model=RuleRead)
def get_rule(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule_to_read(rule)

@router.get("/{sid}/review/history", response_model=ManualReviewHistoryResponse)
def review_history(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    return ManualReviewHistoryResponse(items=[ManualReviewResponse(status=x.status,note=x.note,reviewer_type=x.reviewer_type,reviewed_at=x.created_at) for x in rule.manual_reviews])

@router.post("/{sid}/review", response_model=ManualReviewResponse)
def save_review(sid: int, payload: ManualReviewRequest, db: Session = Depends(get_db)):
    if payload.status not in {"UNREVIEWED","APPROVED","REJECTED","NEEDS_REVIEW"}: raise HTTPException(400,"Invalid manual review status")
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    classification = next((c for c in rule.classifications if payload.classification_id and c.id == payload.classification_id), None)
    if payload.classification_id and classification is None: raise HTTPException(400, "Classification does not belong to this rule")
    classification = classification or (rule.classifications[-1] if rule.classifications else None)
    matching = [r for r in rule.manual_reviews if r.classification_id == (classification.id if classification else None)]
    current = matching[-1] if matching else None
    if current and current.status == payload.status and current.note == payload.note: return ManualReviewResponse(status=current.status,note=current.note,reviewer_type=current.reviewer_type,reviewed_at=current.created_at)
    row=ManualReview(rule_id=rule.id,classification_id=classification.id if classification else None,status=payload.status,note=payload.note,reviewer_type="HUMAN")
    db.add(row); db.commit(); db.refresh(row)
    return ManualReviewResponse(status=row.status,note=row.note,reviewer_type=row.reviewer_type,reviewed_at=row.created_at)


@router.post("/import", response_model=ImportResponse)
async def import_rules(files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    loader, parser, repository = RuleLoader(), SuricataRuleParser(), RuleRepository(db)
    results: list[ImportFileResult] = []
    total_imported = total_skipped = total_failed = 0
    for upload in files:
        errors: list[str] = []
        imported = skipped = 0
        try:
            text = (await upload.read()).decode("utf-8", errors="replace")
            loaded = loader.load_text(text)
        except Exception as exc:
            loaded = None
            errors.append(str(exc))
        if loaded:
            for index, raw in enumerate(loaded.rules, start=1):
                try:
                    _, created = repository.upsert(parser.parse(raw), upload.filename)
                    imported += int(created)
                    skipped += int(not created)
                except Exception as exc:
                    errors.append(f"rule {index}: {exc}")
        db.commit()
        total_imported += imported
        total_skipped += skipped
        total_failed += len(errors)
        results.append(ImportFileResult(filename=upload.filename or "upload.rules", discovered=len(loaded.rules) if loaded else 0, imported=imported, skipped=skipped, errors=errors))
    return ImportResponse(files=results, imported=total_imported, skipped=total_skipped, failed=total_failed)
