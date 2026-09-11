import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.api.schemas import ClassificationRead, ImportFileResult, ImportResponse, ExistingRulesetPreviewFile, ExistingRulesetPreviewResponse, ExistingRulesetImportFile, ExistingRulesetImportResponse, ProductRulesetBatchRead, RuleListResponse, RuleRead, RuleNeighbors, rule_to_read, ManualReviewRequest, ManualReviewResponse, ManualReviewHistoryResponse, ProductDecisionRequest, ProductDecisionRead, ProductHistoryItem, ClassificationOverrideRequest, ForcedMitreRequest, ForcedMitreRead, ForcedMitreState
from app.database.models import Classification, ClassificationStatus, ClassificationOverride, DetectionFamily, ForcedMitreMapping, ProductRulesetImportBatch, ProductRulesetImportItem, Rule, RuleFamilyAssignment, ManualReview, ProductStatus, RuleProductDecision, RuleProductDecisionHistory
from app.database.repository import RuleRepository
from app.database.session import get_db
from app.ingestion.rule_loader import RuleLoader
from app.parser.suricata_parser import SuricataRuleParser
from app.agent.schemas import EntityType
from app.knowledge.kill_chain import KillChainPhase
from app.knowledge.mitre_repository import MitreRepository
from app.knowledge.taxonomy import Category, SUBCATEGORIES
from app.services.product_ruleset_import import process_product_ruleset_batch, retry_product_ruleset_batch
from app.services.forced_mitre import propose_forced_mitre
from app.services.runtime_config import effective_settings
from app.services.dashboard_cache import clear_dashboard_cache, get_dashboard_cache, set_dashboard_cache
from app.config import get_settings


router = APIRouter(prefix="/rules", tags=["rules"])
MAX_BASELINE_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_BASELINE_TOTAL_BYTES = 50 * 1024 * 1024
MAX_BASELINE_FILES = 10
MAX_BASELINE_RULES_PER_FILE = 100_000
MAX_BASELINE_RULE_BYTES = 64 * 1024
MAX_BASELINE_PARSE_ERRORS = 100
BASELINE_ALLOWED_CONTENT_TYPES = {"", "text/plain", "application/octet-stream", "application/x-suricata-rules"}


@dataclass(frozen=True)
class PreparedRulesetUpload:
    filename: str
    rules: list[str]
    errors: list[str]
    size: int


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
    product_status: ProductStatus | None = None,
    family: list[str] | None = Query(None, max_length=140),
    sort: str = Query("sid_desc"),
    search: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    cacheable_dashboard_page = (
        offset == 0 and limit == 50 and sort == "sid_desc" and not family and
        all(value is None for value in (
            category, subcategory, detected_entity, mitre_technique_id, entity_type, status,
            protocol, classtype, confidence, confidence_min, confidence_max, entity_status,
            mitre_status, mitre_tactic, kill_chain_phase, has_cve, inspection_batch, provider,
            model_name, classifier_version, inference_mode, run_id, mitre_mapping_method,
            manual_review_status, product_status, search,
        ))
    )
    if cacheable_dashboard_page:
        cached = get_dashboard_cache(db, "initial-rule-page")
        if cached is not None:
            return RuleListResponse.model_validate(cached)

    # Failed provider attempts are historical diagnostics, not the current
    # user-facing classification. Prefer the latest non-failed result so an
    # old 404 does not mask a later successful classification.
    selection = [column == value for column, value in (
        (Classification.provider, provider), (Classification.model_name, model_name),
        (Classification.classifier_version, classifier_version),
        (Classification.inference_mode, inference_mode), (Classification.run_id, run_id),
    ) if value is not None]
    latest_scope = [Classification.classification_status != ClassificationStatus.FAILED, *selection]
    latest_ids = (select(Classification.rule_id, func.max(Classification.id).label("latest_id"))
                  .where(*latest_scope)
                  .group_by(Classification.rule_id).subquery())
    category_rule_ids = None
    if category is not None:
        # Filter against the globally latest successful classification. A
        # category must not resurrect an older classification for a rule.
        category_rule_ids = (select(latest_ids.c.rule_id)
                             .join(Classification, Classification.id == latest_ids.c.latest_id)
                             .where(Classification.category == category).subquery())
    stmt = select(Rule, Classification, RuleProductDecision).options(
        selectinload(Rule.manual_reviews),
        selectinload(Rule.classification_overrides),
        selectinload(Rule.family_assignments).selectinload(RuleFamilyAssignment.family),
    )
    if category_rule_ids is not None:
        stmt = stmt.join(category_rule_ids, category_rule_ids.c.rule_id == Rule.id)
    stmt = stmt.outerjoin(latest_ids, latest_ids.c.rule_id == Rule.id)
    stmt = (stmt
            .outerjoin(Classification, Classification.id == latest_ids.c.latest_id)
            .outerjoin(RuleProductDecision, RuleProductDecision.rule_id == Rule.id)
            .outerjoin(RuleFamilyAssignment, RuleFamilyAssignment.rule_id == Rule.id)
            .outerjoin(DetectionFamily, DetectionFamily.id == RuleFamilyAssignment.family_id))
    filters = []
    mapping = {
        "category": (Classification.category, None),
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
        "product_status": (RuleProductDecision.status, product_status),
        "classtype": (Rule.classtype, classtype),
        "family": (DetectionFamily.slug, family),
    }
    for column, value in mapping.values():
        if value is not None:
            filters.append(column.in_(value) if isinstance(value, list) else column == value)
    if manual_review_status:
        review_scope = (ManualReview.rule_id == Rule.id, ManualReview.classification_id == Classification.id)
        latest_review = select(func.max(ManualReview.id)).where(*review_scope).correlate(Rule, Classification).scalar_subquery()
        review_exists = select(ManualReview.id).where(ManualReview.id == latest_review, ManualReview.status == manual_review_status).exists()
        if manual_review_status == "UNREVIEWED":
            # UNREVIEWED is a human-review state for an existing
            # classification, not a synonym for "no classification".
            filters.append(Classification.id.is_not(None))
            filters.append(or_(~select(ManualReview.id).where(*review_scope).exists(), review_exists))
        else:
            filters.append(review_exists)
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
                           Classification.cyber_kill_chain_phase.ilike(pattern), DetectionFamily.name.ilike(pattern)))
    if filters:
        stmt = stmt.where(and_(*filters))
    count_query = stmt.subquery()
    # Joins used for family/product filters can produce more than one row for
    # a rule; pagination totals must count unique rule records.
    count = db.scalar(select(func.count(func.distinct(count_query.c.id)))) or 0
    ordering = {"sid_asc": Rule.sid.asc(), "confidence_desc": Classification.confidence.desc(),
                "confidence_asc": Classification.confidence.asc(), "category": Classification.category.asc(),
                "recent": Classification.created_at.desc()}.get(sort, Rule.sid.desc())
    rows = db.execute(stmt.order_by(ordering, Rule.sid.desc()).offset(offset).limit(limit)).all()
    pages = max(1, (count + limit - 1) // limit)
    response = RuleListResponse(
        items=[rule_to_read(rule, classification, product_decision, include_classification_options=False)
               for rule, classification, product_decision in rows],
        total=count,
        offset=offset,
        limit=limit,
        page=(offset // limit) + 1,
        total_pages=pages,
    )
    if cacheable_dashboard_page:
        set_dashboard_cache(db, "initial-rule-page", response.model_dump(mode="json"))
    return response


def warm_rule_explorer(db: Session) -> None:
    """Build the exact unfiltered first page used by the Rule Explorer."""
    list_rules(
        category=None, subcategory=None, detected_entity=None, mitre_technique_id=None,
        entity_type=None, status=None, protocol=None, classtype=None, confidence=None,
        confidence_min=None, confidence_max=None, entity_status=None, mitre_status=None,
        mitre_tactic=None, kill_chain_phase=None, has_cve=None, inspection_batch=None,
        provider=None, model_name=None, classifier_version=None, inference_mode=None,
        run_id=None, mitre_mapping_method=None, manual_review_status=None,
        product_status=None, family=None, sort="sid_desc", search=None, offset=0, limit=50,
        db=db,
    )


def _validated_ruleset_filename(upload: UploadFile) -> tuple[str | None, str | None]:
    filename = (upload.filename or "").strip()
    if not filename or len(filename) > 128 or any(ord(char) < 32 for char in filename):
        return None, "Filename is missing, too long, or contains control characters"
    if PurePosixPath(filename).name != filename or PureWindowsPath(filename).name != filename:
        return None, "Filename must not contain a path"
    if not filename.casefold().endswith(".rules"):
        return None, "Only .rules files are accepted; ZIP, JSON, PDF, executable, and generic text files are rejected"
    return filename, None


async def _read_ruleset_upload(upload: UploadFile) -> PreparedRulesetUpload:
    filename, filename_error = _validated_ruleset_filename(upload)
    display_name = filename or "rejected-upload.rules"
    size_hint = int(getattr(upload, "size", 0) or 0)
    if filename_error:
        await upload.close()
        return PreparedRulesetUpload(display_name, [], [filename_error], size_hint)
    if size_hint > MAX_BASELINE_UPLOAD_BYTES:
        await upload.close()
        return PreparedRulesetUpload(display_name, [], ["File exceeds the 25 MB ruleset limit"], size_hint)
    content_type = (upload.content_type or "").split(";", 1)[0].strip().casefold()
    if content_type not in BASELINE_ALLOWED_CONTENT_TYPES:
        await upload.close()
        return PreparedRulesetUpload(display_name, [], [f"Unsupported content type: {content_type or 'unknown'}"], size_hint)
    payload = bytearray()
    try:
        while chunk := await upload.read(64 * 1024):
            payload.extend(chunk)
            if len(payload) > MAX_BASELINE_UPLOAD_BYTES:
                return PreparedRulesetUpload(display_name, [], ["File exceeds the 25 MB ruleset limit"], len(payload))
        try:
            text = bytes(payload).decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            return PreparedRulesetUpload(display_name, [], ["Ruleset must be valid UTF-8 plain text"], len(payload))
        if "\x00" in text or any(ord(char) < 32 and char not in "\r\n\t" for char in text):
            return PreparedRulesetUpload(display_name, [], ["Binary data or unsupported control characters detected"], len(payload))
        try:
            loaded = RuleLoader().load_text(text)
        except ValueError:
            return PreparedRulesetUpload(display_name, [], ["Ruleset contains an incomplete multiline rule"], len(payload))
        if not loaded.rules:
            return PreparedRulesetUpload(display_name, [], ["No active Suricata rules were found"], len(payload))
        if len(loaded.rules) > MAX_BASELINE_RULES_PER_FILE:
            return PreparedRulesetUpload(display_name, [], ["File exceeds the 100,000-rule safety limit"], len(payload))
        if any(len(rule.encode("utf-8")) > MAX_BASELINE_RULE_BYTES for rule in loaded.rules):
            return PreparedRulesetUpload(display_name, [], ["A rule exceeds the 64 KB per-rule safety limit"], len(payload))
        return PreparedRulesetUpload(display_name, loaded.rules, [], len(payload))
    except Exception:
        return PreparedRulesetUpload(display_name, [], ["Ruleset could not be read safely"], len(payload))
    finally:
        await upload.close()


async def _prepare_ruleset_uploads(files: list[UploadFile]) -> list[PreparedRulesetUpload]:
    if not files:
        raise HTTPException(422, "At least one .rules file is required")
    if len(files) > MAX_BASELINE_FILES:
        raise HTTPException(413, f"A maximum of {MAX_BASELINE_FILES} files can be inspected at once")
    prepared: list[PreparedRulesetUpload] = []
    total_bytes = 0
    for upload in files:
        item = await _read_ruleset_upload(upload)
        total_bytes += item.size
        if total_bytes > MAX_BASELINE_TOTAL_BYTES:
            raise HTTPException(413, "Combined upload exceeds the 50 MB safety limit")
        prepared.append(item)
    return prepared


@router.post("/existing/preview", response_model=ExistingRulesetPreviewResponse)
async def preview_existing_ruleset(files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    parser = SuricataRuleParser()
    uploads = await _prepare_ruleset_uploads(files)
    results: list[ExistingRulesetPreviewFile] = []
    totals = {"discovered": 0, "exact_matches": 0, "new_catalog_rules": 0,
              "revision_updates": 0, "reusable_classifications": 0,
              "gemini_candidates": 0, "duplicates": 0, "failed": 0}
    seen: set[tuple[int, int]] = set()
    for upload in uploads:
        raw_rules, errors = upload.rules, list(upload.errors)
        exact_matches = new_catalog_rules = revision_updates = duplicates = 0
        reusable_classifications = gemini_candidates = 0
        for index, raw in enumerate(raw_rules, start=1):
            try:
                parsed = parser.parse(raw)
                key = (parsed.sid, parsed.rev)
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                exact = db.scalar(select(Rule).where(Rule.sid == parsed.sid, Rule.rev == parsed.rev))
                if exact is not None:
                    exact_matches += 1
                    reusable = db.scalar(select(Classification.id).where(
                        Classification.rule_id == exact.id,
                        Classification.classification_status != ClassificationStatus.FAILED,
                    ).limit(1))
                    if reusable is not None:
                        reusable_classifications += 1
                    else:
                        gemini_candidates += 1
                else:
                    new_catalog_rules += 1
                    gemini_candidates += 1
                    if db.scalar(select(Rule.id).where(Rule.sid == parsed.sid).limit(1)) is not None:
                        revision_updates += 1
            except Exception as exc:
                if len(errors) < MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"rule {index}: {exc}")
                if len(errors) >= MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"Parsing stopped after {MAX_BASELINE_PARSE_ERRORS} errors")
                    break
        item = ExistingRulesetPreviewFile(
            filename=upload.filename, discovered=len(raw_rules),
            exact_matches=exact_matches, new_catalog_rules=new_catalog_rules,
            revision_updates=revision_updates, reusable_classifications=reusable_classifications,
            gemini_candidates=gemini_candidates, duplicates=duplicates, errors=errors,
        )
        results.append(item)
        totals["discovered"] += item.discovered
        totals["exact_matches"] += exact_matches
        totals["new_catalog_rules"] += new_catalog_rules
        totals["revision_updates"] += revision_updates
        totals["reusable_classifications"] += reusable_classifications
        totals["gemini_candidates"] += gemini_candidates
        totals["duplicates"] += duplicates
        totals["failed"] += len(errors)
    return ExistingRulesetPreviewResponse(files=results, **totals)


@router.post("/existing/import", response_model=ExistingRulesetImportResponse)
async def import_existing_ruleset(background_tasks: BackgroundTasks, files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    parser, repository = SuricataRuleParser(), RuleRepository(db)
    uploads = await _prepare_ruleset_uploads(files)
    results: list[ExistingRulesetImportFile] = []
    totals = {"discovered": 0, "matched_existing": 0, "imported": 0,
              "marked_existing": 0, "already_marked": 0, "duplicates": 0, "failed": 0}
    seen: set[tuple[int, int]] = set()
    imported_rules: dict[int, Rule] = {}
    filenames: list[str] = []
    for upload in uploads:
        raw_rules, errors = upload.rules, list(upload.errors)
        matched_existing = imported = marked_existing = already_marked = duplicates = 0
        filename = upload.filename
        filenames.append(filename)
        for index, raw in enumerate(raw_rules, start=1):
            try:
                parsed = parser.parse(raw)
                key = (parsed.sid, parsed.rev)
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                rule, created = repository.upsert(parsed, filename)
                imported_rules[rule.id] = rule
                imported += int(created)
                matched_existing += int(not created)
                decision = db.scalar(select(RuleProductDecision).where(RuleProductDecision.rule_id == rule.id))
                if decision is not None and decision.status == ProductStatus.ALREADY_INTEGRATED:
                    already_marked += 1
                else:
                    previous = decision.status.value if decision else ProductStatus.NOT_EVALUATED.value
                    note = f"Product baseline import: {filename}"
                    if decision is None:
                        decision = RuleProductDecision(rule_id=rule.id, status=ProductStatus.ALREADY_INTEGRATED, note=note)
                        db.add(decision)
                    else:
                        decision.status = ProductStatus.ALREADY_INTEGRATED
                        decision.note = note
                    db.add(RuleProductDecisionHistory(
                        rule_id=rule.id, from_status=previous,
                        to_status=ProductStatus.ALREADY_INTEGRATED.value, note=note,
                    ))
                    marked_existing += 1
            except Exception as exc:
                if len(errors) < MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"rule {index}: {exc}")
                if len(errors) >= MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"Parsing stopped after {MAX_BASELINE_PARSE_ERRORS} errors")
                    break
        item = ExistingRulesetImportFile(
            filename=filename, discovered=len(raw_rules), matched_existing=matched_existing,
            imported=imported, marked_existing=marked_existing, already_marked=already_marked,
            duplicates=duplicates, errors=errors,
        )
        results.append(item)
        totals["discovered"] += item.discovered
        totals["matched_existing"] += matched_existing
        totals["imported"] += imported
        totals["marked_existing"] += marked_existing
        totals["already_marked"] += already_marked
        totals["duplicates"] += duplicates
        totals["failed"] += len(errors)
    db.flush()
    reusable = 0
    queued_rules: list[Rule] = []
    for rule in imported_rules.values():
        existing_classification = db.scalar(select(Classification.id).where(
            Classification.rule_id == rule.id,
            Classification.classification_status != ClassificationStatus.FAILED,
        ).limit(1))
        if existing_classification is not None:
            reusable += 1
        else:
            queued_rules.append(rule)

    batch_id = None
    if queued_rules:
        batch_id = f"product-import-{uuid4().hex[:16]}"
        db.add(ProductRulesetImportBatch(
            batch_id=batch_id,
            filenames=list(dict.fromkeys(filenames)),
            status="PENDING",
            provider="gemini",
            classifier_version="v2.1",
            discovered=sum(totals[key] for key in ("matched_existing", "imported")),
            reused_classifications=reusable,
            queued=len(queued_rules),
        ))
        db.add_all(ProductRulesetImportItem(batch_id=batch_id, rule_id=rule.id) for rule in queued_rules)
    db.commit()
    clear_dashboard_cache()
    if batch_id:
        background_tasks.add_task(process_product_ruleset_batch, batch_id)
    return ExistingRulesetImportResponse(
        files=results, **totals, reused_classifications=reusable,
        queued_for_gemini=len(queued_rules), classification_batch_id=batch_id,
    )


@router.get("/existing/batches/{batch_id}", response_model=ProductRulesetBatchRead)
def get_existing_ruleset_batch(batch_id: str, db: Session = Depends(get_db)):
    batch = db.get(ProductRulesetImportBatch, batch_id)
    if batch is None:
        raise HTTPException(404, "Product ruleset classification batch not found")
    return batch


@router.post("/existing/batches/{batch_id}/retry", response_model=ProductRulesetBatchRead)
def retry_existing_ruleset_batch(batch_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    batch = db.get(ProductRulesetImportBatch, batch_id)
    if batch is None:
        raise HTTPException(404, "Product ruleset classification batch not found")
    if batch.status == "RUNNING":
        raise HTTPException(409, "Product ruleset classification batch is already running")
    if not retry_product_ruleset_batch(batch_id):
        raise HTTPException(409, "Product ruleset classification batch could not be retried")
    db.expire_all()
    batch = db.get(ProductRulesetImportBatch, batch_id)
    background_tasks.add_task(process_product_ruleset_batch, batch_id)
    return batch


@router.get("/{sid}/neighbors", response_model=RuleNeighbors)
def rule_neighbors(sid: int, db: Session = Depends(get_db)):
    previous = db.scalar(select(Rule.sid).where(Rule.sid < sid).order_by(Rule.sid.desc()).limit(1))
    next_sid = db.scalar(select(Rule.sid).where(Rule.sid > sid).order_by(Rule.sid.asc()).limit(1))
    return RuleNeighbors(previous_sid=previous, next_sid=next_sid)

@router.get("/{sid}/product", response_model=ProductDecisionRead)
def get_product_decision(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    decision = db.scalar(select(RuleProductDecision).where(RuleProductDecision.rule_id == rule.id))
    if not decision:
        decision = RuleProductDecision(rule_id=rule.id, status=ProductStatus.NOT_EVALUATED)
        db.add(decision); db.commit(); db.refresh(decision)
    return decision

@router.get("/{sid}/product/history", response_model=list[ProductHistoryItem])
def product_history(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    return db.scalars(select(RuleProductDecisionHistory).where(RuleProductDecisionHistory.rule_id == rule.id).order_by(RuleProductDecisionHistory.created_at.desc())).all()

@router.put("/{sid}/product", response_model=ProductDecisionRead)
def update_product_decision(sid: int, payload: ProductDecisionRequest, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    decision = db.scalar(select(RuleProductDecision).where(RuleProductDecision.rule_id == rule.id))
    previous = decision.status.value if decision else ProductStatus.NOT_EVALUATED.value
    if decision is None:
        decision = RuleProductDecision(rule_id=rule.id, status=payload.status, note=payload.note)
        db.add(decision)
    else:
        decision.status, decision.note = payload.status, payload.note
    db.add(RuleProductDecisionHistory(rule_id=rule.id, from_status=previous, to_status=payload.status.value, note=payload.note))
    db.commit(); db.refresh(decision)
    clear_dashboard_cache()
    return decision

@router.get("/{sid}/classifications")
def list_classifications(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    return {"rule": {"sid": rule.sid, "rev": rule.rev}, "classifications": [ClassificationRead.model_validate(c).model_dump(mode="json") for c in sorted(rule.classifications, key=lambda x: (x.created_at, x.id), reverse=True)]}

@router.get("/filters")
def classification_filters(db: Session = Depends(get_db)):
    cached = get_dashboard_cache(db, "classification-filters")
    if cached is not None:
        return cached

    # Only current provider-owned identities belong in the interactive model
    # selector. Legacy imports encoded model names such as ``v2.1:...`` and
    # had no provider; retaining them made empty filter choices look valid.
    active = and_(Classification.provider.in_(["gemini", "ollama"]),
                  ~Classification.model_name.like("v%:%"))
    result = {"models": [x for (x,) in db.execute(select(Classification.model_name).where(Classification.model_name.is_not(None), active).distinct()).all()],
              "providers": [x for (x,) in db.execute(select(Classification.provider).where(Classification.provider.is_not(None), active).distinct()).all()],
              "classifier_versions": [x for (x,) in db.execute(select(Classification.classifier_version).distinct()).all()],
              "inference_modes": [x for (x,) in db.execute(select(Classification.inference_mode).where(Classification.inference_mode.is_not(None)).distinct()).all()]}
    set_dashboard_cache(db, "classification-filters", result)
    return result


@router.get("/{sid}", response_model=RuleRead)
def get_rule(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule_to_read(rule)


def _forced_mitre_classification(rule: Rule, classification_id: int | None) -> Classification | None:
    successful = [item for item in rule.classifications if item.classification_status != ClassificationStatus.FAILED]
    if classification_id is not None:
        return next((item for item in successful if item.id == classification_id), None)
    return successful[-1] if successful else None


@router.get("/{sid}/forced-mitre", response_model=ForcedMitreState)
def get_forced_mitre(sid: int, classification_id: int | None = None, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule:
        raise HTTPException(404, "Rule not found")
    classification = _forced_mitre_classification(rule, classification_id)
    if classification is None:
        return ForcedMitreState(eligible=False, reason="A successful classification is required.")
    if classification.mitre_technique_id:
        return ForcedMitreState(eligible=False, reason="The normal classification already has a MITRE mapping.")
    row = db.scalar(select(ForcedMitreMapping).where(
        ForcedMitreMapping.rule_id == rule.id,
        ForcedMitreMapping.classification_id == classification.id,
    ).order_by(ForcedMitreMapping.id.desc()))
    return ForcedMitreState(eligible=True, mapping=ForcedMitreRead.model_validate(row) if row else None)


@router.post("/{sid}/forced-mitre", response_model=ForcedMitreRead)
async def create_forced_mitre(sid: int, payload: ForcedMitreRequest, db: Session = Depends(get_db)):
    if payload.acknowledge_risk is not True:
        raise HTTPException(400, "Risk acknowledgement is required.")
    rule = RuleRepository(db).by_sid(sid)
    if not rule:
        raise HTTPException(404, "Rule not found")
    classification = _forced_mitre_classification(rule, payload.classification_id)
    if classification is None:
        raise HTTPException(400, "A successful classification belonging to this rule is required.")
    if classification.mitre_technique_id:
        raise HTTPException(409, "The normal classification already has a MITRE mapping; forced mapping is unavailable.")
    settings = effective_settings(db, get_settings())
    try:
        proposal, technique, candidates, selected, provider, model = await propose_forced_mitre(rule, classification, settings)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, "The selected helper model could not complete the forced MITRE mapping.") from exc
    row = ForcedMitreMapping(
        rule_id=rule.id,
        classification_id=classification.id,
        technique_id=technique.technique_id,
        technique_name=technique.name,
        tactic=technique.tactics[0] if technique.tactics else None,
        confidence=proposal.confidence,
        evidence=[*(selected.get("evidence", []) if selected else []), *[{"type": "HELPER_MODEL_RATIONALE", "value": value} for value in proposal.evidence]][:8],
        explanation=proposal.explanation,
        provider=provider,
        model_name=model,
        candidate_snapshot=candidates,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return ForcedMitreRead.model_validate(row)

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
    clear_dashboard_cache()
    return ManualReviewResponse(status=row.status,note=row.note,reviewer_type=row.reviewer_type,reviewed_at=row.created_at)

OVERRIDE_FIELDS = {"detected_behavior", "detected_entity", "entity_type", "category", "subcategory",
                  "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase"}


def _validate_corrections(classification: Classification, corrections: dict[str, str | None], active_values: dict[str, str | None] | None = None) -> None:
    """Keep manual corrections inside the same controlled vocabularies as AI output."""
    if "entity_type" in corrections and corrections["entity_type"] and corrections["entity_type"] not in {x.value for x in EntityType}:
        raise HTTPException(400, "Invalid entity type")
    if "category" in corrections and corrections["category"] and corrections["category"] not in {x.value for x in Category}:
        raise HTTPException(400, "Invalid category")
    current = active_values or {}
    effective_category = corrections.get("category", current.get("category", classification.category))
    effective_subcategory = corrections.get("subcategory", current.get("subcategory", classification.subcategory))
    if effective_subcategory and effective_category:
        try:
            category_enum = Category(effective_category)
        except ValueError as exc:
            raise HTTPException(400, "Invalid category") from exc
        if effective_subcategory not in SUBCATEGORIES.get(category_enum, ()):
            raise HTTPException(400, "Subcategory does not belong to category")
    if "cyber_kill_chain_phase" in corrections and corrections["cyber_kill_chain_phase"] and corrections["cyber_kill_chain_phase"] not in {x.value for x in KillChainPhase}:
        raise HTTPException(400, "Invalid kill-chain phase")
    mitre_fields = {"mitre_tactic", "mitre_technique", "mitre_technique_id"}
    if mitre_fields.intersection(corrections):
        effective_id = corrections.get("mitre_technique_id", current.get("mitre_technique_id", classification.mitre_technique_id))
        effective_name = corrections.get("mitre_technique", current.get("mitre_technique", classification.mitre_technique))
        effective_tactic = corrections.get("mitre_tactic", current.get("mitre_tactic", classification.mitre_tactic))
        if not effective_id:
            # Clearing MITRE is only valid when all three displayed values are cleared together.
            if any(value for value in (effective_id, effective_name, effective_tactic)):
                raise HTTPException(400, "MITRE ID, technique and tactic must be cleared together")
        else:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", effective_id):
                raise HTTPException(400, "Invalid MITRE technique ID")
            technique = MitreRepository().get(effective_id)
            if technique is None:
                raise HTTPException(400, "MITRE technique is not in the local repository")
            if effective_name and effective_name != technique.name:
                raise HTTPException(400, "MITRE technique name does not match the local repository")
            if effective_tactic and effective_tactic not in technique.tactics:
                raise HTTPException(400, "MITRE tactic does not match the local repository")

@router.get("/{sid}/overrides")
def list_overrides(sid: int, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    rows = db.scalars(select(ClassificationOverride).where(ClassificationOverride.rule_id == rule.id).order_by(ClassificationOverride.created_at.desc())).all()
    # Deliberately omit operator identity. The audit surface is about what
    # changed and when, not who happened to be using the console.
    return {"items": [{"id": r.id, "classification_id": r.classification_id, "field_name": r.field_name,
                       "original_value": r.original_value, "corrected_value": r.corrected_value, "reason": r.reason,
                       "active": r.active, "created_at": r.created_at} for r in rows]}

@router.put("/{sid}/overrides")
def save_overrides(sid: int, payload: ClassificationOverrideRequest, db: Session = Depends(get_db)):
    rule = RuleRepository(db).by_sid(sid)
    if not rule: raise HTTPException(404, "Rule not found")
    if any(field not in OVERRIDE_FIELDS for field in payload.corrections):
        raise HTTPException(400, "Unsupported correction field")
    classification = db.get(Classification, payload.classification_id) if payload.classification_id else None
    if classification and classification.rule_id != rule.id: raise HTTPException(400, "Classification does not belong to rule")
    if classification is None or classification.classification_status == ClassificationStatus.FAILED:
        raise HTTPException(400, "A successful classification is required before correcting fields")
    active_rows = db.scalars(select(ClassificationOverride).where(
        ClassificationOverride.rule_id == rule.id,
        ClassificationOverride.active.is_(True),
        (ClassificationOverride.classification_id == classification.id) |
        ClassificationOverride.classification_id.is_(None),
    )).all()
    active_values = {row.field_name: row.corrected_value for row in active_rows}
    _validate_corrections(classification, payload.corrections, active_values)
    for field, corrected in payload.corrections.items():
        current_override = db.scalar(select(ClassificationOverride).where(
            ClassificationOverride.rule_id == rule.id,
            ClassificationOverride.field_name == field,
            ClassificationOverride.active.is_(True),
            (ClassificationOverride.classification_id == classification.id) |
            ClassificationOverride.classification_id.is_(None),
        ).order_by(ClassificationOverride.id.desc()))
        original = current_override.corrected_value if current_override is not None else getattr(classification, field, None)
        db.query(ClassificationOverride).filter(ClassificationOverride.rule_id == rule.id,
            ClassificationOverride.field_name == field, ClassificationOverride.active.is_(True)).update({"active": False})
        db.add(ClassificationOverride(rule_id=rule.id, classification_id=classification.id if classification else None,
            field_name=field, original_value=None if original is None else str(original),
            corrected_value=corrected, reason=payload.reason, admin_id="not_recorded"))
    db.commit()
    clear_dashboard_cache()
    return list_overrides(sid, db)


@router.post("/import", response_model=ImportResponse)
async def import_rules(files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    parser, repository = SuricataRuleParser(), RuleRepository(db)
    uploads = await _prepare_ruleset_uploads(files)
    results: list[ImportFileResult] = []
    total_imported = total_skipped = total_failed = 0
    for upload in uploads:
        errors = list(upload.errors)
        imported = skipped = 0
        raw_rules = upload.rules
        for index, raw in enumerate(raw_rules, start=1):
            try:
                _, created = repository.upsert(parser.parse(raw), upload.filename)
                imported += int(created)
                skipped += int(not created)
            except Exception as exc:
                if len(errors) < MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"rule {index}: {exc}")
                if len(errors) >= MAX_BASELINE_PARSE_ERRORS:
                    errors.append(f"Parsing stopped after {MAX_BASELINE_PARSE_ERRORS} errors")
                    break
        db.commit()
        clear_dashboard_cache()
        total_imported += imported
        total_skipped += skipped
        total_failed += len(errors)
        results.append(ImportFileResult(filename=upload.filename, discovered=len(raw_rules), imported=imported, skipped=skipped, errors=errors))
    return ImportResponse(files=results, imported=total_imported, skipped=total_skipped, failed=total_failed)
