"""Conservative, deterministic detection-family enrichment and read models."""
from __future__ import annotations

import re
import unicodedata
from copy import deepcopy
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database.models import (
    Classification, ClassificationStatus, DetectionFamily, DetectionFamilyType,
    FamilyAssignmentProvenance, FamilyEvaluationStatus, ProductStatus, Rule, RuleFamilyAssignment, RuleFamilyEvaluation,
    RuleProductDecision,
)

FAMILY_ALGORITHM_VERSION = "family-v1"
_READ_MODEL_CACHE_TTL = 60.0
_READ_MODEL_CACHE: dict[tuple[object, object], tuple[float, object]] = {}
_READ_MODEL_CACHE_LOCK = Lock()
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]

# Aliases are a normalization vocabulary, not query-specific behavior.
ALIASES = {
    "anydesk": "AnyDesk", "any desk": "AnyDesk",
    "cobaltstrike": "Cobalt Strike", "cobalt strike": "Cobalt Strike",
    "sliver": "Sliver", "sliver c2": "Sliver",
    "nmap": "Nmap", "network mapper": "Nmap",
    "psexec": "PsExec", "ps exec": "PsExec",
    "screenconnect": "ScreenConnect", "connectwise control": "ScreenConnect",
    "teamviewer": "TeamViewer", "team viewer": "TeamViewer",
    "remcos": "Remcos", "remcos rat": "Remcos",
    "quasar rat": "Quasar RAT", "quasarrat": "Quasar RAT",
    "cobalt strike beacon": "Cobalt Strike",
    "coinminer": "CoinMiner", "coin miner": "CoinMiner",
}
GENERIC_ENTITIES = {
    "dns", "http", "https", "tls", "tcp", "udp", "ip", "smb", "smtp", "ftp",
    "malware", "trojan", "exploit", "server", "client", "windows", "linux",
    "unknown", "dynamic dns", "c2", "command and control", "maldoc",
}
KNOWN_PATTERNS = (
    (r"\bany\s*desk\b", "AnyDesk", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bcobalt\s+strike(?:\s+beacon)?\b", "Cobalt Strike", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bsliver(?:\s+c2)?\b", "Sliver", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bnmap\b|\bnetwork mapper\b", "Nmap", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bps\s*exec\b", "PsExec", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bscreenconnect\b|\bconnectwise control\b", "ScreenConnect", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bteam\s*viewer\b", "TeamViewer", DetectionFamilyType.TOOL, FamilyAssignmentProvenance.KNOWN_TOOL),
    (r"\bremcos(?: rat)?\b", "Remcos", DetectionFamilyType.MALWARE, FamilyAssignmentProvenance.KNOWN_MALWARE),
    (r"\bquasar(?: rat)?\b", "Quasar RAT", DetectionFamilyType.MALWARE, FamilyAssignmentProvenance.KNOWN_MALWARE),
)


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().casefold()).strip()


def normalize_family_name(value: str) -> tuple[str, str]:
    clean = re.sub(r"\s+", " ", value.strip(" \t\r\n-_/"))
    key = _key(clean)
    if not key or len(clean) > 120:
        raise ValueError("Invalid family name")
    canonical = ALIASES.get(key, clean)
    slug = re.sub(r"[^a-z0-9]+", "-", _key(canonical)).strip("-")
    if not slug:
        raise ValueError("Invalid family name")
    return canonical, slug


@dataclass(frozen=True)
class FamilyProposal:
    name: str
    slug: str
    family_type: DetectionFamilyType
    provenance: FamilyAssignmentProvenance
    evidence: dict


def _proposal(name, family_type, provenance, evidence):
    canonical, slug = normalize_family_name(name)
    return FamilyProposal(canonical, slug, family_type, provenance, evidence)


def derive_family(rule: Rule, classification: Classification | None) -> FamilyProposal | None:
    """Return one defensible primary family, or abstain with None."""
    msg = rule.msg or ""
    combined = " ".join(filter(None, (msg, classification.detected_behavior if classification else None)))
    lower = combined.casefold()

    # A final entity is trusted only when the deterministic candidate layer records
    # the same candidate as non-weak. Model text alone is insufficient.
    if classification and classification.detected_entity and classification.entity_type:
        entity_key = _key(classification.detected_entity)
        entity_slug = normalize_family_name(classification.detected_entity)[1]
        candidates = (classification.agent_activity or {}).get("entity_candidates") or []
        match = next((c for c in candidates if c.get("candidate") and normalize_family_name(str(c["candidate"]))[1] == entity_slug
                      and c.get("weak") is False and c.get("deterministic") is not False), None)
        if match and entity_key not in GENERIC_ENTITIES:
            entity_type = str(getattr(classification.entity_type, "value", classification.entity_type))
            family_type = (DetectionFamilyType.MALWARE if entity_type == "Malware" else
                           DetectionFamilyType.TOOL if entity_type in {"Attack Tool", "Remote Access Tool"} else
                           DetectionFamilyType.PRODUCT)
            provenance = (FamilyAssignmentProvenance.KNOWN_MALWARE if match.get("evidence_type") == "EXPLICIT_MALWARE_NAME"
                          else FamilyAssignmentProvenance.EXPLICIT_ENTITY)
            return _proposal(classification.detected_entity, family_type, provenance, {
                "field": "detected_entity", "value": classification.detected_entity,
                "entity_type": entity_type, "candidate_evidence_type": match.get("evidence_type"),
                "candidate_source": match.get("source"),
            })

    for pattern, name, family_type, provenance in KNOWN_PATTERNS:
        found = re.search(pattern, msg, re.IGNORECASE)
        if found:
            return _proposal(name, family_type, provenance, {
                "field": "msg", "matched_text": found.group(0), "rule_message": msg[:280],
            })

    if re.search(r"\bdns\s+tunnel(?:ing)?\b", combined, re.IGNORECASE):
        return _proposal("DNS Tunneling", DetectionFamilyType.BEHAVIOR,
                         FamilyAssignmentProvenance.BEHAVIOR_PATTERN,
                         {"fields": ["msg", "detected_behavior"], "pattern": "explicit DNS tunneling phrase"})
    if ("smb" in lower and ("lateral movement" in lower or "remote service" in lower)):
        return _proposal("SMB Lateral Movement", DetectionFamilyType.BEHAVIOR,
                         FamilyAssignmentProvenance.BEHAVIOR_PATTERN,
                         {"fields": ["msg", "detected_behavior"], "pattern": "SMB plus explicit lateral movement/remote service"})
    if (("tls" in lower or "certificate" in lower) and
            any(token in lower for token in ("malicious certificate", "malicious tls", "bad certificate"))):
        return _proposal("Malicious TLS Certificates", DetectionFamilyType.BEHAVIOR,
                         FamilyAssignmentProvenance.BEHAVIOR_PATTERN,
                         {"fields": ["msg", "detected_behavior"], "pattern": "explicit malicious TLS certificate"})
    if classification and (classification.subcategory == "Remote Access Software" or
                           classification.mitre_technique_id == "T1219"):
        return _proposal("Remote Access Software", DetectionFamilyType.BEHAVIOR,
                         FamilyAssignmentProvenance.BEHAVIOR_PATTERN,
                         {"fields": ["subcategory", "mitre_technique_id"],
                          "subcategory": classification.subcategory,
                          "mitre_technique_id": classification.mitre_technique_id})

    cve = re.search(r"\bCVE-\d{4}-\d{4,7}\b", rule.raw_rule, re.IGNORECASE)
    if cve and classification and str(classification.category) in {"Exploitation", "Web Attack"}:
        return _proposal(cve.group(0).upper(), DetectionFamilyType.VULNERABILITY,
                         FamilyAssignmentProvenance.CVE_FAMILY,
                         {"field": "raw_rule", "matched_text": cve.group(0).upper()})
    return None


def assign_if_unassigned(db: Session, rule: Rule, classification: Classification | None) -> RuleFamilyAssignment | None:
    existing = db.scalar(select(RuleFamilyAssignment).where(RuleFamilyAssignment.rule_id == rule.id))
    evaluation = db.scalar(select(RuleFamilyEvaluation).where(RuleFamilyEvaluation.rule_id == rule.id))
    if existing:
        if not evaluation:
            evaluation = RuleFamilyEvaluation(rule_id=rule.id,
                source_classification_id=existing.source_classification_id,
                status=FamilyEvaluationStatus.ASSIGNED,
                evidence={"assignment_id": existing.id}, algorithm_version=existing.algorithm_version)
            db.add(evaluation)
        # The original assignment provenance remains immutable, while this
        # checkpoint records that the latest classification was considered.
        evaluation.source_classification_id = classification.id if classification else None
        evaluation.status = FamilyEvaluationStatus.ASSIGNED
        evaluation.evidence = {"assignment_id": existing.id, "retained_family_slug": existing.family.slug}
        evaluation.algorithm_version = FAMILY_ALGORITHM_VERSION
        db.flush()
        clear_family_cache()
        return existing
    if evaluation and evaluation.status == FamilyEvaluationStatus.UNASSIGNED and (
            classification is None or evaluation.source_classification_id == classification.id):
        return None
    proposal = derive_family(rule, classification)
    if proposal is None:
        if not evaluation:
            db.add(RuleFamilyEvaluation(rule_id=rule.id,
                source_classification_id=classification.id if classification else None,
                status=FamilyEvaluationStatus.UNASSIGNED,
                evidence={"reason": "No supported deterministic family evidence."},
                algorithm_version=FAMILY_ALGORITHM_VERSION))
        else:
            evaluation.source_classification_id = classification.id if classification else None
            evaluation.status = FamilyEvaluationStatus.UNASSIGNED
            evaluation.evidence = {"reason": "No supported deterministic family evidence."}
            evaluation.algorithm_version = FAMILY_ALGORITHM_VERSION
        db.flush()
        clear_family_cache()
        return None
    family = db.scalar(select(DetectionFamily).where(DetectionFamily.slug == proposal.slug))
    if not family:
        family = DetectionFamily(slug=proposal.slug, name=proposal.name, family_type=proposal.family_type)
        db.add(family)
        db.flush()
    assignment = RuleFamilyAssignment(
        rule_id=rule.id, family_id=family.id,
        source_classification_id=classification.id if classification else None,
        provenance=proposal.provenance, evidence=proposal.evidence,
        algorithm_version=FAMILY_ALGORITHM_VERSION,
    )
    db.add(assignment)
    if not evaluation:
        evaluation = RuleFamilyEvaluation(rule_id=rule.id)
        db.add(evaluation)
    evaluation.source_classification_id = classification.id if classification else None
    evaluation.status = FamilyEvaluationStatus.ASSIGNED
    evaluation.evidence = {"family_slug": proposal.slug, "provenance": proposal.provenance.value}
    evaluation.algorithm_version = FAMILY_ALGORITHM_VERSION
    db.flush()
    clear_family_cache()
    return assignment


def backfill_families(db: Session, *, limit: int | None = None) -> dict:
    examined = assigned = 0
    while limit is None or examined < limit:
        take = min(250, (limit - examined) if limit is not None else 250)
        latest = select(
            Classification.rule_id.label("rule_id"),
            func.max(Classification.id).label("classification_id"),
        ).where(Classification.classification_status != ClassificationStatus.FAILED).group_by(
            Classification.rule_id
        ).subquery()
        ids = list(db.scalars(
            select(Rule.id)
            .outerjoin(RuleFamilyEvaluation, RuleFamilyEvaluation.rule_id == Rule.id)
            .outerjoin(latest, latest.c.rule_id == Rule.id)
            .where(or_(
                RuleFamilyEvaluation.id.is_(None),
                RuleFamilyEvaluation.source_classification_id.is_distinct_from(latest.c.classification_id),
            ))
            .order_by(Rule.id).limit(take)
        ))
        db.rollback()  # release the read snapshot before acquiring a short write transaction
        if not ids:
            break
        for rule_id in ids:
            rule = db.get(Rule, rule_id)
            classification = db.scalar(select(Classification).where(
                Classification.rule_id == rule_id,
                Classification.classification_status != ClassificationStatus.FAILED,
            ).order_by(Classification.id.desc()).limit(1))
            examined += 1
            assigned += int(assign_if_unassigned(db, rule, classification) is not None)
        db.commit()
    clear_family_cache()
    return {"examined": examined, "assigned": assigned, "unassigned": examined - assigned}


class FamilyFilters(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    search: Text | None = None
    category: Text | None = None
    mitre_tactic: Text | None = None
    mitre_technique_id: Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")] | None = None
    protocol: Text | None = None
    entity_type: Text | None = None
    product_status: ProductStatus | None = None


class FamilySearch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filters: FamilyFilters = Field(default_factory=FamilyFilters)
    offset: int = Field(default=0, ge=0, le=1_000_000)
    limit: int = Field(default=24, ge=1, le=50)


def latest_classification_id():
    return select(func.max(Classification.id)).where(
        Classification.rule_id == Rule.id,
        Classification.classification_status != ClassificationStatus.FAILED,
    ).correlate(Rule).scalar_subquery()


def family_filter_query(filters: FamilyFilters):
    stmt = (select(DetectionFamily.id.label("family_id"), RuleFamilyAssignment.rule_id)
            .join(RuleFamilyAssignment, RuleFamilyAssignment.family_id == DetectionFamily.id)
            .join(Rule, Rule.id == RuleFamilyAssignment.rule_id)
            .outerjoin(Classification, Classification.id == latest_classification_id())
            .outerjoin(RuleProductDecision, RuleProductDecision.rule_id == Rule.id))
    if filters.search:
        _, search_slug = normalize_family_name(filters.search)
        stmt = stmt.where(or_(DetectionFamily.name.icontains(filters.search, autoescape=True),
                              DetectionFamily.slug.icontains(filters.search, autoescape=True),
                              DetectionFamily.slug == search_slug))
    for value, column in ((filters.category, Classification.category),
                          (filters.mitre_tactic, Classification.mitre_tactic),
                          (filters.mitre_technique_id, Classification.mitre_technique_id),
                          (filters.protocol, Rule.protocol), (filters.entity_type, Classification.entity_type)):
        if value:
            stmt = stmt.where(func.lower(column) == value.casefold())
    if filters.product_status:
        stmt = stmt.where(func.coalesce(RuleProductDecision.status, ProductStatus.NOT_EVALUATED.value) == filters.product_status)
    return stmt


def family_summaries(db: Session, request: FamilySearch) -> tuple[list[dict], int]:
    cache_key = ("summaries", _bind_key(db), request.model_dump_json())
    now = monotonic()
    with _READ_MODEL_CACHE_LOCK:
        cached = _READ_MODEL_CACHE.get(cache_key)
        if cached and now - cached[0] < _READ_MODEL_CACHE_TTL:
            items, total = cached[1]
            return deepcopy(items), total

    filtered = family_filter_query(request.filters).subquery()
    total = db.scalar(select(func.count(func.distinct(filtered.c.family_id)))) or 0
    ids = list(db.scalars(select(filtered.c.family_id).group_by(filtered.c.family_id)
                          .order_by(func.count(func.distinct(filtered.c.rule_id)).desc(), filtered.c.family_id)
                          .offset(request.offset).limit(request.limit)))
    if not ids:
        result = ([], total)
        _cache_read_model(cache_key, result)
        return result
    rows = db.execute(
        select(DetectionFamily.id, DetectionFamily.slug, DetectionFamily.name, DetectionFamily.family_type,
               func.count(func.distinct(RuleFamilyAssignment.rule_id)).label("rule_count"),
               func.count(func.distinct(Classification.mitre_technique_id)).label("mitre_count"),
               func.group_concat(func.distinct(Rule.protocol)).label("protocols"),
               func.group_concat(func.distinct(Classification.category)).label("categories"),
               func.group_concat(func.distinct(Classification.mitre_technique_id)).label("mitre_ids"),
               func.group_concat(func.distinct(Classification.entity_type)).label("entity_types"))
        .join(RuleFamilyAssignment, RuleFamilyAssignment.family_id == DetectionFamily.id)
        .join(Rule, Rule.id == RuleFamilyAssignment.rule_id)
        .outerjoin(Classification, Classification.id == latest_classification_id())
        .where(DetectionFamily.id.in_(ids)).group_by(DetectionFamily.id)
    ).mappings()
    products = {(fid, str(getattr(status, "value", status))): count for fid, status, count in db.execute(
        select(RuleFamilyAssignment.family_id,
               func.coalesce(RuleProductDecision.status, ProductStatus.NOT_EVALUATED.value), func.count())
        .join(Rule, Rule.id == RuleFamilyAssignment.rule_id)
        .outerjoin(RuleProductDecision, RuleProductDecision.rule_id == Rule.id)
        .where(RuleFamilyAssignment.family_id.in_(ids))
        .group_by(RuleFamilyAssignment.family_id, func.coalesce(RuleProductDecision.status, ProductStatus.NOT_EVALUATED.value))
    )}
    indexed = {}
    for row in rows:
        item = dict(row)
        for field in ("protocols", "categories", "mitre_ids", "entity_types"):
            item[field] = sorted(filter(None, (item[field] or "").split(",")))
        item["family_type"] = str(getattr(item["family_type"], "value", item["family_type"]))
        item["product_status"] = {status.value: products.get((item["id"], status.value), 0) for status in ProductStatus}
        indexed[item["id"]] = item
    result = ([indexed[i] for i in ids], total)
    _cache_read_model(cache_key, result)
    return deepcopy(result[0]), result[1]


def family_stats(db: Session) -> dict:
    """Return the small family header aggregate from a short-lived read cache."""
    cache_key = ("stats", _bind_key(db))
    now = monotonic()
    with _READ_MODEL_CACHE_LOCK:
        cached = _READ_MODEL_CACHE.get(cache_key)
        if cached and now - cached[0] < _READ_MODEL_CACHE_TTL:
            return dict(cached[1])

    families = db.scalar(select(func.count()).select_from(DetectionFamily)) or 0
    assigned = db.scalar(select(func.count()).select_from(RuleFamilyAssignment)) or 0
    rules = db.scalar(select(func.count()).select_from(Rule)) or 0
    evaluated = db.scalar(select(func.count()).select_from(RuleFamilyEvaluation)) or 0
    unassigned = db.scalar(select(func.count()).select_from(RuleFamilyEvaluation).where(
        RuleFamilyEvaluation.status == FamilyEvaluationStatus.UNASSIGNED)) or 0
    result = {"families": families, "assigned_rules": assigned, "evaluated_rules": evaluated,
              "unassigned_rules": unassigned, "pending_evaluation_rules": max(0, rules - evaluated),
              "assignment_coverage": round(assigned / rules, 4) if rules else 0}
    _cache_read_model(cache_key, result)
    return dict(result)


def _bind_key(db: Session) -> object:
    """Keep cache entries isolated between application databases (including tests)."""
    return db.get_bind()


def _cache_read_model(key: tuple[object, object], value: object) -> None:
    with _READ_MODEL_CACHE_LOCK:
        _READ_MODEL_CACHE[key] = (monotonic(), deepcopy(value))


def clear_family_cache() -> None:
    with _READ_MODEL_CACHE_LOCK:
        _READ_MODEL_CACHE.clear()


def warm_family_cache() -> None:
    """Build the first family read models in a background worker after startup."""
    from app.database.session import SessionLocal

    with SessionLocal() as db:
        family_stats(db)
        family_summaries(db, FamilySearch())


def family_rules(db: Session, family_id: int, offset=0, limit=50):
    stmt = (select(Rule, Classification, RuleFamilyAssignment)
            .join(RuleFamilyAssignment, RuleFamilyAssignment.rule_id == Rule.id)
            .outerjoin(Classification, Classification.id == latest_classification_id())
            .where(RuleFamilyAssignment.family_id == family_id))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    return db.execute(stmt.order_by(Rule.sid.desc()).offset(offset).limit(limit)).all(), total
