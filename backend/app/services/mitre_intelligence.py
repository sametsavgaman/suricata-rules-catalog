"""Read-only MITRE ATT&CK catalogue intelligence built from canonical IDs."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import rule_to_read
from app.database.models import (
    Classification,
    ClassificationStatus,
    DetectionFamily,
    ProductStatus,
    Rule,
    RuleFamilyAssignment,
    RuleProductDecision,
)
from app.knowledge.mitre_repository import MitreRepository, MitreTechnique

MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
METADATA_FIELD = re.compile(r"^mitre[_ ]technique[_ ]id\b", re.IGNORECASE)
_REPOSITORY = MitreRepository()
_CACHE_SECONDS = 15.0
_CACHE: dict[int, tuple[float, "MitreCatalogIndex"]] = {}
_CACHE_LOCK = Lock()


@dataclass(frozen=True)
class MitreCatalogIndex:
    total_rules: int
    rule_ids: frozenset[int]
    mapped_rule_ids: frozenset[int]
    technique_rules: dict[str, tuple[int, ...]]
    rule_sources: dict[tuple[int, str], tuple[str, ...]]
    family_by_id: dict[int, dict]
    rule_family: dict[int, int]


def _canonical_ids_from_metadata(value: object) -> set[str]:
    """Extract only explicitly labelled MITRE technique IDs; ignore text names."""
    found: set[str] = set()
    if isinstance(value, list):
        for item in value:
            found.update(_canonical_ids_from_metadata(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if METADATA_FIELD.match(str(key)):
                found.update(re.findall(r"T\d{4}(?:\.\d{3})?", str(item).upper()))
    elif isinstance(value, str) and METADATA_FIELD.match(value.strip()):
        found.update(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))
    return {technique_id for technique_id in found if _REPOSITORY.get(technique_id)}


def _latest_classification_subquery():
    return select(
        Classification.rule_id.label("rule_id"),
        func.max(Classification.id).label("classification_id"),
    ).where(
        Classification.classification_status != ClassificationStatus.FAILED,
    ).group_by(Classification.rule_id).subquery()


def _build_index(db: Session) -> MitreCatalogIndex:
    latest = _latest_classification_subquery()
    technique_rules: dict[str, list[tuple[int, int]]] = defaultdict(list)
    rule_sources: dict[tuple[int, str], set[str]] = defaultdict(set)
    rule_ids: set[int] = set()
    mapped_rule_ids: set[int] = set()
    for rule_id, sid, metadata, final_id in db.execute(
        select(Rule.id, Rule.sid, Rule.rule_metadata, Classification.mitre_technique_id)
        .outerjoin(latest, latest.c.rule_id == Rule.id)
        .outerjoin(Classification, Classification.id == latest.c.classification_id)
    ):
        rule_ids.add(rule_id)
        ids = _canonical_ids_from_metadata(metadata or [])
        for technique_id in ids:
            rule_sources[(rule_id, technique_id)].add("RULE_METADATA")
        if final_id and MITRE_ID.fullmatch(final_id) and _REPOSITORY.get(final_id):
            ids.add(final_id)
            rule_sources[(rule_id, final_id)].add("LATEST_CLASSIFICATION")
        if ids:
            mapped_rule_ids.add(rule_id)
        for technique_id in ids:
            technique_rules[technique_id].append((sid, rule_id))

    family_by_id: dict[int, dict] = {}
    rule_family: dict[int, int] = {}
    for rule_id, family_id, slug, name, family_type in db.execute(
        select(
            RuleFamilyAssignment.rule_id,
            DetectionFamily.id,
            DetectionFamily.slug,
            DetectionFamily.name,
            DetectionFamily.family_type,
        ).join(DetectionFamily, DetectionFamily.id == RuleFamilyAssignment.family_id)
    ):
        family_by_id[family_id] = {
            "id": family_id,
            "slug": slug,
            "name": name,
            "family_type": str(getattr(family_type, "value", family_type)),
        }
        rule_family[rule_id] = family_id

    return MitreCatalogIndex(
        total_rules=len(rule_ids),
        rule_ids=frozenset(rule_ids),
        mapped_rule_ids=frozenset(mapped_rule_ids),
        technique_rules={key: tuple(rule_id for _, rule_id in sorted(values, reverse=True))
                         for key, values in technique_rules.items()},
        rule_sources={key: tuple(sorted(values)) for key, values in rule_sources.items()},
        family_by_id=family_by_id,
        rule_family=rule_family,
    )


def catalog_index(db: Session) -> MitreCatalogIndex:
    """Short cache avoids rescanning 52k compact rows for adjacent UI requests."""
    engine_key = id(db.get_bind())
    now = monotonic()
    cached = _CACHE.get(engine_key)
    if cached and now - cached[0] < _CACHE_SECONDS:
        return cached[1]
    with _CACHE_LOCK:
        cached = _CACHE.get(engine_key)
        if cached and now - cached[0] < _CACHE_SECONDS:
            return cached[1]
        value = _build_index(db)
        _CACHE[engine_key] = (now, value)
        return value


def clear_mitre_index_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _family_ids(index: MitreCatalogIndex, rule_ids: set[int] | frozenset[int]) -> set[int]:
    return {index.rule_family[rule_id] for rule_id in rule_ids if rule_id in index.rule_family}


def technique_summary(index: MitreCatalogIndex, technique: MitreTechnique) -> dict:
    rule_ids = set(index.technique_rules.get(technique.technique_id, ()))
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactics": list(technique.tactics),
        "parent_id": technique.parent_id,
        "is_subtechnique": technique.parent_id is not None,
        "rule_count": len(rule_ids),
        "family_count": len(_family_ids(index, rule_ids)),
    }


def mitre_overview(db: Session) -> dict:
    index = catalog_index(db)
    represented = [_REPOSITORY.get(key) for key in index.technique_rules]
    represented = [item for item in represented if item]
    tactics = []
    for tactic in sorted({tactic for item in represented for tactic in item.tactics}):
        tactic_techniques = [item for item in represented if tactic in item.tactics]
        rules = {rule_id for item in tactic_techniques
                 for rule_id in index.technique_rules.get(item.technique_id, ())}
        tactics.append({"name": tactic, "technique_count": len(tactic_techniques), "rule_count": len(rules)})
    return {
        "summary": {
            "total_rules": index.total_rules,
            "mapped_rules": len(index.mapped_rule_ids),
            "unmapped_rules": index.total_rules - len(index.mapped_rule_ids),
            "techniques_represented": len(represented),
            "subtechniques_represented": sum(item.parent_id is not None for item in represented),
            "tactics_represented": len(tactics),
            "families_with_mappings": len(_family_ids(index, index.mapped_rule_ids)),
        },
        "tactics": tactics,
        "data_source": "MITRE ATT&CK official STIX 2.1 local repository",
        "coverage_scope": "SURICATA_CATALOG",
    }


def coverage_analysis(db: Session) -> dict:
    """Compare catalogue mappings with the complete local ATT&CK repository.

    This is catalogue coverage, not a claim that a deployed sensor detects the
    represented techniques. Keeping the scope explicit prevents a MITRE heatmap
    from being mistaken for validated product coverage.
    """
    index = catalog_index(db)
    all_techniques = _REPOSITORY.all()
    represented_ids = set(index.technique_rules)
    represented = [item for item in all_techniques if item.technique_id in represented_ids]
    gaps = [item for item in all_techniques if item.technique_id not in represented_ids]
    tactic_names = sorted({tactic for item in all_techniques for tactic in item.tactics})
    tactics = []
    for tactic in tactic_names:
        total_ids = {item.technique_id for item in all_techniques if tactic in item.tactics}
        covered_ids = total_ids & represented_ids
        rule_ids = {rule_id for technique_id in covered_ids
                    for rule_id in index.technique_rules.get(technique_id, ())}
        tactics.append({
            "name": tactic,
            "total_techniques": len(total_ids),
            "represented_techniques": len(covered_ids),
            "gap_techniques": len(total_ids - covered_ids),
            "rule_count": len(rule_ids),
            "coverage_percent": round(100 * len(covered_ids) / max(1, len(total_ids)), 1),
        })
    gap_items = [{
        "technique_id": item.technique_id,
        "name": item.name,
        "tactics": list(item.tactics),
        "parent_id": item.parent_id,
        "is_subtechnique": item.parent_id is not None,
    } for item in sorted(gaps, key=lambda item: (item.parent_id is not None, item.technique_id))]
    return {
        "scope": "SURICATA_CATALOG_MAPPING_COVERAGE",
        "disclaimer": "Catalogue mapping coverage is not validated deployed NDR detection coverage.",
        "summary": {
            "repository_techniques": len(all_techniques),
            "represented_techniques": len(represented),
            "gap_techniques": len(gaps),
            "coverage_percent": round(100 * len(represented) / max(1, len(all_techniques)), 1),
            "mapped_rules": len(index.mapped_rule_ids),
            "unmapped_rules": index.total_rules - len(index.mapped_rule_ids),
        },
        "tactics": tactics,
        "gaps": gap_items,
        "data_source": "MITRE ATT&CK official STIX 2.1 local repository",
    }


def list_techniques(
    db: Session,
    *,
    search: str | None = None,
    tactic: str | None = None,
    kind: Literal["all", "technique", "subtechnique"] = "all",
    offset: int = 0,
    limit: int = 100,
) -> dict:
    index = catalog_index(db)
    values = [_REPOSITORY.get(key) for key in index.technique_rules]
    values = [item for item in values if item]
    if search:
        needle = search.casefold()
        values = [item for item in values if needle in item.technique_id.casefold() or needle in item.name.casefold()]
    if tactic:
        values = [item for item in values if tactic.casefold() in {value.casefold() for value in item.tactics}]
    if kind == "technique":
        values = [item for item in values if item.parent_id is None]
    elif kind == "subtechnique":
        values = [item for item in values if item.parent_id is not None]
    values.sort(key=lambda item: (-len(index.technique_rules[item.technique_id]), item.technique_id))
    total = len(values)
    page = values[offset:offset + limit]
    parents = {item.parent_id: _REPOSITORY.get(item.parent_id) for item in page if item.parent_id}
    items = []
    for item in page:
        value = technique_summary(index, item)
        parent = parents.get(item.parent_id)
        value["parent"] = ({"technique_id": parent.technique_id, "name": parent.name}
                           if parent else None)
        items.append(value)
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "page": offset // limit + 1,
        "total_pages": max(1, (total + limit - 1) // limit),
    }


def _chunks(values: tuple[int, ...] | list[int], size: int = 800):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def technique_detail(db: Session, technique_id: str) -> dict | None:
    technique = _REPOSITORY.get(technique_id)
    if not technique:
        return None
    index = catalog_index(db)
    rule_ids = index.technique_rules.get(technique_id, ())
    rule_id_set = set(rule_ids)
    categories: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    products: Counter[str] = Counter()
    latest = _latest_classification_subquery()
    for chunk in _chunks(rule_ids):
        for protocol, category, product_status in db.execute(
            select(
                Rule.protocol,
                Classification.category,
                func.coalesce(RuleProductDecision.status, ProductStatus.NOT_EVALUATED.value),
            )
            .outerjoin(latest, latest.c.rule_id == Rule.id)
            .outerjoin(Classification, Classification.id == latest.c.classification_id)
            .outerjoin(RuleProductDecision, RuleProductDecision.rule_id == Rule.id)
            .where(Rule.id.in_(chunk))
        ):
            if protocol:
                protocols[str(protocol)] += 1
            if category:
                categories[str(category)] += 1
            products[str(getattr(product_status, "value", product_status))] += 1

    family_counts = Counter(index.rule_family[rule_id] for rule_id in rule_id_set if rule_id in index.rule_family)
    families = [{**index.family_by_id[family_id], "rule_count": count}
                for family_id, count in family_counts.most_common()]
    parent = _REPOSITORY.get(technique.parent_id) if technique.parent_id else None
    children = [item for item in _REPOSITORY.all() if item.parent_id == technique_id]
    source_counts = Counter(source for rule_id in rule_ids
                            for source in index.rule_sources.get((rule_id, technique_id), ()))
    return {
        "technique": {
            **technique_summary(index, technique),
            "description": technique.description,
            "source": technique.source,
        },
        "parent": technique_summary(index, parent) if parent else None,
        "subtechniques": [technique_summary(index, item) for item in sorted(children, key=lambda x: x.technique_id)],
        "related_families": families,
        "categories": [{"value": key, "count": count} for key, count in categories.most_common()],
        "protocols": [{"value": key, "count": count} for key, count in protocols.most_common()],
        "product_status": {status.value: products[status.value] for status in ProductStatus},
        "mapping_sources": dict(source_counts),
    }


def technique_rules(db: Session, technique_id: str, offset: int = 0, limit: int = 50) -> dict | None:
    if not _REPOSITORY.get(technique_id):
        return None
    index = catalog_index(db)
    all_ids = index.technique_rules.get(technique_id, ())
    selected_ids = all_ids[offset:offset + limit]
    latest = _latest_classification_subquery()
    rows = db.execute(
        select(Rule, Classification, DetectionFamily)
        .outerjoin(latest, latest.c.rule_id == Rule.id)
        .outerjoin(Classification, Classification.id == latest.c.classification_id)
        .outerjoin(RuleFamilyAssignment, RuleFamilyAssignment.rule_id == Rule.id)
        .outerjoin(DetectionFamily, DetectionFamily.id == RuleFamilyAssignment.family_id)
        .where(Rule.id.in_(selected_ids))
    ).all() if selected_ids else []
    by_id = {rule.id: (rule, classification, family) for rule, classification, family in rows}
    items = []
    for rule_id in selected_ids:
        rule, classification, family = by_id[rule_id]
        item = rule_to_read(rule, classification).model_dump(mode="json")
        item["family"] = ({"slug": family.slug, "name": family.name} if family else None)
        item["mitre_mapping_sources"] = list(index.rule_sources.get((rule_id, technique_id), ()))
        items.append(item)
    total = len(all_ids)
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "page": offset // limit + 1,
        "total_pages": max(1, (total + limit - 1) // limit),
    }


def family_mitre_profile(db: Session, family_id: int) -> dict:
    index = catalog_index(db)
    family_rule_ids = {rule_id for rule_id, value in index.rule_family.items() if value == family_id}
    counts: Counter[str] = Counter()
    mapped: set[int] = set()
    for technique_id, rule_ids in index.technique_rules.items():
        overlap = family_rule_ids.intersection(rule_ids)
        if overlap:
            counts[technique_id] = len(overlap)
            mapped.update(overlap)
    techniques = []
    for technique_id, count in counts.most_common():
        technique = _REPOSITORY.get(technique_id)
        if technique:
            techniques.append({**technique_summary(index, technique), "rule_count": count})
    return {
        "mapped_rule_count": len(mapped),
        "unmapped_rule_count": len(family_rule_ids - mapped),
        "techniques": techniques,
    }
