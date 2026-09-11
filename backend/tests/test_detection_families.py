import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import catalog_assistant, families
from app.database.models import Classification, ClassificationStatus, DetectionFamily, Rule, RuleFamilyAssignment
from app.database.repository import RuleRepository
from app.database.session import Base, get_db
from app.parser.suricata_parser import SuricataRuleParser
from app.services.catalog_assistant import CatalogFilters, CatalogPlan, CatalogSearch, query_catalog, query_family_catalog
from app.services.detection_families import (
    FamilyFilters, FamilySearch, backfill_families, derive_family, family_summaries,
    normalize_family_name,
)


def add_rule(db, sid, msg, protocol="tcp", classification=None):
    rule, _ = RuleRepository(db).upsert(SuricataRuleParser().parse(
        f'alert {protocol} any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'), "test.rules")
    if classification:
        db.add(Classification(rule_id=rule.id, model_name="test", provider="ollama",
            classifier_version="qwen-v2.2", classification_status=ClassificationStatus.AUTO_CLASSIFIED,
            confidence=.8, evidence=[], explanation="test", **classification))
    return rule


@pytest.fixture
def catalog_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        anydesk = {"detected_entity":"Any Desk", "entity_type":"Remote Access Tool",
            "category":"Command and Control", "subcategory":"Remote Access Software",
            "mitre_technique_id":"T1219", "mitre_technique":"Remote Access Software",
            "mitre_tactic":"Command and Control", "agent_activity":{"entity_candidates":[{
                "candidate":"AnyDesk", "evidence_type":"EXPLICIT_RULE_NAME", "source":"msg", "weak":False,
                "deterministic":True}]}}
        add_rule(db, 810001, "ET POLICY AnyDesk Remote Desktop", "tcp", anydesk)
        add_rule(db, 810002, "ET POLICY ANYDESK TLS Session", "tls")
        add_rule(db, 810003, "Ordinary TCP policy observation", "tcp", {"category":"Policy Violation"})
        add_rule(db, 810004, "Possible DNS tunneling activity", "dns", {"category":"Suspicious DNS"})
        add_rule(db, 810005, "Generic suspicious payload", "tcp")
        db.commit()
        yield db
    engine.dispose()


def test_normalization_aliases_share_one_canonical_family(catalog_db):
    assert normalize_family_name(" ANY DESK ") == ("AnyDesk", "anydesk")
    result = backfill_families(catalog_db)
    assert result == {"examined":5,"assigned":3,"unassigned":2}
    assert catalog_db.scalar(select(func.count()).select_from(DetectionFamily)) == 2
    family = catalog_db.scalar(select(DetectionFamily).where(DetectionFamily.slug == "anydesk"))
    assert family.name == "AnyDesk"
    assert catalog_db.scalar(select(func.count()).select_from(RuleFamilyAssignment).where(RuleFamilyAssignment.family_id == family.id)) == 2


def test_conservative_assignment_and_explainable_provenance(catalog_db):
    rules = list(catalog_db.scalars(select(Rule).order_by(Rule.sid)))
    classifications = {c.rule_id:c for c in catalog_db.scalars(select(Classification))}
    first = derive_family(rules[0], classifications[rules[0].id])
    assert first.name == "AnyDesk" and first.provenance.value == "EXPLICIT_ENTITY"
    assert first.evidence["candidate_evidence_type"] == "EXPLICIT_RULE_NAME"
    dns = derive_family(rules[3], classifications[rules[3].id])
    assert dns.name == "DNS Tunneling" and dns.provenance.value == "BEHAVIOR_PATTERN"
    assert derive_family(rules[2], classifications[rules[2].id]) is None
    assert derive_family(rules[4], None) is None


def test_family_aggregation_filters_counts_and_bounds(catalog_db):
    backfill_families(catalog_db)
    items,total = family_summaries(catalog_db, FamilySearch(filters=FamilyFilters(search="any desk")))
    assert total == 1 and items[0]["name"] == "AnyDesk" and items[0]["rule_count"] == 2
    items,total = family_summaries(catalog_db, FamilySearch(filters=FamilyFilters(protocol="dns")))
    assert total == 1 and items[0]["name"] == "DNS Tunneling"
    assert query_catalog(catalog_db, CatalogSearch(filters=CatalogFilters(family_name="ANYDESK"))).total == 2
    result = query_family_catalog(catalog_db, CatalogSearch(resource="FAMILIES", filters=CatalogFilters(mitre_technique_id="T1219")))
    assert result.total == 1 and result.families[0].name == "AnyDesk"
    with pytest.raises(ValidationError): FamilySearch(limit=5000)


def test_family_api_returns_real_rules_and_never_secrets(catalog_db):
    backfill_families(catalog_db)
    app=FastAPI();app.include_router(families.router,prefix="/api")
    app.dependency_overrides[get_db]=lambda:catalog_db
    with TestClient(app) as client:
        listing=client.get("/api/families",params={"search":"AnyDesk"})
        assert listing.status_code == 200 and listing.json()["total"] == 1
        stats=client.get("/api/families/stats").json()
        assert stats["evaluated_rules"] == 5 and stats["unassigned_rules"] == 2
        assert stats["pending_evaluation_rules"] == 0
        detail=client.get("/api/families/anydesk").json()
        assert detail["total"] == 2
        assert {r["sid"] for r in detail["rules"]} == {810001,810002}
        assert "raw_rule" in detail["rules"][0]
        assert "secret" not in listing.text.casefold()


def test_assistant_family_count_is_database_grounded(catalog_db, monkeypatch):
    backfill_families(catalog_db)
    app=FastAPI();app.include_router(catalog_assistant.router,prefix="/api")
    app.dependency_overrides[get_db]=lambda:catalog_db
    for queue in catalog_assistant._requests.values(): queue.clear()
    monkeypatch.setattr(catalog_assistant,"effective_settings",lambda *args:SimpleNamespace(gemini_api_key="hidden",gemini_model="planner"))
    async def plan(*args): return CatalogPlan(intent="COUNT_RULES",filters=CatalogFilters(family_name="Any Desk"))
    monkeypatch.setattr(catalog_assistant,"plan_question",plan)
    with TestClient(app,base_url="http://localhost",client=("127.0.0.1",50000)) as client:
        value=client.post("/api/catalog/assistant/ask",json={"question":"Kaç AnyDesk rule var?"}).json()
        # Both underlying family rules are real catalogue records. The one without
        # a classification is still counted, but no result is invented for it.
        assert value["total"] == 2 and value["items"] == [] and value["source"] == "LOCAL_CATALOG"
        assert "hidden" not in str(value)


def test_backfill_is_resume_safe_and_unassigned_is_persisted(catalog_db):
    first = backfill_families(catalog_db)
    second = backfill_families(catalog_db)
    assert first == {"examined":5,"assigned":3,"unassigned":2}
    assert second == {"examined":0,"assigned":0,"unassigned":0}
    rule = catalog_db.scalar(select(Rule).where(Rule.sid == 810005))
    catalog_db.add(Classification(
        rule_id=rule.id, model_name="new", provider="ollama",
        classifier_version="qwen-v2.2", classification_status=ClassificationStatus.AUTO_CLASSIFIED,
        confidence=.8, evidence=[], explanation="test", detected_entity="NewTool",
        entity_type="Attack Tool", category="Command and Control",
        agent_activity={"entity_candidates":[{"candidate":"NewTool", "evidence_type":"EXPLICIT_RULE_NAME",
            "source":"msg", "weak":False, "deterministic":True}]},
    ))
    catalog_db.commit()
    assert backfill_families(catalog_db) == {"examined":1,"assigned":1,"unassigned":0}
    assert backfill_families(catalog_db) == {"examined":0,"assigned":0,"unassigned":0}


def test_family_planner_contract_rejects_sql_and_unknown_operations():
    with pytest.raises(ValidationError):
        CatalogPlan.model_validate({"intent":"EXECUTE_SQL","filters":{},"sql":"SELECT * FROM rules"})
    with pytest.raises(ValidationError):
        CatalogSearch.model_validate({"resource":"TABLE_NAME_FROM_USER","filters":{}})
