import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api import mitre
from app.database.models import (
    Classification,
    ClassificationStatus,
    DetectionFamily,
    DetectionFamilyType,
    FamilyAssignmentProvenance,
    RuleFamilyAssignment,
)
from app.database.repository import RuleRepository
from app.database.session import Base, get_db
from app.parser.suricata_parser import SuricataRuleParser
from app.services.mitre_intelligence import clear_mitre_index_cache


def add_rule(db, sid, msg, metadata=(), technique_id=None):
    metadata_text = f"metadata:{', '.join(metadata)}" if metadata else ""
    separator = "; " if metadata_text else ""
    rule, _ = RuleRepository(db).upsert(SuricataRuleParser().parse(
        f'alert tcp any any -> any any (msg:"{msg}"; {metadata_text}{separator}sid:{sid}; rev:1;)'
    ), "mitre-test.rules")
    if technique_id:
        db.add(Classification(
            rule_id=rule.id,
            model_name="test",
            provider="ollama",
            classifier_version="qwen-v2.2",
            classification_status=ClassificationStatus.AUTO_CLASSIFIED,
            confidence=.8,
            evidence=[],
            explanation="test",
            mitre_technique_id=technique_id,
        ))
    return rule


@pytest.fixture
def mitre_client():
    clear_mitre_index_cache()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        multi = add_rule(db, 820001, "Web protocol command channel", (
            "mitre_technique_id T1071", "mitre_technique_id T1071.001",
        ), "T1071.001")
        add_rule(db, 820002, "No ATT&CK evidence")
        remote = add_rule(db, 820003, "AnyDesk remote access", ("mitre_technique_id T1219",), "T1219")
        family = DetectionFamily(slug="anydesk", name="AnyDesk", family_type=DetectionFamilyType.TOOL)
        db.add(family)
        db.flush()
        db.add(RuleFamilyAssignment(
            rule_id=remote.id,
            family_id=family.id,
            provenance=FamilyAssignmentProvenance.KNOWN_TOOL,
            evidence={"field": "msg"},
            algorithm_version="family-v1",
        ))
        db.commit()
        app = FastAPI()
        app.include_router(mitre.router, prefix="/api")
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            yield client, multi.id
    clear_mitre_index_cache()
    engine.dispose()


def test_overview_supports_unmapped_and_multiple_mappings(mitre_client):
    client, _ = mitre_client
    value = client.get("/api/mitre").json()
    assert value["coverage_scope"] == "SURICATA_CATALOG"
    assert value["summary"]["total_rules"] == 3
    assert value["summary"]["mapped_rules"] == 2
    assert value["summary"]["unmapped_rules"] == 1
    assert value["summary"]["techniques_represented"] == 3
    assert value["summary"]["subtechniques_represented"] == 1
    assert value["summary"]["families_with_mappings"] == 1


def test_coverage_analysis_reports_repository_gaps_without_product_claim(mitre_client):
    client, _ = mitre_client
    value = client.get("/api/mitre/coverage").json()
    assert value["scope"] == "SURICATA_CATALOG_MAPPING_COVERAGE"
    assert value["summary"]["represented_techniques"] == 3
    assert value["summary"]["gap_techniques"] > 0
    assert value["summary"]["repository_techniques"] == (
        value["summary"]["represented_techniques"] + value["summary"]["gap_techniques"]
    )
    assert "not validated" in value["disclaimer"].lower()
    assert any(item["technique_id"] == "T1001" for item in value["gaps"])


def test_search_parent_children_family_and_paginated_real_rules(mitre_client):
    client, multi_rule_id = mitre_client
    listing = client.get("/api/mitre/techniques", params={"search": "Web Protocols"}).json()
    assert listing["total"] == 1
    assert listing["items"][0]["technique_id"] == "T1071.001"
    assert listing["items"][0]["parent"] == {
        "technique_id": "T1071", "name": "Application Layer Protocol",
    }

    parent = client.get("/api/mitre/techniques/T1071").json()
    assert any(item["technique_id"] == "T1071.001" for item in parent["subtechniques"])
    rules = client.get("/api/mitre/techniques/T1071.001/rules", params={"limit": 1}).json()
    assert rules["total"] == 1 and rules["items"][0]["id"] == multi_rule_id
    assert set(rules["items"][0]["mitre_mapping_sources"]) == {
        "LATEST_CLASSIFICATION", "RULE_METADATA",
    }

    remote = client.get("/api/mitre/techniques/T1219").json()
    assert remote["related_families"][0]["slug"] == "anydesk"
    assert remote["product_status"]["NOT_EVALUATED"] == 1
    assert client.get("/api/mitre/techniques/T9999").status_code == 404
