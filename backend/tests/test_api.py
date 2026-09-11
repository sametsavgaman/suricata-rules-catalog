from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import Base, get_db
from app.database.models import Classification, ClassificationStatus, ForcedMitreMapping, Rule
from app.api import rules as rules_api
from app.services.forced_mitre import ForcedMitreProposal
from app.knowledge.mitre_repository import MitreRepository
from app.agent.schemas import ClassificationOutput, ProviderResult
from app.main import app


engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, expire_on_commit=False)


def override_db():
    with TestingSession() as db:
        yield db


app.dependency_overrides[get_db] = override_db


def test_import_list_detail_and_stats():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    sample = Path(__file__).resolve().parents[2] / "data" / "samples" / "v1-synthetic.rules"
    with TestClient(app) as client, sample.open("rb") as handle:
        imported = client.post("/api/rules/import", files=[("files", (sample.name, handle, "text/plain"))])
        assert imported.status_code == 200, imported.text
        assert imported.json()["imported"] == 20

        listing = client.get("/api/rules", params={"search": "NMAP"})
        assert listing.status_code == 200
        assert listing.json()["total"] == 1
        assert listing.json()["items"][0]["sid"] == 9900001
        assert listing.json()["items"][0]["classification_options"] == []

        selectors = client.get("/api/rules/filters")
        assert selectors.status_code == 200
        assert "runs" not in selectors.json()

        detail = client.get("/api/rules/9900001")
        assert detail.status_code == 200
        assert detail.json()["contents"] == []

        stats = client.get("/api/stats")
        assert stats.status_code == 200
        assert stats.json()["total_rules"] == 20
        assert stats.json()["classified_rules"] == 0
        assert stats.json()["manual_review"]["UNREVIEWED"] == 20
        assert stats.json()["manual_review"]["CLASSIFIED_UNREVIEWED"] == 0
        assert stats.json()["manual_review"]["NOT_CLASSIFIED"] == 20


def test_missing_rule_is_404():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        assert client.get("/api/rules/123456789").status_code == 404


def test_forced_mitre_is_only_available_after_normal_classifier_abstains(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestingSession() as db:
        rule = Rule(
            sid=7770001, rev=1,
            raw_rule='alert tcp any any -> any 445 (msg:"Possible remote service activity"; sid:7770001; rev:1;)',
            msg="Possible remote service activity", action="alert", protocol="tcp", source="any",
            source_port="any", direction="->", destination="any", destination_port="445",
            classtype=None, rule_metadata=[], references=[], flow=[], flowbits=[], contents=[], pcre=[], app_layer=[],
        )
        db.add(rule); db.flush()
        classification = Classification(
            rule_id=rule.id, detected_behavior="Possible remote service activity", detected_entity=None,
            entity_type=None, category="Network Abuse", subcategory="Suspicious TCP Activity",
            mitre_tactic=None, mitre_technique=None, mitre_technique_id=None,
            cyber_kill_chain_phase=None, confidence=.61, evidence=["TCP destination port 445"],
            explanation="The normal classifier abstained from MITRE mapping.", provider="ollama",
            model_name="qwen3:8b", classifier_version="v2.2", agent_activity={},
            classification_status=ClassificationStatus.REVIEW_REQUIRED, validation_issues=[],
        )
        db.add(classification); db.commit(); classification_id = classification.id

    async def fake_proposal(rule, classification, settings):
        technique = MitreRepository().get("T1021.002")
        candidate = {"id": "T1021.002", "name": technique.name, "tactics": list(technique.tactics), "score": .42,
                     "evidence": [{"type": "LOCAL_NAME_MATCH", "value": "SMB/Windows Admin Shares"}]}
        proposal = ForcedMitreProposal(technique_id="T1021.002", confidence=.48,
                                       explanation="Best-effort mapping from SMB service evidence.", evidence=["Destination port 445"])
        return proposal, technique, [candidate], candidate, "claude", "claude-test"

    monkeypatch.setattr(rules_api, "propose_forced_mitre", fake_proposal)
    monkeypatch.setattr(rules_api, "effective_settings", lambda *args: type("S", (), {})())
    with TestClient(app) as client:
        before = client.get(f"/api/rules/7770001/forced-mitre?classification_id={classification_id}")
        assert before.status_code == 200 and before.json() == {"eligible": True, "reason": None, "mapping": None}
        assert client.post("/api/rules/7770001/forced-mitre", json={"classification_id": classification_id, "acknowledge_risk": False}).status_code == 400
        created = client.post("/api/rules/7770001/forced-mitre", json={"classification_id": classification_id, "acknowledge_risk": True})
        assert created.status_code == 200, created.text
        assert created.json()["technique_id"] == "T1021.002"
        assert created.json()["forced"] is True
        assert "may be misleading" in created.json()["warning"]
        state = client.get(f"/api/rules/7770001/forced-mitre?classification_id={classification_id}").json()
        assert state["mapping"]["provider"] == "claude"
        assert state["mapping"]["model_name"] == "claude-test"
        audit = client.get("/api/audit-log", params={"action": "FORCED_MITRE", "sid": 7770001})
        assert audit.status_code == 200 and audit.json()["total"] == 1


def test_forced_mitre_is_blocked_when_normal_result_is_already_mapped():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestingSession() as db:
        rule = Rule(sid=7770002, rev=1, raw_rule='alert tcp any any -> any any (msg:"Mapped"; sid:7770002; rev:1;)',
                    msg="Mapped", action="alert", protocol="tcp", source="any", source_port="any", direction="->",
                    destination="any", destination_port="any", classtype=None, rule_metadata=[], references=[], flow=[],
                    flowbits=[], contents=[], pcre=[], app_layer=[])
        db.add(rule); db.flush()
        classification = Classification(rule_id=rule.id, detected_behavior="PowerShell execution", detected_entity="PowerShell",
            entity_type="Software", category="Command and Control", subcategory="HTTP C2 Communication",
            mitre_tactic="Execution", mitre_technique="PowerShell", mitre_technique_id="T1059.001",
            cyber_kill_chain_phase=None, confidence=.8, evidence=[], explanation="Mapped", provider="ollama",
            model_name="qwen3:8b", classifier_version="v2.2", agent_activity={},
            classification_status=ClassificationStatus.AUTO_CLASSIFIED, validation_issues=[])
        db.add(classification); db.commit(); classification_id = classification.id
    with TestClient(app) as client:
        state = client.get(f"/api/rules/7770002/forced-mitre?classification_id={classification_id}")
        assert state.status_code == 200 and state.json()["eligible"] is False
        response = client.post("/api/rules/7770002/forced-mitre", json={"classification_id": classification_id, "acknowledge_risk": True})
        assert response.status_code == 409


def test_product_ruleset_preview_and_import_marks_existing_without_ai():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    sample = Path(__file__).resolve().parents[2] / "data" / "samples" / "v1-synthetic.rules"
    with TestClient(app) as client:
        with sample.open("rb") as handle:
            preview = client.post(
                "/api/rules/existing/preview",
                files=[("files", (sample.name, handle, "text/plain"))],
            )
        assert preview.status_code == 200, preview.text
        assert preview.json()["discovered"] == 20
        assert preview.json()["exact_matches"] == 0
        assert preview.json()["new_catalog_rules"] == 20
        assert preview.json()["failed"] == 0

        with sample.open("rb") as handle:
            imported = client.post(
                "/api/rules/existing/import",
                files=[("files", (sample.name, handle, "text/plain"))],
            )
        assert imported.status_code == 200, imported.text
        assert imported.json()["imported"] == 20
        assert imported.json()["marked_existing"] == 20
        assert imported.json()["already_marked"] == 0

        listing = client.get("/api/rules", params={"product_status": "ALREADY_INTEGRATED"})
        assert listing.status_code == 200, listing.text
        assert listing.json()["total"] == 20
        assert all(item["classification"] is None for item in listing.json()["items"])
        assert all(item["product_decision"]["status"] == "ALREADY_INTEGRATED" for item in listing.json()["items"])

        with sample.open("rb") as handle:
            repeated = client.post(
                "/api/rules/existing/import",
                files=[("files", (sample.name, handle, "text/plain"))],
            )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["imported"] == 0
        assert repeated.json()["marked_existing"] == 0
        assert repeated.json()["already_marked"] == 20


@pytest.mark.parametrize(
    ("filename", "payload", "content_type", "expected"),
    [
        ("notes.txt", b"not a ruleset", "text/plain", "Only .rules files are accepted"),
        ("renamed.rules", b"\x00\x01\x02binary", "application/octet-stream", "Binary data"),
        ("photo.rules", b"not really an image", "image/jpeg", "Unsupported content type"),
        ("invalid.rules", b"\xff\xfe\xfd", "text/plain", "valid UTF-8"),
        ("empty.rules", b"# comments only\n", "text/plain", "No active Suricata rules"),
        ("../escaped.rules", b'alert tcp any any -> any any (sid:1;)', "text/plain", "must not contain a path"),
    ],
)
def test_ruleset_upload_rejects_unrelated_or_unsafe_files_without_database_writes(filename, payload, content_type, expected):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        preview = client.post("/api/rules/existing/preview", files=[("files", (filename, payload, content_type))])
        assert preview.status_code == 200, preview.text
        body = preview.json()
        assert body["discovered"] == 0 and body["new_catalog_rules"] == 0
        assert expected in " ".join(body["files"][0]["errors"])

        imported = client.post("/api/rules/existing/import", files=[("files", (filename, payload, content_type))])
        assert imported.status_code == 200, imported.text
        assert imported.json()["imported"] == 0
        assert client.get("/api/rules", params={"limit": 1}).json()["total"] == 0


def test_ruleset_upload_enforces_file_count_and_streamed_size_limits(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    valid = b'alert tcp any any -> any any (msg:"safe"; sid:9991001; rev:1;)'
    with TestClient(app) as client:
        too_many = [("files", (f"{index}.rules", valid, "text/plain")) for index in range(rules_api.MAX_BASELINE_FILES + 1)]
        response = client.post("/api/rules/existing/preview", files=too_many)
        assert response.status_code == 413

        monkeypatch.setattr(rules_api, "MAX_BASELINE_UPLOAD_BYTES", 16)
        response = client.post("/api/rules/existing/preview", files=[("files", ("large.rules", valid, "text/plain"))])
        assert response.status_code == 200
        assert "25 MB ruleset limit" in " ".join(response.json()["files"][0]["errors"])


def test_product_rule_can_be_removed_from_existing_baseline_without_deleting_catalogue_record():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    sample = Path(__file__).resolve().parents[2] / "data" / "samples" / "v1-synthetic.rules"
    with TestClient(app) as client:
        with sample.open("rb") as handle:
            imported = client.post(
                "/api/rules/existing/import",
                files=[("files", (sample.name, handle, "text/plain"))],
            )
        assert imported.status_code == 200, imported.text

        removed = client.put(
            "/api/rules/9900001/product",
            json={
                "status": "NOT_EVALUATED",
                "note": "Removed from the current product baseline on the Existing Rules page.",
            },
        )
        assert removed.status_code == 200, removed.text
        assert removed.json()["status"] == "NOT_EVALUATED"

        listing = client.get("/api/rules", params={"product_status": "ALREADY_INTEGRATED"})
        assert listing.status_code == 200, listing.text
        assert listing.json()["total"] == 19
        assert all(item["sid"] != 9900001 for item in listing.json()["items"])

        detail = client.get("/api/rules/9900001")
        assert detail.status_code == 200
        assert detail.json()["sid"] == 9900001

        history = client.get("/api/rules/9900001/product/history")
        assert history.status_code == 200
        assert history.json()[0]["from_status"] == "ALREADY_INTEGRATED"
        assert history.json()[0]["to_status"] == "NOT_EVALUATED"


def test_product_ruleset_reuses_qwen_and_classifies_only_new_rules_with_gemini(monkeypatch):
    from app.services import product_ruleset_import

    class FakeGemini:
        provider_name = "gemini"
        model_name = "fake-gemini"
        inference_mode = "API"
        configuration = {}

        def __init__(self):
            self.calls: list[int] = []

        async def classify(self, context):
            self.calls.append(context.sid)
            return ProviderResult(output=ClassificationOutput(
                detected_behavior="Synthetic product rule activity",
                detected_entity=None,
                entity_type=None,
                category="Network Abuse",
                subcategory="Suspicious TCP Activity",
                mitre_tactic=None,
                mitre_technique=None,
                mitre_technique_id=None,
                cyber_kill_chain_phase=None,
                confidence=0.9,
                evidence=["Rule message and TCP protocol"],
                explanation="Synthetic test classification",
            ))

    fake = FakeGemini()
    monkeypatch.setattr(product_ruleset_import, "SessionLocal", TestingSession)
    monkeypatch.setattr(product_ruleset_import, "provider_config_error", lambda settings: None)
    monkeypatch.setattr(product_ruleset_import, "create_classification_provider", lambda settings: fake)

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    existing_rule = 'alert tcp any any -> any any (msg:"EXISTING QWEN RULE"; sid:9988001; rev:1;)'
    new_rule = 'alert tcp any any -> any any (msg:"NEW PRODUCT RULE"; sid:9988002; rev:1;)'
    with TestClient(app) as client:
        imported = client.post("/api/rules/import", files=[("files", ("catalog.rules", existing_rule.encode(), "text/plain"))])
        assert imported.status_code == 200, imported.text

        with TestingSession() as db:
            rule = db.scalar(select(Rule).where(Rule.sid == 9988001))
            db.add(Classification(
                rule_id=rule.id,
                model_name="qwen3:8b",
                provider="ollama",
                classifier_version="qwen-v2.2",
                classification_status=ClassificationStatus.AUTO_CLASSIFIED,
                confidence=0.95,
                evidence=["existing qwen result"],
                explanation="Existing catalogue classification",
            ))
            db.commit()

        product_ruleset = f"{existing_rule}\n{new_rule}\n".encode()
        preview = client.post("/api/rules/existing/preview", files=[("files", ("product.rules", product_ruleset, "text/plain"))])
        assert preview.status_code == 200, preview.text
        assert preview.json()["reusable_classifications"] == 1
        assert preview.json()["gemini_candidates"] == 1

        result = client.post("/api/rules/existing/import", files=[("files", ("product.rules", product_ruleset, "text/plain"))])
        assert result.status_code == 200, result.text
        payload = result.json()
        assert payload["reused_classifications"] == 1
        assert payload["queued_for_gemini"] == 1
        assert payload["classification_batch_id"]
        assert fake.calls == [9988002]

        batch = client.get(f"/api/rules/existing/batches/{payload['classification_batch_id']}")
        assert batch.status_code == 200, batch.text
        assert batch.json()["status"] == "COMPLETED"
        assert batch.json()["processed"] == 1

        with TestingSession() as db:
            existing_providers = list(db.scalars(
                select(Classification.provider).join(Rule).where(Rule.sid == 9988001)
            ))
            new_classification = db.scalar(
                select(Classification).join(Rule).where(Rule.sid == 9988002)
            )
        assert existing_providers == ["ollama"]
        assert new_classification.provider == "gemini"
        assert new_classification.inspection_batch == payload["classification_batch_id"]
        assert new_classification.agent_activity["classification_trigger"] == "PRODUCT_RULESET_IMPORT"
