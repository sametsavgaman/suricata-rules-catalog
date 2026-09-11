from app.services import scenario_analysis as service
from app.services.catalog_assistant import CatalogAnswer, CatalogItem
from pydantic import ValidationError


def item(sid, mitre_id=None):
    return CatalogItem(sid=sid, rev=1, classification_id=1, message=f"sample {sid}",
                       category="Remote Access", subcategory="Remote Desktop", entity=None,
                       mitre_id=mitre_id, mitre_tactic="Lateral Movement" if mitre_id else None,
                       provider="ollama", model="qwen3:8b", product_status="NOT_EVALUATED")


def test_evaluate_uses_exact_mitre_as_authoritative(monkeypatch):
    plan = service.ScenarioPlan(summary="RDP", steps=[service.ScenarioPlanStep(
        title="RDP lateral movement", technique_id="T1021.001", keywords=["rdp"], confidence=.9)])
    calls = []
    def search(_, filters, limit):
        calls.append(filters)
        return CatalogAnswer(status="RESULTS", answer="", total=1, items=[item(900001, "T1021.001")])
    monkeypatch.setattr(service, "_search", search)
    result = service.evaluate_scenario(None, plan, "gemini-test")
    assert result.status == "COVERED"
    assert result.steps[0].status == "COVERED"
    assert result.recommendations[0].match_type == "MITRE"
    assert len(calls) == 1  # keyword/protocol broadening is skipped after exact evidence


def test_evaluate_marks_gap_without_local_evidence(monkeypatch):
    plan = service.ScenarioPlan(summary="Unknown", steps=[service.ScenarioPlanStep(title="Unknown behavior", keywords=["never-seen"] )])
    monkeypatch.setattr(service, "_search", lambda *_: CatalogAnswer(status="RESULTS", answer="", total=0, items=[]))
    result = service.evaluate_scenario(None, plan, "gemini-test")
    assert result.status == "GAP"
    assert result.steps[0].matched_rule_count == 0
    assert result.recommendations == []


def test_scenario_question_allows_only_supported_providers():
    assert service.ScenarioQuestion(question="A concrete customer attack scenario", provider="claude").provider == "claude"
    try:
        service.ScenarioQuestion(question="A concrete customer attack scenario", provider="mistral")
    except ValidationError:
        pass
    else:
        raise AssertionError("unsupported provider accepted")
