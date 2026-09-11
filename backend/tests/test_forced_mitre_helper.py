import asyncio
from types import SimpleNamespace

from app.services import forced_mitre
from app.services.forced_mitre import ForcedMitreProposal


def test_forced_mitre_accepts_a_locally_verified_technique_outside_suggestions(monkeypatch):
    monkeypatch.setattr(forced_mitre, "retrieve_candidates", lambda *args, **kwargs: [
        {"id": "T1046", "name": "Network Service Discovery", "tactics": ["Discovery"], "evidence": []}
    ])

    async def generate(*args, **kwargs):
        return ForcedMitreProposal(
            technique_id="T1059.001",
            confidence=.44,
            explanation="Best-effort PowerShell mapping.",
            evidence=["The signature message explicitly names PowerShell."],
        ), "openai", "gpt-test"

    monkeypatch.setattr(forced_mitre, "generate_structured", generate)
    rule = SimpleNamespace(
        raw_rule='alert http any any -> any any (msg:"PowerShell command"; sid:9900001; rev:1;)',
        sid=9900001, msg="PowerShell command", protocol="http", classtype=None,
        rule_metadata=[], references=[], flow=[], flowbits=[], contents=[], pcre=[], app_layer=[],
    )
    classification = SimpleNamespace(
        detected_behavior="PowerShell command execution", detected_entity="PowerShell",
        entity_type="Software", category="Execution", subcategory=None, evidence=[],
        explanation="MITRE evidence was insufficient for the normal decision.",
    )
    proposal, technique, candidates, selected, provider, model = asyncio.run(
        forced_mitre.propose_forced_mitre(rule, classification, SimpleNamespace(), provider="openai")
    )
    assert proposal.technique_id == "T1059.001"
    assert technique.technique_id == "T1059.001"
    assert selected is None and candidates[0]["id"] == "T1046"
    assert (provider, model) == ("openai", "gpt-test")
