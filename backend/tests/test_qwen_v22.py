from app.agent.schemas import ClassificationOutput
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.v2.qwen_hardening import canonicalize, observation_type, build_semantic_context, qwen_entity_candidates
from app.v2.mitre_decision import retrieve_candidates, resolve_selected


def proposal(**kwargs):
    value = dict(detected_behavior="Web Attack", detected_entity=None, entity_type=None,
                 category="Web Attack", subcategory="Unusual DNS Query", mitre_tactic="Web Attack",
                 mitre_technique="Web Shell", mitre_technique_id=None, cyber_kill_chain_phase=None,
                 confidence=.8, evidence=["http.host"], explanation="test")
    value.update(kwargs)
    return ClassificationOutput.model_validate(value)


def test_http_host_observation_rejects_dns_subcategory_and_idless_mitre():
    rule = SuricataRuleParser().parse('alert http any any -> any any (http.host; content:"example.test"; msg:"dynamic dns host"; sid:1;)')
    assert observation_type(rule) == "HTTP_HOST_MATCH"
    out, reasons = canonicalize(proposal(), rule=rule, mitre_candidates=[], repository=MitreRepository())
    assert out.subcategory is None
    assert out.mitre_tactic is None and out.mitre_technique is None and out.mitre_technique_id is None
    assert "mitre_atomicity_rejected" in reasons


def test_mitre_selection_is_atomic_and_resolved_from_local_repository():
    rule = SuricataRuleParser().parse('alert dns any any -> any any (msg:"DNS query"; sid:2;)')
    out, _ = canonicalize(proposal(category="Suspicious DNS", subcategory="Unusual DNS Query",
                                    mitre_tactic="garbage", mitre_technique="garbage",
                                    mitre_technique_id="T1071.004"), rule=rule,
                           mitre_candidates=[{"id":"T1071.004","name":"wrong","tactics":[],"score":.4}],
                           repository=MitreRepository())
    assert out.mitre_technique_id == "T1071.004" and out.mitre_technique == "DNS"


def test_qwen_context_is_compact_and_versioned():
    rule = SuricataRuleParser().parse('alert http any any -> any any (http.uri; msg:"possible SQL injection"; sid:3;)')
    context = build_semantic_context(rule, hints=None, entity_candidates=[], mitre_candidates=[], cves=[], similar_rules=[], controlled_subcategories={})
    assert context["input_version"] == "qwen_semantic_input_v2"
    assert context["observable"]["observation_type"] == "HTTP_URI_MATCH"


def test_ioc_association_is_not_labeled_as_direct_fingerprint():
    rule = SuricataRuleParser().parse('alert ip any any -> any any (msg:"Threatview C2 IP association"; sid:4;)')
    candidate = {"candidate": "Cobalt Strike", "entity_type": "Attack Tool", "evidence_type": "EXPLICIT_RULE_NAME", "weak": False}
    assert qwen_entity_candidates(rule, [candidate])[0]["evidence_type"] == "IOC_ASSOCIATION"


def test_mitre_decision_layer_retrieves_and_resolves_canonical_tuple():
    rule = SuricataRuleParser().parse('alert dns any any -> any any (msg:"DNS C2 lookup"; sid:5;)')
    repo = MitreRepository()
    candidates = retrieve_candidates(rule, repo)
    assert any(x["id"] == "T1071.004" for x in candidates)
    decision = resolve_selected("T1071.004", candidates, rule, repo)
    assert decision.technique_name == "DNS"
    assert decision.tactic.casefold() == "command and control"
