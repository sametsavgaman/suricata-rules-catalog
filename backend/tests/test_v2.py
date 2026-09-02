from pathlib import Path
from app.agent.schemas import ClassificationOutput
from app.evaluation.metrics import normalize_behavior
from app.knowledge.taxonomy import canonical_subcategory
from app.parser.suricata_parser import SuricataRuleParser
from app.v2.pipeline import finalize
from app.v2.tools import entity_candidates,extract_cves,search_similar_rules
from app.knowledge.mitre_repository import MitreRepository
from app.v2.state import build_field_decisions, confidence_summary

def output(**kw):
    base=dict(detected_behavior="test",detected_entity=None,entity_type=None,category="Reconnaissance",subcategory="Scanning",mitre_tactic=None,mitre_technique=None,mitre_technique_id=None,cyber_kill_chain_phase=None,confidence=.8,evidence=[],explanation="test")
    base.update(kw); return ClassificationOutput(**base)

def test_controlled_subcategory_alias(): assert canonical_subcategory("Reconnaissance","Scanning")=="Web Scan"
def test_weak_port_entity_abstains():
    rule=SuricataRuleParser().parse('alert tcp any any -> any 1433 (msg:"MSSQL port"; sid:1;)')
    final,activity=finalize(output(detected_entity="MSSQL",entity_type="Product"),rule=rule,entity_candidates=entity_candidates(rule),mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.detected_entity is None and "detected_entity" in activity.abstained_fields
def test_explicit_anydesk_entity_allowed():
    rule=SuricataRuleParser().parse('alert tls any any -> any any (msg:"Observed AnyDesk"; content:"anydesk"; sid:2;)')
    final,_=finalize(output(detected_entity="AnyDesk",entity_type="Remote Access Tool"),rule=rule,entity_candidates=entity_candidates(rule),mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.detected_entity=="AnyDesk"
def test_arbitrary_mitre_blocked():
    rule=SuricataRuleParser().parse('alert tcp any any -> any any (msg:"test"; sid:4;)')
    final,_=finalize(output(mitre_tactic="Discovery",mitre_technique="Network Service Scanning",mitre_technique_id="T1046"),rule=rule,entity_candidates=[],mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.mitre_technique_id is None
def test_cve_extraction():
    rule=SuricataRuleParser().parse('alert http any any -> any any (msg:"CVE-2024-45519"; sid:3;)')
    assert extract_cves(rule)[0]["id"]=="CVE-2024-45519"
def test_behavior_semantic_normalization(): assert normalize_behavior("Observed AnyDesk remote access software connection")==normalize_behavior("Remote administration software traffic")
def test_similar_rule_excludes_same_sid():
    rule=SuricataRuleParser().parse('alert tcp any any -> any 1433 (msg:"ET SCAN Suspicious inbound to MSSQL port 1433"; sid:2010935; rev:3;)')
    rows=search_similar_rules(rule,Path(__file__).resolve().parents[2]/"data/evaluation/golden_dataset.jsonl")
    assert all(r["sid"]!=2010935 and r["source"]=="AUDITED_BENCHMARK" for r in rows)

def test_mitre_derived_subtechnique_provenance():
    rule=SuricataRuleParser().parse('alert dns any any -> any any (msg:"DNS C2"; metadata:mitre_technique_id T1071; sid:5;)')
    final,activity=finalize(output(mitre_tactic="Command and Control",mitre_technique="DNS",mitre_technique_id="T1071.004"),rule=rule,entity_candidates=[],mitre_candidates=[{"id":"T1071.004","name":"DNS","tactics":["Command and Control"],"score":.55}],tool_names=["search_mitre"],similar_count=0)
    assert activity.as_dict()["mitre_mapping_method"] == "DERIVED_SUBTECHNIQUE"
    assert activity.as_dict()["validator_mitre_status"] == "PASS_WITH_ENRICHMENT"
    assert activity.as_dict()["model_confidence"] != activity.as_dict()["mitre_retrieval_score"]

def test_generic_web_attack_subcategory_abstains_instead_of_invalid_label():
    rule=SuricataRuleParser().parse('alert http any any -> any any (msg:"Generic browser exploit attempt"; sid:6;)')
    final,_=finalize(output(category="Web Attack",subcategory="Browser Exploit"),rule=rule,entity_candidates=[],mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.subcategory is None

def test_official_mitre_repository_is_comprehensive():
    repository=MitreRepository()
    assert len(repository.all()) >= 600
    assert repository.get("T1071.004").parent_id == "T1071"

def test_explicit_cobalt_strike_entity_candidate():
    rule=SuricataRuleParser().parse('alert ip any any -> any any (msg:"Cobalt Strike C2 IP"; sid:7;)')
    assert entity_candidates(rule)[0]["candidate"] == "Cobalt Strike"

def test_single_explicit_entity_fills_model_abstention():
    rule=SuricataRuleParser().parse('alert ip any any -> any any (msg:"Cobalt Strike C2 IP"; sid:8;)')
    final,activity=finalize(output(),rule=rule,entity_candidates=entity_candidates(rule),mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.detected_entity == "Cobalt Strike"
    assert final.entity_type == "Attack Tool"
    assert "deterministically resolved" in final.explanation

def test_generic_affected_product_is_not_entity():
    rule=SuricataRuleParser().parse('alert http any any -> any any (msg:"Generic web rule"; metadata:affected_product Web_Browsers; sid:9;)')
    assert entity_candidates(rule) == []

def test_specific_affected_product_is_strong_entity():
    rule=SuricataRuleParser().parse('alert http any any -> any any (msg:"Exploit"; metadata:affected_product Apache_HTTP_server; sid:10;)')
    candidate=entity_candidates(rule)[0]
    assert candidate["candidate"] == "Apache HTTP server"
    assert candidate["evidence_type"] == "SPECIFIC_AFFECTED_PRODUCT"

def test_multiple_explicit_entities_do_not_auto_select():
    rule=SuricataRuleParser().parse('alert http any any -> any any (msg:"PowerShell delivered Cobalt Strike"; sid:11;)')
    final,_=finalize(output(),rule=rule,entity_candidates=entity_candidates(rule),mitre_candidates=[],tool_names=[],similar_count=0)
    assert final.detected_entity is None

def test_field_decisions_distinguish_abstained_and_not_applicable():
    values={"detected_behavior":"Traffic from known malicious infrastructure","detected_entity":None,"entity_type":None,"category":"Network Abuse","subcategory":"Suspicious IP Activity","mitre_tactic":None,"mitre_technique":None,"mitre_technique_id":None,"cyber_kill_chain_phase":None}
    d=build_field_decisions(values,["detected_entity","mitre_tactic","mitre_technique","mitre_technique_id","cyber_kill_chain_phase"])
    assert d["detected_entity"]["status"] == "ABSTAINED"
    assert d["entity_type"]["status"] == "NOT_APPLICABLE"
    assert d["mitre_technique"]["status"] == "ABSTAINED"

def test_field_decisions_assigned_requires_value():
    d=build_field_decisions({"detected_behavior":None},[],legacy=False)
    assert d["detected_behavior"]["status"] == "ABSTAINED"

def test_confidence_band_is_raw_and_transparent():
    class C: model_confidence=.85; confidence=.85
    summary=confidence_summary(C(), {"detected_behavior":{"status":"ASSIGNED"}})
    assert summary["band"] == "HIGH"
    assert "coverage is not applied" in summary["band_definition"]
