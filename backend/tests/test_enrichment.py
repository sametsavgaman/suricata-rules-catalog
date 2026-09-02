from app.enrichment.deterministic_enrichment import enrich_rule
from app.parser.suricata_parser import SuricataRuleParser


def test_nmap_and_scan_hints_are_explainable():
    rule = SuricataRuleParser().parse('alert tcp any any -> any any (msg:"ET SCAN NMAP -sS window 1024"; sid:1; rev:1;)')
    hints = enrich_rule(rule)
    assert hints.entity_hint == "Nmap"
    assert hints.category_hint == "Reconnaissance"
    assert len(hints.hint_evidence) == 2


def test_unknown_message_produces_null_hints():
    rule = SuricataRuleParser().parse('alert tcp any any -> any any (msg:"Generic sample"; sid:2; rev:1;)')
    hints = enrich_rule(rule)
    assert hints.entity_hint is None
    assert hints.category_hint is None

