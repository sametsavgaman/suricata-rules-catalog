import pytest

from app.ingestion.rule_loader import RuleLoader
from app.parser.models import RuleParseError
from app.parser.suricata_parser import SuricataRuleParser


parser = SuricataRuleParser()


def test_normal_tcp_rule():
    rule = parser.parse('alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -sS window 1024"; flags:S; window:1024; classtype:attempted-recon; sid:1000001; rev:2;)')
    assert rule.sid == 1000001
    assert rule.rev == 2
    assert rule.protocol == "tcp"
    assert rule.msg == "ET SCAN NMAP -sS window 1024"
    assert rule.source == "$EXTERNAL_NET"


def test_http_sticky_buffers_and_multiple_contents():
    rule = parser.parse('alert http any any -> any any (msg:"sample HTTP"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/login"; nocase; sid:1000002; rev:1;)')
    assert rule.contents == ["POST", "/login"]
    assert rule.flow == ["established", "to_server"]
    assert [field["name"] for field in rule.app_layer] == ["http.method", "http.uri"]


def test_dns_metadata_reference_and_pcre():
    rule = parser.parse('alert dns any any -> any any (msg:"sample DNS"; dns.query; content:"evil.example"; pcre:"/^[a-z0-9]{12}\\.example$/i"; metadata:attack_target Client_Endpoint, created_at 2026_01_01; reference:url,example.test/advisory; sid:1000003; rev:1;)')
    assert rule.metadata == ["attack_target Client_Endpoint", "created_at 2026_01_01"]
    assert rule.references == ["url,example.test/advisory"]
    assert rule.pcre == ["/^[a-z0-9]{12}\\.example$/i"]
    assert rule.app_layer[0]["name"] == "dns.query"


def test_flowbits_and_escaped_semicolon_in_quote():
    rule = parser.parse('alert tcp any any -> any any (msg:"escaped; semicolon"; content:"foo\\;bar"; flowbits:set,ET.sample; flowbits:noalert; sid:1000004; rev:1;)')
    assert rule.msg == "escaped; semicolon"
    assert rule.contents == ["foo\\;bar"]
    assert rule.flowbits == ["set,ET.sample", "noalert"]


def test_multiline_rule_loader():
    text = '''# disabled rule
alert tcp any any -> any 443 (
  msg:"multiline sample";
  flow:established,to_server;
  content:"hello";
  sid:1000005; rev:1;
)
'''
    loaded = RuleLoader().load_text(text)
    assert len(loaded.rules) == 1
    assert parser.parse(loaded.rules[0]).sid == 1000005


def test_address_list_with_spaces_is_one_header_field():
    rule = parser.parse('alert ip [10.0.0.0/8, 192.168.0.0/16] any <> any any (msg:"list"; sid:1000006; rev:1;)')
    assert rule.source == "[10.0.0.0/8, 192.168.0.0/16]"
    assert rule.direction == "<>"


def test_invalid_rule_has_clear_error():
    with pytest.raises(RuleParseError, match="sid and rev"):
        parser.parse('alert tcp any any -> any any (msg:"missing sid";)')

