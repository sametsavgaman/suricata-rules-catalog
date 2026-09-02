import asyncio
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.agent.schemas import ClassificationOutput, ProviderResult, TokenUsage
from app.config import Settings
from app.database.models import ClassificationStatus
from app.database.repository import RuleRepository
from app.database.session import Base
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService


class FakeProvider:
    model_name = "fake-structured-model"

    def __init__(self):
        self.calls = 0

    async def classify(self, context):
        self.calls += 1
        assert context.sid == 1001
        assert context.entity_hint == "Nmap"
        output = ClassificationOutput(
            detected_behavior="TCP SYN network scanning",
            detected_entity="Nmap",
            entity_type="Attack Tool",
            category="Reconnaissance",
            subcategory="Port Scan",
            mitre_tactic="Discovery",
            mitre_technique="Network Service Scanning",
            mitre_technique_id="T1046",
            cyber_kill_chain_phase="Reconnaissance",
            confidence=0.96,
            evidence=["NMAP appears directly in msg", "flags:S and window:1024 are signature conditions"],
            explanation="Direct tool name and SYN scan signature evidence.",
        )
        return ProviderResult(output=output, usage=TokenUsage(input_tokens=120, output_tokens=30, total_tokens=150))


def test_single_call_and_sid_rev_cache(tmp_path):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    mitre_path = tmp_path / "mitre.json"
    mitre_path.write_text(json.dumps([{"technique_id":"T1046","name":"Network Service Scanning","tactics":["Discovery"]}]), encoding="utf-8")
    with Session() as db:
        parsed = SuricataRuleParser().parse('alert tcp any any -> any any (msg:"ET SCAN NMAP -sS window 1024"; flags:S; window:1024; sid:1001; rev:1;)')
        rule, _ = RuleRepository(db).upsert(parsed, "test.rules")
        db.commit()
        provider = FakeProvider()
        service = ClassificationService(db, provider, Settings(), MitreRepository(mitre_path))
        first = asyncio.run(service.classify(rule))
        assert first._token_usage.total_tokens == 150
        second = asyncio.run(service.classify(rule))
        assert first.classification_status == ClassificationStatus.AUTO_CLASSIFIED
        assert first.id == second.id
        assert provider.calls == 1
        assert second._cache_hit is True
        assert second._token_usage.total_tokens == 0

        forced = asyncio.run(service.classify(rule, force=True))
        assert forced.id != first.id
        assert provider.calls == 2
