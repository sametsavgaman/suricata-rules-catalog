import asyncio
import json

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.agent.schemas import ClassificationOutput, ProviderResult
from app.api.schemas import rule_to_read
from app.config import Settings
from app.database.models import Classification, ClassificationStatus, ManualReview
from app.database.repository import RuleRepository
from app.database.session import Base, get_db
from app.evaluation.compare_models import frozen_sample, summarize, SAMPLE, digest
from app.knowledge.mitre_repository import MitreRepository
from app.main import app
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService
from app.evaluation.comparison_report import paired_analysis
import pytest


def test_frozen_sample_and_fresh_metrics_have_no_accuracy():
    before = digest(SAMPLE)
    rows = frozen_sample()
    assert len(rows) == 250
    assert sum(r['cohort'] == 'AUDITED_BENCHMARK' for r in rows) == 97
    assert rows == frozen_sample()
    assert digest(SAMPLE) == before
    summary = summarize([dict(sid=1,rev=1,cohort='FRESH_OPERATIONAL',succeeded=True,
        final_classification={'category':None,'detected_entity':None,'mitre_technique_id':None},
        usage=dict(input_tokens=10,output_tokens=20,total_tokens=30),wall_seconds=1,
        agent_activity={},validator={'status':'PASS'})], {})
    assert summary['audited_metrics'] is None
    assert 'accuracy' not in json.dumps(summary['fresh_operational'])
    assert summary['usage']['total_tokens'] == 30


def test_paired_report_checks_identity_and_does_not_call_agreement_accuracy():
    common = dict(sid=1,rev=1,cohort='FRESH_OPERATIONAL',succeeded=True,
        final_classification={'category':'Reconnaissance'},classification_id=1,
        configuration={'context_sha256':'same','prompt_sha256':'same'})
    g,q = {**common,'provider':'gemini'}, {**common,'provider':'ollama'}
    report = paired_analysis([g,q])
    assert report['successful_pairs']==1
    assert report['agreement_not_accuracy']['category']==1
    assert report['context_or_prompt_mismatches']==[]
    q['configuration']={'context_sha256':'different','prompt_sha256':'same'}
    assert paired_analysis([g,q])['context_or_prompt_mismatches']==[[1,1]]
    with pytest.raises(ValueError,match='Duplicate'):
        paired_analysis([g,q,q])


def test_provider_filter_selects_each_models_result_and_review_is_scoped():
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        rule, _ = RuleRepository(db).upsert(SuricataRuleParser().parse('alert tcp any any -> any any (msg:"test"; sid:991123; rev:1;)'), 'test.rules')
        for provider in ('gemini', 'ollama'):
            db.add(Classification(rule_id=rule.id,provider=provider,model_name=provider,confidence=.8,
                classifier_version='v2.1',classification_status=ClassificationStatus.AUTO_CLASSIFIED,
                evidence=[],explanation='test',validation_issues=[],agent_activity={'validator_result':'PASS'}))
        db.commit()
        ids = [c.id for c in rule.classifications]

    def override():
        with Session(engine) as db:
            yield db
    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = override
    try:
        with TestClient(app) as client:
            for name in ('gemini','ollama'):
                r = client.get('/api/rules', params={'provider':name})
                assert r.status_code == 200
                assert r.json()['total'] == 1
                assert r.json()['items'][0]['classification']['provider'] == name
            for cid in ids:
                r = client.post('/api/rules/991123/review',json={'classification_id':cid,'status':'APPROVED','note':'checked'})
                assert r.status_code == 200
                if cid == ids[0]:
                    unreviewed = client.get('/api/rules',params={'provider':'ollama','manual_review_status':'UNREVIEWED'})
                    assert unreviewed.status_code == 200
                    assert unreviewed.json()['total'] == 1
                    assert client.get('/api/rules',params={'provider':'ollama','manual_review_status':'APPROVED'}).json()['total'] == 0
            options = client.get('/api/rules/991123').json()['classification_options']
            assert all(c['manual_review']['status']=='APPROVED' for c in options)
            assert all(c['validation']['status']=='PASS' for c in options)
            # An unreviewed third result must not inherit either approval.
            with Session(engine) as db:
                assert len(db.query(ManualReview).all()) == 2
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def test_model_cache_isolated_and_run_configuration_persisted():
    class GeminiClassificationProvider:
        model_name = 'test-gemini'
        calls = 0
        async def classify(self, context):
            self.calls += 1
            return ProviderResult(output=ClassificationOutput(detected_behavior='Test',detected_entity=None,
                entity_type=None,category=None,subcategory=None,mitre_tactic=None,mitre_technique=None,
                mitre_technique_id=None,cyber_kill_chain_phase=None,confidence=.5,evidence=[],explanation='test'))
    class OllamaClassificationProvider(GeminiClassificationProvider):
        model_name = 'test-qwen'
        inference_mode = 'LOCAL'
        configuration = {'think':False}
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        rule, _ = RuleRepository(db).upsert(SuricataRuleParser().parse('alert tcp any any -> any any (msg:"test"; sid:991124; rev:1;)'),'test.rules')
        db.commit()
        g,q = GeminiClassificationProvider(),OllamaClassificationProvider()
        s = Settings(_env_file=None, classifier_version='v2.1')
        services = [ClassificationService(db, p, s, MitreRepository()) for p in (g,q)]
        records = [asyncio.run(service.classify(rule)) for service in services]
        assert records[0].id != records[1].id
        assert records[0].inference_mode=='API' and records[1].inference_mode=='LOCAL'
        assert records[0].model_config_json['context_sha256']==records[1].model_config_json['context_sha256']
        assert records[1].model_config_json['think'] is False
        for service, record in zip(services,records):
            assert asyncio.run(service.classify(rule)).id == record.id
        assert (g.calls,q.calls)==(1,1)
