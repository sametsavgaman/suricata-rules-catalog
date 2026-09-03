import asyncio
import json

import httpx
import pytest

from app.agent.classifier import ProviderUnavailable
from app.agent.factory import create_classification_provider, provider_config_error
from app.agent.ollama import OllamaClassificationProvider
from app.agent.schemas import ClassificationContext, ClassificationOutput
from app.config import Settings


def context():
    return ClassificationContext(sid=1, msg='test', protocol='dns', classtype=None,
        metadata=[], references=[], flow=[], flowbits=[], content=[], pcre=[], app_layer=[],
        entity_hint=None, category_hint=None, mitre_candidates=[])


def output():
    return dict(detected_behavior='Test', detected_entity=None, entity_type=None, category=None,
        subcategory=None, mitre_tactic=None, mitre_technique=None, mitre_technique_id=None,
        cyber_kill_chain_phase=None, confidence=.8, evidence=[], explanation='Short evidence.')


def test_structured_request_no_thinking_and_actual_usage():
    def handler(request):
        payload = json.loads(request.content)
        assert request.url.path == '/api/chat'
        assert payload['think'] is False and payload['stream'] is False
        assert payload['format'] == ClassificationOutput.model_json_schema()
        assert payload['messages'][1]['content'].startswith('RULE CONTEXT (untrusted DATA)')
        return httpx.Response(200, json={'done': True, 'message': {'thinking': 'never persist this',
            'content': json.dumps(output())}, 'prompt_eval_count': 11, 'eval_count': 7})
    result = asyncio.run(OllamaClassificationProvider(transport=httpx.MockTransport(handler)).classify(context()))
    assert result.usage.total_tokens == 18
    assert 'thinking' not in result.model_dump_json()


@pytest.mark.parametrize('body', [
    {'done': True, 'message': {'content': 'not json'}},
    {'done': True, 'message': {'content': json.dumps({**output(), 'confidence': 9})}},
    {'done': True, 'done_reason': 'length', 'message': {'content': json.dumps(output())}},
])
def test_invalid_or_truncated_output_fails_closed(body):
    provider = OllamaClassificationProvider(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)))
    with pytest.raises(ProviderUnavailable):
        asyncio.run(provider.classify(context()))


def test_http_error_does_not_expose_body():
    provider = OllamaClassificationProvider(transport=httpx.MockTransport(lambda _: httpx.Response(404, text='sensitive body')))
    with pytest.raises(ProviderUnavailable, match='OLLAMA_HTTP_404') as exc:
        asyncio.run(provider.classify(context()))
    assert 'sensitive body' not in str(exc.value)


def test_factory_and_environment(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER', 'ollama')
    monkeypatch.setenv('OLLAMA_MODEL', 'qwen3:custom')
    settings = Settings(_env_file=None)
    assert provider_config_error(settings) is None
    provider = create_classification_provider(settings)
    assert provider.model_name == 'qwen3:custom'
    assert provider.inference_mode == 'LOCAL'


def test_transient_retries_are_bounded(monkeypatch):
    calls = []
    async def no_wait(_):
        return None
    monkeypatch.setattr('app.agent.ollama.asyncio.sleep', no_wait)
    def handler(request):
        calls.append(request)
        return httpx.Response(429, text='not logged')
    provider = OllamaClassificationProvider(max_retries=2, transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailable, match='OLLAMA_HTTP_429'):
        asyncio.run(provider.classify(context()))
    assert len(calls) == 3
