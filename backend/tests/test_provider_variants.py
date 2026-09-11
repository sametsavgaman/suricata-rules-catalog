import asyncio
import json
from types import SimpleNamespace

import pytest

from app.agent.classifier import OpenAIClassificationProvider
from app.agent.claude import ClaudeClassificationProvider
from app.agent.schemas import ClassificationContext, ClassificationOutput


def context():
    return ClassificationContext(
        sid=1, msg="test", protocol="tcp", classtype=None, metadata=[], references=[],
        flow=[], flowbits=[], content=[], pcre=[], app_layer=[], entity_hint=None,
        category_hint=None, mitre_candidates=[],
    )


def output():
    return ClassificationOutput(
        detected_behavior="Test behavior", detected_entity=None, entity_type=None,
        category=None, subcategory=None, mitre_tactic=None, mitre_technique=None,
        mitre_technique_id=None, cyber_kill_chain_phase=None, confidence=0.5,
        evidence=[], explanation="Valid test output",
    )


def test_openai_adapter_uses_configured_model_and_structured_responses_api():
    captured = {}

    class Responses:
        async def parse(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                output_parsed=output(),
                usage=SimpleNamespace(input_tokens=11, output_tokens=7, total_tokens=18),
            )

    provider = OpenAIClassificationProvider(None, "gpt-test")
    provider._client = SimpleNamespace(responses=Responses())
    result = asyncio.run(provider.classify(context()))
    assert captured["model"] == "gpt-test"
    assert captured["text_format"] is ClassificationOutput
    assert captured["store"] is False
    assert result.output.detected_behavior == "Test behavior"
    assert result.usage.total_tokens == 18


@pytest.mark.parametrize(
    ("base_url", "expected_url"),
    [
        ("https://api.anthropic.com", "https://api.anthropic.com/v1/messages"),
        ("https://api.anthropic.com/v1", "https://api.anthropic.com/v1/messages"),
        ("https://gateway.example/v1/messages", "https://gateway.example/v1/messages"),
    ],
)
def test_claude_adapter_url_variants_and_structured_output(monkeypatch, base_url, expected_url):
    captured = {}

    class Response:
        status_code = 200

        def json(self):
            return {
                "content": [{"type": "text", "text": json.dumps(output().model_dump(mode="json"))}],
                "usage": {"input_tokens": 13, "output_tokens": 5},
            }

    class Client:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            captured["url"] = url
            captured["request"] = kwargs
            return Response()

    monkeypatch.setattr("app.agent.claude.httpx.AsyncClient", Client)
    result = asyncio.run(ClaudeClassificationProvider("claude-key", "claude-test", base_url).classify(context()))
    assert captured["url"] == expected_url
    assert captured["request"]["headers"]["x-api-key"] == "claude-key"
    assert captured["request"]["json"]["model"] == "claude-test"
    assert result.output.detected_behavior == "Test behavior"
    assert result.usage.total_tokens == 18
