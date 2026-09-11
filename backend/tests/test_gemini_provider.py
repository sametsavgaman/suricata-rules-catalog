import asyncio
from types import SimpleNamespace
from app.agent.factory import create_classification_provider, provider_config_error
from app.agent.gemini import GeminiClassificationProvider
from app.agent.schemas import ClassificationContext
from app.config import Settings

def context():
    return ClassificationContext(sid=1,msg='test',protocol='tcp',classtype=None,metadata=[],references=[],flow=[],flowbits=[],content=[],pcre=[],app_layer=[],entity_hint=None,category_hint=None,mitre_candidates=[])

def test_gemini_selection_does_not_require_openai():
    s=Settings(ai_provider='gemini',gemini_api_key='x',gemini_model='gemini-test',openai_api_key=None,openai_model=None)
    assert provider_config_error(s) is None
    assert create_classification_provider(s).model_name=='gemini-test'

def test_gemini_missing_config():
    s=SimpleNamespace(ai_provider='gemini',gemini_api_key=None,gemini_model=None)
    assert provider_config_error(s)=='GEMINI_API_KEY_NOT_CONFIGURED'

def test_gemini_structured_response_and_usage():
    output='{"detected_behavior":"test","detected_entity":null,"entity_type":null,"category":null,"subcategory":null,"mitre_tactic":null,"mitre_technique":null,"mitre_technique_id":null,"cyber_kill_chain_phase":null,"confidence":0.5,"evidence":[],"explanation":"ok"}'
    class Models:
        async def generate_content(self, **kwargs): return SimpleNamespace(text=output, usage_metadata=SimpleNamespace(prompt_token_count=3,candidates_token_count=4,total_token_count=7))
    client=SimpleNamespace(aio=SimpleNamespace(models=Models()))
    result=asyncio.run(GeminiClassificationProvider('x','gemini-test',client=client).classify(context()))
    assert result.output.detected_behavior=='test'; assert result.usage.total_tokens==7
