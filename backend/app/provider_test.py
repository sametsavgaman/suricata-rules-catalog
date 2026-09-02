import asyncio
from app.agent.factory import create_classification_provider, provider_config_error
from app.agent.schemas import ClassificationContext
from app.config import get_settings

async def main():
    settings=get_settings(); error=provider_config_error(settings)
    if error: print(error); return 2
    provider=create_classification_provider(settings)
    context=ClassificationContext(sid=1,msg="benign tcp test",protocol="tcp",classtype=None,metadata=[],references=[],flow=[],flowbits=[],content=[],pcre=[],app_layer=[],entity_hint=None,category_hint=None,mitre_candidates=[])
    await provider.classify(context)
    print(f"Provider: {settings.ai_provider}\nModel: {provider.model_name}\nStatus: OK"); return 0
if __name__=="__main__": raise SystemExit(asyncio.run(main()))
