from app.agent.classifier import OpenAIClassificationProvider, ClassificationProvider, ProviderUnavailable
from app.agent.gemini import GeminiClassificationProvider
from app.agent.ollama import OllamaClassificationProvider
from app.config import Settings

def create_classification_provider(settings: Settings) -> ClassificationProvider:
    provider=settings.ai_provider.casefold()
    if provider=="openai": return OpenAIClassificationProvider(settings.openai_api_key, settings.openai_model)
    if provider=="gemini": return GeminiClassificationProvider(settings.gemini_api_key, settings.gemini_model, settings.ai_max_retries)
    if provider=="ollama": return OllamaClassificationProvider(settings.ollama_model, settings.ollama_base_url, settings.ollama_timeout_seconds, settings.ollama_num_ctx, settings.ollama_num_predict, settings.ai_max_retries)
    raise ProviderUnavailable(f"Unsupported AI_PROVIDER: {settings.ai_provider}")

def provider_config_error(settings: Settings) -> str | None:
    if settings.ai_provider.casefold()=="openai":
        if not settings.openai_api_key: return "OPENAI_API_KEY_NOT_CONFIGURED"
        if not settings.openai_model: return "OPENAI_MODEL_NOT_CONFIGURED"
    elif settings.ai_provider.casefold()=="gemini":
        if not settings.gemini_api_key: return "GEMINI_API_KEY_NOT_CONFIGURED"
        if not settings.gemini_model: return "GEMINI_MODEL_NOT_CONFIGURED"
    elif settings.ai_provider.casefold()=="ollama":
        if not settings.ollama_model: return "OLLAMA_MODEL_NOT_CONFIGURED"
    else: return "UNSUPPORTED_AI_PROVIDER"
    return None
