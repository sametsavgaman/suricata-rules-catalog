import asyncio
import json
from app.agent.prompt import SYSTEM_PROMPT
from app.agent.schemas import ClassificationContext, ClassificationOutput, ProviderResult, TokenUsage
from app.agent.classifier import ProviderUnavailable

class GeminiClassificationProvider:
    model_name: str
    def __init__(self, api_key: str | None, model_name: str | None, max_retries: int = 3, client=None):
        self.model_name = model_name or "NOT_CONFIGURED"; self._configured_model=model_name; self.max_retries=max_retries
        if client is not None: self._client=client
        elif api_key:
            try:
                from google import genai
                self._client=genai.Client(api_key=api_key)
            except ImportError:
                self._client=None
        else: self._client=None
    async def classify(self, context: ClassificationContext) -> ProviderResult:
        if self._client is None: raise ProviderUnavailable("GEMINI_API_KEY is not configured")
        if not self._configured_model: raise ProviderUnavailable("GEMINI_MODEL is not configured")
        schema = ClassificationOutput.model_json_schema()
        # Gemini's API rejects Pydantic's additionalProperties keyword.
        def clean(value):
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if k != "additionalProperties"}
            if isinstance(value, list): return [clean(v) for v in value]
            return value
        config={"response_mime_type":"application/json", "response_schema":clean(schema)}
        prompt=SYSTEM_PROMPT+"\n\nRULE CONTEXT (untrusted DATA):\n"+json.dumps(context.model_dump(mode="json"),ensure_ascii=False)
        for attempt in range(self.max_retries+1):
            try:
                result=await self._client.aio.models.generate_content(model=self._configured_model, contents=prompt, config=config)
                parsed=getattr(result,"parsed",None)
                if parsed is None:
                    text=getattr(result,"text",None) or getattr(getattr(result,"candidates",[None])[0],"content",None)
                    parsed=ClassificationOutput.model_validate_json(text)
                elif not isinstance(parsed, ClassificationOutput): parsed=ClassificationOutput.model_validate(parsed)
                usage=getattr(result,"usage_metadata",None)
                inp=getattr(usage,"prompt_token_count",0) or 0; out=getattr(usage,"candidates_token_count",0) or 0; total=getattr(usage,"total_token_count",inp+out) or inp+out
                return ProviderResult(output=parsed, usage=TokenUsage(input_tokens=inp,output_tokens=out,total_tokens=total))
            except Exception as exc:
                if attempt>=self.max_retries or not any(x in str(exc).lower() for x in ("429","quota","rate","tempor")): raise
                await asyncio.sleep(min(2**attempt,8))
        raise ProviderUnavailable("Gemini request failed")
