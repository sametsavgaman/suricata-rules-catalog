import json
from typing import Protocol

from openai import AsyncOpenAI

from app.agent.prompt import SYSTEM_PROMPT
from app.agent.schemas import ClassificationContext, ClassificationOutput, ProviderResult, TokenUsage


class ClassificationProvider(Protocol):
    model_name: str

    async def classify(self, context: ClassificationContext) -> ClassificationOutput | ProviderResult: ...


class ProviderUnavailable(RuntimeError):
    pass


class OpenAIClassificationProvider:
    """One Responses API call per rule, validated directly into a Pydantic model."""

    def __init__(self, api_key: str | None, model_name: str | None):
        self.model_name = model_name or "NOT_CONFIGURED"
        self._configured_model = model_name
        self._client = AsyncOpenAI(api_key=api_key) if api_key else None

    async def classify(self, context: ClassificationContext) -> ProviderResult:
        if self._client is None:
            raise ProviderUnavailable("OPENAI_API_KEY is not configured")
        if not self._configured_model:
            raise ProviderUnavailable("OPENAI_MODEL is not configured")
        response = await self._client.responses.parse(
            model=self._configured_model,
            instructions=SYSTEM_PROMPT,
            input=json.dumps(context.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")),
            text_format=ClassificationOutput,
            store=False,
        )
        if response.output_parsed is None:
            raise ValueError("Model returned no parsed classification")
        usage = response.usage
        return ProviderResult(
            output=response.output_parsed,
            usage=TokenUsage(
                input_tokens=usage.input_tokens if usage else 0,
                output_tokens=usage.output_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
            ),
        )
