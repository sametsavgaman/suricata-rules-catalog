"""Anthropic Claude classification adapter using the Messages API."""
import json

import httpx
from pydantic import ValidationError

from app.agent.classifier import ProviderUnavailable
from app.agent.prompt import SYSTEM_PROMPT
from app.agent.schemas import ClassificationContext, ClassificationOutput, ProviderResult, TokenUsage


class ClaudeClassificationProvider:
    inference_mode = "API"

    def __init__(self, api_key: str | None, model_name: str | None,
                 base_url: str = "https://api.anthropic.com", timeout: float = 180):
        self.model_name = model_name or "NOT_CONFIGURED"
        self._configured_model = model_name
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self.configuration = {"temperature": 0, "max_tokens": 1536}

    async def classify(self, context: ClassificationContext) -> ProviderResult:
        if not self._api_key:
            raise ProviderUnavailable("CLAUDE_API_KEY is not configured")
        if not self._configured_model:
            raise ProviderUnavailable("CLAUDE_MODEL is not configured")
        if self._base_url.endswith("/messages"):
            url = self._base_url
        elif self._base_url.endswith("/v1"):
            url = f"{self._base_url}/messages"
        else:
            url = f"{self._base_url}/v1/messages"
        payload = {
            "model": self._configured_model,
            "max_tokens": self.configuration["max_tokens"],
            "temperature": self.configuration["temperature"],
            "system": SYSTEM_PROMPT + "\nReturn only one valid JSON object matching the requested schema.",
            "messages": [{
                "role": "user",
                "content": json.dumps(context.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")),
            }],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=self._timeout, trust_env=False) as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
            except httpx.RequestError:
                raise ProviderUnavailable("CLAUDE_CONNECTION_FAILED_OR_TIMEOUT") from None
        if response.status_code >= 400:
            raise ProviderUnavailable(f"CLAUDE_HTTP_{response.status_code}")
        try:
            data = response.json()
            text = "".join(
                block.get("text", "") for block in data.get("content", [])
                if block.get("type") == "text"
            ).strip()
            if text.startswith("```"):
                text = text.removeprefix("```").removeprefix("json").removesuffix("```").strip()
            output = ClassificationOutput.model_validate_json(text)
        except (ValidationError, ValueError, TypeError, json.JSONDecodeError):
            raise ProviderUnavailable("CLAUDE_INVALID_STRUCTURED_OUTPUT") from None
        usage = data.get("usage", {})
        inp = int(usage.get("input_tokens", 0) or 0)
        out = int(usage.get("output_tokens", 0) or 0)
        return ProviderResult(output=output, usage=TokenUsage(input_tokens=inp, output_tokens=out, total_tokens=inp + out))
