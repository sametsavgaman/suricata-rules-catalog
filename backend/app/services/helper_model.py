"""Provider-neutral structured output for optional assistant workflows."""
from __future__ import annotations

import asyncio
import json
from typing import Literal, TypeVar

import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel


HelperProvider = Literal["gemini", "claude", "openai"]
StructuredModel = TypeVar("StructuredModel", bound=BaseModel)
HELPER_PROVIDERS: tuple[HelperProvider, ...] = ("gemini", "claude", "openai")


def selected_helper_provider(settings) -> HelperProvider:
    value = str(getattr(settings, "helper_provider", "gemini") or "gemini").casefold()
    if value not in HELPER_PROVIDERS:
        raise RuntimeError("The selected helper provider is not supported.")
    return value  # type: ignore[return-value]


def helper_model_name(settings, provider: HelperProvider | None = None) -> str:
    provider = provider or selected_helper_provider(settings)
    return str(getattr(settings, f"{provider}_model", "") or "")


def helper_config_error(settings, provider: HelperProvider | None = None) -> str | None:
    provider = provider or selected_helper_provider(settings)
    key = getattr(settings, f"{provider}_api_key", None)
    model = helper_model_name(settings, provider)
    if not key:
        return f"{provider.upper()}_API_KEY_NOT_CONFIGURED"
    if not model:
        return f"{provider.upper()}_MODEL_NOT_CONFIGURED"
    return None


def _clean_schema(value):
    if isinstance(value, dict):
        return {key: _clean_schema(item) for key, item in value.items() if key != "additionalProperties"}
    if isinstance(value, list):
        return [_clean_schema(item) for item in value]
    return value


def _json_text(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("```"):
        text = text.removeprefix("```").removeprefix("json").removesuffix("```").strip()
    return text


async def generate_structured(
    settings,
    *,
    instruction: str,
    payload: str,
    schema: type[StructuredModel],
    max_output_tokens: int,
    timeout_seconds: int = 35,
    provider: HelperProvider | None = None,
) -> tuple[StructuredModel, HelperProvider, str]:
    provider = provider or selected_helper_provider(settings)
    error = helper_config_error(settings, provider)
    if error:
        raise RuntimeError(error)
    model = helper_model_name(settings, provider)

    if provider == "gemini":
        from google import genai

        client = genai.Client(
            api_key=settings.gemini_api_key,
            http_options={"timeout": timeout_seconds * 1000, "retry_options": {"attempts": 1}},
        )
        try:
            async with asyncio.timeout(timeout_seconds):
                response = await client.aio.models.generate_content(
                    model=model,
                    contents=payload,
                    config={
                        "system_instruction": instruction,
                        "temperature": 0,
                        "max_output_tokens": max_output_tokens,
                        "response_mime_type": "application/json",
                        "response_schema": _clean_schema(schema.model_json_schema()),
                    },
                )
            raw = getattr(response, "parsed", None)
            result = schema.model_validate(raw) if raw is not None else schema.model_validate_json(response.text or "")
            return result, provider, model
        finally:
            await client.aio.aclose()
            client.close()

    if provider == "openai":
        client = AsyncOpenAI(api_key=settings.openai_api_key, base_url=settings.openai_base_url or None)
        try:
            async with asyncio.timeout(timeout_seconds):
                response = await client.responses.parse(
                    model=model,
                    instructions=instruction,
                    input=payload,
                    text_format=schema,
                    store=False,
                )
            if response.output_parsed is None:
                raise ValueError("The helper model returned no structured output.")
            return schema.model_validate(response.output_parsed), provider, model
        finally:
            await client.close()

    base_url = settings.claude_base_url.rstrip("/")
    url = base_url if base_url.endswith("/messages") else f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"
    schema_instruction = instruction + "\nReturn only JSON matching this schema:\n" + json.dumps(schema.model_json_schema())
    async with httpx.AsyncClient(timeout=timeout_seconds, trust_env=False) as client:
        async with asyncio.timeout(timeout_seconds):
            response = await client.post(
                url,
                headers={
                    "x-api-key": settings.claude_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": max_output_tokens,
                    "temperature": 0,
                    "system": schema_instruction,
                    "messages": [{"role": "user", "content": payload}],
                },
            )
        response.raise_for_status()
        data = response.json()
        text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        )
        return schema.model_validate_json(_json_text(text)), provider, model
