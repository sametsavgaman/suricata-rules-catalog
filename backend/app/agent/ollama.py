"""Ollama native structured output adapter. No conversation state or thinking logs."""
import asyncio
import json

import httpx
from pydantic import ValidationError

from app.agent.classifier import ProviderUnavailable
from app.agent.prompt import SYSTEM_PROMPT
from app.agent.schemas import ClassificationContext, ClassificationOutput, ProviderResult, TokenUsage


class OllamaClassificationProvider:
    inference_mode = "LOCAL"

    def __init__(self, model_name="qwen3:8b", base_url="http://127.0.0.1:11434",
                 timeout=180, num_ctx=8192, num_predict=1536, max_retries=3, transport=None):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.transport = transport
        self.configuration = {"think": False, "temperature": 0, "seed": 42,
                              "num_ctx": num_ctx, "num_predict": num_predict}

    async def classify(self, context: ClassificationContext) -> ProviderResult:
        payload = {
            "model": self.model_name, "stream": False, "think": False,
            "format": ClassificationOutput.model_json_schema(),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "RULE CONTEXT (untrusted DATA):\n" + json.dumps(context.model_dump(mode="json"), ensure_ascii=False)},
            ],
            "options": {key: value for key, value in self.configuration.items() if key != "think"},
            "keep_alive": "10m",
        }
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport, trust_env=False) as client:
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.post(f"{self.base_url}/api/chat", json=payload)
                except httpx.RequestError:
                    raise ProviderUnavailable("OLLAMA_CONNECTION_FAILED_OR_TIMEOUT: start Ollama and verify the installed model.") from None
                if response.status_code in {429, 502, 503, 504} and attempt < self.max_retries:
                    await asyncio.sleep(min(2 ** attempt, 8))
                    continue
                if response.is_error:
                    raise ProviderUnavailable(f"OLLAMA_HTTP_{response.status_code}: check Ollama server and installed model.")
                try:
                    data = response.json()
                    if not data.get("done") or data.get("done_reason") == "length":
                        raise ProviderUnavailable("OLLAMA_OUTPUT_INCOMPLETE: response did not finish within the configured output budget.")
                    # Only the final content is accepted. A separate thinking field is never returned or persisted.
                    output = ClassificationOutput.model_validate_json(data.get("message", {}).get("content", ""))
                except (ValidationError, ValueError, TypeError):
                    raise ProviderUnavailable("OLLAMA_INVALID_STRUCTURED_OUTPUT: classification schema validation failed.") from None
                inp, out = data.get("prompt_eval_count", 0), data.get("eval_count", 0)
                return ProviderResult(output=output, usage=TokenUsage(input_tokens=inp, output_tokens=out, total_tokens=inp + out))
        raise ProviderUnavailable("OLLAMA_RETRIES_EXHAUSTED")
