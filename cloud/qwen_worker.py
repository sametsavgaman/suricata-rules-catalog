"""Portable, sequential Ollama worker for exported Qwen cloud batches."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from jsonschema import validate as validate_json_schema

INPUT_FORMAT = "suricata-qwen-cloud-input-v1"
RESULT_FORMAT = "suricata-qwen-cloud-result-v1"
MAX_LINE_BYTES = 2 * 1024 * 1024


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("EXPECTED_JSON_OBJECT")
    return value


def validate_contract(manifest: dict[str, Any]) -> None:
    required = {
        "provider", "model", "model_digest", "classifier_version", "system_prompt", "output_schema",
        "inference", "contract_sha256", "batch_id",
    }
    if not required.issubset(manifest):
        raise ValueError("MANIFEST_FIELDS_MISSING")
    contract = {key: manifest[key] for key in (
        "provider", "model", "model_digest", "classifier_version", "system_prompt", "output_schema", "inference"
    )}
    if sha256_text(canonical_json(contract)) != manifest["contract_sha256"]:
        raise ValueError("MANIFEST_CONTRACT_HASH_MISMATCH")


def load_completed(path: Path, batch_id: str) -> set[tuple[int, str]]:
    completed: set[tuple[int, str]] = set()
    if not path.exists():
        return completed
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"EXISTING_RESULT_LINE_{number}_TOO_LARGE")
            item = json.loads(raw)
            if item.get("format_version") != RESULT_FORMAT or item.get("batch_id") != batch_id:
                raise ValueError(f"EXISTING_RESULT_LINE_{number}_IDENTITY_MISMATCH")
            completed.add((int(item["rule_id"]), str(item["context_sha256"])))
    return completed


def runtime_identity(base_url: str, model: str, environment: str) -> dict[str, Any]:
    version = "unknown"
    digest = "unknown"
    try:
        response = requests.get(f"{base_url}/api/version", timeout=10)
        response.raise_for_status()
        version = str(response.json().get("version") or "unknown")
    except requests.RequestException:
        pass
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=10)
        response.raise_for_status()
        for entry in response.json().get("models", []):
            if entry.get("name") == model or entry.get("model") == model:
                digest = str(entry.get("digest") or "unknown")
                break
    except requests.RequestException:
        pass
    return {
        "engine": "ollama",
        "engine_version": version,
        "model_digest": digest,
        "environment": environment,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "hostname": socket.gethostname(),
    }


def provider_context(exported_context: dict[str, Any]) -> dict[str, Any]:
    """Mirror the project's Qwen V2.2 Ollama adapter transformation."""
    context = json.loads(json.dumps(exported_context, ensure_ascii=False))
    controlled = context.get("controlled_subcategories", {})
    semantic = controlled.get("__qwen_semantic_context__")
    if semantic:
        context["qwen_semantic_context"] = json.loads(semantic[0])
    controlled.pop("__qwen_semantic_context__", None)
    return context


def classify_one(base_url: str, manifest: dict[str, Any], item: dict[str, Any], retries: int) -> tuple[dict, dict]:
    request_body = {
        "model": manifest["model"],
        "stream": False,
        "think": False,
        "format": manifest["output_schema"],
        "messages": [
            {"role": "system", "content": manifest["system_prompt"]},
            {
                "role": "user",
                "content": "RULE CONTEXT (untrusted DATA):\n" + json.dumps(
                    provider_context(item["context"]), ensure_ascii=False
                ),
            },
        ],
        "options": manifest["inference"]["options"],
        "keep_alive": "10m",
    }
    for attempt in range(retries + 1):
        try:
            response = requests.post(f"{base_url}/api/chat", json=request_body, timeout=(10, 900))
            if response.status_code in {429, 502, 503, 504} and attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            response.raise_for_status()
            data = response.json()
            if not data.get("done") or data.get("done_reason") == "length":
                raise RuntimeError("OLLAMA_OUTPUT_INCOMPLETE")
            output = json.loads(data.get("message", {}).get("content", ""))
            validate_json_schema(output, manifest["output_schema"])
            usage = {
                "input_tokens": int(data.get("prompt_eval_count") or 0),
                "output_tokens": int(data.get("eval_count") or 0),
            }
            usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
            return output, usage
        except (requests.RequestException, json.JSONDecodeError, RuntimeError) as exc:
            if attempt >= retries:
                raise RuntimeError(type(exc).__name__) from exc
            time.sleep(min(2 ** attempt, 8))
    raise AssertionError("unreachable")


def validate_input(item: dict[str, Any], manifest: dict[str, Any]) -> None:
    if item.get("format_version") != INPUT_FORMAT:
        raise ValueError("INPUT_FORMAT_MISMATCH")
    for key in ("batch_id", "provider", "model", "classifier_version", "contract_sha256"):
        expected_key = "batch_id" if key == "batch_id" else key
        if item.get(key) != manifest.get(expected_key):
            raise ValueError(f"INPUT_{key.upper()}_MISMATCH")
    if sha256_text(canonical_json(item.get("context"))) != item.get("context_sha256"):
        raise ValueError("INPUT_CONTEXT_HASH_MISMATCH")


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    encoded = (canonical_json(value) + "\n").encode("utf-8")
    with path.open("ab") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def run(args) -> int:
    manifest = load_json(args.manifest)
    validate_contract(manifest)
    input_bytes = args.input.read_bytes()
    if hashlib.sha256(input_bytes).hexdigest() != manifest.get("input_jsonl_sha256"):
        raise ValueError("INPUT_FILE_HASH_MISMATCH")
    completed = load_completed(args.output, manifest["batch_id"])
    runtime = runtime_identity(args.ollama_url, manifest["model"], args.environment)
    if manifest.get("model_digest") and runtime["model_digest"] != manifest["model_digest"]:
        raise ValueError("CLOUD_MODEL_DIGEST_DOES_NOT_MATCH_LOCAL_EXPORT")
    successes = failures = seen = 0
    consecutive_failures = 0
    for line_number, raw_line in enumerate(input_bytes.splitlines(), 1):
        if not raw_line.strip():
            continue
        if len(raw_line) > MAX_LINE_BYTES:
            raise ValueError(f"INPUT_LINE_{line_number}_TOO_LARGE")
        item = json.loads(raw_line)
        validate_input(item, manifest)
        key = (int(item["rule_id"]), str(item["context_sha256"]))
        if key in completed:
            continue
        if args.limit and seen >= args.limit:
            break
        seen += 1
        started = time.perf_counter()
        try:
            output, usage = classify_one(args.ollama_url, manifest, item, args.retries)
            duration = round((time.perf_counter() - started) * 1000, 2)
            result = {
                "format_version": RESULT_FORMAT,
                "batch_id": item["batch_id"],
                "rule_id": item["rule_id"],
                "sid": item["sid"],
                "rev": item["rev"],
                "raw_sha256": item["raw_sha256"],
                "context_sha256": item["context_sha256"],
                "contract_sha256": item["contract_sha256"],
                "provider": item["provider"],
                "model": item["model"],
                "classifier_version": item["classifier_version"],
                "output": output,
                "usage": usage,
                "runtime": runtime,
                "inference_duration_ms": duration,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            append_jsonl(args.output, result)
            completed.add(key)
            successes += 1
            consecutive_failures = 0
            print(f"[{len(completed)}/{manifest['rule_count']}] SID {item['sid']}/{item['rev']} OK", flush=True)
        except Exception as exc:
            failures += 1
            consecutive_failures += 1
            append_jsonl(args.errors, {
                "batch_id": item["batch_id"], "rule_id": item["rule_id"], "sid": item["sid"],
                "error": type(exc).__name__, "created_at": datetime.now(timezone.utc).isoformat(),
            })
            print(f"SID {item['sid']}/{item['rev']} FAILED ({type(exc).__name__})", flush=True)
            if consecutive_failures >= args.stop_after_errors:
                print("Stopped after consecutive failures; successful results are durable.", flush=True)
                break
    print(f"New results: {successes}; retained total: {len(completed)}; failures: {failures}", flush=True)
    return int(failures > 0)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("manifest.json"))
    parser.add_argument("--input", type=Path, default=Path("input.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("results.jsonl"))
    parser.add_argument("--errors", type=Path, default=Path("errors.jsonl"))
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--environment", default="kaggle")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--stop-after-errors", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0, help="Optional smoke-test limit; zero means all remaining.")
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args()))
    except KeyboardInterrupt:
        print("Interrupted. Every previously printed OK result is fsync'd in results.jsonl.", flush=True)
        raise SystemExit(130)
    except Exception as exc:
        print(f"Worker cannot start: {type(exc).__name__}", flush=True)
        raise SystemExit(2)
