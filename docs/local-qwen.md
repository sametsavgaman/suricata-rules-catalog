# Local Qwen3-8B

Ollama serves the installed `qwen3:8b` model. Native Windows setup uses two terminals:

```powershell
ollama serve
```

```powershell
ollama list
ollama run qwen3:8b --think=false
```

If Ollama is already running, a second `serve` process is unnecessary. `ollama ps` reports GPU/CPU placement and context allocation. The tested machine uses an RTX 4060 Laptop GPU with 8 GB VRAM; the installed 5.2 GB model ran with 8192 context tokens and 100% GPU placement.

## Application

In Rule Inspector, choose **Run classification with → Qwen · Local Ollama**, then press **Reclassify**. Gemini can be chosen in the same control. The classification result selector displays saved results for each model. Reviews belong to the selected classification; approving Gemini does not approve Qwen.

For a local-only server, set these environment variables before starting the backend:

```powershell
cd C:\Users\Savgaman\Desktop\suricata-rule-agent\backend
$env:AI_PROVIDER="ollama"
$env:OLLAMA_MODEL="qwen3:8b"
$env:CLASSIFIER_VERSION="v2.1"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Project-root `.env` loads regardless of terminal directory. Process environment overrides `.env`. Native Ollama URL defaults to `http://127.0.0.1:11434`; Docker requires an explicitly configured reachable host URL.

The adapter uses native `/api/chat`, `think:false`, `stream:false`, Pydantic's JSON schema in `format`, temperature 0 and seed 42. Each rule is a new independent request. Output is parsed strictly; extra fields, invalid enums and incomplete responses fail classification. Thinking output is not saved. The JSON schema guarantees a format only; semantic correctness still needs evaluation and evidence checks.

No new prompt, taxonomy, retrieval policy or entity policy is introduced. Qwen receives the existing V2.1 context: entity candidates, controlled categories, retrieved canonical MITRE candidates, similar reviewed examples and CVE identifiers. This already supplies external knowledge to the model. A vector database is not required for this integration.

## Paired comparison

From `backend`:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.compare_models --limit 5
.\.venv\Scripts\python.exe -m app.evaluation.compare_models --limit 250
.\.venv\Scripts\python.exe -m app.evaluation.compare_models --limit 250 --parallel
```

The command uses the configured Gemini model and `OLLAMA_MODEL`. It reads the existing operational sample, requires 250 unique SID/REV pairs (97 audited + 153 fresh), and verifies sample/golden hashes at completion. Smaller smoke subsets cover both cohorts. Missing exact database revisions fail preflight rather than silently resampling.

Every run writes a timestamped directory under `data/evaluation/model-comparison/` containing `results.jsonl`, `report.json`, and `report.md`. Both providers run fresh; old Gemini results are retained. Each result includes provider/model/version, classification ID, prompt/context fingerprints, measured token counts and timing. Failures are retained and the batch continues. Gemini uses existing bounded retries; local transient HTTP errors have bounded retries. API failure messages are not exported. No training data or ground truth is created automatically.

`--parallel` uses one independent worker per provider, with separate DB sessions and serialized result writes. GPU requests remain sequential. `--resume PATH` continues a saved results directory and skips every recorded attempt, including failures. Use the same sample size, providers and models. To regenerate the readable comparison and disagreement queues without making any API calls:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.comparison_report ..\data\evaluation\model-comparison\RUN_DIRECTORY
```

Accuracy applies only to reviewed audited records. Fresh rules provide descriptive statistics, not accuracy. Existing similar-rule retrieval draws from other reviewed benchmark examples, so these results should not be described as a fully held-out test. Small smoke metrics are not representative. Token counts use different tokenizers; wall time includes cold model loading when it occurs. Hardware/electricity costs are not measured: `COST_NOT_CALCULATED`.

Before fine-tuning, inspect disagreements, assemble independently reviewed training data, and reserve a disjoint evaluation set. Keep the frozen 250-rule sample out of training. LoRA/QLoRA feasibility and settings require a separate training experiment.

References: [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs), [thinking controls](https://docs.ollama.com/capabilities/thinking).
