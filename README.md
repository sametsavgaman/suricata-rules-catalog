# Emerging Threats Suricata Rule Classification Agent — V1

Deterministically parses Suricata `.rules` files, enriches each parsed rule with explainable hints, and uses exactly one AI classification call per uncached `SID + REV`. The result is validated before it is stored and exposed through a FastAPI API and React dashboard.

The included 20-rule dataset is explicitly synthetic test data. It is not presented as Emerging Threats content.

## Architecture

```text
.rules -> loader -> deterministic parser -> SQL database
                                           |
                                           v
                     deterministic hints -> one classification provider call
                                           |
                    local taxonomy + MITRE validation -> status + database
                                           |
                                      FastAPI -> React
```

Core boundaries are deliberately small:

- `parser/` understands Suricata syntax and never calls an LLM.
- `enrichment/` emits non-authoritative, explainable hints.
- `agent/` owns the provider protocol, prompt, and strict Pydantic result.
- `validation/` checks schema-level and MITRE consistency without a second agent.
- `services/` owns the single-call, cache, status, and persistence flow.
- `knowledge/` can later be replaced with semantic retrieval or pgvector without changing the parser.

The OpenAI adapter uses the Responses API's Pydantic structured-output parser and disables response storage for this stateless classification call.

## Quick start with Docker

```bash
cp .env.example .env
# Set OPENAI_API_KEY and an OPENAI_MODEL available to your account in .env
docker compose up --build
```

Open the dashboard at `http://localhost:5173`; API docs are at `http://localhost:8000/docs`.

## Local development (SQLite)

Backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = "sqlite:///./suricata_rules.db"
$env:OPENAI_API_KEY = "your-key"
$env:OPENAI_MODEL = "your-available-model"
uvicorn app.main:app --reload
```

Frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` to port 8000. Without `OPENAI_API_KEY`, parsing, imports, browsing, tests, and statistics still work; classification attempts are recorded as `FAILED` with a clear explanation.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./suricata_rules.db` | SQLAlchemy URL; PostgreSQL uses `postgresql+psycopg://...` |
| `OPENAI_API_KEY` | unset | Required only for classification |
| `OPENAI_MODEL` | unset | Responses API model available to your account; no model is assumed |
| `FRONTEND_ORIGIN` | `http://localhost:5173` | CORS origin |
| `MAX_AGENT_CONTENTS` | `20` | Maximum content clauses sent per rule |
| `MAX_AGENT_CONTENT_CHARS` | `4000` | Combined content-character budget |

## Adding Emerging Threats rules

Use the dashboard's **Import .rules** button or call the multipart endpoint. Disabled/commented rules are ignored; multiline rules are joined only after balanced option parentheses are found.

```bash
curl -X POST http://localhost:8000/api/rules/import \
  -F "files=@data/rules/emerging.rules"
```

An existing `SID + REV` is skipped. A new revision is stored as a separate immutable rule record.

## Classification

Classify one rule:

```bash
curl -X POST "http://localhost:8000/api/rules/9900001/classify"
```

The service returns a cached successful/review result for the same stored rule. Add `?force=true` only when an analyst intentionally requests a fresh classification.

Classify up to 100 unclassified rules:

```bash
curl -X POST "http://localhost:8000/api/classify/all?limit=100"
```

Each rule is isolated: a provider or validation failure is persisted and does not stop the batch.

## API

- `GET /api/rules` — filters: `category`, `subcategory`, `detected_entity`, `mitre_technique_id`, `entity_type`, `status`, `protocol`, `classtype`, minimum `confidence`, and `search`.
- `GET /api/rules/{sid}` — newest revision plus its latest classification.
- `POST /api/rules/import` — one or more multipart `.rules` files.
- `POST /api/rules/{sid}/classify` — single rule; `force=true` bypasses the successful-result cache.
- `POST /api/classify/all` — bounded batch of rules without successful classifications.
- `GET /api/stats` — totals, statuses, distributions, top entities/techniques, average confidence.
- `GET /health` — liveness response.

Example filtered query:

```bash
curl "http://localhost:8000/api/rules?category=Reconnaissance&confidence=0.75&protocol=tcp"
```

## Tests and verification

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q

cd ..\frontend
npm run build
```

Parser tests cover TCP, HTTP sticky buffers, DNS, multiple content clauses, metadata, references, flow, flowbits, PCRE, escaped semicolons, quoted semicolons, address lists, and multiline rules. API tests import all 20 samples and verify list, search, detail, and stats.

## Local MITRE knowledge

`data/mitre/enterprise-techniques.json` is a compact V1 list. The repository accepts records shaped as:

```json
{"technique_id":"T1046","name":"Network Service Scanning","tactics":["Discovery"]}
```

A future ingest command can populate the same contract from official ATT&CK STIX data. V1 sends only this bounded candidate list to the classifier and rejects unknown or mismatched ID/name/tactic combinations.

## V1 limits

- No autonomous browsing, RAG, vector database, self-reflection, second validator agent, or orchestrator.
- No full Suricata grammar implementation; uncommon plugin-specific keywords remain preserved in `options` during parsing but only selected semantic fields are persisted.
- The compact MITRE file is intentionally incomplete, so unsupported mappings become `null` or require review.
- Batch execution is sequential and intended for the first working version, not a distributed job system.
- Human corrections and analyst audit history are future work.

## Roadmap

The existing interfaces leave room for official ATT&CK ingestion, semantic MITRE retrieval, pgvector/similar-rule search, CVE/reference tools, analyst corrections, confidence routing, background jobs, ET update detection, and a later LangGraph workflow—without moving deterministic parsing into an LLM.

## Real ET Open quality evaluation

V1 now includes a human-grounded evaluation pipeline. Real and synthetic rules are kept separate:

- `data/rules/et-open/` contains the ET Open Suricata 8.0.4 distribution downloaded from `rules.emergingthreats.net`.
- `data/rules/et-open/SOURCE.json` records provenance and download date.
- `data/samples/` remains synthetic and is never used for reported accuracy.
- `data/evaluation/golden_dataset.jsonl` contains 100 reproducibly sampled real rules.

The current real-data parser baseline is recorded in `data/evaluation/parser_summary.json`. Accuracy is not calculated until a human marks golden records `REVIEWED`.

Run all evaluation commands from `backend` with the project virtual environment:

```powershell
cd C:\Users\Savgaman\Desktop\suricata-rule-agent\backend
```

### 1. Rebuild the reproducible 100-rule sample

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.sample --count 100 --seed 42
```

Sampling is stratified across available ET categories/protocols instead of being purely random. Existing annotations are preserved by `SID + REV`; pass `--force-golden` only when you deliberately want to reset them.

If you provide the rules manually, put `.rules` files under:

```text
data/rules/et-open/
```

When that directory has no real rule files the sampler exits with `REAL_DATA_NOT_AVAILABLE`. It never substitutes synthetic rules.

### 2. Human annotation

Öneri tabanlı güvenli review akışı (ground truth değiştirilmez):

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.proposals
.\.venv\Scripts\python.exe -m app.evaluation.verifier
.\.venv\Scripts\python.exe -m app.evaluation.review --annotator "analyst-name"
```

`proposals` yalnızca `proposal` ve evidence üretir; kayıtlar `AI_PROPOSED/UNREVIEWED` kalır. `verifier` local MITRE repository ile canonical ID/name/tactic kontrolü yapar ve agreement kuyruğu oluşturur. Review CLI varsayılan olarak öneriyi gizler; kayıt ekranında `Show suggestion? [y/N]` ile açılır. Hızlı mod ve kuyruk filtreleri: `--show-proposals`, `--only high-confidence`, `--only disagreement`, `--only unreviewed`.

`[A]pprove` veya düzenleme sonrası açıkça `Save as REVIEWED` seçilmedikçe `expected` alanı değişmez. `DISPUTED` ve `UNREVIEWED` kayıtlar evaluation'a girmez.

Review ekranı kaynakları açıkça ayırır: `[ET DATA]` raw rule, `[PARSER]` deterministic parser çıktısı, `[DETERMINISTIC]` enrichment hint'leri, `[AI INPUT]` provider'a gönderilen ortak `ClassificationContext`, `[AI OUTPUT]` proposal, `[VERIFIER]` bağımsız critic ve `[REVIEW]` insan kararıdır. Varsayılan görünüm compact'tır; `[V]` veya `--verbose` ile full raw rule, parsed JSON, enrichment ve gerçek structured AI input gösterilir. Secret/API key, hidden prompt ve chain-of-thought hiçbir zaman yazdırılmaz.

Özetler: `data/evaluation/proposal_summary.json`, `data/evaluation/verification_summary.json`, `data/evaluation/annotation_proposals.jsonl`.

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.annotate --annotator "analyst-name"
```

The CLI displays the raw rule, parsed fields, and deterministic hints. AI output is intentionally hidden to reduce annotation bias. Enter `-` for an explicit `null`, leave a prompt blank to keep its current value, then choose `REVIEWED`, `DISPUTED`, or `UNREVIEWED`.

Annotate one SID directly:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.annotate --annotator "analyst-name" --sid 2034151
```

Only `REVIEWED` records participate in accuracy evaluation.

### 3. Accuracy evaluation

Configure the provider in the current terminal:

```powershell
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="a-model-available-to-your-account"
```

Then run:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.run
```

Use `--force` only for a controlled cache-bypass run. Production cache behavior remains unchanged. Outputs:

- `data/evaluation/evaluation_results.jsonl`
- `data/evaluation/reports/evaluation-report.json`
- `data/evaluation/reports/evaluation-report.md`

The report includes exact and normalized field accuracy, null preservation, `NULL_HALLUCINATION_RATE`, unexpected-null rate, confidence calibration, error taxonomy, lowest-performing categories, sample errors, and token usage. Without reviewed ground truth it reports `NO_REVIEWED_GOLDEN_SAMPLES`; without a key it reports `OPENAI_API_KEY_NOT_CONFIGURED`. Neither state produces an AI accuracy claim.

### 4. Stability evaluation

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.stability --samples 20 --runs 5 --seed 42
```

This intentionally bypasses cache and measures the most-common-result fraction for entity, category, MITRE technique ID, and Kill Chain phase. Output is `data/evaluation/stability_results.json`.

### 5. Operational batch test

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.batch --count 1000 --seed 42
```

This is a resilience/performance test, not an accuracy test. It records processed, classified, review-required, failed, cache-hit, elapsed-time, per-rule duration, and individual-failure continuation metrics in `data/evaluation/batch_results.json`.

### Token pricing

### Using Gemini

Gemini provider'ı seçmek için `.env` dosyasına şunları ekleyin:

```env
AI_PROVIDER=gemini
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-flash-lite-latest
```

Smoke test (gerçek API çağrısı yapar):

```powershell
\.venv\Scripts\python.exe -m app.provider_test
```

100 Claude-reviewed kayıt üzerinde evaluation aynı komutla çalışır:

```powershell
\.venv\Scripts\python.exe -m app.evaluation.run
```

Token fiyatları `GEMINI_INPUT_COST_PER_1M` ve `GEMINI_OUTPUT_COST_PER_1M` ile verilmezse maliyet `COST_NOT_CALCULATED` kalır. Free-tier quota/rate limitleri Google tarafından yönetilir; aşım durumunda sınırlı retry ve açık failure kaydı uygulanır.

Responses API usage is collected as input/output/total tokens. Pricing is deliberately not hard-coded. To estimate cost, supply the prices that apply to your chosen model/account:

```powershell
$env:OPENAI_INPUT_COST_PER_MILLION="0.00"
$env:OPENAI_OUTPUT_COST_PER_MILLION="0.00"
```

When either value is absent the report emits `COST_NOT_CALCULATED` while still reporting token totals.

### Evaluation tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover normalized comparison, null hallucination, unexpected nulls, field metrics, confidence buckets, stability scoring, reviewed-only filtering, cache behavior, error taxonomy, token cost handling, and missing-key behavior.
