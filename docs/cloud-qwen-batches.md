# Reserved cloud Qwen batches

---

## NORMAL DAILY USAGE

```powershell
# 1. Prepare — create Kaggle and Colab batch bundles
.\cloud-start.ps1

# Optional overrides:
.\cloud-start.ps1 -KaggleLimit 2000 -ColabLimit 500
.\cloud-start.ps1 -KaggleOnly -KaggleLimit 1000
.\cloud-start.ps1 -ColabOnly
```

```
# 2. KAGGLE (manual browser steps)
#    Upload cloud_batch_kaggle-*.zip as a Kaggle dataset input
#    Enable GPU in Kaggle settings
#    Open qwen_kaggle.ipynb → Run All
#    Download <batch-id>-results.jsonl → place in data\cloud_results\
```

```
# 3. COLAB (manual browser steps)
#    Open Google Colab → Runtime → Change runtime type → GPU
#    Upload cloud_batch_colab-*.zip to /content
#    Open qwen_colab.ipynb → Run All
#    Download <batch-id>-results.jsonl → place in data\cloud_results\
```

```powershell
# 4. Import results
.\cloud-import.ps1

# 5. Check status
.\cloud-status.ps1

# 6. If a batch needs to be abandoned (recover unfinished reservations):
.\cloud-release.ps1 -BatchId kaggle-20260904-003
```

Local Qwen classification runs independently and is unaffected by cloud batches:

```powershell
.\run-qwen-1000.ps1
```

---



This workflow accelerates the ET Open Qwen V2.2 catalog run without exposing the
local database. The database remains authoritative for both completed work and
exclusive ownership:

```text
local database -> atomic reservation -> portable ZIP -> Kaggle Ollama
               <- validated/idempotent import <- results.jsonl
```

The target identity is `ollama / qwen3:8b / qwen-v2.2` (with the model name read
from the existing local Ollama runtime setting). Gemini code, prompts, identities,
and cache behavior are unchanged.

## Schema and ownership

- `cloud_batches` stores the immutable target identity, worker, lifecycle,
  contract/manifest hashes, counts, and timestamps.
- `cloud_batch_reservations` stores SID, revision, rule/input hashes, lifecycle,
  and the imported classification link. A partial unique index permits only one
  `RESERVED` owner for a rule while preserving released/imported history.
- `local_classification_claims` is a short-lived race barrier. The supported local
  runner claims the next rule before model inference and releases the claim after
  the attempt. A new OS-serialized runner clears claims left by a killed predecessor.

SQLite uses `BEGIN IMMEDIATE`; PostgreSQL uses a transaction-scoped advisory lock
for batch sequencing plus rule locks with `SKIP LOCKED`. Both the exporter and
local runner lock/check before claiming. Two exporters cannot reserve the same
rule, and the local runner cannot begin an exported reservation.

Reservation states are `RESERVED`, `IMPORTED`, `RELEASED`, and `FAILED` (reserved
work remains `RESERVED` when a supplied result is rejected). Batch states are
`PREPARING`, `ACTIVE`, `PARTIALLY_IMPORTED`, `COMPLETED`, and `RELEASED`.

## Commands

Run these from `backend`:

```powershell
# Reserve first, then create data/cloud_batches/<batch-id>/ and its ZIP.
.\.venv\Scripts\python.exe -m app.cloud_batch export --limit 2000 --worker kaggle

# Read-only with respect to model execution: it performs zero inference.
.\.venv\Scripts\python.exe -m app.cloud_batch status

# Validate every line and append only absent successful target classifications.
.\.venv\Scripts\python.exe -m app.cloud_batch import C:\path\to\results.jsonl

# Release only unfinished rules; imported classifications remain intact.
.\.venv\Scripts\python.exe -m app.cloud_batch release kaggle-20260904-001
```

From the project root, the existing local command is unchanged:

```powershell
.\run-qwen-1000.ps1
```

It now transparently excludes active cloud reservations as well as completed
target classifications.

## Portable bundle

Each export creates:

```text
data/cloud_batches/<batch-id>/
  input.jsonl
  manifest.json
  worker.py
  requirements.txt
  README.md
  qwen_kaggle.ipynb
data/cloud_batches/cloud_batch_<batch-id>.zip
```

No `.env`, database, credentials, API keys, or unrelated project data is copied.
`input.jsonl` contains the exact prepared `ClassificationContext` used by the local
service plus immutable rule/context/contract identity. `manifest.json` contains the
Qwen V2.2 prompt, Pydantic JSON schema, and the configured deterministic Ollama
options.

## Kaggle run

1. Upload the generated ZIP as a private Kaggle dataset.
2. Open the bundled notebook and enable a GPU accelerator and Internet access for
   the Ollama/model download.
3. Run its cells to install/start Ollama, pull the manifest's model, and launch the
   sequential worker (`concurrency=1`).
4. Download `results.jsonl`, including after an interruption.
5. Import the file locally with the command above.

The worker appends and `fsync`s every successful result. On resume it validates the
existing file and skips the immutable `(rule_id, context_sha256)` successes. Failed
attempts are recorded separately in `errors.jsonl` and remain retryable.

## Validation and provenance

The importer rejects an unknown batch, unreserved/released rule, SID/revision or
raw/context hash mismatch, target identity mismatch, contract mismatch, oversized
line, malformed JSON, or invalid `ClassificationOutput`. It then passes the raw
cloud proposal through the normal local Qwen canonicalizer, MITRE decision layer,
shared V2 finalizer, deterministic validator, and classification service commit.

Reimport is harmless: a completed target identity is linked to the reservation and
reported as `Already present` without creating another classification. Cloud engine
version, model digest, platform, timing, contract hash, and batch ID are persisted in
classification/run provenance.

## Runtime equivalence and caveats

The notebook deliberately uses Ollama rather than a Transformers-specific prompt
template. Export performs a zero-inference local `/api/tags` lookup and, when the
local server is reachable, pins the observed model digest; the cloud worker refuses
a different digest. It also sends the same model tag, Qwen V2.2 prompt, structured schema,
`think=false`, temperature, seed, context window, and output budget as the local
adapter. Different Ollama builds, GPU kernels, and a mutable model tag can still
produce non-bit-identical output. The recorded Ollama version and model digest make
that difference explicit. Pin and compare the digest when strict weight identity is
required. If local Ollama is unavailable during export, the digest is left unpinned
and the importer still records the cloud digest for audit.

A `PREPARING` batch means reservation succeeded but artifact generation did not
finish. Its rules stay safely unavailable until the batch is released. Do not hand
edit manifests or results; hash validation is intentionally fail-closed.
