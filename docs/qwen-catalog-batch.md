# Resume-safe Qwen catalog batches

## Daily PowerShell commands

```powershell
cd "C:\Users\Savgaman\Desktop\suricata-rule-agent"
.\run-qwen-1000.ps1
```

This starts **at most 1000 remaining rule attempts**, sequentially, then returns.
Repeat the same command tomorrow. No activation, cursor, SID list, or JSON checkpoint
is required. A smaller batch is available with `-Limit 50`.

```powershell
.\run-qwen-1000.ps1 -Status
```

Status reads the database and active local ET files. It does not construct a provider,
call Ollama, download rules, acquire the worker lock, or change the database.
Reading/parsing the 52k local rules can take several seconds before counts appear.

Equivalent backend commands:

```powershell
cd "C:\Users\Savgaman\Desktop\suricata-rule-agent\backend"
.\.venv\Scripts\python.exe -u -m app.evaluation.run_qwen_catalog_batch --limit 1000
.\.venv\Scripts\python.exe -m app.evaluation.run_qwen_catalog_batch --status
```

Ollama must already be running with the configured model installed. The frontend and
uvicorn need not be running. No Gemini API access is needed. The PowerShell wrapper
starts the installed Ollama server when necessary; the Python runner verifies both
server readiness and configured-model availability before selecting a rule. It does
not download a missing model. If local execution policy blocks the wrapper,
use the direct backend command rather than changing machine-wide security policy.

## Audit findings before implementation

| Layer | Existing behavior |
|---|---|
| `/api/classify/all` | Calls `RuleRepository.unclassified(limit)`; not suitable for identity-scoped continuation. |
| `RuleRepository.unclassified()` | Any non-FAILED classification excludes a rule, regardless of provider/model/version. A Gemini or old Qwen result can therefore suppress Qwen V2.2 work. |
| Service cache | Already checks `rule_id + provider + model_name + classifier_version`, excluding FAILED. `force=True` bypasses cache. |
| Service attempt transaction | Adds/flushes `ClassificationRun`, assembles input, commits the attempt **before** awaiting inference. No SQLite write lock is held across model inference. |
| Service result transaction | Adds full normalized/validated Classification, completes its run, adds product default if absent, then commits **per rule**, not at the end of the batch. |
| Interruption | Earlier service commits already survive cancellation. Only the current uncommitted transaction can roll back. An unfinished run alone is not a successful classification. |
| Existing generic bulk CLI | Already uses isolated sessions and identity-scoped selection, but defaults to skipping FAILED attempts unless `--retry-failed` is supplied. Has no 1000 cap, active ET membership check, status-only command, or dedicated OS worker lock. |

The Ollama adapter uses the existing `/api/chat` structured-output/Pydantic path.
Its Qwen prompt, hardening, retrieval, validator and retry behavior were inspected
and left unchanged. The HTTP bulk route and generic CLI are also unchanged.

## Identity and exact completion rule

- Provider: **`ollama`**, fixed.
- Model: `OLLAMA_MODEL`, currently **`qwen3:8b`**. As in Model Lab, a non-secret DB
  runtime override takes precedence over the environment/.env configuration.
- Classifier version: **`qwen-v2.2`**, fixed.
- SID/REV is represented by the unique `Rule.id` referencing the rules table.

The identity is frozen at invocation start. Changing the model deliberately creates
a different workload; existing results for the previous model stay in history.
No aliases such as `v2.1` or `v2.2-qwen` are silently treated as the target identity.

`AUTO_CLASSIFIED` and `REVIEW_REQUIRED` both mean the pipeline produced a result.
Review required is not a provider failure or an instruction to infer forever.
Null entity/MITRE/etc. may be deliberate abstention and does not invalidate completion.
This is **operational completion, not an accuracy or human-approval assertion**.

The completion SQL predicate requires:

1. Exact target identity and one of these two successful statuses.
2. Stored confidence in [0,1], non-null evidence and explanation.
3. A linked completed `ClassificationRun` for the same rule and identity with
   `successful_rules > 0`; **or**, for unlinked legacy records, explicit canonical
   `agent_activity.validation.status` equal to `PASS` or `REVIEW`.

The existing service validates structured output before its atomic result write.
The checkpoint predicate uses proof of that completed pipeline, not new semantic
thresholds. Bare default Classification rows, FAILED records, and unfinished runs
do not count. Legacy records without completion proof remain eligible and are
preserved if a new result is generated. A single valid successful result suffices;
a later failed forced run does not undo completed progress.

Conceptually the query is:

```sql
SELECT rules.id
FROM rules
WHERE NOT EXISTS (
  SELECT 1 FROM classifications c
  WHERE c.rule_id = rules.id
    AND c.provider = 'ollama'
    AND c.model_name = :configured_model
    AND c.classifier_version = 'qwen-v2.2'
    AND <completion proof described above>
)
ORDER BY rules.id;
```

The runner intersects these results with **active SID/REV membership** obtained from
local `data/rules/et-open/*.rules` using the existing loader/parser, then takes at
most N. Comments/disabled rules and retired revisions are excluded. Historical
`source_file` values vary between basenames and paths, so they are not a reliable
active-membership test. Missing active imports fail preflight; the runner does not
silently classify a subset or mutate/import rules.

`completed_query()` and `completion_proof()` in the runner implement the actual
SQLAlchemy expression. Selection, progress counts, pre-call checks and the optional
service cache predicate use the **same** proof. That last optional service argument
prevents a partial positive cache row from blocking a valid retry; default callers,
Gemini caching and `force=True` retain their previous behavior.

## Transactions, interruption and failures

Each rule uses a fresh session. The service commits the attempt before inference,
then commits the entire output plus run completion before moving to the next rule.
There is no batch-wide transaction. Errors/cancellation roll back only the current
session. SQLite busy/locked errors get at most two retries, each in a fresh session,
with 1/2 second backoff. Before retrying, completion is checked again, covering a
commit that succeeded even if a subsequent response/refresh failed.

- Ctrl+C/cancellation prints a summary when Python can handle it, returns 130 and
  leaves already committed output intact.
- Terminal close, hard process kill or power loss may prevent the summary. Next
  invocation still reads persisted progress from SQLite.
- The currently in-flight rule may need another model call if no result was committed.
  Exactly-once external inference cannot be guaranteed across loss between model
  response and database commit; **already committed successes are skipped**.
- Three consecutive errors pause the batch. Other isolated errors do not discard
  successes. Each selected rule is attempted once per invocation (apart from bounded
  existing provider/DB retry); failed/incomplete work is eligible next invocation.
- A zero-inference `/api/tags` readiness check runs before every rule. If Ollama died
  after the previous commit, the next rule is `NOT ATTEMPTED` and the batch pauses
  without creating cascading FAILED rows. A connection loss between that check and
  inference can fail at most the current attempt; the safe `OLLAMA_*` reason is shown
  and processing stops immediately. Re-running the wrapper restarts and resumes.
- When the wrapper starts Ollama, server output is captured in
  `backend/ollama-batch.out.log` and `backend/ollama-batch.err.log`. This makes a
  future GPU/server crash diagnosable; both log files remain excluded from Git.
- `failed/retryable` counts distinct active rules with target attempts but no valid
  completion, including interrupted run records. Failed history followed by success
  does not inflate this number.
- Exit 0: invocation completed successfully; 1: failures/pause; 2: preflight/configuration
  problem or competing worker; 130: interruption. A 1000-rule invocation finishing
  does not imply the entire catalog is complete; check Remaining.

The observed SQLite configuration is WAL with synchronous=2 (FULL). No database
migration or global uniqueness constraint was added. Normal SQLite durability
depends on functioning storage and OS flush guarantees; backups are still advisable.

## Duplicate prevention and scope of the lock

The runner checks the database during selection **and again immediately before**
the service call, always uses `force=False`, and uses an OS-held project worker lock.
It also takes a short-lived database claim before inference. Cloud export locks the
same rule rows and excludes these local claims; local selection excludes active
cloud reservations. This makes the supported local runner safe to operate while an
exported cloud batch is being processed.
Another copy of this dedicated runner cannot infer concurrently. The file
`.runtime-qwen-catalog.lock` is ignored by Git and may remain after exit; it is not
a stale checkpoint. OS ownership is released on process death/reboot; do not delete
the lock file to bypass a running worker.

**Do not overlap this command with the old bulk script, a custom stdin Qwen worker,
or Qwen Model Lab inference.** Those intentional/legacy paths do not participate in
the local claim protocol. Exported batches created with `app.cloud_batch` are safe
to overlap. Existing Model Lab forced comparisons and immutable history remain
possible; no global constraint forbids them. Stop/wait for an old worker before
switching to the dedicated command.

## Tests and data safety

Tests use temporary **disk SQLite databases**, never destructive production fixtures.
The acceptance test starts a subprocess with 100 rules, kills it with `os._exit(130)`
on its 38th provider call after 37 real service commits, starts a second Python
process, and verifies exactly 63 calls, **zero calls for the first 37**, and exactly
100 persisted classifications. A third process makes zero calls. The same test proves
the OS worker lock is released despite no Python cleanup.

Other regression tests cover identities, Gemini-only/old-version/model eligibility,
commit visibility from independent connections, cancellation, FAILED and incomplete
retry, explicit force history, default Gemini cache behavior, read-only zero-provider
status, 1000 cap, active membership, lock conflicts, SQLite lock recovery, runtime
model settings, and three-failure circuit breaking.

No existing classification, manual review, comparison, ET source, operational-250
artifact, audited expected value or golden dataset was deleted/rewritten. Real
inference was not started by this implementation/test task. Existing unrelated
workspace edits were preserved.

### Measured verification (2026-09-03)

- New dedicated regression tests: **14 passed**.
- Focused suite (dedicated + bulk + model comparison + Gemini/Ollama provider +
  Qwen V2.2): **38 passed**, 1 existing Starlette/httpx deprecation warning.
- Entire backend suite: **123 passed, 1 failed**, same warning. The failing existing
  `test_database_read_only_snapshot_matches_all_100_outputs` requires an old snapshot
  classification ID that is absent from the current production DB: SID 2023019,
  Gemini classification ID 1303. This is not repaired by rewriting historical reports
  or database records. The test remains visible and failing, not skipped.
- Production **read-only status**, at the time checked: total 52,155; completed 1,352;
  remaining 50,803; failed/retryable 1; completion 2.59%. An existing user-started
  background worker was still adding results, so these are a snapshot, not frozen totals.
- PowerShell wrapper `-Status`: exited 0 with no inference.
- `git diff --check`: passed.

Reproduce the focused suite from backend:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_qwen_catalog_batch.py tests/test_bulk_classify.py tests/test_model_comparison.py tests/test_gemini_provider.py tests/test_ollama_provider.py tests/test_qwen_v22.py -q
```

Files in this implementation: `run-qwen-1000.ps1`,
`backend/app/evaluation/run_qwen_catalog_batch.py`,
`backend/app/services/classification_service.py` (optional cache predicate only),
`backend/tests/test_qwen_catalog_batch.py`, `backend/tests/qwen_catalog_worker.py`,
`.gitignore` (lock file only), `README.md`, and this document.
