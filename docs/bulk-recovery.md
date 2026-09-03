# Bulk classification recovery — 2026-09-03

The second historical chunk requested 2,000 rules. Records 1–106 succeeded. Record 107 (SID 2403407, REV 111389) recorded OperationalError; the following 1,893 recorded InvalidRequestError. The batch finished with 106 successes and 1,894 failures. Only exception type names were retained, so the original OperationalError message cannot be recovered from this log. A SQLite lock is a plausible initial trigger, not a confirmed historical message.

The runner reused one SQLAlchemy session across the entire batch and did not roll back after the exception. A failed transaction therefore poisoned later iterations. The historical FAILED lines are batch-attempt outcomes, not 1,894 persisted failed Qwen classifications.

## Changes

- Selection uses short-lived sessions returning scalar rule IDs/SID/REV.
- Each inference attempt has its own session, with rollback and close on errors.
- SQLite BUSY/LOCKED errors get at most two retries by default with bounded backoff and a fresh session. Logs contain exception types/numeric SQLite codes, never SQL parameters.
- SQLite connections now wait up to 30 seconds for a lock. The current catalog DB was backed up via SQLite backup and switched from DELETE journaling to WAL. WAL is persistent for this database; the CLI does not silently convert other databases.
- Three consecutive failures pause the batch with a nonzero exit code. Unattempted records are counted separately.
- Progress checkpoints occur every ten records, on failures, at chunk boundaries and on interruption. Successful database commits remain the resume authority.
- The retry flag was inverted in the old selection logic. Now default mode skips prior attempts; --retry-failed includes historical failures, but always skips successful results for the exact provider/model/version.
- Rule IDs advance monotonically within each invocation, preventing a failed rule from being reselected repeatedly during the same run.
- CLI reports this invocation's counters separately from cumulative historical state. Existing state files and benchmark labels were preserved.

## Verification

- Real SQLite lock/recovery, session isolation, retry scope, failure circuit, and resume without duplicate successful classifications: five new tests passed.
- Existing ClassificationService cache test passed.
- Full backend suite: 92 passed, 1 failed. The failing historical snapshot test references 27 missing/mismatched classification IDs. The same 27 are absent/mismatched in the pre-fix backup, proving it predates this change.
- Live qwen3:8b / qwen-v2.2 smoke: SIDs 2403407, 2403408, 2403409 all AUTO_CLASSIFIED, IDs 2093, 2094, 2095; API detail responses verified. No prompt or taxonomy changes were made.
- Backup: data/backups/suricata-rules-before-bulk-recovery-20260903T114256Z.db. SQLite quick_check: ok.
- Smoke run state: data/evaluation/bulk-recovery-smoke.json.

## Resume

Run from the backend directory, with one bulk process at a time:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.bulk_classify --provider ollama --classifier-version qwen-v2.2 --chunk-size 2000 --max-rules 2000 --retry-failed
```

This handles up to 2,000 eligible rule attempts in this invocation; it does not mean the original 2,000-rule chunk is selected again. The first 106 successful results and the three recovery successes are skipped. A historical failed attempt may be retried first. If a recurring infrastructure problem pauses the run, the terminal reports its safe reason code and preserves unattempted work.
