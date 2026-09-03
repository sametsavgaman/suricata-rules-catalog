"""Resumable classification with isolated per-rule database transactions.

The database is the resume authority. State files record attempts, not new rules
or model-verified successes. Successful results for the exact provider, model
and classifier version are never reclassified by this runner.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import exists, select
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.agent.factory import create_classification_provider, provider_config_error
from app.config import get_settings
from app.database.models import Classification, ClassificationStatus, Rule
from app.database.session import Base, SessionLocal, engine, ensure_schema_extensions
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService

ROOT = Path(__file__).resolve().parents[3]


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"chunks": [], "processed": 0, "succeeded": 0, "failed": 0}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _db_reason(exc: SQLAlchemyError) -> str:
    # Do not expose exception SQL, bound parameters, rule text or credentials.
    orig = getattr(exc, "orig", None)
    code = getattr(orig, "sqlite_errorcode", None)
    if isinstance(code, int):
        return f"DATABASE_{type(exc).__name__}_SQLITE_{code}"
    return f"DATABASE_{type(exc).__name__}"


def _transient_db_error(exc: SQLAlchemyError) -> bool:
    if not isinstance(exc, OperationalError):
        return False
    orig = getattr(exc, "orig", None)
    code = getattr(orig, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 255 in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
    return str(orig).lower() in {"database is locked", "database table is locked"}


def _select_rules(settings, model: str, args, after_id: int):
    scope = [
        Classification.rule_id == Rule.id,
        Classification.provider == args.provider,
        Classification.model_name == model,
        Classification.classifier_version == settings.classifier_version,
    ]
    # Default: skip all prior attempts. --retry-failed includes rules without
    # any successful result, even if they have historical FAILED attempts.
    if args.retry_failed:
        scope.append(Classification.classification_status != ClassificationStatus.FAILED)
    stmt = select(Rule.id, Rule.sid, Rule.rev).where(
        Rule.id > after_id, ~exists(select(Classification.id).where(*scope))
    )
    if args.sid:
        stmt = stmt.where(Rule.sid.in_(args.sid))
    # Return scalar snapshots only; never share ORM instances or a transaction
    # across the inference loop.
    with SessionLocal() as db:
        return list(db.execute(stmt.order_by(Rule.id).limit(args.chunk_size)))


async def _classify_one(rule_id: int, provider, settings, repo, db_retries: int = 2) -> dict:
    for attempt in range(db_retries + 1):
        try:
            with SessionLocal() as db:
                try:
                    rule = db.get(Rule, rule_id)
                    if rule is None:
                        return {"status": "FAILED", "reason": "RULE_NOT_FOUND", "db_retries": attempt}
                    service = ClassificationService(db, provider, settings, repo)
                    result = await service.classify(rule, force=False)
                    record = {
                        "classification_id": result.id,
                        "status": result.classification_status.value,
                        "cache_hit": bool(getattr(result, "_cache_hit", False)),
                        "db_retries": attempt,
                    }
                    if result.classification_status == ClassificationStatus.FAILED:
                        # Persist a safe, bounded code. Full SQL/provider exception
                        # text must never be printed by the batch runner.
                        code = (result.explanation or "").split(":", 1)[0]
                        record["reason"] = code if code.startswith("OLLAMA_") and code.replace("_", "").isalnum() else "CLASSIFICATION_FAILED"
                    return record
                except BaseException:
                    db.rollback()
                    raise
        except SQLAlchemyError as exc:
            reason = _db_reason(exc)
            if _transient_db_error(exc) and attempt < db_retries:
                print(f"DB RETRY {attempt + 1}/{db_retries}: {reason}", flush=True)
                await asyncio.sleep(min(2 ** attempt, 8))
                continue
            return {"status": "FAILED", "reason": reason, "database_error": True, "db_retries": attempt}
        except Exception as exc:
            return {"status": "FAILED", "reason": type(exc).__name__, "db_retries": attempt}
    raise AssertionError("unreachable")


async def run(args) -> int:
    settings = get_settings().model_copy(update={
        "ai_provider": args.provider, "classifier_version": args.classifier_version,
    })
    if error := provider_config_error(settings):
        print(error)
        return 2
    provider = create_classification_provider(settings)
    model = provider.model_name
    if args.state is None:
        args.state = ROOT / f"data/evaluation/bulk-state-{args.provider}.json"
    state = _load_state(args.state)
    state.update({
        "provider": args.provider, "model": model, "classifier_version": args.classifier_version,
        "chunk_size": args.chunk_size, "status": "RUNNING",
        "started_or_resumed_at": datetime.now(timezone.utc).isoformat(),
    })
    state.pop("stop_reason", None)
    state.pop("finished_at", None)
    Base.metadata.create_all(bind=engine)
    ensure_schema_extensions()
    repo = MitreRepository()
    processed = succeeded = failed = retries = streak = after_id = 0
    exit_code = 0
    print(f"Provider={args.provider} model={model} classifier={settings.classifier_version}; "
          f"maximum={args.max_rules}; retry_failed={args.retry_failed}; resume=DATABASE", flush=True)
    try:
        while processed < args.max_rules:
            try:
                rules = _select_rules(settings, model, args, after_id)[:args.max_rules - processed]
            except SQLAlchemyError as exc:
                state.update(status="PAUSED_ON_FAILURE", stop_reason=_db_reason(exc))
                exit_code = 1
                break
            if not rules:
                break
            chunk = {"index": len(state["chunks"]) + 1, "started_at": datetime.now(timezone.utc).isoformat(),
                     "requested": len(rules), "processed": 0, "succeeded": 0, "failed": 0, "records": []}
            state["chunks"].append(chunk)
            _write_state(args.state, state)
            for rule_id, sid, rev in rules:
                result = await _classify_one(rule_id, provider, settings, repo, args.db_retries)
                ok = result["status"] != "FAILED"
                record = {"sid": sid, "rev": rev, **result}
                chunk["records"].append(record)
                chunk["processed"] += 1
                chunk["succeeded" if ok else "failed"] += 1
                state["processed"] += 1
                state["succeeded" if ok else "failed"] += 1
                processed += 1
                succeeded += int(ok)
                failed += int(not ok)
                retries += result.get("db_retries", 0)
                after_id = rule_id
                streak = 0 if ok else streak + 1
                label = "cached" if ok and result.get("cache_hit") else "classified" if ok else f"FAILED ({result.get('reason', 'UNKNOWN')})"
                print(f"[{processed}/{args.max_rules}] SID {sid}/{rev} {label}", flush=True)
                if processed % 10 == 0 or not ok:
                    _write_state(args.state, state)
                if streak >= args.max_consecutive_failures:
                    state.update(status="PAUSED_ON_FAILURE", stop_reason=f"{streak} consecutive failures; {result.get('reason', 'UNKNOWN')}")
                    exit_code = 1
                    break
            chunk["completed_at"] = datetime.now(timezone.utc).isoformat()
            chunk["unattempted"] = chunk["requested"] - chunk["processed"]
            _write_state(args.state, state)
            print(f"CHUNK {chunk['index']}: {chunk['succeeded']} succeeded, {chunk['failed']} failed, "
                  f"{chunk['unattempted']} unattempted", flush=True)
            if exit_code or args.once:
                break
        if state["status"] == "RUNNING":
            state["status"] = "COMPLETED"
    except (KeyboardInterrupt, asyncio.CancelledError):
        state.update(status="INTERRUPTED", stop_reason="Interrupted; committed results are preserved.")
        raise
    finally:
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["last_invocation"] = {"processed": processed, "succeeded": succeeded, "failed": failed, "db_retries": retries}
        state["remaining_estimate"] = None
        _write_state(args.state, state)
        print(json.dumps({"status": state["status"], **state["last_invocation"],
                          "stop_reason": state.get("stop_reason")}, ensure_ascii=False), flush=True)
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("gemini", "ollama"), required=True)
    parser.add_argument("--classifier-version", default=None)
    parser.add_argument("--chunk-size", type=int, default=2000)
    parser.add_argument("--max-rules", type=int, default=2000)
    parser.add_argument("--state", type=Path, default=None)
    parser.add_argument("--once", action="store_true", help="Process at most one chunk.")
    parser.add_argument("--retry-failed", action="store_true", help="Include historical failed attempts, but always skip successful results.")
    parser.add_argument("--sid", type=int, action="append", default=[], help="Limit to specific SIDs (repeatable); useful for recovery checks.")
    parser.add_argument("--db-retries", type=int, default=2, help="Bounded retries for SQLite busy/locked errors.")
    parser.add_argument("--max-consecutive-failures", type=int, default=3, help="Pause after repeated failures instead of cascading across the batch.")
    args = parser.parse_args()
    if args.classifier_version is None:
        args.classifier_version = "qwen-v2.2" if args.provider == "ollama" else "v2.1"
    if args.chunk_size < 1 or args.max_rules < 1 or args.max_consecutive_failures < 1 or args.db_retries < 0:
        parser.error("limits must be positive and db-retries must be nonnegative")
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
