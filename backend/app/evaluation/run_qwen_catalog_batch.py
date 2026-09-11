"""Sequential Qwen V2.2 ET catalog batches. Only committed DB results are checkpoints."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import socket
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import and_, delete, exists, or_, select, text
from sqlalchemy.exc import SQLAlchemyError

from app.agent.factory import create_classification_provider
from app.config import get_settings
from app.database.models import (
    Classification,
    ClassificationRun,
    ClassificationStatus,
    CloudBatchReservation,
    CloudReservationStatus,
    LocalClassificationClaim,
    Rule,
)
from app.database.session import SessionLocal, ensure_schema_extensions
from app.evaluation.bulk_classify import _db_reason, _transient_db_error
from app.ingestion.rule_loader import RuleLoader
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService, LocalOwnershipLost
from app.services.runtime_config import get_value

ROOT = Path(__file__).resolve().parents[3]
ET_ROOT = ROOT / "data/rules/et-open"
VERSION = "qwen-v2.2"
MAX_BATCH = 1000
SUCCESS = (ClassificationStatus.AUTO_CLASSIFIED, ClassificationStatus.REVIEW_REQUIRED)


def completion_proof():
    """Persisted successful pipeline run, or explicit legacy validator evidence.

    Null semantic fields are legitimate abstentions, not incomplete processing.
    A default/empty Classification or an unfinished ClassificationRun is NOT proof.
    """
    finished_run = exists(select(ClassificationRun.id).where(
        ClassificationRun.id == Classification.classification_run_id,
        ClassificationRun.provider == Classification.provider,
        ClassificationRun.model_name == Classification.model_name,
        ClassificationRun.classifier_version == Classification.classifier_version,
        ClassificationRun.rule_id == Classification.rule_id,
        ClassificationRun.completed_at.is_not(None), ClassificationRun.successful_rules > 0,
    ))
    legacy_validated = and_(
        Classification.classification_run_id.is_(None),
        Classification.agent_activity["validation"]["status"].as_string().in_(("PASS", "REVIEW")),
    )
    return and_(Classification.classification_status.in_(SUCCESS),
                Classification.confidence.between(0, 1),
                Classification.evidence.is_not(None), Classification.explanation.is_not(None),
                or_(finished_run, legacy_validated))


def target_scope(model):
    return (Classification.provider == "ollama", Classification.model_name == model,
            Classification.classifier_version == VERSION)


def completed_query(model):
    return select(Classification.rule_id).where(*target_scope(model), completion_proof()).distinct()


def cloud_reservation_exists(rule_id=Rule.id):
    return exists(select(CloudBatchReservation.id).where(
        CloudBatchReservation.rule_id == rule_id,
        CloudBatchReservation.status == CloudReservationStatus.RESERVED,
    ))


def active_local_claim_exists(model, rule_id=Rule.id, now=None):
    now = now or datetime.now(timezone.utc)
    return exists(select(LocalClassificationClaim.rule_id).where(
        LocalClassificationClaim.rule_id == rule_id,
        LocalClassificationClaim.target_provider == "ollama",
        LocalClassificationClaim.target_model == model,
        LocalClassificationClaim.classifier_version == VERSION,
        LocalClassificationClaim.expires_at > now,
    ))


def configured_settings(factory=SessionLocal):
    settings = get_settings()
    # Read ONLY Ollama non-secret settings; never instantiate Gemini or read its key.
    with factory() as db:
        model = get_value(db, "OLLAMA_MODEL") or settings.ollama_model
        url = get_value(db, "OLLAMA_BASE_URL") or settings.ollama_base_url
    return settings.model_copy(update={"ai_provider": "ollama", "classifier_version": VERSION,
                                       "ollama_model": model, "ollama_base_url": url})


def verify_ollama_ready(settings, transport=None):
    """Zero-inference readiness check performed before any rule is attempted."""
    try:
        with httpx.Client(timeout=5, transport=transport, trust_env=False) as client:
            response = client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            response.raise_for_status()
            names = {item.get("name") for item in response.json().get("models", [])}
    except (httpx.HTTPError, ValueError, TypeError):
        raise RuntimeError("OLLAMA_NOT_RUNNING") from None
    if settings.ollama_model not in names:
        raise RuntimeError("CONFIGURED_OLLAMA_MODEL_NOT_INSTALLED")


def active_rules(factory, directory=ET_ROOT):
    """Use active local ET SID/REV membership, not inconsistent source_file labels.

    No download/import/update. Missing imports fail closed instead of silently
    claiming completion for a subset of the active dataset.
    """
    files = sorted(directory.glob("*.rules"))
    if not files:
        raise ValueError("ACTIVE_ET_FILES_MISSING")
    identities = set()
    loader, parser = RuleLoader(), SuricataRuleParser()
    for path in files:
        for raw in loader.load_file(path).rules:
            parsed = parser.parse(raw)
            identities.add((parsed.sid, parsed.rev))
    if not identities:
        raise ValueError("ACTIVE_ET_DATASET_EMPTY")
    with factory() as db:
        rules = {rid: (sid, rev) for rid, sid, rev in db.execute(select(Rule.id, Rule.sid, Rule.rev))
                 if (sid, rev) in identities}
    if len(rules) != len(identities):
        raise ValueError(f"ACTIVE_ET_NOT_FULLY_IMPORTED: missing={len(identities) - len(rules)}")
    return rules


def status(factory, active, model):
    with factory() as db:
        completed = set(db.scalars(completed_query(model))) & active.keys()
        attempted = set(db.scalars(select(Classification.rule_id).where(*target_scope(model)))) & active.keys()
        attempted |= set(db.scalars(select(ClassificationRun.rule_id).where(
            ClassificationRun.provider == "ollama", ClassificationRun.model_name == model,
            ClassificationRun.classifier_version == VERSION,
        ))) & active.keys()
    remaining = len(active) - len(completed)
    return {"total": len(active), "completed": len(completed), "remaining": remaining,
            "failed_retryable": len(attempted - completed),
            "completion_percentage": round(100 * len(completed) / len(active), 2) if active else 0}


def select_remaining(factory, active, model, limit):
    proof = exists(completed_query(model).where(Classification.rule_id == Rule.id))
    with factory() as db:
        eligible = db.scalars(select(Rule.id).where(
            ~proof,
            ~cloud_reservation_exists(),
            ~active_local_claim_exists(model),
        ).order_by(Rule.id))
        selected = []
        for rid in eligible:
            if rid in active:
                selected.append(rid)
                if len(selected) == limit:
                    break
        return selected


def _begin_claim_transaction(db):
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def claim_local_rule(factory, rid, model, ttl=timedelta(hours=1)):
    """Atomically claim one rule before inference so export cannot take it."""
    claim_id = f"local-{uuid4().hex}"
    now = datetime.now(timezone.utc)
    with factory() as db:
        _begin_claim_transaction(db)
        rule = db.scalar(select(Rule).where(Rule.id == rid).with_for_update())
        if rule is None:
            db.rollback()
            return "MISSING", None
        if db.scalar(completed_query(model).where(Classification.rule_id == rid)):
            db.rollback()
            return "COMPLETED", None
        if db.scalar(select(CloudBatchReservation.id).where(
            CloudBatchReservation.rule_id == rid,
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )):
            db.rollback()
            return "CLOUD_RESERVED", None
        db.execute(delete(LocalClassificationClaim).where(
            LocalClassificationClaim.rule_id == rid,
            LocalClassificationClaim.expires_at <= now,
        ))
        if db.get(LocalClassificationClaim, rid) is not None:
            db.rollback()
            return "LOCAL_BUSY", None
        db.add(LocalClassificationClaim(
            rule_id=rid,
            claim_id=claim_id,
            target_provider="ollama",
            target_model=model,
            classifier_version=VERSION,
            owner_pid=os.getpid(),
            owner_host=socket.gethostname(),
            created_at=now,
            expires_at=now + ttl,
        ))
        db.commit()
    return "CLAIMED", claim_id


def release_local_claim(factory, claim_id):
    if not claim_id:
        return
    with factory() as db:
        db.execute(delete(LocalClassificationClaim).where(LocalClassificationClaim.claim_id == claim_id))
        db.commit()


def clear_stale_runner_claims(factory, model):
    """Called once by the OS-serialized runner after a prior process crash."""
    now = datetime.now(timezone.utc)
    host = socket.gethostname()

    def process_alive(pid):
        if not pid or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    with factory() as db:
        claims = db.scalars(select(LocalClassificationClaim).where(
            LocalClassificationClaim.target_provider == "ollama",
            LocalClassificationClaim.target_model == model,
            LocalClassificationClaim.classifier_version == VERSION,
        )).all()
        for claim in claims:
            expires_at = claim.expires_at
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            expired = expires_at is not None and expires_at <= now
            dead_owner = (
                claim.owner_host == host
                and claim.owner_pid is not None
                and not process_alive(claim.owner_pid)
            )
            if expired or dead_owner:
                db.delete(claim)
        db.commit()


@contextmanager
def batch_lock(path=ROOT / ".runtime-qwen-catalog.lock"):
    """OS-held lock: crash/reboot releases ownership; file is not a checkpoint.

    Serializes this dedicated runner across models/versions on this project.
    Does not block intentional Model Lab force-runs or the legacy bulk runner.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if __import__("os").name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("QWEN_CATALOG_BATCH_ALREADY_RUNNING") from None
        try:
            yield
        finally:
            handle.seek(0)
            if __import__("os").name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_UN)


async def classify_one(factory, rid, provider, settings, repository):
    claim_id = None
    for claim_attempt in range(3):
        try:
            claim_ttl = timedelta(seconds=max(
                3600,
                settings.ollama_timeout_seconds * (settings.ai_max_retries + 1) + 300,
            ))
            claim_state, claim_id = claim_local_rule(
                factory, rid, settings.ollama_model, ttl=claim_ttl
            )
            break
        except SQLAlchemyError as exc:
            if _transient_db_error(exc) and claim_attempt < 2:
                print(f"DB RETRY {claim_attempt + 1}/2: {_db_reason(exc)}", flush=True)
                await asyncio.sleep(2 ** claim_attempt)
                continue
            return {"ok": False, "reason": _db_reason(exc)}
    else:
        raise AssertionError("unreachable")
    if claim_state == "COMPLETED":
        return {"ok": True, "cached": True}
    if claim_state in {"CLOUD_RESERVED", "LOCAL_BUSY"}:
        return {"ok": True, "cached": True, "reserved": True}
    if claim_state == "MISSING":
        return {"ok": False, "reason": "RULE_NOT_FOUND"}
    try:
        for attempt in range(3):
            try:
                with factory() as db:
                    try:
                        # Recheck persisted completion immediately before building input/inference.
                        if db.scalar(completed_query(settings.ollama_model).where(Classification.rule_id == rid)):
                            return {"ok": True, "cached": True}
                        rule = db.get(Rule, rid)
                        if rule is None:
                            return {"ok": False, "reason": "RULE_NOT_FOUND"}
                        result = await ClassificationService(
                            db,
                            provider,
                            settings,
                            repository,
                            cache_completion_filter=completion_proof(),
                            ownership_claim_id=claim_id,
                        ).classify(rule, force=False)
                        # Service commits the full result before returning. Confirm the DB proof.
                        ok = bool(db.scalar(completed_query(settings.ollama_model).where(Classification.rule_id == rid)))
                        reason = None
                        if not ok:
                            code = (result.explanation or "").split(":", 1)[0]
                            if code.startswith("OLLAMA_") and code.replace("_", "").isalnum():
                                reason = code
                        return {"ok": ok, "cached": bool(getattr(result, "_cache_hit", False)),
                                "reason": None if ok else reason or "CLASSIFICATION_FAILED_OR_INCOMPLETE"}
                    except BaseException:
                        db.rollback()  # only this session/current transaction, never earlier commits
                        raise
            except SQLAlchemyError as exc:
                if _transient_db_error(exc) and attempt < 2:
                    print(f"DB RETRY {attempt + 1}/2: {_db_reason(exc)}", flush=True)
                    await asyncio.sleep(2 ** attempt)
                    continue
                return {"ok": False, "reason": _db_reason(exc)}
            except LocalOwnershipLost:
                return {"ok": True, "cached": True, "reserved": True}
            except Exception as exc:
                return {"ok": False, "reason": type(exc).__name__}
        raise AssertionError("unreachable")
    finally:
        release_local_claim(factory, claim_id)


def print_status(values):
    print(f"Total active ET rules: {values['total']}\nCompleted: {values['completed']}\n"
          f"Remaining: {values['remaining']}\nFailed/retryable: {values['failed_retryable']}\n"
          f"Progress: {values['completion_percentage']:.2f}%", flush=True)


async def run_batch(factory, active, provider, settings, repository, limit, readiness_check=None):
    if not 1 <= limit <= MAX_BATCH:
        raise ValueError("BATCH_LIMIT_MUST_BE_1_TO_1000")
    if settings.ai_provider != "ollama" or settings.classifier_version != VERSION or provider.model_name != settings.ollama_model:
        raise ValueError("QWEN_BATCH_IDENTITY_MISMATCH")
    for cleanup_attempt in range(3):
        try:
            clear_stale_runner_claims(factory, settings.ollama_model)
            break
        except SQLAlchemyError as exc:
            if _transient_db_error(exc) and cleanup_attempt < 2:
                print(f"DB RETRY {cleanup_attempt + 1}/2: {_db_reason(exc)}", flush=True)
                await asyncio.sleep(2 ** cleanup_attempt)
                continue
            raise
    selected = select_remaining(factory, active, settings.ollama_model, limit)
    committed = failed = cached = streak = 0
    code = 0
    print(f"Requested batch size: {limit}; selected: {len(selected)}; concurrency=1; force=False", flush=True)
    readiness_check = readiness_check or (lambda: verify_ollama_ready(settings))
    try:
        for i, rid in enumerate(selected, 1):
            sid, rev = active[rid]
            try:
                # Prevent a dead local server from creating cascading FAILED rows.
                readiness_check()
            except RuntimeError as exc:
                reason = str(exc).split(":", 1)[0]
                print(f"[{i}/{len(selected)}] SID {sid}/{rev} NOT ATTEMPTED ({reason})", flush=True)
                print("Paused before inference because Ollama became unavailable. Re-run the wrapper to restart and resume.", flush=True)
                code = 1
                break
            result = await classify_one(factory, rid, provider, settings, repository)
            ok = result["ok"]
            cached += int(ok and result.get("cached", False))
            committed += int(ok and not result.get("cached", False))
            failed += int(not ok)
            streak = 0 if ok else streak + 1
            label = "CACHED" if ok and result.get("cached") else "OK" if ok else f"FAILED ({result['reason']})"
            print(f"[{i}/{len(selected)}] SID {sid}/{rev} {label}", flush=True)
            if not ok and result.get("reason") == "OLLAMA_CONNECTION_FAILED_OR_TIMEOUT":
                print("Paused after the current failed attempt because the Ollama connection was lost.", flush=True)
                code = 1
                break
            if streak >= 3:
                print("Paused after 3 consecutive failures; unattempted rules remain eligible.", flush=True)
                code = 1
                break
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Interrupted. Previously committed results are preserved; safe to resume later.", flush=True)
        code = 130
    finally:
        print(f"Committed this batch: {committed}; cache hits: {cached}; failed: {failed}", flush=True)
        # Counts after cancellation are DB-backed; a commit just before cancellation
        # may be reflected here even if the progress line had not yet printed.
        try:
            print_status(status(factory, active, settings.ollama_model))
        except SQLAlchemyError:
            print("Final status unavailable; query --status when DB is available.", flush=True)
    return code or int(failed > 0)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=1000, help="Maximum attempts this invocation (1-1000).")
    parser.add_argument("--status", action="store_true", help="Read-only progress, zero model calls.")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= MAX_BATCH:
        parser.error("--limit must be between 1 and 1000")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        ensure_schema_extensions()
        settings = configured_settings()
        print(f"Qwen Catalog Batch\nTarget: ollama / {settings.ollama_model} / {VERSION}", flush=True)
        if not args.status:
            verify_ollama_ready(settings)
        print("Checking local active ET membership (no download or inference)...", flush=True)
        active = active_rules(SessionLocal)
        print_status(status(SessionLocal, active, settings.ollama_model))
        if args.status:
            return 0
        with batch_lock():
            print("Do not run legacy Qwen bulk commands or Qwen Model Lab inference alongside this batch.", flush=True)
            provider = create_classification_provider(settings)
            return asyncio.run(run_batch(SessionLocal, active, provider, settings, MitreRepository(), args.limit))
    except KeyboardInterrupt:
        print("Interrupted. Committed database progress is safe; resume with the same command.", flush=True)
        return 130
    except (ValueError, RuntimeError) as exc:
        # Only explicitly generated, safe operational codes; parser errors may include raw rule text.
        safe = str(exc).split(":", 1)[0]
        print(safe if safe.isupper() and safe.replace("_", "").isalnum() else type(exc).__name__, flush=True)
        return 2
    except Exception as exc:
        print(f"Batch cannot start: {type(exc).__name__}. Check local DB and dataset configuration.", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
