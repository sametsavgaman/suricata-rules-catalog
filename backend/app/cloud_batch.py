"""Portable Qwen V2.2 cloud batches backed by local database reservations."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import exists, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agent.schemas import ClassificationOutput, ProviderResult, TokenUsage
from app.database.models import (
    Classification,
    ClassificationRun,
    ClassificationStatus,
    CloudBatch,
    CloudBatchReservation,
    CloudBatchStatus,
    CloudReservationStatus,
    LocalClassificationClaim,
    Rule,
)
from app.database.session import SessionLocal, ensure_schema_extensions
from app.evaluation.run_qwen_catalog_batch import (
    VERSION,
    active_local_claim_exists,
    active_rules,
    cloud_reservation_exists,
    completed_query,
    completion_proof,
    configured_settings,
)
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import (
    ClassificationService,
    classification_context_sha256,
    prepare_classification,
)
from app.v2.qwen_hardening import QWEN_SYSTEM_PROMPT

ROOT = Path(__file__).resolve().parents[2]
CLOUD_SOURCE = ROOT / "cloud"
DEFAULT_OUTPUT_ROOT = ROOT / "data" / "cloud_batches"
TARGET_PROVIDER = "ollama"
INPUT_FORMAT = "suricata-qwen-cloud-input-v1"
RESULT_FORMAT = "suricata-qwen-cloud-result-v1"
WORKER_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
MAX_RESULT_LINE_BYTES = 2 * 1024 * 1024


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def raw_rule_sha256(rule: Rule) -> str:
    return sha256_text(rule.raw_rule)


def cloud_contract(
    model: str,
    *,
    model_digest: str | None = None,
    num_ctx: int = 8192,
    num_predict: int = 1536,
) -> dict[str, Any]:
    options = {"temperature": 0, "seed": 42, "num_ctx": num_ctx, "num_predict": num_predict}
    contract = {
        "provider": TARGET_PROVIDER,
        "model": model,
        "model_digest": model_digest,
        "classifier_version": VERSION,
        "system_prompt": QWEN_SYSTEM_PROMPT,
        "output_schema": ClassificationOutput.model_json_schema(),
        "inference": {"api": "POST /api/chat", "stream": False, "think": False, "options": options},
    }
    contract["contract_sha256"] = sha256_text(canonical_json(contract))
    return contract


def discover_local_model_digest(settings) -> str | None:
    """Best-effort, zero-inference provenance lookup from the local Ollama API."""
    try:
        with httpx.Client(timeout=5, trust_env=False) as client:
            response = client.get(f"{settings.ollama_base_url.rstrip('/')}/api/tags")
            response.raise_for_status()
            for item in response.json().get("models", []):
                if item.get("name") == settings.ollama_model or item.get("model") == settings.ollama_model:
                    digest = item.get("digest")
                    return str(digest) if digest else None
    except (httpx.HTTPError, ValueError, TypeError):
        return None
    return None


class CloudResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: Literal[RESULT_FORMAT]
    batch_id: str = Field(min_length=1, max_length=96)
    rule_id: int = Field(gt=0)
    sid: int = Field(gt=0)
    rev: int = Field(ge=0)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: str = Field(min_length=1, max_length=32)
    model: str = Field(min_length=1, max_length=128)
    classifier_version: str = Field(min_length=1, max_length=32)
    output: ClassificationOutput
    usage: TokenUsage = Field(default_factory=TokenUsage)
    runtime: dict[str, Any] = Field(default_factory=dict)
    inference_duration_ms: float | None = Field(default=None, ge=0)
    created_at: datetime


def _begin_immediate_if_sqlite(db: Session) -> None:
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def _begin_export_transaction(db: Session) -> None:
    _begin_immediate_if_sqlite(db)
    if db.get_bind().dialect.name == "postgresql":
        # Serializes the human-facing date/sequence ID and reservation commit,
        # while local inference remains concurrent through per-rule locks.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('suricata_cloud_batch_export'))"))


def _next_batch_id(db: Session, worker: str, now: datetime) -> str:
    prefix = f"{worker}-{now:%Y%m%d}-"
    values = db.scalars(select(CloudBatch.batch_id).where(CloudBatch.batch_id.like(f"{prefix}%")))
    sequence = max((int(value.rsplit("-", 1)[1]) for value in values if value.rsplit("-", 1)[1].isdigit()), default=0)
    return f"{prefix}{sequence + 1:03d}"


def _eligible_statement(model: str, now: datetime):
    completed = exists(completed_query(model).where(Classification.rule_id == Rule.id))
    return select(Rule).where(
        ~completed,
        ~cloud_reservation_exists(),
        ~active_local_claim_exists(model, now=now),
    ).order_by(Rule.id)


def reserve_rules(
    factory,
    active: dict[int, tuple[int, int]],
    model: str,
    limit: int,
    worker: str,
    *,
    contract: dict[str, Any] | None = None,
):
    if not 1 <= limit <= 10_000:
        raise ValueError("BATCH_LIMIT_MUST_BE_1_TO_10000")
    if not WORKER_PATTERN.fullmatch(worker):
        raise ValueError("INVALID_WORKER_NAME")
    now = datetime.now(timezone.utc)
    with factory() as db:
        _begin_export_transaction(db)
        selected: list[Rule] = []
        if db.get_bind().dialect.name == "sqlite":
            for rule in db.scalars(_eligible_statement(model, now)):
                if rule.id in active:
                    selected.append(rule)
                    if len(selected) == limit:
                        break
        else:
            # Active ET membership is held in Python, so lock bounded pages
            # instead of every unclassified database row.
            cursor = 0
            page_size = max(256, min(limit * 2, 5000))
            while len(selected) < limit:
                candidate_ids = list(db.scalars(
                    _eligible_statement(model, now)
                    .with_only_columns(Rule.id)
                    .where(Rule.id > cursor)
                    .limit(page_size)
                ))
                if not candidate_ids:
                    break
                cursor = candidate_ids[-1]
                active_candidates = [rule_id for rule_id in candidate_ids if rule_id in active]
                if not active_candidates:
                    continue
                locked = list(db.scalars(
                    _eligible_statement(model, now)
                    .where(Rule.id.in_(active_candidates))
                    .limit(limit - len(selected))
                    .with_for_update(skip_locked=True)
                ))
                selected.extend(locked)
        if not selected:
            db.rollback()
            raise ValueError("NO_ELIGIBLE_RULES")
        batch_id = _next_batch_id(db, worker, now)
        contract = contract or cloud_contract(model)
        batch = CloudBatch(
            batch_id=batch_id,
            worker=worker,
            status=CloudBatchStatus.PREPARING,
            target_provider=TARGET_PROVIDER,
            target_model=model,
            target_model_digest=contract.get("model_digest"),
            classifier_version=VERSION,
            rule_count=len(selected),
            contract_sha256=contract["contract_sha256"],
            created_at=now,
        )
        db.add(batch)
        db.flush()
        for rule in selected:
            db.add(CloudBatchReservation(
                batch_id=batch_id,
                rule_id=rule.id,
                sid=rule.sid,
                rev=rule.rev,
                raw_sha256=raw_rule_sha256(rule),
                status=CloudReservationStatus.RESERVED,
                created_at=now,
            ))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise RuntimeError("CONCURRENT_RESERVATION_CONFLICT_RETRY_EXPORT") from None
    return batch_id, [rule.id for rule in selected], contract


def available_rule_ids(factory, active: dict[int, tuple[int, int]], model: str) -> set[int]:
    now = datetime.now(timezone.utc)
    with factory() as db:
        return {rule_id for rule_id in db.scalars(_eligible_statement(model, now).with_only_columns(Rule.id))
                if rule_id in active}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def export_batch(
    factory,
    active: dict[int, tuple[int, int]],
    settings,
    *,
    limit: int,
    worker: str,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
) -> dict[str, Any]:
    contract = cloud_contract(
        settings.ollama_model,
        model_digest=discover_local_model_digest(settings),
        num_ctx=settings.ollama_num_ctx,
        num_predict=settings.ollama_num_predict,
    )
    batch_id, rule_ids, contract = reserve_rules(
        factory, active, settings.ollama_model, limit, worker, contract=contract
    )
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    final_dir = output_root / batch_id
    temp_dir = output_root / f".{batch_id}.tmp-{uuid4().hex[:8]}"
    temp_dir.mkdir()
    try:
        repository = MitreRepository()
        input_path = temp_dir / "input.jsonl"
        input_hasher = hashlib.sha256()
        context_hashes: dict[int, str] = {}
        with factory() as db, input_path.open("wb") as handle:
            rows = db.execute(
                select(CloudBatchReservation, Rule)
                .join(Rule, Rule.id == CloudBatchReservation.rule_id)
                .where(CloudBatchReservation.batch_id == batch_id)
                .order_by(CloudBatchReservation.id)
            )
            for reservation, rule in rows:
                prepared = prepare_classification(
                    rule, settings, repository, provider_name=TARGET_PROVIDER
                )
                context_hash = classification_context_sha256(prepared.context)
                context_hashes[rule.id] = context_hash
                item = {
                    "format_version": INPUT_FORMAT,
                    "batch_id": batch_id,
                    "rule_id": rule.id,
                    "sid": rule.sid,
                    "rev": rule.rev,
                    "raw_sha256": reservation.raw_sha256,
                    "context_sha256": context_hash,
                    "contract_sha256": contract["contract_sha256"],
                    "provider": TARGET_PROVIDER,
                    "model": settings.ollama_model,
                    "classifier_version": VERSION,
                    "context": prepared.context.model_dump(mode="json"),
                }
                encoded = (canonical_json(item) + "\n").encode("utf-8")
                handle.write(encoded)
                input_hasher.update(encoded)
        manifest = {
            "format_version": "suricata-qwen-cloud-manifest-v1",
            "batch_id": batch_id,
            "worker": worker,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rule_count": len(rule_ids),
            "input_file": "input.jsonl",
            "result_file": "results.jsonl",
            "input_jsonl_sha256": input_hasher.hexdigest(),
            **contract,
            "runtime_note": (
                "The cloud worker uses Ollama's /api/chat contract with the same model tag, prompt, "
                "JSON schema, and deterministic options. Engine version, model digest, hardware, and "
                "timing are recorded per result because cross-GPU execution is not bit-identical."
            ),
        }
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        (temp_dir / "manifest.json").write_bytes(manifest_bytes)
        bundle_files = [
            ("qwen_worker.py", "worker.py"),
            ("requirements.txt", "requirements.txt"),
            ("README.md", "README.md"),
        ]
        if worker == "kaggle":
            bundle_files.append(("qwen_kaggle.ipynb", "qwen_kaggle.ipynb"))
        elif worker == "colab":
            bundle_files.append(("qwen_colab.ipynb", "qwen_colab.ipynb"))
        for source_name, destination_name in bundle_files:
            shutil.copy2(CLOUD_SOURCE / source_name, temp_dir / destination_name)
        temp_dir.replace(final_dir)
        bundle_base = output_root / f"cloud_batch_{batch_id}"
        bundle_path = Path(shutil.make_archive(str(bundle_base), "zip", root_dir=final_dir))
        with factory() as db:
            batch = db.get(CloudBatch, batch_id)
            if batch is None:
                raise RuntimeError("RESERVED_BATCH_DISAPPEARED")
            for reservation in db.scalars(select(CloudBatchReservation).where(
                CloudBatchReservation.batch_id == batch_id
            )):
                reservation.context_sha256 = context_hashes[reservation.rule_id]
            batch.status = CloudBatchStatus.ACTIVE
            batch.activated_at = datetime.now(timezone.utc)
            batch.manifest_sha256 = sha256_bytes(manifest_bytes)
            try:
                batch.export_path = str((final_dir / "input.jsonl").relative_to(ROOT))
            except ValueError:
                batch.export_path = str(final_dir / "input.jsonl")
            db.commit()
        return {
            "batch_id": batch_id,
            "reserved": len(rule_ids),
            "remaining_unreserved": len(available_rule_ids(factory, active, settings.ollama_model)),
            "input_path": final_dir / "input.jsonl",
            "manifest_path": final_dir / "manifest.json",
            "bundle_path": bundle_path,
        }
    except BaseException:
        if temp_dir.exists() and temp_dir.parent == output_root:
            shutil.rmtree(temp_dir)
        raise


class CloudReplayProvider:
    provider_name = TARGET_PROVIDER
    inference_mode = "CLOUD_KAGGLE"

    def __init__(self, result: CloudResult, expected_context_sha256: str):
        self.model_name = result.model
        self.result = result
        self.expected_context_sha256 = expected_context_sha256
        self.configuration = {
            "cloud_batch_id": result.batch_id,
            "cloud_runtime": result.runtime,
            "cloud_created_at": result.created_at.isoformat(),
            "cloud_contract_sha256": result.contract_sha256,
        }

    async def classify(self, context):
        if classification_context_sha256(context) != self.expected_context_sha256:
            raise ValueError("CLOUD_CONTEXT_HASH_MISMATCH")
        return ProviderResult(output=self.result.output, usage=self.result.usage)


def _matching_completed(db: Session, rule_id: int, model: str) -> Classification | None:
    return db.scalar(
        select(Classification)
        .where(
            Classification.rule_id == rule_id,
            Classification.provider == TARGET_PROVIDER,
            Classification.model_name == model,
            Classification.classifier_version == VERSION,
            completion_proof(),
        )
        .order_by(Classification.created_at.desc())
    )


def _validate_result_identity(result: CloudResult, batch: CloudBatch, reservation: CloudBatchReservation) -> None:
    expected = (
        result.batch_id == batch.batch_id,
        result.rule_id == reservation.rule_id,
        result.sid == reservation.sid,
        result.rev == reservation.rev,
        result.raw_sha256 == reservation.raw_sha256,
        result.context_sha256 == reservation.context_sha256,
        result.contract_sha256 == batch.contract_sha256,
        result.provider == batch.target_provider,
        result.model == batch.target_model,
        result.classifier_version == batch.classifier_version,
    )
    if not all(expected):
        raise ValueError("RESULT_IDENTITY_MISMATCH")
    if batch.target_model_digest and result.runtime.get("model_digest") != batch.target_model_digest:
        raise ValueError("RESULT_MODEL_DIGEST_MISMATCH")


async def import_one(factory, result: CloudResult, settings, repository: MitreRepository) -> str:
    with factory() as db:
        batch = db.scalar(select(CloudBatch).where(
            CloudBatch.batch_id == result.batch_id
        ).with_for_update())
        if batch is None:
            raise ValueError("BATCH_NOT_FOUND")
        reservation = db.scalar(select(CloudBatchReservation).where(
            CloudBatchReservation.batch_id == result.batch_id,
            CloudBatchReservation.rule_id == result.rule_id,
        ).with_for_update())
        if reservation is None:
            raise ValueError("RULE_NOT_RESERVED_BY_BATCH")
        _validate_result_identity(result, batch, reservation)
        if reservation.status == CloudReservationStatus.RELEASED:
            raise ValueError("RESERVATION_ALREADY_RELEASED")
        rule = db.scalar(select(Rule).where(Rule.id == result.rule_id).with_for_update())
        if rule is None or rule.sid != result.sid or rule.rev != result.rev:
            raise ValueError("LOCAL_RULE_IDENTITY_MISMATCH")
        if raw_rule_sha256(rule) != result.raw_sha256:
            raise ValueError("LOCAL_RULE_HASH_MISMATCH")
        prepared = prepare_classification(rule, settings, repository, provider_name=TARGET_PROVIDER)
        if classification_context_sha256(prepared.context) != result.context_sha256:
            raise ValueError("LOCAL_CONTEXT_HASH_MISMATCH")
        existing = _matching_completed(db, rule.id, result.model)
        if existing is not None:
            reservation.status = CloudReservationStatus.IMPORTED
            reservation.classification_id = existing.id
            reservation.imported_at = reservation.imported_at or datetime.now(timezone.utc)
            _refresh_batch_state(db, batch)
            db.commit()
            return "already_present"
        replay = CloudReplayProvider(result, result.context_sha256)
        service_settings = settings.model_copy(update={
            "ai_provider": TARGET_PROVIDER,
            "ollama_model": result.model,
            "classifier_version": VERSION,
        })
        record = await ClassificationService(
            db, replay, service_settings, repository, cache_completion_filter=completion_proof()
        ).classify(rule, force=False)
        if record.classification_status == ClassificationStatus.FAILED:
            raise ValueError("CLOUD_RESULT_POST_PROCESSING_FAILED")
        activity = dict(record.agent_activity or {})
        activity["cloud_batch"] = {
            "batch_id": result.batch_id,
            "worker": batch.worker,
            "runtime": result.runtime,
            "cloud_created_at": result.created_at.isoformat(),
            "contract_sha256": result.contract_sha256,
            "context_sha256": result.context_sha256,
        }
        record.agent_activity = activity
        record.inference_mode = replay.inference_mode
        record.inference_duration_ms = result.inference_duration_ms
        config = dict(record.model_config_json or {})
        config.update(replay.configuration)
        record.model_config_json = config
        if record.classification_run_id:
            run = db.get(ClassificationRun, record.classification_run_id)
            if run is not None:
                run.inference_mode = replay.inference_mode
                run.configuration_json = config
        reservation.status = CloudReservationStatus.IMPORTED
        reservation.classification_id = record.id
        reservation.imported_at = datetime.now(timezone.utc)
        _refresh_batch_state(db, batch)
        db.commit()
        return "imported"


def _refresh_batch_state(db: Session, batch: CloudBatch) -> None:
    db.flush()
    imported = db.scalar(select(func.count()).select_from(CloudBatchReservation).where(
        CloudBatchReservation.batch_id == batch.batch_id,
        CloudBatchReservation.status == CloudReservationStatus.IMPORTED,
    )) or 0
    batch.imported_count = imported
    if batch.status == CloudBatchStatus.RELEASED:
        return
    if imported == batch.rule_count:
        batch.status = CloudBatchStatus.COMPLETED
        batch.completed_at = datetime.now(timezone.utc)
    elif imported:
        batch.status = CloudBatchStatus.PARTIALLY_IMPORTED


def _parse_result_line(raw_line: bytes, line_number: int) -> CloudResult:
    if len(raw_line) > MAX_RESULT_LINE_BYTES:
        raise ValueError(f"LINE_{line_number}_TOO_LARGE")
    try:
        payload = json.loads(raw_line)
        return CloudResult.model_validate(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"LINE_{line_number}_INVALID_RESULT") from exc


def import_results(factory, path: Path, settings) -> dict[str, int]:
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("RESULT_FILE_NOT_FOUND")
    counts = {"imported": 0, "already_present": 0, "rejected": 0}
    repository = MitreRepository()
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            if not raw_line.strip():
                continue
            try:
                result = _parse_result_line(raw_line, line_number)
                outcome = asyncio.run(import_one(factory, result, settings, repository))
                counts[outcome] += 1
            except Exception as exc:
                counts["rejected"] += 1
                safe = str(exc).split(":", 1)[0]
                safe = safe if safe.isupper() and safe.replace("_", "").isalnum() else type(exc).__name__
                print(f"Rejected line {line_number}: {safe}", flush=True)
    return counts


def release_batch(factory, batch_id: str) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    released = completed = 0
    with factory() as db:
        _begin_immediate_if_sqlite(db)
        batch = db.scalar(select(CloudBatch).where(CloudBatch.batch_id == batch_id).with_for_update())
        if batch is None:
            raise ValueError("BATCH_NOT_FOUND")
        reservations = db.scalars(select(CloudBatchReservation).where(
            CloudBatchReservation.batch_id == batch_id,
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        ).with_for_update()).all()
        for reservation in reservations:
            existing = _matching_completed(db, reservation.rule_id, batch.target_model)
            if existing is not None:
                reservation.status = CloudReservationStatus.IMPORTED
                reservation.classification_id = existing.id
                reservation.imported_at = reservation.imported_at or now
                completed += 1
            else:
                reservation.status = CloudReservationStatus.RELEASED
                reservation.released_at = now
                released += 1
        db.flush()
        imported_total = db.scalar(select(func.count()).select_from(CloudBatchReservation).where(
            CloudBatchReservation.batch_id == batch_id,
            CloudBatchReservation.status == CloudReservationStatus.IMPORTED,
        )) or 0
        batch.imported_count = imported_total
        if imported_total == batch.rule_count:
            batch.status = CloudBatchStatus.COMPLETED
            batch.completed_at = batch.completed_at or now
        else:
            batch.status = CloudBatchStatus.RELEASED
            batch.released_at = now
        db.commit()
    return {"released": released, "completed": completed, "imported_total": imported_total}


def cloud_status(factory, active: dict[int, tuple[int, int]], model: str) -> dict[str, Any]:
    active_ids = set(active)
    now = datetime.now(timezone.utc)
    with factory() as db:
        completed_ids = set(db.scalars(completed_query(model))) & active_ids
        raw_reserved_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        ))) & active_ids
        reserved_ids = raw_reserved_ids - completed_ids
        raw_local_claimed = set(db.scalars(select(LocalClassificationClaim.rule_id).where(
            LocalClassificationClaim.target_provider == TARGET_PROVIDER,
            LocalClassificationClaim.target_model == model,
            LocalClassificationClaim.classifier_version == VERSION,
            LocalClassificationClaim.expires_at > now,
        ))) & active_ids
        local_claimed = raw_local_claimed - completed_ids - reserved_ids
        batches = []
        for batch in db.scalars(select(CloudBatch).where(CloudBatch.status.in_((
            CloudBatchStatus.PREPARING,
            CloudBatchStatus.ACTIVE,
            CloudBatchStatus.PARTIALLY_IMPORTED,
        ))).order_by(CloudBatch.created_at)):
            counts = dict(db.execute(select(
                CloudBatchReservation.status, func.count()
            ).where(CloudBatchReservation.batch_id == batch.batch_id).group_by(
                CloudBatchReservation.status
            )).all())
            batches.append({
                "batch_id": batch.batch_id,
                "worker": batch.worker,
                "status": batch.status.value,
                "reserved": counts.get(CloudReservationStatus.RESERVED, 0),
                "imported": counts.get(CloudReservationStatus.IMPORTED, 0),
                "released": counts.get(CloudReservationStatus.RELEASED, 0),
                "total": batch.rule_count,
            })
    available = active_ids - completed_ids - reserved_ids - local_claimed
    return {
        "total": len(active_ids),
        "completed": len(completed_ids),
        "cloud_reserved": len(reserved_ids),
        "local_claimed": len(local_claimed),
        "available_local": len(available),
        "active_batches": batches,
    }


def print_cloud_status(values: dict[str, Any]) -> None:
    print(f"Total active ET rules: {values['total']}")
    print(f"Completed target:      {values['completed']}")
    print(f"Cloud reserved:        {values['cloud_reserved']}")
    print(f"Local in flight:       {values['local_claimed']}")
    print(f"Available for local:   {values['available_local']}")
    if values["active_batches"]:
        print("\nActive batches:")
        for batch in values["active_batches"]:
            print(
                f"{batch['batch_id']} ({batch['status']})\n"
                f"  Reserved: {batch['reserved']}  Imported: {batch['imported']}  "
                f"Remaining: {batch['reserved']}  Total: {batch['total']}"
            )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="Atomically reserve and export a portable cloud batch.")
    export.add_argument("--limit", type=int, default=2000)
    export.add_argument("--worker", default="kaggle")
    export.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    import_command = commands.add_parser("import", help="Validate and idempotently import results JSONL.")
    import_command.add_argument("results", type=Path)
    commands.add_parser("status", help="Show DB-backed progress without model inference.")
    release = commands.add_parser("release", help="Release unfinished reservations in an abandoned batch.")
    release.add_argument("batch_id")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        ensure_schema_extensions()
        settings = configured_settings()
        if args.command == "export":
            active = active_rules(SessionLocal)
            result = export_batch(
                SessionLocal,
                active,
                settings,
                limit=args.limit,
                worker=args.worker,
                output_root=args.output_root,
            )
            print(f"Cloud batch: {result['batch_id']}")
            print(f"Reserved: {result['reserved']}")
            print(f"Remaining unreserved: {result['remaining_unreserved']}")
            print(f"Export: {result['input_path']}")
            print(f"Bundle: {result['bundle_path']}")
            return 0
        if args.command == "import":
            counts = import_results(SessionLocal, args.results, settings)
            print(f"Imported: {counts['imported']}")
            print(f"Already present: {counts['already_present']}")
            print(f"Rejected: {counts['rejected']}")
            return int(counts["rejected"] > 0)
        if args.command == "release":
            counts = release_batch(SessionLocal, args.batch_id)
            print(f"Released unfinished: {counts['released']}")
            print(f"Already completed: {counts['completed']}")
            print(f"Imported total retained: {counts['imported_total']}")
            return 0
        active = active_rules(SessionLocal)
        print_cloud_status(cloud_status(SessionLocal, active, settings.ollama_model))
        return 0
    except (ValueError, RuntimeError) as exc:
        safe = str(exc).split(":", 1)[0]
        print(safe if safe.isupper() and safe.replace("_", "").isalnum() else type(exc).__name__, flush=True)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Existing reservations and imported results remain durable.", flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
