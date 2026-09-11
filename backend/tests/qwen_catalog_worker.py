"""Disk-SQLite subprocess fixture; never contacts Ollama or the production DB."""
import asyncio
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.agent.schemas import ClassificationOutput
from app.config import Settings
from app.database.models import Classification
from app.evaluation import run_qwen_catalog_batch as batch
from app.knowledge.mitre_repository import MitreRepository


class OllamaClassificationProvider:
    model_name = "qwen3:8b"
    inference_mode = "LOCAL"

    def __init__(self, factory, terminate_at=0, cancel_at=0, fail_sid=None):
        self.factory = factory
        self.terminate_at = terminate_at
        self.cancel_at = cancel_at
        self.fail_sid = fail_sid
        self.calls = []
        self.durable_before_call = []

    async def classify(self, context):
        self.calls.append(context.sid)
        # Independent connection proves the preceding result is already committed.
        with self.factory() as db:
            self.durable_before_call.append(db.scalar(select(func.count()).select_from(Classification)))
        print(f"MODEL_CALL {context.sid}", flush=True)
        if len(self.calls) == self.terminate_at:
            os._exit(130)  # simulate process loss; no Python finally/rollback runs
        if len(self.calls) == self.cancel_at:
            raise asyncio.CancelledError
        if context.sid == self.fail_sid:
            raise RuntimeError("FAKE_PROVIDER_FAILURE")
        return ClassificationOutput(
            detected_behavior="Listed IP traffic", detected_entity=None, entity_type=None,
            category="Network Abuse", subcategory="Suspicious IP Activity", mitre_tactic=None,
            mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None,
            confidence=.6, evidence=["IP selector"], explanation="Listed IP traffic.",
        )


def settings():
    return Settings(_env_file=None, ai_provider="ollama", ollama_model="qwen3:8b",
                    classifier_version=batch.VERSION)


if __name__ == "__main__":
    path, terminate_at = Path(sys.argv[1]), int(sys.argv[2])
    engine = create_engine(f"sqlite:///{path}")
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as db:
        from app.database.models import Rule
        active = {rid: (sid, rev) for rid, sid, rev in db.execute(select(Rule.id, Rule.sid, Rule.rev))}
    # The second process must acquire the same lock left behind by the killed first one.
    with batch.batch_lock(path.with_suffix(".lock")):
        provider = OllamaClassificationProvider(factory, terminate_at=terminate_at)
        result = asyncio.run(batch.run_batch(factory, active, provider, settings(), MitreRepository(), 100,
                                             readiness_check=lambda: None))
    engine.dispose()
    raise SystemExit(result)
