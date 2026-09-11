import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.cloud_batch import (
    RESULT_FORMAT,
    cloud_status,
    export_batch,
    import_results,
    release_batch,
    reserve_rules,
)
from app.config import Settings
from app.database.models import (
    Classification,
    ClassificationRun,
    ClassificationStatus,
    CloudBatchReservation,
    CloudReservationStatus,
    Rule,
)
from app.database.repository import RuleRepository
from app.database.session import Base
from app.evaluation import run_qwen_catalog_batch as local_batch
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService, CloudReservationConflict


def raw_rule(sid):
    return f'alert ip 1.2.3.4 any -> any any (msg:"Listed IP"; sid:{sid}; rev:1;)'


def settings_for_test():
    return Settings(
        _env_file=None,
        ai_provider="ollama",
        ollama_base_url="http://127.0.0.1:1",
        ollama_model="qwen3:8b",
        classifier_version=local_batch.VERSION,
    )


def make_db(tmp_path, count=100):
    path = tmp_path / "cloud.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as db:
        for sid in range(10_001, 10_001 + count):
            RuleRepository(db).upsert(SuricataRuleParser().parse(raw_rule(sid)), "test.rules")
        db.commit()
        active = {rid: (sid, rev) for rid, sid, rev in db.execute(select(Rule.id, Rule.sid, Rule.rev))}
    return engine, factory, active


def add_completed(factory, rule_id):
    now = datetime.now(timezone.utc)
    with factory() as db:
        run = ClassificationRun(
            run_id=f"historical-{rule_id}", provider="ollama", model_name="qwen3:8b",
            model_display_name="Qwen3 8B", classifier_version=local_batch.VERSION,
            inference_mode="LOCAL", rule_id=rule_id, total_rules=1, successful_rules=1,
            failed_rules=0, completed_at=now,
        )
        db.add(run)
        db.flush()
        db.add(Classification(
            rule_id=rule_id, provider="ollama", model_name="qwen3:8b",
            classifier_version=local_batch.VERSION,
            classification_status=ClassificationStatus.AUTO_CLASSIFIED,
            confidence=.5, evidence=[], explanation="done", agent_activity={},
            classification_run_id=run.id, run_id=run.run_id,
        ))
        db.commit()


class OllamaClassificationProvider:
    model_name = "qwen3:8b"
    inference_mode = "LOCAL"

    def __init__(self):
        self.calls = []

    async def classify(self, context):
        from app.agent.schemas import ClassificationOutput

        self.calls.append(context.sid)
        return ClassificationOutput(
            detected_behavior="Listed IP traffic", detected_entity=None, entity_type=None,
            category="Network Abuse", subcategory="Suspicious IP Activity",
            mitre_tactic=None, mitre_technique=None, mitre_technique_id=None,
            cyber_kill_chain_phase=None, confidence=.6, evidence=["msg: Listed IP"],
            explanation="The rule identifies listed IP traffic.",
        )


def make_results(exported, count, path):
    manifest = json.loads(exported["manifest_path"].read_text(encoding="utf-8"))
    inputs = [json.loads(line) for line in exported["input_path"].read_text(encoding="utf-8").splitlines()]
    output = {
        "detected_behavior": "Listed IP traffic", "detected_entity": None, "entity_type": None,
        "category": "Network Abuse", "subcategory": "Suspicious IP Activity",
        "mitre_tactic": None, "mitre_technique": None, "mitre_technique_id": None,
        "cyber_kill_chain_phase": None, "confidence": .6, "evidence": ["msg: Listed IP"],
        "explanation": "The rule identifies listed IP traffic.",
    }
    values = []
    for item in inputs[:count]:
        values.append({
            "format_version": RESULT_FORMAT,
            **{key: item[key] for key in (
                "batch_id", "rule_id", "sid", "rev", "raw_sha256", "context_sha256",
                "contract_sha256", "provider", "model", "classifier_version",
            )},
            "output": output,
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            "runtime": {"engine": "ollama", "engine_version": "test", "model_digest": "sha256:test"},
            "inference_duration_ms": 100.0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    path.write_text("".join(json.dumps(value) + "\n" for value in values), encoding="utf-8")
    return values, manifest


def test_completed_rules_are_not_reserved_and_reservations_survive_restart(tmp_path):
    engine, factory, active = make_db(tmp_path, 5)
    add_completed(factory, 1)
    batch_id, selected, _ = reserve_rules(factory, active, "qwen3:8b", 5, "kaggle")
    assert selected == [2, 3, 4, 5]
    engine.dispose()

    restarted_engine = create_engine(f"sqlite:///{tmp_path / 'cloud.db'}")
    restarted = sessionmaker(bind=restarted_engine, expire_on_commit=False, autoflush=False)
    with restarted() as db:
        rows = db.scalars(select(CloudBatchReservation).where(
            CloudBatchReservation.batch_id == batch_id,
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )).all()
        assert {row.rule_id for row in rows} == {2, 3, 4, 5}
        assert [rule.id for rule in RuleRepository(db).unclassified(10)] == []
    restarted_engine.dispose()


def test_parallel_exports_never_reserve_the_same_rule(tmp_path):
    engine, factory, active = make_db(tmp_path)

    def reserve(worker):
        return set(reserve_rules(factory, active, "qwen3:8b", 60, worker)[1])

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(reserve, "kaggle")
        second_future = executor.submit(reserve, "colab")
        first, second = first_future.result(), second_future.result()
    assert first.isdisjoint(second)
    assert len(first | second) == 100
    engine.dispose()


def test_preloaded_local_candidates_skip_rules_reserved_mid_run(tmp_path):
    """Regression: cloud can reserve future in-memory candidates without overlap."""
    engine, factory, active = make_db(tmp_path)
    settings = settings_for_test()
    cloud_ids = set()

    class MidRunCloudProvider(OllamaClassificationProvider):
        provider_name = "ollama"

        async def classify(self, context):
            from app.agent.schemas import ClassificationOutput

            self.calls.append(context.sid)
            if len(self.calls) == 30:
                _, ids, _ = reserve_rules(factory, active, "qwen3:8b", 20, "kaggle")
                cloud_ids.update(ids)
            return ClassificationOutput(
                detected_behavior="Listed IP traffic", detected_entity=None, entity_type=None,
                category="Network Abuse", subcategory="Suspicious IP Activity",
                mitre_tactic=None, mitre_technique=None, mitre_technique_id=None,
                cyber_kill_chain_phase=None, confidence=.6, evidence=["msg: Listed IP"],
                explanation="The rule identifies listed IP traffic.",
            )

    provider = MidRunCloudProvider()
    assert asyncio.run(local_batch.run_batch(
        factory, active, provider, settings, MitreRepository(), 100, readiness_check=lambda: None
    )) == 0
    cloud_sids = {active[rule_id][0] for rule_id in cloud_ids}
    assert cloud_ids == set(range(31, 51))
    assert len(provider.calls) == 80
    assert not cloud_sids.intersection(provider.calls)
    with factory() as db:
        assert db.scalar(select(Classification).where(Classification.rule_id.in_(cloud_ids))) is None
        assert len(db.scalars(select(Classification)).all()) == 80
        assert db.scalar(select(CloudBatchReservation).where(
            CloudBatchReservation.rule_id.in_(cloud_ids),
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )) is not None
    engine.dispose()


def test_simultaneous_local_and_cloud_acquisition_has_one_owner(tmp_path):
    engine, factory, active = make_db(tmp_path, 1)
    from threading import Barrier

    barrier = Barrier(2)

    def local_attempt():
        barrier.wait()
        return local_batch.claim_local_rule(factory, 1, "qwen3:8b")

    def cloud_attempt():
        barrier.wait()
        try:
            return ("CLOUD", reserve_rules(factory, active, "qwen3:8b", 1, "kaggle")[1])
        except ValueError as exc:
            return ("NONE", str(exc))

    with ThreadPoolExecutor(max_workers=2) as executor:
        local_result = executor.submit(local_attempt)
        cloud_result = executor.submit(cloud_attempt)
        local_state, local_claim = local_result.result()
        cloud_state, cloud_value = cloud_result.result()
    assert (local_state == "CLAIMED" and cloud_state == "NONE") or (
        local_state == "CLOUD_RESERVED" and cloud_state == "CLOUD"
    )
    if local_claim:
        local_batch.release_local_claim(factory, local_claim)
    engine.dispose()


def test_deterministic_ownership_ordering_and_completed_exclusion(tmp_path):
    engine, factory, active = make_db(tmp_path, 3)

    local_state, claim_id = local_batch.claim_local_rule(factory, 1, "qwen3:8b")
    assert local_state == "CLAIMED"
    try:
        with pytest.raises(ValueError):
            reserve_rules(factory, {1: active[1]}, "qwen3:8b", 1, "kaggle")
    finally:
        local_batch.release_local_claim(factory, claim_id)

    _, reserved, _ = reserve_rules(factory, {2: active[2]}, "qwen3:8b", 1, "kaggle")
    assert reserved == [2]
    assert local_batch.claim_local_rule(factory, 2, "qwen3:8b") == ("CLOUD_RESERVED", None)

    add_completed(factory, 3)
    assert local_batch.claim_local_rule(factory, 3, "qwen3:8b") == ("COMPLETED", None)
    with pytest.raises(ValueError):
        reserve_rules(factory, {3: active[3]}, "qwen3:8b", 1, "kaggle")
    engine.dispose()


def test_acceptance_30_cloud_70_local_import_12_release_18(tmp_path):
    engine, factory, active = make_db(tmp_path)
    settings = settings_for_test()
    exported = export_batch(
        factory, active, settings, limit=30, worker="kaggle", output_root=tmp_path / "exports"
    )
    assert {path.name for path in exported["input_path"].parent.iterdir()} == {
        "README.md", "input.jsonl", "manifest.json", "qwen_kaggle.ipynb",
        "requirements.txt", "worker.py",
    }
    with factory() as db:
        cloud_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.batch_id == exported["batch_id"],
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )))
    assert len(cloud_ids) == 30
    local_ids = set(local_batch.select_remaining(factory, active, "qwen3:8b", 100))
    assert len(local_ids) == 70
    assert cloud_ids.isdisjoint(local_ids)

    blocked_provider = OllamaClassificationProvider()
    with factory() as db:
        blocked_rule = db.get(Rule, next(iter(cloud_ids)))
        try:
            asyncio.run(ClassificationService(
                db, blocked_provider, settings, MitreRepository()
            ).classify(blocked_rule))
            raise AssertionError("reserved local inference should have been blocked")
        except CloudReservationConflict:
            pass
    assert blocked_provider.calls == []

    provider = OllamaClassificationProvider()
    code = asyncio.run(local_batch.run_batch(
        factory, active, provider, settings, MitreRepository(), 100, readiness_check=lambda: None
    ))
    assert code == 0
    assert set(provider.calls) == {active[rule_id][0] for rule_id in local_ids}
    assert not ({active[rule_id][0] for rule_id in cloud_ids} & set(provider.calls))

    results_path = tmp_path / "results.jsonl"
    make_results(exported, 12, results_path)
    assert import_results(factory, results_path, settings) == {
        "imported": 12, "already_present": 0, "rejected": 0,
    }
    assert import_results(factory, results_path, settings) == {
        "imported": 0, "already_present": 12, "rejected": 0,
    }
    released = release_batch(factory, exported["batch_id"])
    assert released == {"released": 18, "completed": 0, "imported_total": 12}
    assert import_results(factory, results_path, settings) == {
        "imported": 0, "already_present": 12, "rejected": 0,
    }
    values = cloud_status(factory, active, "qwen3:8b")
    assert len(provider.calls) == 70  # status performs no provider/model work
    assert values["completed"] == 82
    assert values["cloud_reserved"] == 0
    assert values["available_local"] == 18
    with factory() as db:
        assert len(db.scalars(select(Classification)).all()) == 82
        states = list(db.scalars(select(CloudBatchReservation.status).where(
            CloudBatchReservation.batch_id == exported["batch_id"]
        )))
        assert states.count(CloudReservationStatus.IMPORTED) == 12
        assert states.count(CloudReservationStatus.RELEASED) == 18
    assert len(local_batch.select_remaining(factory, active, "qwen3:8b", 100)) == 18
    engine.dispose()


def test_import_rejects_wrong_identity_without_persisting(tmp_path):
    engine, factory, active = make_db(tmp_path, 2)
    settings = settings_for_test()
    exported = export_batch(
        factory, active, settings, limit=1, worker="kaggle", output_root=tmp_path / "exports"
    )
    path = tmp_path / "invalid.jsonl"
    values, _ = make_results(exported, 1, path)
    values[0]["sid"] += 1
    path.write_text(json.dumps(values[0]) + "\n", encoding="utf-8")
    assert import_results(factory, path, settings) == {
        "imported": 0, "already_present": 0, "rejected": 1,
    }
    with factory() as db:
        assert db.scalar(select(Classification).where(Classification.rule_id == values[0]["rule_id"])) is None
        reservation = db.scalar(select(CloudBatchReservation).where(
            CloudBatchReservation.batch_id == exported["batch_id"]
        ))
        assert reservation.status == CloudReservationStatus.RESERVED
    engine.dispose()
