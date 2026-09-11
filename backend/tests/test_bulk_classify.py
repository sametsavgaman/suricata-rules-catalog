import asyncio
import json
import sqlite3
from argparse import Namespace

import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker

from app.agent.schemas import ClassificationOutput
from app.config import Settings
from app.database.models import Classification, ClassificationStatus, Rule
from app.database.repository import RuleRepository
from app.database.session import Base
from app.evaluation import bulk_classify as bulk
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser


class OllamaClassificationProvider:
    model_name = "test-model"

    def __init__(self):
        self.calls = 0

    async def classify(self, context):
        self.calls += 1
        return ClassificationOutput(
            detected_behavior="Listed IP traffic", detected_entity=None, entity_type=None,
            category="Network Abuse", subcategory="Suspicious IP Activity", mitre_tactic=None,
            mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None,
            confidence=.6, evidence=["IP selector"], explanation="Listed IP traffic.",
        )


@pytest.fixture
def setup(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": .01})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    sessions = []

    def new_session():
        db = factory()
        sessions.append(db)
        return db

    with factory() as db:
        for sid in range(1001, 1006):
            RuleRepository(db).upsert(SuricataRuleParser().parse(
                f'alert ip 1.2.3.4 any -> any any (msg:"Listed IP"; sid:{sid}; rev:1;)'
            ), "test.rules")
        db.commit()
    provider = OllamaClassificationProvider()
    settings = Settings(_env_file=None, ai_provider="ollama", ollama_model="test-model", classifier_version="v1")
    mitre_path = tmp_path / "mitre.json"
    mitre_path.write_text("[]", encoding="utf-8")
    repo = MitreRepository(mitre_path)
    monkeypatch.setattr(bulk, "SessionLocal", new_session)
    monkeypatch.setattr(bulk, "engine", engine)
    monkeypatch.setattr(bulk, "ensure_schema_extensions", lambda: None)
    monkeypatch.setattr(bulk, "get_settings", lambda: settings)
    monkeypatch.setattr(bulk, "create_classification_provider", lambda _: provider)
    monkeypatch.setattr(bulk, "MitreRepository", lambda: repo)
    args = Namespace(provider="ollama", classifier_version="v1", state=tmp_path / "state.json",
                     retry_failed=True, chunk_size=5, max_rules=5, sid=[], db_retries=2,
                     max_consecutive_failures=3, once=False)
    yield path, factory, sessions, provider, settings, repo, args
    engine.dispose()


def test_real_sqlite_lock_retries_in_fresh_session_without_poisoning_following_rule(setup, monkeypatch):
    path, factory, sessions, provider, settings, repo, args = setup
    lock = sqlite3.connect(path)
    lock.execute("BEGIN IMMEDIATE")

    async def release_lock(_):
        lock.rollback()

    monkeypatch.setattr(bulk.asyncio, "sleep", release_lock)
    try:
        first = asyncio.run(bulk._classify_one(1, provider, settings, repo, 2))
        second = asyncio.run(bulk._classify_one(2, provider, settings, repo, 2))
    finally:
        lock.close()
    assert first["db_retries"] == 1
    assert first["status"] != "FAILED" and second["status"] != "FAILED"
    assert len(sessions) == 3 and len({id(s) for s in sessions}) == 3
    assert provider.calls == 2
    cached = asyncio.run(bulk._classify_one(1, provider, settings, repo))
    assert cached["cache_hit"] is True and provider.calls == 2
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Classification)) == 2


def test_exhausted_lock_does_not_break_next_rule(setup):
    path, factory, sessions, provider, settings, repo, args = setup
    lock = sqlite3.connect(path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        failed = asyncio.run(bulk._classify_one(1, provider, settings, repo, 0))
    finally:
        lock.rollback()
        lock.close()
    assert failed["database_error"] and failed["status"] == "FAILED"
    assert failed["reason"] == "DATABASE_OperationalError_SQLITE_5"
    assert "INSERT" not in failed["reason"]
    assert asyncio.run(bulk._classify_one(2, provider, settings, repo))["status"] != "FAILED"


def test_retry_failed_flag_and_scope_always_preserve_successful_results(setup):
    _, factory, _, provider, settings, _, args = setup
    with factory() as db:
        for rid, status in [(1, ClassificationStatus.AUTO_CLASSIFIED), (2, ClassificationStatus.FAILED)]:
            db.add(Classification(rule_id=rid, provider="ollama", model_name=provider.model_name,
                                  classifier_version="v1", classification_status=status))
        db.add(Classification(rule_id=3, provider="gemini", model_name="other", classifier_version="v1"))
        db.commit()
    args.retry_failed = False
    assert [r.id for r in bulk._select_rules(settings, provider.model_name, args, 0)] == [3, 4, 5]
    args.retry_failed = True
    assert [r.id for r in bulk._select_rules(settings, provider.model_name, args, 0)] == [2, 3, 4, 5]


def test_failure_circuit_stops_before_marking_unattempted_rules_failed(setup, monkeypatch):
    *_, args = setup
    calls = []

    async def fail(rule_id, *a):
        calls.append(rule_id)
        return {"status": "FAILED", "reason": "DATABASE_OperationalError_SQLITE_5", "database_error": True}

    monkeypatch.setattr(bulk, "_classify_one", fail)
    assert asyncio.run(bulk.run(args)) == 1
    state = json.loads(args.state.read_text())
    assert calls == [1, 2, 3]
    assert state["failed"] == 3 and state["processed"] == 3
    assert state["chunks"][0]["unattempted"] == 2
    assert state["status"] == "PAUSED_ON_FAILURE"


def test_rule_is_not_retried_again_in_same_run_and_resume_skips_committed_successes(setup, monkeypatch):
    _, factory, _, provider, _, _, args = setup
    args.chunk_size = 1
    original = bulk._classify_one
    calls = []

    async def first_fails(rule_id, *a):
        calls.append(rule_id)
        if rule_id == 1:
            return {"status": "FAILED", "reason": "TEST_FAILURE"}
        return await original(rule_id, *a)

    monkeypatch.setattr(bulk, "_classify_one", first_fails)
    assert asyncio.run(bulk.run(args)) == 0
    assert calls == [1, 2, 3, 4, 5]
    monkeypatch.setattr(bulk, "_classify_one", original)
    assert asyncio.run(bulk.run(args)) == 0
    assert provider.calls == 5
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Classification)) == 5
    state = json.loads(args.state.read_text())
    assert state["last_invocation"]["processed"] == 1
