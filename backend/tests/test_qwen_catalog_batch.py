import asyncio
import os
from pathlib import Path
import subprocess
import sys

import pytest
import httpx
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.database.models import Classification, ClassificationRun, ClassificationStatus, Rule
from app.database.repository import RuleRepository
from app.database.session import Base
from app.evaluation import run_qwen_catalog_batch as batch
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService
from qwen_catalog_worker import OllamaClassificationProvider, settings


def raw(sid, rev=1):
    return f'alert ip 1.2.3.4 any -> any any (msg:"Listed IP"; sid:{sid}; rev:{rev};)'


@pytest.fixture
def disk(tmp_path):
    path = tmp_path / "catalog.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as db:
        for sid in range(1001, 1101):
            RuleRepository(db).upsert(SuricataRuleParser().parse(raw(sid)), "test.rules")
        db.commit()
        active = {rid: (sid, rev) for rid, sid, rev in db.execute(select(Rule.id, Rule.sid, Rule.rev))}
    yield path, factory, active
    engine.dispose()


def historical(factory, rid, provider="ollama", model="qwen3:8b", version=batch.VERSION,
               status=ClassificationStatus.AUTO_CLASSIFIED, validated=True):
    with factory() as db:
        db.add(Classification(rule_id=rid, provider=provider, model_name=model, classifier_version=version,
            classification_status=status, confidence=.6, evidence=[], explanation="Historical result",
            agent_activity={"validation": {"status": "PASS"}} if validated else {}))
        db.commit()


def run(factory, active, provider, limit=100):
    return asyncio.run(batch.run_batch(factory, active, provider, settings(), MitreRepository(), limit,
                                       readiness_check=lambda: None))


def test_hard_process_loss_37_commits_restart_exactly_63_zero_duplicate_calls(disk):
    path, factory, active = disk
    helper = Path(__file__).with_name("qwen_catalog_worker.py")
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), DATABASE_URL="sqlite:///:memory:")
    first = subprocess.run([sys.executable, str(helper), str(path), "38"], env=env,
                           capture_output=True, text=True, timeout=120)
    assert first.returncode == 130, first.stdout + first.stderr
    with factory() as db:
        first_ids = set(db.scalars(batch.completed_query("qwen3:8b")))
        assert len(first_ids) == 37
        assert db.scalar(select(func.count()).select_from(ClassificationRun).where(ClassificationRun.completed_at.is_(None))) == 1
    assert batch.status(factory, active, "qwen3:8b")["failed_retryable"] == 1
    second = subprocess.run([sys.executable, str(helper), str(path), "0"], env=env,
                            capture_output=True, text=True, timeout=120)
    assert second.returncode == 0, second.stdout + second.stderr
    calls = [int(line.split()[1]) for line in second.stdout.splitlines() if line.startswith("MODEL_CALL ")]
    assert calls == list(range(1038, 1101))
    assert not ({active[rid][0] for rid in first_ids} & set(calls))
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Classification)) == 100
        assert len(set(db.scalars(batch.completed_query("qwen3:8b")))) == 100
    third = subprocess.run([sys.executable, str(helper), str(path), "0"], env=env,
                           capture_output=True, text=True, timeout=60)
    assert third.returncode == 0 and "MODEL_CALL " not in third.stdout


def test_identity_scoped_selection_partial_and_failed_are_not_completed(disk):
    _, factory, active = disk
    historical(factory, 1)
    historical(factory, 2, provider="gemini")
    historical(factory, 3, version="v2.1")
    historical(factory, 4, model="other-qwen")
    historical(factory, 5, status=ClassificationStatus.FAILED)
    historical(factory, 6, validated=False)  # empty/partial positive state must not be accepted
    historical(factory, 7, status=ClassificationStatus.REVIEW_REQUIRED)
    assert batch.select_remaining(factory, active, "qwen3:8b", 6) == [2, 3, 4, 5, 6, 8]
    progress = batch.status(factory, active, "qwen3:8b")
    assert progress == dict(total=100, completed=2, remaining=98, failed_retryable=2, completion_percentage=2.0)


def test_pre_call_database_recheck_skips_result_completed_after_selection(disk):
    _, factory, active = disk
    assert batch.select_remaining(factory, active, "qwen3:8b", 1) == [1]
    historical(factory, 1)
    p = OllamaClassificationProvider(factory)
    result = asyncio.run(batch.classify_one(factory, 1, p, settings(), MitreRepository()))
    assert result == {"ok": True, "cached": True} and p.calls == []


def test_commits_before_next_call_cancel_and_resume(disk):
    _, factory, active = disk
    p = OllamaClassificationProvider(factory, cancel_at=4)
    assert run(factory, active, p) == 130
    assert p.durable_before_call == [0, 1, 2, 3]
    assert batch.status(factory, active, "qwen3:8b")["completed"] == 3
    p2 = OllamaClassificationProvider(factory)
    assert run(factory, active, p2, 2) == 0
    assert p2.calls == [1004, 1005]


def test_failed_and_partial_positive_retry_without_overwriting_history(disk):
    _, factory, active = disk
    p = OllamaClassificationProvider(factory, fail_sid=1001)
    assert run(factory, active, p, 2) == 1
    assert batch.status(factory, active, "qwen3:8b")["failed_retryable"] == 1
    p2 = OllamaClassificationProvider(factory)
    assert run(factory, active, p2, 1) == 0
    assert p2.calls == [1001]
    historical(factory, 3, validated=False)
    assert run(factory, active, p2, 1) == 0
    assert p2.calls == [1001, 1003]
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Classification)) == 5
        assert db.scalar(select(func.count()).select_from(Classification).where(Classification.classification_status == ClassificationStatus.FAILED)) == 1


def test_force_keeps_history_and_default_gemini_cache_unchanged(disk):
    _, factory, _ = disk
    class GeminiClassificationProvider(OllamaClassificationProvider):
        model_name = "test-gemini"
    for provider in (OllamaClassificationProvider(factory), GeminiClassificationProvider(factory)):
        cfg = settings().model_copy(update={"classifier_version": batch.VERSION if provider.model_name == "qwen3:8b" else "v2.1"})
        with factory() as db:
            service = ClassificationService(db, provider, cfg, MitreRepository())
            rule = db.get(Rule, 1)
            first = asyncio.run(service.classify(rule))
            assert asyncio.run(service.classify(rule)).id == first.id
            second = asyncio.run(service.classify(rule, force=True))
            assert first.id != second.id and len(provider.calls) == 2


def test_status_zero_provider_calls_no_lock_no_data_mutation(disk, monkeypatch):
    path, factory, active = disk
    historical(factory, 1)
    before = path.read_bytes()
    monkeypatch.setattr(batch, "configured_settings", settings)
    monkeypatch.setattr(batch, "SessionLocal", factory)
    monkeypatch.setattr(batch, "active_rules", lambda _: active)
    def forbidden(*a, **kw):
        pytest.fail("status must not instantiate a provider or acquire a writer lock")
    monkeypatch.setattr(batch, "create_classification_provider", forbidden)
    monkeypatch.setattr(batch, "batch_lock", forbidden)
    monkeypatch.setattr(batch, "verify_ollama_ready", forbidden)
    assert batch.main(["--status"]) == 0
    assert path.read_bytes() == before


def test_readiness_is_zero_inference_and_requires_configured_model():
    requests = []
    def handler(request):
        requests.append((request.method, request.url.path))
        return httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})
    batch.verify_ollama_ready(settings(), httpx.MockTransport(handler))
    assert requests == [("GET", "/api/tags")]
    missing = httpx.MockTransport(lambda request: httpx.Response(200, json={"models": []}))
    with pytest.raises(RuntimeError, match="MODEL_NOT_INSTALLED"):
        batch.verify_ollama_ready(settings(), missing)
    down = httpx.MockTransport(lambda request: httpx.Response(503))
    with pytest.raises(RuntimeError, match="OLLAMA_NOT_RUNNING"):
        batch.verify_ollama_ready(settings(), down)


def test_mid_batch_server_loss_stops_before_model_call_or_failed_write(disk, capsys):
    _, factory, active = disk
    checks = 0
    def readiness():
        nonlocal checks
        checks += 1
        if checks == 2:
            raise RuntimeError("OLLAMA_NOT_RUNNING")
    provider = OllamaClassificationProvider(factory)
    code = asyncio.run(batch.run_batch(factory, active, provider, settings(), MitreRepository(), 5,
                                       readiness_check=readiness))
    assert code == 1 and provider.calls == [1001]
    with factory() as db:
        rows = db.scalars(select(Classification)).all()
        assert len(rows) == 1 and rows[0].classification_status != ClassificationStatus.FAILED
    assert "NOT ATTEMPTED (OLLAMA_NOT_RUNNING)" in capsys.readouterr().out


def test_failed_provider_reason_code_is_not_hidden_by_generic_label(disk):
    from app.agent.classifier import ProviderUnavailable
    _, factory, _ = disk
    provider = OllamaClassificationProvider(factory)
    async def disconnected(_):
        raise ProviderUnavailable("OLLAMA_CONNECTION_FAILED_OR_TIMEOUT: hidden detail")
    provider.classify = disconnected
    result = asyncio.run(batch.classify_one(factory, 1, provider, settings(), MitreRepository()))
    assert result == {"ok": False, "cached": False, "reason": "OLLAMA_CONNECTION_FAILED_OR_TIMEOUT"}


def test_limit_at_most_1000_and_no_force_flag(disk):
    _, factory, active = disk
    with factory() as db:
        for sid in range(1101, 2011):
            row, _ = RuleRepository(db).upsert(SuricataRuleParser().parse(raw(sid)), "test.rules")
            active[row.id] = (row.sid, row.rev)
        db.commit()
    assert len(batch.select_remaining(factory, active, "qwen3:8b", 1000)) == 1000
    assert batch.parse_args([]).limit == 1000
    for args in (["--limit", "1001"], ["--limit", "0"], ["--force"]):
        with pytest.raises(SystemExit):
            batch.parse_args(args)
    with pytest.raises(ValueError, match="BATCH_LIMIT"):
        run(factory, active, OllamaClassificationProvider(factory), 1001)


def test_active_membership_excludes_comments_old_revisions_and_non_et(disk, tmp_path):
    _, factory, _ = disk
    et = tmp_path / "et"
    et.mkdir()
    (et / "sample.rules").write_text(raw(1001) + "\n# " + raw(1002) + "\n", encoding="utf-8")
    assert batch.active_rules(factory, et) == {1: (1001, 1)}
    (et / "sample.rules").write_text(raw(1001, 2), encoding="utf-8")
    with pytest.raises(ValueError, match="NOT_FULLY_IMPORTED"):
        batch.active_rules(factory, et)


def test_os_lock_rejects_second_worker_and_releases(tmp_path):
    path = tmp_path / "batch.lock"
    with batch.batch_lock(path):
        with pytest.raises(RuntimeError, match="ALREADY_RUNNING"):
            with batch.batch_lock(path):
                pytest.fail("must not acquire the same worker lock")
    with batch.batch_lock(path):
        pass


def test_three_failures_stop_without_marking_unattempted(disk, monkeypatch):
    _, factory, active = disk
    p = OllamaClassificationProvider(factory)
    attempts = []
    async def failed(*args):
        attempts.append(args[1])
        return {"ok": False, "reason": "TEST_FAILURE"}
    monkeypatch.setattr(batch, "classify_one", failed)
    assert run(factory, active, p, 100) == 1
    assert attempts == [1, 2, 3]
    assert batch.status(factory, active, "qwen3:8b")["remaining"] == 100


def test_runtime_model_override_and_env_configuration_are_frozen_per_batch(disk, monkeypatch):
    from app.database.models import ApplicationSetting
    _, factory, _ = disk
    monkeypatch.setattr(batch, "get_settings", settings)
    monkeypatch.setenv("OLLAMA_MODEL", "env-model")
    assert batch.configured_settings(factory).ollama_model == "env-model"
    with factory() as db:
        db.add(ApplicationSetting(key="OLLAMA_MODEL", value="runtime-model", is_secret=False))
        db.commit()
    configured = batch.configured_settings(factory)
    assert configured.ollama_model == "runtime-model"
    assert configured.ai_provider == "ollama" and configured.classifier_version == batch.VERSION


def test_sqlite_lock_rolls_back_current_session_and_next_attempt_recovers(disk, monkeypatch):
    import sqlite3
    path, _, active = disk
    quick_engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": .01})
    factory = sessionmaker(bind=quick_engine, expire_on_commit=False, autoflush=False)
    lock = sqlite3.connect(path)
    lock.execute("BEGIN IMMEDIATE")
    async def release(_):
        lock.rollback()
    monkeypatch.setattr(batch.asyncio, "sleep", release)
    p = OllamaClassificationProvider(factory)
    try:
        assert run(factory, active, p, 2) == 0
    finally:
        lock.close()
        quick_engine.dispose()
    assert p.calls == [1001, 1002]


def test_incomplete_linked_classification_is_not_checkpoint(disk):
    _, factory, active = disk
    historical(factory, 1)
    with factory() as db:
        unfinished = ClassificationRun(run_id="interrupted", provider="ollama", model_name="qwen3:8b",
            model_display_name="Qwen", classifier_version=batch.VERSION, inference_mode="LOCAL",
            rule_id=1, successful_rules=0, completed_at=None)
        db.add(unfinished)
        db.flush()
        row = db.scalar(select(Classification).where(Classification.rule_id == 1))
        row.classification_run_id = unfinished.id
        db.commit()
    assert batch.status(factory, active, "qwen3:8b")["completed"] == 0
    p = OllamaClassificationProvider(factory)
    assert run(factory, active, p, 1) == 0
    assert p.calls == [1001]
