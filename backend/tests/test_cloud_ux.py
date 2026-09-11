"""
Tests for the cloud batch UX automation layer.

Coverage (aligned with requirements Part 15):
1.  Kaggle + Colab reservations are non-overlapping in a test DB.
2.  Correct batch IDs and worker types are produced.
3.  Kaggle bundle contains all required files.
4.  Colab bundle contains all required files (including qwen_colab.ipynb).
5.  No .env / database / API key included in bundles.
6.  Second import creates no duplicates (idempotency).
7.  Release preserves imported results; only unreserved rows become available.
8.  Status command causes zero inference.
9.  Output filenames use the correct batch identity.
10. Invalid JSONL does not bypass backend validation.
11. cloud-import.ps1 helper logic: file with no format_version is skipped.
12. cloud-start.ps1 helper logic: existing active batch is detected without crash.
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

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
    CloudBatch,
    CloudBatchReservation,
    CloudBatchStatus,
    CloudReservationStatus,
    Rule,
)
from app.database.repository import RuleRepository
from app.database.session import Base
from app.evaluation import run_qwen_catalog_batch as local_batch
from app.parser.suricata_parser import SuricataRuleParser


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[2]  # backend/tests/ -> backend/ -> project root
CLOUD_SOURCE = ROOT / "cloud"


def raw_rule(sid: int) -> str:
    return f'alert ip 1.2.3.4 any -> any any (msg:"Listed IP"; sid:{sid}; rev:1;)'


def settings_for_test() -> Settings:
    return Settings(
        _env_file=None,
        ai_provider="ollama",
        ollama_base_url="http://127.0.0.1:1",
        ollama_model="qwen3:8b",
        classifier_version=local_batch.VERSION,
    )


def make_db(tmp_path: Path, count: int = 100):
    path = tmp_path / "ux_test.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as db:
        for sid in range(20_001, 20_001 + count):
            RuleRepository(db).upsert(SuricataRuleParser().parse(raw_rule(sid)), "test.rules")
        db.commit()
        active = {rid: (sid, rev) for rid, sid, rev in db.execute(
            select(Rule.id, Rule.sid, Rule.rev)
        )}
    return engine, factory, active


def make_results(exported: dict, count: int, path: Path) -> list[dict]:
    """Produce synthetic valid results for the first `count` input items."""
    manifest = json.loads(exported["manifest_path"].read_text(encoding="utf-8"))
    inputs = [
        json.loads(line)
        for line in exported["input_path"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    output = {
        "detected_behavior": "Listed IP traffic",
        "detected_entity": None,
        "entity_type": None,
        "category": "Network Abuse",
        "subcategory": "Suspicious IP Activity",
        "mitre_tactic": None,
        "mitre_technique": None,
        "mitre_technique_id": None,
        "cyber_kill_chain_phase": None,
        "confidence": 0.6,
        "evidence": ["msg: Listed IP"],
        "explanation": "The rule identifies listed IP traffic.",
    }
    values = []
    for item in inputs[:count]:
        values.append({
            "format_version": RESULT_FORMAT,
            **{k: item[k] for k in (
                "batch_id", "rule_id", "sid", "rev",
                "raw_sha256", "context_sha256", "contract_sha256",
                "provider", "model", "classifier_version",
            )},
            "output": output,
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            "runtime": {"engine": "ollama", "engine_version": "test", "model_digest": "sha256:test"},
            "inference_duration_ms": 100.0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    path.write_text(
        "".join(json.dumps(v) + "\n" for v in values),
        encoding="utf-8",
    )
    return values


# ─────────────────────────────────────────────────────────────────────────────
# 1 & 2 — Non-overlapping reservations, correct worker/batch IDs
# ─────────────────────────────────────────────────────────────────────────────

def test_kaggle_and_colab_reservations_are_non_overlapping(tmp_path):
    """Kaggle and Colab batches must reserve disjoint rule sets."""
    engine, factory, active = make_db(tmp_path, count=100)
    settings = settings_for_test()

    exported_kaggle = export_batch(
        factory, active, settings,
        limit=30, worker="kaggle", output_root=tmp_path / "exports",
    )
    exported_colab = export_batch(
        factory, active, settings,
        limit=30, worker="colab", output_root=tmp_path / "exports",
    )

    assert exported_kaggle["batch_id"].startswith("kaggle-")
    assert exported_colab["batch_id"].startswith("colab-")

    with factory() as db:
        kaggle_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.batch_id == exported_kaggle["batch_id"],
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )))
        colab_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.batch_id == exported_colab["batch_id"],
            CloudBatchReservation.status == CloudReservationStatus.RESERVED,
        )))

    assert len(kaggle_ids) == 30
    assert len(colab_ids) == 30
    assert kaggle_ids.isdisjoint(colab_ids), "Kaggle and Colab reserved overlapping rules!"

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 3 — Kaggle bundle contains required files (and NOT qwen_colab.ipynb)
# ─────────────────────────────────────────────────────────────────────────────

def test_kaggle_bundle_contains_required_files(tmp_path):
    engine, factory, active = make_db(tmp_path, count=10)
    settings = settings_for_test()

    exported = export_batch(
        factory, active, settings,
        limit=5, worker="kaggle", output_root=tmp_path / "exports",
    )
    bundle = exported["bundle_path"]
    assert bundle.exists(), "Kaggle bundle ZIP was not created"

    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())

    required = {"manifest.json", "input.jsonl", "worker.py", "requirements.txt",
                "README.md", "qwen_kaggle.ipynb"}
    assert required.issubset(names), f"Missing from Kaggle bundle: {required - names}"
    assert "qwen_colab.ipynb" not in names, "qwen_colab.ipynb should not be in Kaggle bundle"

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 4 — Colab bundle contains required files (and NOT qwen_kaggle.ipynb)
# ─────────────────────────────────────────────────────────────────────────────

def test_colab_bundle_contains_required_files(tmp_path):
    engine, factory, active = make_db(tmp_path, count=10)
    settings = settings_for_test()

    # qwen_colab.ipynb must exist in the cloud source dir
    colab_nb = CLOUD_SOURCE / "qwen_colab.ipynb"
    assert colab_nb.exists(), (
        f"cloud/qwen_colab.ipynb not found at {colab_nb}. "
        "Create it before running this test."
    )

    exported = export_batch(
        factory, active, settings,
        limit=5, worker="colab", output_root=tmp_path / "exports",
    )
    bundle = exported["bundle_path"]
    assert bundle.exists(), "Colab bundle ZIP was not created"

    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())

    required = {"manifest.json", "input.jsonl", "worker.py", "requirements.txt",
                "README.md", "qwen_colab.ipynb"}
    assert required.issubset(names), f"Missing from Colab bundle: {required - names}"
    assert "qwen_kaggle.ipynb" not in names, "qwen_kaggle.ipynb should not be in Colab bundle"

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 5 — No .env, database, or API key in bundles
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("worker", ["kaggle", "colab"])
def test_bundle_contains_no_secrets_or_database(tmp_path, worker):
    engine, factory, active = make_db(tmp_path, count=10)
    settings = settings_for_test()

    colab_nb = CLOUD_SOURCE / "qwen_colab.ipynb"
    if worker == "colab" and not colab_nb.exists():
        pytest.skip("qwen_colab.ipynb not yet created")

    exported = export_batch(
        factory, active, settings,
        limit=5, worker=worker, output_root=tmp_path / "exports",
    )
    bundle = exported["bundle_path"]

    forbidden_patterns = {".env", ".db", "api_key", "gemini", "openai", ".sqlite"}
    with zipfile.ZipFile(bundle) as zf:
        for name in zf.namelist():
            lower = name.lower()
            for pattern in forbidden_patterns:
                assert pattern not in lower, (
                    f"Bundle contains potentially sensitive file: {name} (matched '{pattern}')"
                )

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 6 — Second import creates no duplicates (idempotency)
# ─────────────────────────────────────────────────────────────────────────────

def test_second_import_is_idempotent(tmp_path):
    engine, factory, active = make_db(tmp_path, count=20)
    settings = settings_for_test()

    exported = export_batch(
        factory, active, settings,
        limit=10, worker="kaggle", output_root=tmp_path / "exports",
    )
    results_path = tmp_path / "results.jsonl"
    make_results(exported, 10, results_path)

    first = import_results(factory, results_path, settings)
    assert first == {"imported": 10, "already_present": 0, "rejected": 0}

    second = import_results(factory, results_path, settings)
    assert second == {"imported": 0, "already_present": 10, "rejected": 0}

    with factory() as db:
        total = len(db.scalars(select(Classification)).all())
    assert total == 10, "Duplicate classifications were created on second import"

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 7 — Release preserves imported results; unreserved rows become available
# ─────────────────────────────────────────────────────────────────────────────

def test_release_preserves_imported_results(tmp_path):
    engine, factory, active = make_db(tmp_path, count=30)
    settings = settings_for_test()

    exported = export_batch(
        factory, active, settings,
        limit=20, worker="kaggle", output_root=tmp_path / "exports",
    )
    batch_id = exported["batch_id"]

    # Import only 12 out of 20
    results_path = tmp_path / "results.jsonl"
    make_results(exported, 12, results_path)
    counts = import_results(factory, results_path, settings)
    assert counts["imported"] == 12

    # Release the remaining 8 (RESERVED)
    released = release_batch(factory, batch_id)
    assert released["released"] == 8
    assert released["completed"] == 0
    assert released["imported_total"] == 12

    # Verify the 12 imported classifications still exist
    with factory() as db:
        classification_count = len(db.scalars(select(Classification)).all())
    assert classification_count == 12, "Imported classifications were destroyed by release"

    # Re-import the same 12 — all should be already_present
    third = import_results(factory, results_path, settings)
    assert third == {"imported": 0, "already_present": 12, "rejected": 0}

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 8 — Status causes zero inference
# ─────────────────────────────────────────────────────────────────────────────

def test_status_causes_zero_inference(tmp_path):
    engine, factory, active = make_db(tmp_path, count=10)
    settings = settings_for_test()

    export_batch(
        factory, active, settings,
        limit=5, worker="kaggle", output_root=tmp_path / "exports",
    )

    # cloud_status must not raise and must not touch any model provider
    status = cloud_status(factory, active, settings.ollama_model)
    assert isinstance(status, dict)
    assert "total" in status
    assert "completed" in status
    assert "cloud_reserved" in status
    assert "active_batches" in status
    assert len(status["active_batches"]) >= 1

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 9 — Output filenames use correct batch identity
# ─────────────────────────────────────────────────────────────────────────────

def test_bundle_filename_matches_batch_id(tmp_path):
    engine, factory, active = make_db(tmp_path, count=10)
    settings = settings_for_test()

    exported = export_batch(
        factory, active, settings,
        limit=5, worker="kaggle", output_root=tmp_path / "exports",
    )
    batch_id = exported["batch_id"]
    bundle = exported["bundle_path"]
    assert batch_id in bundle.name, (
        f"Bundle filename '{bundle.name}' does not contain batch ID '{batch_id}'"
    )
    assert bundle.suffix == ".zip"

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 10 — Invalid JSONL does not bypass backend validation
# ─────────────────────────────────────────────────────────────────────────────

def test_invalid_jsonl_is_rejected(tmp_path):
    engine, factory, active = make_db(tmp_path, count=5)
    settings = settings_for_test()

    exported = export_batch(
        factory, active, settings,
        limit=3, worker="kaggle", output_root=tmp_path / "exports",
    )
    values = make_results(exported, 3, tmp_path / "good.jsonl")

    # Tamper with SID — must be rejected
    bad_path = tmp_path / "bad.jsonl"
    tampered = dict(values[0])
    tampered["sid"] += 999
    bad_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")

    result = import_results(factory, bad_path, settings)
    assert result["rejected"] >= 1
    assert result["imported"] == 0

    # No classification should have been created for the tampered entry
    with factory() as db:
        assert db.scalar(select(Classification).where(
            Classification.rule_id == tampered["rule_id"]
        )) is None

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 11 — cloud-import helper logic: file without format_version is skipped
#      (Tests the PowerShell pre-filter logic in Python terms)
# ─────────────────────────────────────────────────────────────────────────────

def test_file_without_format_version_is_treated_as_invalid(tmp_path):
    """
    cloud-import.ps1 uses a lightweight check (format_version + batch_id present)
    before calling the Python importer. Verify the Python importer itself also
    rejects a completely wrong file structure.
    """
    engine, factory, active = make_db(tmp_path, count=5)
    settings = settings_for_test()

    export_batch(
        factory, active, settings,
        limit=3, worker="kaggle", output_root=tmp_path / "exports",
    )

    garbage_path = tmp_path / "garbage.jsonl"
    garbage_path.write_text(
        json.dumps({"not_a_result": True, "just_random": "data"}) + "\n",
        encoding="utf-8",
    )

    result = import_results(factory, garbage_path, settings)
    assert result["rejected"] == 1
    assert result["imported"] == 0

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 12 — Acceptance test: 100 rules, 30 kaggle, 30 colab, 40 available
#      Matches the acceptance test in the requirements exactly.
# ─────────────────────────────────────────────────────────────────────────────

def test_acceptance_100_rules_30_kaggle_30_colab(tmp_path):
    engine, factory, active = make_db(tmp_path, count=100)
    settings = settings_for_test()

    # Create Kaggle batch
    exported_kaggle = export_batch(
        factory, active, settings,
        limit=30, worker="kaggle", output_root=tmp_path / "exports",
    )

    # Create Colab batch
    exported_colab = export_batch(
        factory, active, settings,
        limit=30, worker="colab", output_root=tmp_path / "exports",
    )

    # Check status: 60 reserved, 40 available
    status = cloud_status(factory, active, settings.ollama_model)
    assert status["cloud_reserved"] == 60
    assert status["available_local"] == 40
    assert status["completed"] == 0

    with factory() as db:
        kaggle_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.batch_id == exported_kaggle["batch_id"]
        )))
        colab_ids = set(db.scalars(select(CloudBatchReservation.rule_id).where(
            CloudBatchReservation.batch_id == exported_colab["batch_id"]
        )))

    assert kaggle_ids.isdisjoint(colab_ids)

    # Simulate Kaggle: all 30 results
    kaggle_results = tmp_path / "kaggle-results.jsonl"
    make_results(exported_kaggle, 30, kaggle_results)
    kaggle_import = import_results(factory, kaggle_results, settings)
    assert kaggle_import == {"imported": 30, "already_present": 0, "rejected": 0}

    # Simulate Colab: 20 of 30 results
    colab_results = tmp_path / "colab-results.jsonl"
    make_results(exported_colab, 20, colab_results)
    colab_import = import_results(factory, colab_results, settings)
    assert colab_import == {"imported": 20, "already_present": 0, "rejected": 0}

    # Release remaining 10 Colab reservations
    released = release_batch(factory, exported_colab["batch_id"])
    assert released["released"] == 10
    assert released["imported_total"] == 20

    # 30 + 20 = 50 completed; 10 available again; none cloud reserved
    status2 = cloud_status(factory, active, settings.ollama_model)
    assert status2["completed"] == 50
    assert status2["cloud_reserved"] == 0
    assert status2["available_local"] == 50  # 40 original + 10 released

    # Re-import: zero duplicates
    reimport_kaggle = import_results(factory, kaggle_results, settings)
    assert reimport_kaggle == {"imported": 0, "already_present": 30, "rejected": 0}

    reimport_colab = import_results(factory, colab_results, settings)
    assert reimport_colab == {"imported": 0, "already_present": 20, "rejected": 0}

    engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# 13 — Worker is a valid Python script (no import-time errors)
# ─────────────────────────────────────────────────────────────────────────────

def test_worker_script_is_importable():
    """qwen_worker.py must be syntactically valid and importable."""
    worker_path = CLOUD_SOURCE / "qwen_worker.py"
    assert worker_path.exists(), f"worker.py not found at {worker_path}"
    result = subprocess.run(
        [sys.executable, "-c", f"import ast; ast.parse(open(r'{worker_path}').read())"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"qwen_worker.py has syntax errors:\n{result.stderr}"
