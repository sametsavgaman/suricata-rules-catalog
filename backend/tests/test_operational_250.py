import json
from pathlib import Path

from app.evaluation.golden_dataset import reviewed_records
from app.evaluation.run_operational_250 import ROOT, choose_sample
from app.evaluation.schemas import GoldenRecord


def test_operational_sample_shape_and_no_overlap():
    audited, fresh = choose_sample(reviewed_records(ROOT / "data/evaluation/golden_dataset.jsonl"))
    assert len(audited) == 97
    assert len(fresh) == 153
    assert not ({(r.sid, r.rev) for r in audited} & {(r.sid, r.rev) for r in fresh})
    prior = {(r.sid, r.rev) for r in __import__('app.evaluation.golden_dataset', fromlist=['read_jsonl']).read_jsonl(ROOT / "data/evaluation/sample.jsonl", GoldenRecord)}
    assert not ({(r.sid, r.rev) for r in fresh} & prior)


def test_operational_artifacts_are_complete_and_fresh_has_no_accuracy_claim():
    out = ROOT / "data/evaluation/operational-250"
    assert sum(1 for line in (out / "sample-250.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()) == 250
    assert sum(1 for line in (out / "results-250.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()) == 250
    report = json.loads((out / "operational-250-report.json").read_text(encoding="utf-8"))
    assert report["cohorts"] == {"audited": 97, "fresh": 153}
    assert "accuracy" not in report["fresh_summary"]
    assert (out / "inspection-manifest.json").exists()
