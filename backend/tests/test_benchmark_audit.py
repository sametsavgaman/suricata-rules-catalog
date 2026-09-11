import json
from pathlib import Path
from app.evaluation.golden_dataset import read_jsonl, reviewed_records
from app.evaluation.schemas import AnnotationStatus, GoldenRecord

ROOT=Path(__file__).resolve().parents[2]

def test_audit_preserves_original_expected():
    records=read_jsonl(ROOT/"data/evaluation/golden_dataset.jsonl",GoldenRecord)
    changed=[r for r in records if r.benchmark_audit and r.benchmark_audit["original_expected"]!=r.benchmark_audit["audited_expected"]]
    assert changed
    assert all(r.benchmark_audit["secondary_audit"]=="CODEX_BENCHMARK_AUDIT" for r in records)

def test_ambiguous_records_are_disputed_and_excluded():
    records=read_jsonl(ROOT/"data/evaluation/golden_dataset.jsonl",GoldenRecord)
    ambiguous=[r for r in records if r.benchmark_audit["audit_decision"]=="AMBIGUOUS"]
    assert ambiguous and all(r.annotation.status==AnnotationStatus.DISPUTED for r in ambiguous)
    assert len(reviewed_records(ROOT/"data/evaluation/golden_dataset.jsonl"))==97

def test_audited_outputs_exist_without_overwriting_original_report():
    reports=ROOT/"data/evaluation/reports"
    assert (reports/"evaluation-report.md").exists()
    assert (reports/"evaluation-report-audited.md").exists()
    rows=json.loads((reports/"benchmark-audit.json").read_text(encoding="utf-8"))
    assert len(rows)==100 and all(set(r["final_expected"])==set(rows[0]["final_expected"]) for r in rows)
