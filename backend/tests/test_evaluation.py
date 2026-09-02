import asyncio
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.agent.classifier import OpenAIClassificationProvider, ProviderUnavailable
from app.evaluation.cost_analysis import calculate_costs
from app.evaluation.batch import run_batch
from app.evaluation.golden_dataset import reviewed_records, write_jsonl
from app.evaluation.metrics import calculate_metrics, compare_fields, confidence_bucket, normalize_text
from app.evaluation.schemas import (
    Annotation, AnnotationStatus, EvaluationResult, ExpectedClassification,
    GoldenRecord, TokenUsage,
    RuleSample,
)
from app.evaluation.stability import stability_score
from app.evaluation.sampler import stratified_sample
from app.database.models import ClassificationStatus
from app.database.session import Base


def golden(sid: int, status: AnnotationStatus) -> GoldenRecord:
    return GoldenRecord(
        sid=sid, rev=1, msg="ET TEST", source_file="real.rules",
        raw_rule=f'alert tcp any any -> any any (msg:"ET TEST"; sid:{sid}; rev:1;)',
        stratum="GENERIC_TCP", expected=ExpectedClassification(),
        annotation=Annotation(status=status, annotator="analyst"),
    )


def result(expected: dict, actual: dict, confidence: float = 0.9) -> EvaluationResult:
    exact, normalized, errors = compare_fields(expected, actual)
    return EvaluationResult(
        sid=1, rev=1, msg="test", source_file="real.rules", expected=expected,
        actual=actual, matches=exact, normalized_matches=normalized, errors=errors,
        confidence=confidence, status="AUTO_CLASSIFIED", usage=TokenUsage(),
    )


def blank_fields(**overrides):
    fields = ExpectedClassification().model_dump()
    fields.update(overrides)
    return fields


def test_normalized_comparison_ignores_case_punctuation_and_space():
    assert normalize_text(" Network-Service   Scanning ") == normalize_text("network service scanning")
    expected = blank_fields(detected_behavior="Network-Service Scanning")
    actual = blank_fields(detected_behavior="network service scanning")
    exact, normalized, _ = compare_fields(expected, actual)
    assert not exact["detected_behavior"]
    assert normalized["detected_behavior"]


def test_null_hallucination_and_error_taxonomy():
    expected = blank_fields(detected_entity=None)
    actual = blank_fields(detected_entity="Cobalt Strike")
    _, _, errors = compare_fields(expected, actual)
    assert "NULL_HALLUCINATION" in errors
    assert "ENTITY_ERROR" in errors


def test_unexpected_null_taxonomy():
    _, _, errors = compare_fields(blank_fields(category="Malware"), blank_fields(category=None))
    assert {"UNEXPECTED_NULL", "CATEGORY_ERROR"}.issubset(errors)


def test_metrics_field_accuracy_and_null_rates():
    rows = [
        result(blank_fields(category="Malware", detected_entity=None), blank_fields(category="Malware", detected_entity=None), .95),
        result(blank_fields(category="Malware", detected_entity=None), blank_fields(category="Other", detected_entity="X"), .85),
    ]
    metrics = calculate_metrics(rows)
    assert metrics["field_metrics"]["category"]["exact_accuracy"] == 0.5
    assert metrics["null_metrics"]["detected_entity"]["null_hallucination_rate"] == 0.5
    assert metrics["evaluated"] == 2


def test_confidence_buckets():
    assert confidence_bucket(.95) == "0.90-1.00"
    assert confidence_bucket(.89) == "0.80-0.89"
    assert confidence_bucket(.75) == "0.70-0.79"
    assert confidence_bucket(.55) == "0.50-0.69"
    assert confidence_bucket(.2) == "<0.50"


def test_stability_score_uses_most_common_fraction():
    assert stability_score(["T1046", "T1046", "T1046", "T1018", "T1018"]) == 0.6
    assert stability_score([]) == 0.0


def test_reviewed_sample_filtering(tmp_path):
    path = tmp_path / "golden.jsonl"
    write_jsonl(path, [golden(1, AnnotationStatus.REVIEWED), golden(2, AnnotationStatus.UNREVIEWED), golden(3, AnnotationStatus.DISPUTED)])
    assert [item.sid for item in reviewed_records(path)] == [1]

def test_claude_reviewed_records_are_included_and_provenance_preserved(tmp_path):
    path = tmp_path / "golden.jsonl"
    item = golden(10, AnnotationStatus.REVIEWED)
    item.annotation.review_method = "CLAUDE_INDEPENDENT_REVIEW"
    write_jsonl(path, [item])
    rows = reviewed_records(path)
    assert len(rows) == 1
    assert rows[0].annotation.review_method == "CLAUDE_INDEPENDENT_REVIEW"

def test_reviewed_record_with_missing_expected_field_is_excluded(tmp_path):
    path = tmp_path / "golden.jsonl"
    payload = golden(11, AnnotationStatus.REVIEWED).model_dump(mode="json")
    payload["expected"].pop("category")
    path.write_text(__import__("json").dumps(payload) + "\n", encoding="utf-8")
    assert reviewed_records(path) == []


def test_cost_is_not_calculated_without_configured_pricing():
    row = result(blank_fields(), blank_fields())
    row.usage = TokenUsage(input_tokens=100, output_tokens=20, total_tokens=120)
    costs = calculate_costs([row], None, None)
    assert costs["cost_status"] == "COST_NOT_CALCULATED"
    assert costs["total_tokens"] == 120


def test_cost_uses_external_pricing_values():
    row = result(blank_fields(), blank_fields())
    row.usage = TokenUsage(input_tokens=1_000_000, output_tokens=1_000_000, total_tokens=2_000_000)
    costs = calculate_costs([row], 1.5, 6.0)
    assert costs["estimated_total_cost"] == 7.5


def test_provider_without_api_key_fails_cleanly():
    provider = OpenAIClassificationProvider(None, "configured-by-environment")
    try:
        asyncio.run(provider.classify(SimpleNamespace()))
    except ProviderUnavailable as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("Provider should reject a missing API key")


def test_batch_continues_after_individual_failure():
    class FakeService:
        async def classify(self, rule):
            return SimpleNamespace(classification_status=ClassificationStatus.AUTO_CLASSIFIED, _cache_hit=False)

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    samples = [
        RuleSample(sid=10, rev=1, msg="valid", source_file="real.rules", stratum="GENERIC_TCP", raw_rule='alert tcp any any -> any any (msg:"valid"; sid:10; rev:1;)'),
        RuleSample(sid=11, rev=1, msg="invalid", source_file="real.rules", stratum="GENERIC_TCP", raw_rule="not a rule"),
    ]
    with Session() as db:
        payload = asyncio.run(run_batch(FakeService(), db, samples))
    assert payload["total_processed"] == 1
    assert payload["failed"] == 1
    assert payload["batch_continued_after_individual_failures"] is True


def test_sampling_is_reproducible():
    records = [
        RuleSample(sid=i, rev=1, msg=str(i), source_file="real.rules", stratum="SCAN" if i % 2 else "DNS", raw_rule=f"rule {i}")
        for i in range(1, 21)
    ]
    first = stratified_sample(records, 10, 42)
    second = stratified_sample(records, 10, 42)
    assert [item.sid for item in first] == [item.sid for item in second]
