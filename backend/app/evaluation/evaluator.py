from sqlalchemy.orm import Session

from app.database.models import ClassificationStatus
from app.database.repository import RuleRepository
from app.evaluation.schemas import EVALUATED_FIELDS, EvaluationResult, GoldenRecord, TokenUsage
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService
from app.evaluation.metrics import compare_fields


def _actual_dict(classification) -> dict:
    return {field: getattr(classification, field) for field in EVALUATED_FIELDS}


async def evaluate_records(
    db: Session,
    service: ClassificationService,
    golden_records: list[GoldenRecord],
    force: bool = False,
) -> list[EvaluationResult]:
    parser, repository = SuricataRuleParser(), RuleRepository(db)
    results: list[EvaluationResult] = []
    for golden in golden_records:
        expected = golden.expected.model_dump()
        try:
            parsed = parser.parse(golden.raw_rule)
            rule, _ = repository.upsert(parsed, golden.source_file)
            db.commit()
            classification = await service.classify(rule, force=force)
            if classification.classification_status == ClassificationStatus.FAILED:
                results.append(EvaluationResult(
                    sid=golden.sid, rev=golden.rev, msg=golden.msg, source_file=golden.source_file,
                    expected=expected, actual=None, matches={}, normalized_matches={},
                    errors=["API_FAILURE"], confidence=0.0, status="FAILED",
                    cache_hit=getattr(classification, "_cache_hit", False),
                    usage=getattr(classification, "_token_usage", TokenUsage()),
                    classifier_version=getattr(classification,"classifier_version","v1"), agent_activity=getattr(classification,"agent_activity",{}) or {},
                ))
                continue
            actual = _actual_dict(classification)
            matches, normalized, errors = compare_fields(expected, actual)
            if classification.validation_issues:
                errors.append("VALIDATION_FAILURE")
            results.append(EvaluationResult(
                sid=golden.sid, rev=golden.rev, msg=golden.msg, source_file=golden.source_file,
                expected=expected, actual=actual, matches=matches, normalized_matches=normalized,
                errors=list(dict.fromkeys(errors)), confidence=classification.confidence,
                status=classification.classification_status.value,
                cache_hit=getattr(classification, "_cache_hit", False),
                usage=getattr(classification, "_token_usage", TokenUsage()),
                classifier_version=getattr(classification,"classifier_version","v1"), agent_activity=getattr(classification,"agent_activity",{}) or {},
            ))
        except Exception:
            results.append(EvaluationResult(
                sid=golden.sid, rev=golden.rev, msg=golden.msg, source_file=golden.source_file,
                expected=expected, actual=None, matches={}, normalized_matches={}, errors=["PARSER_ERROR"],
                confidence=0.0, status="FAILED", cache_hit=False,
            ))
    return results
