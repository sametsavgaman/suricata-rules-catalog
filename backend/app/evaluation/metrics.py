import re
import unicodedata
from collections import Counter, defaultdict
from typing import Any

from app.evaluation.schemas import EVALUATED_FIELDS, EvaluationResult


ERROR_BY_FIELD = {
    "detected_entity": "ENTITY_ERROR",
    "entity_type": "ENTITY_ERROR",
    "category": "CATEGORY_ERROR",
    "subcategory": "SUBCATEGORY_ERROR",
    "mitre_tactic": "MITRE_TACTIC_ERROR",
    "mitre_technique": "MITRE_TECHNIQUE_ERROR",
    "mitre_technique_id": "MITRE_TECHNIQUE_ERROR",
    "cyber_kill_chain_phase": "KILL_CHAIN_ERROR",
    "detected_behavior": "OTHER",
}


def normalize_text(value: Any) -> Any:
    if value is None:
        return None
    text = unicodedata.normalize("NFKC", str(value)).casefold()
    text = re.sub(r"[^\w]+", " ", text, flags=re.UNICODE)
    return " ".join(text.split())

BEHAVIOR_PATTERNS={
 "REMOTE_ACCESS_SOFTWARE_COMMUNICATION":("remote access software","remote administration software","anydesk","teamviewer"),
 "NETWORK_SERVICE_SCANNING":("network service scan","port scan","service scan"),
 "HTTP_C2_COMMUNICATION":("http command and control","http c2","cnc architecture post"),
 "DNS_C2_COMMUNICATION":("dns c2","cnc domain in dns","command and control domain"),
 "BRUTE_FORCE":("brute force","login failures"), "SQL_INJECTION":("sql injection","union select"),
 "LOCAL_FILE_INCLUSION":("local file inclusion",), "REMOTE_FILE_INCLUSION":("remote file inclusion","rfi scan"),
 "CREDENTIAL_DUMPING":("credential dumping","pwdump"),
}
def normalize_behavior(value: Any) -> Any:
    text=normalize_text(value)
    if text is None:return None
    for canonical,patterns in BEHAVIOR_PATTERNS.items():
        if any(normalize_text(p) in text for p in patterns): return canonical
    tokens=[x for x in text.split() if x not in {"suspicious","possible","observed","attempt","activity","traffic","network"}]
    return " ".join(tokens)


def compare_fields(expected: dict, actual: dict | None) -> tuple[dict[str, bool], dict[str, bool], list[str]]:
    actual = actual or {}
    exact: dict[str, bool] = {}
    normalized: dict[str, bool] = {}
    errors: list[str] = []
    for field in EVALUATED_FIELDS:
        wanted, got = expected.get(field), actual.get(field)
        exact[field] = wanted == got
        normalized[field] = normalize_text(wanted) == normalize_text(got)
        if exact[field]:
            continue
        if wanted is None and got is not None:
            errors.append("NULL_HALLUCINATION")
        elif wanted is not None and got is None:
            errors.append("UNEXPECTED_NULL")
        errors.append(ERROR_BY_FIELD[field])
    return exact, normalized, list(dict.fromkeys(errors))


def confidence_bucket(confidence: float) -> str:
    if confidence >= 0.9:
        return "0.90-1.00"
    if confidence >= 0.8:
        return "0.80-0.89"
    if confidence >= 0.7:
        return "0.70-0.79"
    if confidence >= 0.5:
        return "0.50-0.69"
    return "<0.50"


def calculate_metrics(results: list[EvaluationResult]) -> dict[str, Any]:
    evaluated = [item for item in results if item.actual is not None]
    field_metrics = {}
    for field in EVALUATED_FIELDS:
        denominator = len(evaluated)
        field_metrics[field] = {
            "count": denominator,
            "exact_accuracy": sum(r.matches.get(field, False) for r in evaluated) / denominator if denominator else 0.0,
            "normalized_accuracy": sum(r.normalized_matches.get(field, False) for r in evaluated) / denominator if denominator else 0.0,
        }

    null_metrics = {}
    for field in EVALUATED_FIELDS:
        expected_null = [r for r in evaluated if r.expected.get(field) is None]
        expected_non_null = [r for r in evaluated if r.expected.get(field) is not None]
        actual_null_when_expected = sum(r.actual.get(field) is None for r in expected_null)
        hallucinated = len(expected_null) - actual_null_when_expected
        unexpected_null = sum(r.actual.get(field) is None for r in expected_non_null)
        null_metrics[field] = {
            "expected_null_count": len(expected_null),
            "expected_null_actual_null_rate": actual_null_when_expected / len(expected_null) if expected_null else 0.0,
            "null_hallucination_rate": hallucinated / len(expected_null) if expected_null else 0.0,
            "expected_non_null_count": len(expected_non_null),
            "unexpected_null_rate": unexpected_null / len(expected_non_null) if expected_non_null else 0.0,
        }

    buckets: dict[str, list[float]] = defaultdict(list)
    for result in evaluated:
        per_rule_accuracy = sum(result.matches.values()) / len(result.matches) if result.matches else 0.0
        buckets[confidence_bucket(result.confidence)].append(per_rule_accuracy)
    calibration = {
        name: {"count": len(values), "actual_accuracy": sum(values) / len(values) if values else 0.0}
        for name in ("0.90-1.00", "0.80-0.89", "0.70-0.79", "0.50-0.69", "<0.50")
        if (values := buckets.get(name, []))
    }
    error_counts = Counter(error for result in results for error in result.errors)
    category_groups: dict[str, list[bool]] = defaultdict(list)
    for result in evaluated:
        category_groups[str(result.expected.get("category") or "<null>")].append(result.matches.get("category", False))
    lowest_categories = sorted(
        ({"category": name, "count": len(values), "accuracy": sum(values) / len(values)} for name, values in category_groups.items()),
        key=lambda row: (row["accuracy"], -row["count"]),
    )
    behavior_semantic=sum(normalize_behavior(r.expected.get("detected_behavior"))==normalize_behavior(r.actual.get("detected_behavior")) for r in evaluated)/len(evaluated) if evaluated else 0.0
    def null_pr(field):
        predicted=[r for r in evaluated if r.actual.get(field) is None]; expected=[r for r in evaluated if r.expected.get(field) is None]
        tp=sum(r.expected.get(field) is None for r in predicted)
        return {"precision":tp/len(predicted) if predicted else 0.0,"recall":tp/len(expected) if expected else 0.0}
    tools=Counter(t for r in evaluated for t in r.agent_activity.get("tools_used",[])); total=len(evaluated)
    tool_usage={"rates":{k:v/total for k,v in tools.items()} if total else {},"average_tool_calls_per_rule":sum(r.agent_activity.get("tool_calls",0) for r in evaluated)/total if total else 0.0,"semantic_verifier_rate":sum(bool(r.agent_activity.get("verifier_verdict")) for r in evaluated)/total if total else 0.0,"average_llm_calls_per_rule":1.0 if total else 0.0}
    return {
        "golden_samples": len(results),
        "evaluated": len(evaluated),
        "failed": len(results) - len(evaluated),
        "field_metrics": field_metrics,
        "null_metrics": null_metrics,
        "confidence_calibration": calibration,
        "error_counts": dict(error_counts),
        "lowest_performing_categories": lowest_categories,
        "average_confidence": sum(r.confidence for r in evaluated) / len(evaluated) if evaluated else 0.0,
        "behavior_semantic_normalized_accuracy": behavior_semantic,
        "v2_null_metrics":{"entity":null_pr("detected_entity"),"mitre":null_pr("mitre_technique_id"),"kill_chain":null_pr("cyber_kill_chain_phase")},
        "tool_usage":tool_usage,
    }
