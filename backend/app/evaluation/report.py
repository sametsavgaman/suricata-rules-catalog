import json
from pathlib import Path
from typing import Any

from app.evaluation.schemas import EvaluationResult


def _pct(value: float) -> str:
    return f"{value:.1%}"


def build_report_payload(
    results: list[EvaluationResult], metrics: dict, costs: dict,
    parser_summary: dict | None = None, stability: dict | None = None,
    status: str = "COMPLETED", golden_records: list | None = None, provider: str | None = None, model: str | None = None,
) -> dict[str, Any]:
    records = golden_records or []
    provenance: dict[str, int] = {}
    for record in records:
        method = record.annotation.review_method or "UNSPECIFIED"
        provenance[method] = provenance.get(method, 0) + 1
    return {
        "status": status,
        "provider": provider,
        "model": model,
        "parser": parser_summary,
        "metrics": metrics,
        "cost_analysis": costs,
        "stability": stability or {"status": "NOT_RUN"},
        "golden_provenance": provenance,
        "sample_errors": [item.model_dump(mode="json") for item in results if item.errors][:10],
    }


def write_reports(report_dir: Path, payload: dict) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "evaluation-report.json"
    markdown_path = report_dir / "evaluation-report.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    metrics = payload.get("metrics", {})
    lines = ["# Evaluation Summary", "", f"**Status:** `{payload['status']}`", f"**Provider:** `{payload.get('provider') or 'unknown'}`", f"**Model:** `{payload.get('model') or 'unknown'}`", ""]
    parser = payload.get("parser") or {}
    if parser:
        lines += ["## Parser", "", f"- Total rules: {parser.get('total_rules', 0)}", f"- Parsed successfully: {parser.get('parsed_successfully', 0)}", f"- Failed parsing: {parser.get('failed_parsing', 0)}", f"- Success rate: {parser.get('parser_success_rate', 0.0):.2%}", ""]
    lines += [
        f"- Golden samples: {metrics.get('golden_samples', 0)}",
        f"- Evaluated: {metrics.get('evaluated', 0)}",
        f"- Failed: {metrics.get('failed', 0)}", "",
    ]
    provenance = payload.get("golden_provenance", {})
    if provenance:
        lines += ["## Golden Provenance", "", *[f"- {method}: {count}" for method, count in provenance.items()], ""]
    if payload["status"] != "COMPLETED":
        lines += ["No accuracy claim was produced. Human-reviewed ground truth and real model results are required.", ""]
    fields = metrics.get("field_metrics", {}) if payload["status"] == "COMPLETED" else {}
    if fields:
        lines += ["## Accuracy", "", "| Field | Exact | Normalized |", "|---|---:|---:|"]
        for field, row in fields.items():
            lines.append(f"| {field} | {_pct(row['exact_accuracy'])} | {_pct(row['normalized_accuracy'])} |")
        lines.append("")
    nulls = metrics.get("null_metrics", {}) if payload["status"] == "COMPLETED" else {}
    if nulls:
        lines += ["## Null Safety", "", "| Field | Null preserved | NULL_HALLUCINATION_RATE | Unexpected null |", "|---|---:|---:|---:|"]
        for field, row in nulls.items():
            lines.append(f"| {field} | {_pct(row['expected_null_actual_null_rate'])} | {_pct(row['null_hallucination_rate'])} | {_pct(row['unexpected_null_rate'])} |")
        lines.append("")
    calibration = metrics.get("confidence_calibration", {})
    if calibration:
        lines += ["## Confidence Calibration", "", "| Bucket | Count | Actual field accuracy |", "|---|---:|---:|"]
        for bucket, row in calibration.items():
            lines.append(f"| {bucket} | {row['count']} | {_pct(row['actual_accuracy'])} |")
        lines.append("")
    errors = metrics.get("error_counts", {})
    if errors:
        lines += ["## Most Common Errors", "", "| Error | Count |", "|---|---:|"]
        for error, count in sorted(errors.items(), key=lambda item: -item[1]):
            lines.append(f"| {error} | {count} |")
        lines.append("")
    categories = metrics.get("lowest_performing_categories", [])[:10]
    if categories:
        lines += ["## Lowest Performing Categories", "", "| Category | Count | Accuracy |", "|---|---:|---:|"]
        for row in categories:
            lines.append(f"| {row['category']} | {row['count']} | {_pct(row['accuracy'])} |")
        lines.append("")
    costs = payload.get("cost_analysis", {})
    lines += ["## Token and Cost Analysis", "", f"- Total tokens: {costs.get('total_tokens', 0)}", f"- Average tokens/rule: {costs.get('average_total_tokens_per_rule', 0):.1f}", f"- Cost status: `{costs.get('cost_status', 'COST_NOT_CALCULATED')}`", ""]
    sample_errors = payload.get("sample_errors", [])
    if sample_errors:
        lines += ["## Sample Errors", ""]
        for item in sample_errors[:10]:
            lines += [f"### SID {item['sid']}", "", f"- Message: {item.get('msg')}", f"- Confidence: {item.get('confidence', 0):.2f}", f"- Error types: {', '.join(item.get('errors', []))}", "", "```json", json.dumps({"expected": item.get("expected"), "actual": item.get("actual")}, indent=2, ensure_ascii=False), "```", ""]
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return markdown_path, json_path
