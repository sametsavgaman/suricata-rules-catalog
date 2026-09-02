import argparse
import asyncio
import json
from pathlib import Path

from app.agent.factory import create_classification_provider, provider_config_error
from app.config import get_settings
from app.database.session import Base, SessionLocal, engine, ensure_schema_extensions
from app.evaluation.cost_analysis import calculate_costs
from app.evaluation.evaluator import evaluate_records
from app.evaluation.golden_dataset import reviewed_records, write_jsonl
from app.evaluation.metrics import calculate_metrics
from app.evaluation.report import build_report_payload, write_reports
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService


async def _run(args) -> int:
    settings = get_settings()
    records = reviewed_records(args.golden)
    config_error = provider_config_error(settings)
    parser_summary_path = args.golden.parent / "parser_summary.json"
    parser_summary = json.loads(parser_summary_path.read_text(encoding="utf-8")) if parser_summary_path.exists() else None
    if not records:
        write_jsonl(args.output, [])
        empty_metrics = calculate_metrics([])
        payload = build_report_payload([], empty_metrics, calculate_costs([], None, None), parser_summary, status="NO_REVIEWED_GOLDEN_SAMPLES")
        write_reports(args.report_dir, payload)
        print("NO_REVIEWED_GOLDEN_SAMPLES")
        return 2
    if config_error == "OPENAI_API_KEY_NOT_CONFIGURED":
        metrics = calculate_metrics([])
        metrics["golden_samples"] = len(records)
        metrics["failed"] = 0
        payload = build_report_payload([], metrics, calculate_costs([], None, None), parser_summary, status="OPENAI_API_KEY_NOT_CONFIGURED", golden_records=records, provider=settings.ai_provider)
        write_reports(args.report_dir, payload)
        print("OPENAI_API_KEY_NOT_CONFIGURED")
        return 3
    if config_error == "OPENAI_MODEL_NOT_CONFIGURED":
        metrics = calculate_metrics([])
        metrics["golden_samples"] = len(records)
        metrics["failed"] = 0
        payload = build_report_payload([], metrics, calculate_costs([], None, None), parser_summary, status="OPENAI_MODEL_NOT_CONFIGURED", golden_records=records, provider=settings.ai_provider)
        write_reports(args.report_dir, payload)
        print("OPENAI_MODEL_NOT_CONFIGURED")
        return 4

    if config_error:
        metrics = calculate_metrics([]); metrics["golden_samples"] = len(records); metrics["failed"] = 0
        payload = build_report_payload([], metrics, calculate_costs([], None, None), parser_summary, status=config_error, golden_records=records, provider=settings.ai_provider)
        write_reports(args.report_dir, payload); print(config_error); return 4
    Base.metadata.create_all(bind=engine)
    ensure_schema_extensions()
    with SessionLocal() as db:
        provider = create_classification_provider(settings)
        service = ClassificationService(db, provider, settings, MitreRepository())
        results = []
        for index, record in enumerate(records, 1):
            print(f"[{index}/{len(records)}] SID {record.sid} classified", flush=True)
            results.extend(await evaluate_records(db, service, [record], force=args.force))
    write_jsonl(args.output, results)
    metrics = calculate_metrics(results)
    if settings.ai_provider.casefold() == "gemini":
        costs = calculate_costs(results, settings.gemini_input_cost_per_million, settings.gemini_output_cost_per_million)
    else:
        costs = calculate_costs(results, settings.openai_input_cost_per_million, settings.openai_output_cost_per_million)
    payload = build_report_payload(results, metrics, costs, parser_summary, golden_records=records, provider=settings.ai_provider, model=provider.model_name)
    write_reports(args.report_dir, payload)
    print(f"Provider: {settings.ai_provider} | Model: {provider.model_name}")
    print(f"Evaluated {metrics['evaluated']}/{metrics['golden_samples']}; report: {args.report_dir}")
    return 0


def main() -> int:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Evaluate reviewed golden samples using the production classification service.")
    parser.add_argument("--golden", type=Path, default=project_root / "data" / "evaluation" / "golden_dataset.jsonl")
    parser.add_argument("--output", type=Path, default=project_root / "data" / "evaluation" / "evaluation_results.jsonl")
    parser.add_argument("--report-dir", type=Path, default=project_root / "data" / "evaluation" / "reports")
    parser.add_argument("--force", action="store_true", help="Bypass production cache for controlled evaluation.")
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
