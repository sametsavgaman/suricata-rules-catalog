import argparse
import asyncio
import json
import time
from pathlib import Path

from app.agent.factory import create_classification_provider
from app.config import get_settings
from app.database.models import ClassificationStatus
from app.database.repository import RuleRepository
from app.database.session import Base, SessionLocal, engine
from app.evaluation.sampler import scan_rules, stratified_sample
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService


async def run_batch(service, db, samples) -> dict:
    parser, repository = SuricataRuleParser(), RuleRepository(db)
    counts = {status.value: 0 for status in ClassificationStatus}
    cache_hits = processed = 0
    individual_failures: list[dict] = []
    started = time.perf_counter()
    for sample in samples:
        try:
            rule, _ = repository.upsert(parser.parse(sample.raw_rule), sample.source_file)
            db.commit()
            result = await service.classify(rule)
            processed += 1
            counts[result.classification_status.value] += 1
            cache_hits += int(getattr(result, "_cache_hit", False))
        except Exception as exc:
            individual_failures.append({"sid": sample.sid, "error": str(exc)})
            continue
    elapsed = time.perf_counter() - started
    return {
        "total_requested": len(samples),
        "total_processed": processed,
        "classification_success": counts[ClassificationStatus.AUTO_CLASSIFIED.value],
        "review_required": counts[ClassificationStatus.REVIEW_REQUIRED.value],
        "failed": counts[ClassificationStatus.FAILED.value] + len(individual_failures),
        "skipped_from_cache": cache_hits,
        "elapsed_seconds": elapsed,
        "average_duration_per_rule": elapsed / len(samples) if samples else 0.0,
        "batch_continued_after_individual_failures": bool(individual_failures) and processed > 0,
        "individual_failures": individual_failures[:100],
    }


async def _main(args) -> int:
    settings = get_settings()
    records, parser_summary = scan_rules(args.rules_dir)
    if parser_summary.data_status == "REAL_DATA_NOT_AVAILABLE":
        print("REAL_DATA_NOT_AVAILABLE")
        return 2
    if not settings.openai_api_key:
        print("OPENAI_API_KEY_NOT_CONFIGURED")
        return 3
    if not settings.openai_model:
        print("OPENAI_MODEL_NOT_CONFIGURED")
        return 4
    selected = stratified_sample(records, args.count, args.seed)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        service = ClassificationService(db, create_classification_provider(settings), settings, MitreRepository())
        payload = await run_batch(service, db, selected)
    payload["parser"] = parser_summary.model_dump(mode="json")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Batch report: {args.output}")
    return 0


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Operational batch test on real ET Open rules (not an accuracy test).")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rules-dir", type=Path, default=root / "data" / "rules" / "et-open")
    parser.add_argument("--output", type=Path, default=root / "data" / "evaluation" / "batch_results.json")
    return asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
