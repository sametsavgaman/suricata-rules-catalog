import argparse
import asyncio
import json
import random
from collections import Counter
from pathlib import Path

from app.agent.factory import create_classification_provider
from app.config import get_settings
from app.database.repository import RuleRepository
from app.database.session import Base, SessionLocal, engine
from app.evaluation.golden_dataset import reviewed_records
from app.evaluation.schemas import GoldenRecord, TokenUsage
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.services.classification_service import ClassificationService


STABILITY_FIELDS = ("detected_entity", "category", "mitre_technique_id", "cyber_kill_chain_phase")


def stability_score(values: list[str | None]) -> float:
    return max(Counter(values).values()) / len(values) if values else 0.0


async def run_stability(service: ClassificationService, db, records: list[GoldenRecord], sample_count: int, runs: int, seed: int) -> dict:
    chosen = list(records)
    random.Random(seed).shuffle(chosen)
    chosen = chosen[:sample_count]
    parser, repository = SuricataRuleParser(), RuleRepository(db)
    output = []
    total_usage = TokenUsage()
    for record in chosen:
        rule, _ = repository.upsert(parser.parse(record.raw_rule), record.source_file)
        db.commit()
        values = {field: [] for field in STABILITY_FIELDS}
        failures = 0
        for _ in range(runs):
            result = await service.classify(rule, force=True)
            if result.classification_status.value == "FAILED":
                failures += 1
                continue
            for field in STABILITY_FIELDS:
                values[field].append(getattr(result, field))
            usage = getattr(result, "_token_usage", TokenUsage())
            total_usage.input_tokens += usage.input_tokens
            total_usage.output_tokens += usage.output_tokens
            total_usage.total_tokens += usage.total_tokens
        output.append({
            "sid": record.sid,
            "runs": runs,
            "failures": failures,
            "scores": {field: stability_score(items) for field, items in values.items()},
            "values": values,
        })
    aggregate = {
        field: sum(item["scores"][field] for item in output) / len(output) if output else 0.0
        for field in STABILITY_FIELDS
    }
    return {"status": "COMPLETED", "samples": len(output), "runs_per_sample": runs, "aggregate": aggregate, "rules": output, "usage": total_usage.model_dump()}


async def _main(args) -> int:
    settings = get_settings()
    records = reviewed_records(args.golden)
    if not records:
        print("NO_REVIEWED_GOLDEN_SAMPLES")
        return 2
    if not settings.openai_api_key:
        print("OPENAI_API_KEY_NOT_CONFIGURED")
        return 3
    if not settings.openai_model:
        print("OPENAI_MODEL_NOT_CONFIGURED")
        return 4
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        service = ClassificationService(db, create_classification_provider(settings), settings, MitreRepository())
        payload = await run_stability(service, db, records, args.samples, args.runs, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Stability report: {args.output}")
    return 0


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Repeat classifications with cache bypass and measure stability.")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--golden", type=Path, default=root / "data" / "evaluation" / "golden_dataset.jsonl")
    parser.add_argument("--output", type=Path, default=root / "data" / "evaluation" / "stability_results.json")
    return asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
