import argparse
import json
from pathlib import Path

from app.evaluation.golden_dataset import initialize_golden, write_jsonl
from app.evaluation.sampler import scan_rules, stratified_sample


def main() -> int:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Create a reproducible stratified ET Open evaluation sample.")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rules-dir", type=Path, default=project_root / "data" / "rules" / "et-open")
    parser.add_argument("--output", type=Path, default=project_root / "data" / "evaluation" / "sample.jsonl")
    parser.add_argument("--golden", type=Path, default=project_root / "data" / "evaluation" / "golden_dataset.jsonl")
    parser.add_argument("--force-golden", action="store_true")
    args = parser.parse_args()

    records, summary = scan_rules(args.rules_dir)
    summary_path = args.output.parent / "parser_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary.model_dump(mode="json"), indent=2), encoding="utf-8")
    if summary.data_status == "REAL_DATA_NOT_AVAILABLE":
        print("REAL_DATA_NOT_AVAILABLE")
        return 2
    selected = stratified_sample(records, args.count, args.seed)
    write_jsonl(args.output, selected)
    initialize_golden(selected, args.golden, force=args.force_golden)
    print(f"Parser: {summary.parsed_successfully}/{summary.total_rules} ({summary.parser_success_rate:.2%})")
    print(f"Sample: {len(selected)} -> {args.output}")
    print(f"Golden: {args.golden}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

