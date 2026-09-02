import argparse
import json
from pathlib import Path

from app.enrichment.deterministic_enrichment import enrich_rule
from app.evaluation.golden_dataset import read_jsonl, write_jsonl
from app.evaluation.schemas import AnnotationStatus, EVALUATED_FIELDS, GoldenRecord
from app.parser.suricata_parser import SuricataRuleParser


def _value(prompt: str, current: str | None) -> str | None:
    shown = current if current is not None else "null"
    raw = input(f"{prompt} [{shown}] (blank=keep, -=null): ").strip()
    if not raw:
        return current
    return None if raw == "-" else raw


def main() -> int:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Human-only golden dataset annotation CLI.")
    parser.add_argument("--golden", type=Path, default=project_root / "data" / "evaluation" / "golden_dataset.jsonl")
    parser.add_argument("--annotator", required=True)
    parser.add_argument("--sid", type=int)
    args = parser.parse_args()
    records = read_jsonl(args.golden, GoldenRecord)
    rule_parser = SuricataRuleParser()

    for index, record in enumerate(records):
        if args.sid and record.sid != args.sid:
            continue
        if not args.sid and record.annotation.status == AnnotationStatus.REVIEWED:
            continue
        parsed = rule_parser.parse(record.raw_rule)
        hints = enrich_rule(parsed)
        print("\n" + "=" * 90)
        print(f"{index + 1}/{len(records)} SID {record.sid} rev {record.rev} [{record.stratum}]")
        print(f"MSG: {record.msg}")
        print(f"RAW: {record.raw_rule}")
        print("PARSED:", json.dumps(parsed.model_dump(exclude={"raw_rule", "options"}), indent=2, ensure_ascii=False))
        print("DETERMINISTIC HINTS:", json.dumps(hints.__dict__, indent=2, ensure_ascii=False))
        print("AI output is intentionally hidden to avoid annotation bias.")
        if input("Annotate this rule? [Y/n/q]: ").strip().lower() == "q":
            break
        expected = record.expected.model_dump()
        for field in EVALUATED_FIELDS:
            expected[field] = _value(field, expected[field])
        record.expected = record.expected.model_validate(expected)
        notes = input(f"notes [{record.annotation.notes or ''}]: ").strip()
        status_raw = input("status [REVIEWED] (REVIEWED/DISPUTED/UNREVIEWED): ").strip().upper() or "REVIEWED"
        record.annotation.status = AnnotationStatus(status_raw)
        record.annotation.annotator = args.annotator
        if notes:
            record.annotation.notes = notes
        write_jsonl(args.golden, records)
        print("Saved.")
        if args.sid:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

