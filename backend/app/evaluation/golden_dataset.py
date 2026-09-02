import json
from pathlib import Path

from app.evaluation.schemas import AnnotationStatus, GoldenRecord, RuleSample, EVALUATED_FIELDS


def read_jsonl(path: Path, model_type):
    if not path.exists():
        return []
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                records.append(model_type.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records


def write_jsonl(path: Path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(record.model_dump_json() for record in records)
    path.write_text(payload + ("\n" if payload else ""), encoding="utf-8")


def initialize_golden(samples: list[RuleSample], path: Path, force: bool = False) -> list[GoldenRecord]:
    existing = {} if force else {(r.sid, r.rev): r for r in read_jsonl(path, GoldenRecord)}
    records = [
        existing.get((sample.sid, sample.rev), GoldenRecord(**sample.model_dump()))
        for sample in samples
    ]
    write_jsonl(path, records)
    return records


def reviewed_records(path: Path) -> list[GoldenRecord]:
    records = read_jsonl(path, GoldenRecord)
    raw_rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []
    valid: list[GoldenRecord] = []
    for index, record in enumerate(records):
        if record.annotation.status != AnnotationStatus.REVIEWED:
            continue
        # A reviewed row must carry the complete expected schema. Null is a valid
        # annotation value; a missing key is not.
        expected = raw_rows[index].get("expected", {}) if index < len(raw_rows) else {}
        if not all(field in expected for field in EVALUATED_FIELDS):
            continue
        valid.append(record)
    return valid
