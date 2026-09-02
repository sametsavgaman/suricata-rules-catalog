"""Version-preserving backfill for unambiguous explicit entity evidence."""

from __future__ import annotations

import argparse
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Classification, ClassificationStatus, Rule
from app.database.session import engine, ensure_schema_extensions
from app.parser.models import ParsedRule
from app.v2.tools import entity_candidates


def _parsed(rule: Rule) -> ParsedRule:
    return ParsedRule(
        raw_rule=rule.raw_rule, action=rule.action, protocol=rule.protocol,
        source=rule.source, source_port=rule.source_port,
        direction=rule.direction, destination=rule.destination,
        destination_port=rule.destination_port, sid=rule.sid, rev=rule.rev,
        msg=rule.msg, classtype=rule.classtype, metadata=rule.rule_metadata,
        references=rule.references, flow=rule.flow, flowbits=rule.flowbits,
        contents=rule.contents, pcre=rule.pcre, app_layer=rule.app_layer,
    )


def backfill(inspection_batch: str, *, apply: bool) -> dict:
    ensure_schema_extensions()
    summary = {
        "inspection_batch": inspection_batch,
        "mode": "APPLY" if apply else "DRY_RUN",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "eligible": [],
        "existing_backfills": [],
        "ambiguous": [],
    }
    with Session(engine) as db:
        rows = db.execute(
            select(Rule, Classification)
            .join(Classification)
            .where(
                Classification.inspection_batch == inspection_batch,
                Classification.classification_status != ClassificationStatus.FAILED,
            )
            .order_by(Rule.id, Classification.created_at.desc(), Classification.id.desc())
        ).all()
        latest: dict[int, tuple[Rule, Classification]] = {}
        for rule, classification in rows:
            latest.setdefault(rule.id, (rule, classification))

        for rule, classification in latest.values():
            if classification.detected_entity:
                if (classification.agent_activity or {}).get("entity_resolution_method") == "DETERMINISTIC_EXPLICIT_EVIDENCE":
                    summary["existing_backfills"].append({
                        "sid": rule.sid, "rev": rule.rev,
                        "entity": classification.detected_entity,
                        "entity_type": classification.entity_type,
                    })
                continue
            candidates = [c for c in entity_candidates(_parsed(rule)) if not c.get("weak")]
            if len(candidates) > 1:
                summary["ambiguous"].append({
                    "sid": rule.sid, "rev": rule.rev,
                    "candidates": [c["candidate"] for c in candidates],
                })
                continue
            if len(candidates) != 1 or not candidates[0].get("deterministic"):
                continue

            candidate = candidates[0]
            summary["eligible"].append({
                "sid": rule.sid, "rev": rule.rev,
                "entity": candidate["candidate"],
                "entity_type": candidate["entity_type"],
                "evidence_type": candidate["evidence_type"],
            })
            if not apply:
                continue

            payload = {
                column.name: copy.deepcopy(getattr(classification, column.name))
                for column in Classification.__table__.columns
                if column.name not in {"id", "created_at"}
            }
            payload.update(
                detected_entity=candidate["candidate"],
                entity_type=candidate["entity_type"],
                evidence=list(dict.fromkeys((classification.evidence or []) + [
                    f"entity_candidate:{candidate['candidate']}:{candidate['evidence_type']}"
                ]))[:10],
                explanation=(
                    (classification.explanation or "").rstrip()
                    + f" Entity was deterministically resolved as {candidate['candidate']} from explicit rule evidence."
                )[:800],
            )
            activity = copy.deepcopy(classification.agent_activity or {})
            activity.update(
                entity_candidates=candidates,
                entity_resolution_method="DETERMINISTIC_EXPLICIT_EVIDENCE",
                entity_evidence_strength="STRONG",
            )
            payload["agent_activity"] = activity
            db.add(Classification(**payload))

        if apply:
            db.commit()

    summary["eligible_count"] = len(summary["eligible"])
    summary["existing_backfill_count"] = len(summary["existing_backfills"])
    summary["ambiguous_count"] = len(summary["ambiguous"])
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inspection-batch", default="operational-250")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("data/evaluation/operational-250/entity-backfill-report.json"),
    )
    args = parser.parse_args()
    result = backfill(args.inspection_batch, apply=args.apply)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "mode": result["mode"],
        "eligible": result["eligible_count"],
        "existing_backfills": result["existing_backfill_count"],
        "ambiguous": result["ambiguous_count"],
        "report": str(args.report),
    }))


if __name__ == "__main__":
    main()
