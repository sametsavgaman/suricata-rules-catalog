"""Add canonical state to historical V2 records without changing classifications."""
from __future__ import annotations

import argparse
import copy
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import Classification, ClassificationStatus, Rule
from app.database.session import engine, ensure_schema_extensions
from app.parser.models import ParsedRule
from app.v2.state import build_field_decisions
from app.v2.tools import entity_candidates


def _parsed(r: Rule) -> ParsedRule:
    return ParsedRule(raw_rule=r.raw_rule, action=r.action, protocol=r.protocol, source=r.source,
        source_port=r.source_port, direction=r.direction, destination=r.destination,
        destination_port=r.destination_port, sid=r.sid, rev=r.rev, msg=r.msg,
        classtype=r.classtype, metadata=r.rule_metadata, references=r.references,
        flow=r.flow, flowbits=r.flowbits, contents=r.contents, pcre=r.pcre, app_layer=r.app_layer)


def backfill(*, apply: bool = False) -> dict:
    ensure_schema_extensions(); result = {"mode": "APPLY" if apply else "DRY_RUN", "updated": [], "skipped": 0}
    with Session(engine) as db:
        rows = db.execute(select(Rule, Classification).join(Classification).where(
            Classification.classifier_version.ilike("v2%"),
            Classification.classification_status != ClassificationStatus.FAILED,
        ).order_by(Rule.id, Classification.created_at.desc(), Classification.id.desc())).all()
        latest = {}
        for rule, classification in rows: latest.setdefault(rule.id, (rule, classification))
        for rule, c in latest.values():
            activity = c.agent_activity or {}
            if (activity.get("field_decisions") and isinstance(activity.get("validation"), dict)
                    and "deterministic_validator" in activity["validation"]
                    and c.model_confidence is not None and c.evidence_strength is not None):
                result["skipped"] += 1; continue
            strong = [x for x in entity_candidates(_parsed(rule)) if not x.get("weak")]
            abstained = []
            if c.detected_entity is None: abstained.append("detected_entity")
            if c.mitre_technique_id is None: abstained.extend(["mitre_tactic", "mitre_technique", "mitre_technique_id"])
            if c.cyber_kill_chain_phase is None: abstained.append("cyber_kill_chain_phase")
            values = {name: getattr(c, name) for name in (
                "detected_behavior", "detected_entity", "entity_type", "category", "subcategory",
                "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase")}
            decisions = build_field_decisions(values, abstained, legacy=False)
            new_activity = copy.deepcopy(activity)
            new_activity.update(
                field_decisions=decisions,
                abstained_fields=[k for k, v in decisions.items() if v["status"] == "ABSTAINED"],
                validation={"status": "REVIEW" if c.validation_issues else "PASS",
                            "reason": "; ".join(c.validation_issues) if c.validation_issues else "Classification satisfies evidence and taxonomy checks.",
                            "checks": list(c.validation_issues), "source": "HISTORICAL_V2_VALIDATOR",
                            "deterministic_validator": {"status": "REVIEW" if c.validation_issues else "PASS"},
                            "semantic_verifier": {"status": activity.get("verifier_verdict", "NOT_RUN")}},
                state_source="HISTORICAL_V2_DETERMINISTIC_BACKFILL",
            )
            if c.evidence_strength is None:
                c.evidence_strength = "NONE" if c.mitre_technique_id is None else "MEDIUM"
            if c.model_confidence is None:
                c.model_confidence = c.confidence
            result["updated"].append({"sid": rule.sid, "classification_id": c.id,
                                      "abstained_fields": new_activity["abstained_fields"]})
            if apply: c.agent_activity = new_activity
        if apply: db.commit()
    result["updated_count"] = len(result["updated"])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--apply", action="store_true"); args = parser.parse_args()
    print(backfill(apply=args.apply))
