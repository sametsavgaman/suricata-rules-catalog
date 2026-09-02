"""Canonical classification state shared by persistence, API and UI."""

from __future__ import annotations

CLASSIFICATION_FIELDS = (
    "detected_behavior", "detected_entity", "entity_type", "category", "subcategory",
    "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase",
)

ABSTENTION_REASONS = {
    "detected_entity": "No specific product, malware family, tool, or other supported named entity is identified by the rule.",
    "entity_type": "Entity type is not applicable because no entity was assigned.",
    "mitre_tactic": "No defensible ATT&CK tactic is supported by the available evidence.",
    "mitre_technique": "No defensible ATT&CK technique is supported by the available evidence.",
    "mitre_technique_id": "No defensible ATT&CK technique is supported by the available evidence.",
    "cyber_kill_chain_phase": "No defensible Kill Chain phase is supported by the available evidence.",
}


def build_field_decisions(values: dict, abstained_fields: list[str] | None = None, *, legacy: bool = False) -> dict:
    """Build the sole source of truth for field assignment/abstention."""
    abstained = set(abstained_fields or [])
    result = {}
    for name in CLASSIFICATION_FIELDS:
        value = values.get(name)
        if value is not None and name not in abstained:
            status, reason = "ASSIGNED", None
        elif name == "entity_type" and values.get("detected_entity") is None and ("detected_entity" in abstained or not legacy):
            status, reason = "NOT_APPLICABLE", ABSTENTION_REASONS[name]
        elif name in abstained:
            status, reason = "ABSTAINED", ABSTENTION_REASONS.get(name, "Evidence was insufficient for a reliable decision.")
        elif legacy:
            status, reason = "UNAVAILABLE", "Field decision metadata was not recorded in this historical classification."
        else:
            status, reason = "ABSTAINED", ABSTENTION_REASONS.get(name, "No supported value was produced.")
        result[name] = {"status": status, "value": value, "reason": reason}
    return result


def canonical_state(classification) -> tuple[dict, list[str], dict | None, str, list[str]]:
    """Normalize a current or historical ORM classification for API output."""
    activity = classification.agent_activity or {}
    values = {name: getattr(classification, name, None) for name in CLASSIFICATION_FIELDS}
    stored = activity.get("field_decisions")
    legacy_abstained = activity.get("abstained_fields")
    decisions = stored if isinstance(stored, dict) else build_field_decisions(
        values, legacy_abstained if isinstance(legacy_abstained, list) else [],
        legacy=stored is None,
    )
    # Enforce consistency even if a historical record contains malformed JSON.
    warnings: list[str] = []
    for name in CLASSIFICATION_FIELDS:
        decision = decisions.get(name)
        if not isinstance(decision, dict):
            decisions[name] = {"status": "UNAVAILABLE", "value": values[name], "reason": "Invalid historical field decision metadata."}
            warnings.append(f"Invalid field decision: {name}")
            continue
        decision["value"] = values[name]
        status = decision.get("status")
        if status == "ASSIGNED" and values[name] is None:
            warnings.append(f"Assigned field has null value: {name}")
            decision["status"] = "UNAVAILABLE"
        elif status in {"ABSTAINED", "NOT_APPLICABLE"} and values[name] is not None:
            warnings.append(f"Non-null value has {status} status: {name}")
            decision["status"] = "ASSIGNED"
    abstained = [name for name, decision in decisions.items() if decision.get("status") == "ABSTAINED"]
    validation = activity.get("validation")
    if not isinstance(validation, dict):
        legacy_status = activity.get("validator_result") or activity.get("validator_status")
        if legacy_status in {"PASS", "REVIEW", "FAIL", "NOT_RUN"}:
            validation = {"status": legacy_status, "reason": "Normalized from legacy validator metadata.", "source": "LEGACY_VALIDATOR_RESULT", "checks": []}
        else:
            validation = None
            warnings.append("Validation metadata unavailable for historical classification.")
    evidence_strength = getattr(classification, "evidence_strength", None) or activity.get("evidence_strength") or "UNKNOWN"
    return decisions, abstained, validation, evidence_strength, warnings


def confidence_summary(classification, decisions: dict) -> dict:
    """Expose model self-assessment separately from deterministic coverage."""
    confidence = getattr(classification, "model_confidence", None)
    if confidence is None:
        confidence = getattr(classification, "confidence", None)
    confidence = float(confidence or 0.0)
    assigned = sum(1 for d in decisions.values() if d.get("status") == "ASSIGNED")
    total = len(CLASSIFICATION_FIELDS)
    return {
        "semantics": "MODEL_SELF_REPORTED_UNCALIBRATED",
        "band": "HIGH" if confidence >= .85 else "MEDIUM" if confidence >= .70 else "LOW",
        "band_definition": "HIGH >= 0.85; MEDIUM 0.70-0.849; LOW < 0.70. Band uses raw model confidence only; field coverage is not applied.",
        "field_coverage": {"assigned": assigned, "total": total, "ratio": round(assigned / total, 3)},
    }
