import re
from dataclasses import dataclass

from app.agent.schemas import ClassificationOutput
from app.knowledge.mitre_repository import MitreRepository
from app.knowledge.taxonomy import SUBCATEGORIES


MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    review_required: bool
    issues: tuple[str, ...]


class ClassificationValidator:
    def __init__(self, mitre_repository: MitreRepository):
        self.mitre_repository = mitre_repository

    def validate(self, output: ClassificationOutput, provenance: dict | None = None) -> ValidationResult:
        issues: list[str] = []
        if output.subcategory and output.category and output.subcategory not in SUBCATEGORIES.get(output.category, ()):
            issues.append("Subcategory is not in the controlled taxonomy for its category")
        if output.detected_entity and not any(output.detected_entity.casefold() in item.casefold() for item in output.evidence):
            issues.append("Entity has no explicit evidence")
        mitre_fields = [output.mitre_tactic, output.mitre_technique, output.mitre_technique_id]
        if any(mitre_fields) and not all(mitre_fields):
            issues.append("MITRE tactic, technique and ID must be set together")
        if output.mitre_technique_id:
            if not MITRE_ID_PATTERN.fullmatch(output.mitre_technique_id):
                issues.append("MITRE technique ID has an invalid format")
            else:
                technique = self.mitre_repository.get(output.mitre_technique_id)
                if not technique:
                    issues.append("MITRE technique ID is not present in the local repository")
                elif output.mitre_technique != technique.name:
                    issues.append("MITRE technique name does not match its ID")
                elif output.mitre_tactic not in technique.tactics:
                    issues.append("MITRE tactic is not valid for the selected technique")
        if provenance:
            method = provenance.get("mitre_mapping_method"); source = provenance.get("source_mitre_mapping") or {}; final = provenance.get("final_mitre_mapping") or {}
            source_id, final_id = source.get("technique_id"), final.get("technique_id")
            if method == "EXACT_SOURCE_MAPPING" and source_id != final_id: issues.append("MITRE provenance exact mapping mismatch")
            elif method == "DERIVED_SUBTECHNIQUE" and not (source_id and final_id and self.mitre_repository.get(final_id) and self.mitre_repository.get(final_id).parent_id == source_id): issues.append("MITRE derived sub-technique is not canonical")
            elif method == "INFERRED_MAPPING" and source_id: issues.append("MITRE inferred mapping has source metadata")
            elif method == "SOURCE_MAPPING_OVERRIDDEN" and (not source_id or source_id == final_id): issues.append("MITRE override provenance mismatch")
            elif method == "NO_SUPPORTED_MAPPING" and any((output.mitre_tactic, output.mitre_technique, output.mitre_technique_id)): issues.append("MITRE no-mapping provenance has final fields")

        text = " ".join(filter(None, [output.detected_behavior, output.subcategory])).lower()
        incompatible = {
            "port scan": {"T1003"},
            "network scanning": {"T1003"},
            "credential dumping": {"T1046"},
        }
        for phrase, forbidden_ids in incompatible.items():
            if phrase in text and output.mitre_technique_id in forbidden_ids:
                issues.append(f"Behavior '{phrase}' conflicts with {output.mitre_technique_id}")
        if output.confidence >= 0.85 and not output.evidence:
            issues.append("High-confidence classification has no evidence")
        return ValidationResult(valid=not issues, review_required=bool(issues), issues=tuple(issues))
