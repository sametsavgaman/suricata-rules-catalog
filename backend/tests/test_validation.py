import json

from app.agent.schemas import ClassificationOutput
from app.knowledge.mitre_repository import MitreRepository
from app.validation.classification_validator import ClassificationValidator


def make_repository(tmp_path):
    path = tmp_path / "mitre.json"
    path.write_text(json.dumps([{"technique_id": "T1046", "name": "Network Service Scanning", "tactics": ["Discovery"]}]), encoding="utf-8")
    return MitreRepository(path)


def output(**overrides):
    data = dict(
        detected_behavior="TCP SYN network scanning",
        detected_entity="Nmap",
        entity_type="Attack Tool",
        category="Reconnaissance",
        subcategory="Port Scan",
        mitre_tactic="Discovery",
        mitre_technique="Network Service Scanning",
        mitre_technique_id="T1046",
        cyber_kill_chain_phase="Reconnaissance",
        confidence=0.95,
        evidence=["NMAP appears in msg"],
        explanation="Direct signature evidence.",
    )
    data.update(overrides)
    return ClassificationOutput(**data)


def test_valid_mitre_mapping(tmp_path):
    assert ClassificationValidator(make_repository(tmp_path)).validate(output()).valid


def test_partial_mitre_mapping_requires_review(tmp_path):
    result = ClassificationValidator(make_repository(tmp_path)).validate(output(mitre_tactic=None))
    assert result.review_required


def test_mismatched_mitre_name_requires_review(tmp_path):
    result = ClassificationValidator(make_repository(tmp_path)).validate(output(mitre_technique="OS Credential Dumping"))
    assert "does not match" in " ".join(result.issues)

