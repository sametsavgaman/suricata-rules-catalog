import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str = ""
    parent_id: str | None = None
    source: str = "LOCAL_REPOSITORY"


class MitreRepository:
    """Small V1 repository; accepts an ingestible ATT&CK-derived JSON list."""

    def __init__(self, path: Path | None = None):
        self.path = path or Path(__file__).resolve().parents[3] / "data" / "mitre" / "enterprise-techniques.json"
        self._techniques: dict[str, MitreTechnique] | None = None

    def all(self) -> list[MitreTechnique]:
        if self._techniques is None:
            data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else []
            self._techniques = {
                item["technique_id"]: MitreTechnique(
                    technique_id=item["technique_id"],
                    name=item["name"],
                    tactics=tuple(item.get("tactics", [])),
                    description=item.get("description", ""),
                    parent_id=item.get("parent_id"),
                    source=item.get("source", "LOCAL_REPOSITORY"),
                )
                for item in data
            }
        return list(self._techniques.values())

    def get(self, technique_id: str) -> MitreTechnique | None:
        self.all()
        return self._techniques.get(technique_id) if self._techniques else None

    def compact_context(self) -> list[dict]:
        return [{"id": item.technique_id, "name": item.name, "tactics": item.tactics} for item in self.all()]
