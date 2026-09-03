from fastapi import Depends
from typing import Literal
from sqlalchemy.orm import Session

from app.agent.factory import create_classification_provider
from app.config import get_settings
from app.database.session import get_db
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService


_mitre_repository = MitreRepository()


def get_classification_service(db: Session = Depends(get_db), execution_provider: Literal["gemini", "ollama"] | None = None) -> ClassificationService:
    settings = get_settings()
    if execution_provider:
        settings = settings.model_copy(update={"ai_provider": execution_provider, "classifier_version": "v2.1"})
    provider = create_classification_provider(settings)
    return ClassificationService(db, provider, settings, _mitre_repository)
