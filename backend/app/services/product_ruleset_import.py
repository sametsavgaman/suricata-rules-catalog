from datetime import datetime, timezone

from sqlalchemy import select

from app.agent.factory import create_classification_provider, provider_config_error
from app.config import get_settings
from app.database.models import (
    Classification,
    ClassificationStatus,
    ProductRulesetImportBatch,
    ProductRulesetImportItem,
    Rule,
)
from app.database.session import SessionLocal
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService
from app.services.runtime_config import effective_settings


TERMINAL_ITEM_STATUSES = {"REUSED", "AUTO_CLASSIFIED", "REVIEW_REQUIRED", "FAILED"}


def _successful_classification(db, rule_id: int) -> Classification | None:
    return db.scalar(
        select(Classification)
        .where(
            Classification.rule_id == rule_id,
            Classification.classification_status != ClassificationStatus.FAILED,
        )
        .order_by(Classification.id.desc())
    )


def _refresh_counts(db, batch: ProductRulesetImportBatch) -> None:
    items = list(db.scalars(select(ProductRulesetImportItem).where(
        ProductRulesetImportItem.batch_id == batch.batch_id
    )))
    batch.processed = sum(item.status in TERMINAL_ITEM_STATUSES for item in items)
    batch.auto_classified = sum(item.status == "AUTO_CLASSIFIED" for item in items)
    batch.review_required = sum(item.status == "REVIEW_REQUIRED" for item in items)
    batch.failed = sum(item.status == "FAILED" for item in items)


async def process_product_ruleset_batch(batch_id: str) -> None:
    """Classify only rules queued by a product-ruleset import, always with Gemini."""
    with SessionLocal() as db:
        batch = db.get(ProductRulesetImportBatch, batch_id)
        if batch is None or batch.status == "RUNNING":
            return
        settings = effective_settings(db, get_settings()).model_copy(update={
            "ai_provider": "gemini",
            "classifier_version": "v2.1",
        })
        configuration_error = provider_config_error(settings)
        if configuration_error:
            batch.status = "FAILED"
            batch.model_name = settings.gemini_model
            batch.error_message = configuration_error
            batch.completed_at = datetime.now(timezone.utc)
            db.commit()
            return

        batch.status = "RUNNING"
        batch.model_name = settings.gemini_model
        batch.error_message = None
        batch.completed_at = None
        db.commit()

        service = ClassificationService(
            db,
            create_classification_provider(settings),
            settings,
            MitreRepository(),
        )
        items = list(db.scalars(
            select(ProductRulesetImportItem)
            .where(
                ProductRulesetImportItem.batch_id == batch_id,
                ProductRulesetImportItem.status == "PENDING",
            )
            .order_by(ProductRulesetImportItem.id)
        ))
        for item in items:
            rule = db.get(Rule, item.rule_id)
            if rule is None:
                item.status = "FAILED"
                item.error_message = "RULE_NOT_FOUND"
                item.completed_at = datetime.now(timezone.utc)
                _refresh_counts(db, batch)
                db.commit()
                continue

            existing = _successful_classification(db, rule.id)
            if existing is not None:
                item.status = "REUSED"
                item.classification_id = existing.id
                item.completed_at = datetime.now(timezone.utc)
                batch.reused_classifications += 1
                _refresh_counts(db, batch)
                db.commit()
                continue

            item.status = "RUNNING"
            item.error_message = None
            db.commit()
            try:
                result = await service.classify(rule)
                activity = dict(result.agent_activity or {})
                activity["classification_trigger"] = "PRODUCT_RULESET_IMPORT"
                activity["product_ruleset_batch_id"] = batch_id
                result.agent_activity = activity
                result.inspection_batch = batch_id
                item.classification_id = result.id
                if result.classification_status == ClassificationStatus.AUTO_CLASSIFIED:
                    item.status = "AUTO_CLASSIFIED"
                elif result.classification_status == ClassificationStatus.REVIEW_REQUIRED:
                    item.status = "REVIEW_REQUIRED"
                else:
                    item.status = "FAILED"
                    item.error_message = result.explanation
                db.commit()
            except Exception as exc:
                db.rollback()
                item = db.get(ProductRulesetImportItem, item.id)
                batch = db.get(ProductRulesetImportBatch, batch_id)
                item.status = "FAILED"
                item.error_message = str(exc)[:800]
            item.completed_at = datetime.now(timezone.utc)
            _refresh_counts(db, batch)
            db.commit()

        _refresh_counts(db, batch)
        batch.status = "PARTIAL_FAILED" if batch.failed else "COMPLETED"
        batch.completed_at = datetime.now(timezone.utc)
        db.commit()


def retry_product_ruleset_batch(batch_id: str) -> bool:
    with SessionLocal() as db:
        batch = db.get(ProductRulesetImportBatch, batch_id)
        if batch is None or batch.status == "RUNNING":
            return False
        items = list(db.scalars(select(ProductRulesetImportItem).where(
            ProductRulesetImportItem.batch_id == batch_id,
            ProductRulesetImportItem.status == "FAILED",
        )))
        for item in items:
            item.status = "PENDING"
            item.classification_id = None
            item.error_message = None
            item.completed_at = None
        batch.status = "PENDING"
        batch.error_message = None
        batch.completed_at = None
        _refresh_counts(db, batch)
        db.commit()
        return True
