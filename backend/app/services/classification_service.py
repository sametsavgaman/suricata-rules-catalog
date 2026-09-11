from dataclasses import dataclass
from sqlalchemy import select
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4
from sqlalchemy.orm import Session

from app.agent.classifier import ClassificationProvider
from app.agent.context import build_classification_context
from app.agent.schemas import ClassificationContext, ProviderResult, TokenUsage
from app.config import Settings
from app.database.models import (
    Classification,
    ClassificationRun,
    ClassificationStatus,
    CloudBatch,
    CloudBatchReservation,
    CloudReservationStatus,
    LocalClassificationClaim,
    ProductStatus,
    Rule,
    RuleProductDecision,
)
from app.enrichment.deterministic_enrichment import enrich_rule
from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule
from app.validation.classification_validator import ClassificationValidator
from app.knowledge.taxonomy import SUBCATEGORIES
from app.v2.tools import entity_candidates, extract_cves, search_mitre, search_similar_rules
from app.v2.pipeline import finalize
from app.v2.state import build_field_decisions
from app.v2.qwen_hardening import QWEN_SYSTEM_PROMPT, build_semantic_context, canonicalize, qwen_entity_candidates
from app.v2.mitre_decision import retrieve_candidates
from pathlib import Path
import hashlib
import json
from app.agent.prompt import SYSTEM_PROMPT


class CloudReservationConflict(RuntimeError):
    pass


class LocalOwnershipLost(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedClassification:
    parsed: ParsedRule
    context: ClassificationContext
    entity_candidates: list[dict]
    mitre_candidates: list[dict]
    tool_names: list[str]
    similar_rules: list[dict]
    qwen_mode: bool


def classification_context_sha256(context: ClassificationContext) -> str:
    payload = json.dumps(
        context.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def prepare_classification(
    rule: Rule,
    settings: Settings,
    mitre_repository: MitreRepository,
    *,
    provider_name: str,
) -> PreparedClassification:
    """Build the single canonical provider input without performing inference."""
    parsed = ParsedRule(
        raw_rule=rule.raw_rule,
        action=rule.action,
        protocol=rule.protocol,
        source=rule.source,
        source_port=rule.source_port,
        direction=rule.direction,
        destination=rule.destination,
        destination_port=rule.destination_port,
        sid=rule.sid,
        rev=rule.rev,
        msg=rule.msg,
        classtype=rule.classtype,
        metadata=rule.rule_metadata,
        references=rule.references,
        flow=rule.flow,
        flowbits=rule.flowbits,
        contents=rule.contents,
        pcre=rule.pcre,
        app_layer=rule.app_layer,
    )
    hints = enrich_rule(parsed)
    v2_data = None
    tool_names: list[str] = []
    v2_entity: list[dict] = []
    v2_mitre: list[dict] = []
    similar: list[dict] = []
    qwen_mode = provider_name == "ollama" and settings.classifier_version.casefold() in {
        "qwen-v2.2", "v2.2-qwen"
    }
    if settings.classifier_version.casefold().startswith("v2") or qwen_mode:
        v2_entity = entity_candidates(parsed)
        if qwen_mode:
            v2_entity = qwen_entity_candidates(parsed, v2_entity)
        tool_names.append("entity_candidates")
        v2_mitre = (
            retrieve_candidates(parsed, mitre_repository)
            if qwen_mode else search_mitre(parsed, mitre_repository)
        )
        tool_names.append("mitre_decision_layer" if qwen_mode else "search_mitre")
        cves = extract_cves(parsed)
        if cves:
            tool_names.append("lookup_cve")
        elif len(tool_names) < settings.max_tool_calls_per_rule:
            similar = search_similar_rules(
                parsed, Path(__file__).resolve().parents[3] / "data/evaluation/golden_dataset.jsonl"
            )
            tool_names.append("search_similar_rules")
        tool_names = tool_names[:settings.max_tool_calls_per_rule]
        controlled = {key.value: list(value) for key, value in SUBCATEGORIES.items()}
        if qwen_mode:
            controlled["__qwen_semantic_context__"] = [json.dumps(build_semantic_context(
                parsed,
                hints=hints,
                entity_candidates=v2_entity,
                mitre_candidates=v2_mitre,
                cves=cves,
                similar_rules=similar,
                controlled_subcategories={key.value: list(value) for key, value in SUBCATEGORIES.items()},
            ), ensure_ascii=False)]
        v2_data = {
            "classifier_version": settings.classifier_version if qwen_mode else "v2",
            "controlled_subcategories": controlled,
            "entity_candidates": v2_entity,
            "mitre_candidates": v2_mitre,
            "cve_context": cves,
            "similar_rules": similar,
        }
    context = build_classification_context(
        parsed,
        mitre_repository,
        max_contents=settings.max_agent_contents,
        max_content_chars=settings.max_agent_content_chars,
        hints=hints,
        v2_data=v2_data,
    )
    return PreparedClassification(
        parsed=parsed,
        context=context,
        entity_candidates=v2_entity,
        mitre_candidates=v2_mitre,
        tool_names=tool_names,
        similar_rules=similar,
        qwen_mode=qwen_mode,
    )


class ClassificationService:
    def __init__(
        self,
        db: Session,
        provider: ClassificationProvider,
        settings: Settings,
        mitre_repository: MitreRepository,
        cache_completion_filter=None,
        ownership_claim_id: str | None = None,
    ):
        self.db = db
        self.provider = provider
        self.settings = settings
        self.mitre_repository = mitre_repository
        self.validator = ClassificationValidator(mitre_repository)
        # Optional operational checkpoint proof; default cache behavior is unchanged.
        self.cache_completion_filter = cache_completion_filter
        self.ownership_claim_id = ownership_claim_id

    async def classify(self, rule: Rule, force: bool = False) -> Classification:
        provider_name = (
            getattr(self.provider, "provider_name", None)
            or self.provider.__class__.__name__.replace("ClassificationProvider", "").lower()
            or "unknown"
        )
        model_name = self.provider.model_name
        if not force:
            cached = self.db.scalar(
                select(Classification)
                .where(
                    Classification.rule_id == rule.id,
                    Classification.provider == provider_name,
                    Classification.model_name == model_name,
                    Classification.classifier_version == self.settings.classifier_version,
                    Classification.classification_status != ClassificationStatus.FAILED,
                    self.cache_completion_filter if self.cache_completion_filter is not None else True,
                )
                .order_by(Classification.created_at.desc())
            )
            if cached:
                cached._cache_hit = True
                cached._token_usage = TokenUsage()
                return cached

        inference_mode = getattr(self.provider, "inference_mode", "API")
        if provider_name == "ollama" and not str(inference_mode).startswith("CLOUD"):
            reserved = self.db.scalar(
                select(CloudBatchReservation.id)
                .join(CloudBatch, CloudBatch.batch_id == CloudBatchReservation.batch_id)
                .where(
                    CloudBatchReservation.rule_id == rule.id,
                    CloudBatchReservation.status == CloudReservationStatus.RESERVED,
                    CloudBatch.target_provider == provider_name,
                    CloudBatch.target_model == model_name,
                    CloudBatch.classifier_version == self.settings.classifier_version,
                )
            )
            if reserved is not None:
                raise CloudReservationConflict("RULE_RESERVED_FOR_CLOUD_BATCH")

        run_id = f"{provider_name}-{self.settings.classifier_version}-{uuid4().hex[:12]}"
        display_name = {"gemini-3.5-flash-lite": "Gemini 3.5 Flash Lite", "qwen3:8b": "Qwen3 8B"}.get(model_name, model_name)
        run = ClassificationRun(run_id=run_id, provider=provider_name, model_name=model_name,
                                model_display_name=display_name, classifier_version=self.settings.classifier_version,
                                inference_mode=inference_mode,
                                started_at=datetime.now(timezone.utc), total_rules=1, configuration_json=getattr(self.provider, "configuration", {}), rule_id=rule.id)
        self.db.add(run); self.db.flush(); started = perf_counter()
        prepared = prepare_classification(
            rule, self.settings, self.mitre_repository, provider_name=provider_name
        )
        parsed = prepared.parsed
        context = prepared.context
        v2_entity = prepared.entity_candidates
        v2_mitre = prepared.mitre_candidates
        tool_names = prepared.tool_names
        similar = prepared.similar_rules
        qwen_mode = prepared.qwen_mode
        run.configuration_json = {**run.configuration_json,
            "context_sha256": classification_context_sha256(context),
            "prompt_sha256": hashlib.sha256((QWEN_SYSTEM_PROMPT if qwen_mode else SYSTEM_PROMPT).encode()).hexdigest()}
        # Record the attempt without holding a SQLite write lock during inference.
        # The final classification and its canonical state are still saved together.
        self.db.commit()
        if self.ownership_claim_id:
            # Fresh transaction/state check immediately before the provider call.
            # The durable claim is the local side of the same rule-lock invariant
            # used by cloud export; a vanished/replaced claim must never infer.
            owned = self.db.scalar(select(LocalClassificationClaim.rule_id).where(
                LocalClassificationClaim.rule_id == rule.id,
                LocalClassificationClaim.claim_id == self.ownership_claim_id,
                LocalClassificationClaim.target_provider == provider_name,
                LocalClassificationClaim.target_model == model_name,
                LocalClassificationClaim.classifier_version == self.settings.classifier_version,
                LocalClassificationClaim.expires_at > datetime.now(timezone.utc),
            ))
            cloud_reserved = self.db.scalar(select(CloudBatchReservation.id).where(
                CloudBatchReservation.rule_id == rule.id,
                CloudBatchReservation.status == CloudReservationStatus.RESERVED,
            ))
            completion_filter = (
                self.cache_completion_filter
                if self.cache_completion_filter is not None
                else Classification.classification_status != ClassificationStatus.FAILED
            )
            completed = self.db.scalar(select(Classification.id).where(
                Classification.rule_id == rule.id,
                Classification.provider == provider_name,
                Classification.model_name == model_name,
                Classification.classifier_version == self.settings.classifier_version,
                completion_filter,
            ))
            if not owned or cloud_reserved or completed:
                raise LocalOwnershipLost("LOCAL_OWNERSHIP_LOST_BEFORE_INFERENCE")
        try:
            provider_result = await self.provider.classify(context)
            if isinstance(provider_result, ProviderResult):
                output = provider_result.output
                usage = provider_result.usage
            else:  # Backwards compatible with simple/fake V1 providers.
                output = provider_result
                usage = TokenUsage()
            if not hasattr(output, "model_dump"):
                from app.agent.schemas import ClassificationOutput
                output = ClassificationOutput.model_validate(output)
            activity={}
            if qwen_mode:
                output, qwen_reasons = canonicalize(output, rule=parsed, mitre_candidates=v2_mitre, repository=self.mitre_repository)
            else:
                qwen_reasons = []
            if self.settings.classifier_version.casefold().startswith("v2") or qwen_mode:
                output,activity_obj=finalize(output,rule=parsed,entity_candidates=v2_entity,mitre_candidates=v2_mitre,tool_names=tool_names,similar_count=len(similar)); activity=activity_obj.as_dict()
                if qwen_reasons:
                    activity.setdefault("qwen_normalization", {})["reason_codes"] = qwen_reasons
                    activity["qwen_normalization"]["input_version"] = "qwen_semantic_input_v2"
            validation = self.validator.validate(output, activity)
            values = output.model_dump(mode="json")
            decisions = activity.get("field_decisions") or build_field_decisions(values, activity.get("abstained_fields", []), legacy=False)
            activity["field_decisions"] = decisions
            activity["abstained_fields"] = [name for name, decision in decisions.items() if decision.get("status") == "ABSTAINED"]
            activity["validation"] = {
                "status": "REVIEW" if validation.review_required else "PASS",
                "reason": "; ".join(validation.issues) if validation.issues else "Classification satisfies evidence and taxonomy checks.",
                "checks": list(validation.issues),
                "deterministic_validator": {"status": "REVIEW" if validation.review_required else "PASS"},
                "semantic_verifier": {"status": activity.get("verifier_verdict", "NOT_RUN")},
            }
            record = Classification(
                rule_id=rule.id,
                **output.model_dump(mode="json"),
                model_name=model_name,
                provider=provider_name,
                classifier_version=self.settings.classifier_version,
                agent_activity=activity,
                classification_status=(
                    ClassificationStatus.REVIEW_REQUIRED if validation.review_required else ClassificationStatus.AUTO_CLASSIFIED
                ),
                validation_issues=list(validation.issues),
                source_mitre_mapping=activity.get("source_mitre_mapping"), final_mitre_mapping=activity.get("final_mitre_mapping"),
                mitre_mapping_method=activity.get("mitre_mapping_method"), mapping_reason=activity.get("mapping_reason"),
                mitre_retrieval_score=activity.get("mitre_retrieval_score"), evidence_strength=activity.get("evidence_strength"),
                model_confidence=activity.get("model_confidence"), validator_mitre_status=activity.get("validator_mitre_status"),
                run_id=run_id, classification_run_id=run.id, model_display_name=display_name,
                inference_mode=run.inference_mode, model_config_json=run.configuration_json,
                inference_duration_ms=round((perf_counter() - started) * 1000, 2),
            )
        except Exception as exc:
            record = Classification(
                rule_id=rule.id,
                model_name=model_name,
                provider=provider_name,
                run_id=run_id, classification_run_id=run.id, model_display_name=display_name,
                inference_mode=run.inference_mode, model_config_json=run.configuration_json,
                inference_duration_ms=round((perf_counter() - started) * 1000, 2),
                classifier_version=self.settings.classifier_version,
                agent_activity={},
                classification_status=ClassificationStatus.FAILED,
                confidence=0.0,
                evidence=[],
                explanation=str(exc)[:800],
                validation_issues=[type(exc).__name__],
            )
        run.completed_at = datetime.now(timezone.utc)
        run.successful_rules = int(record.classification_status != ClassificationStatus.FAILED)
        run.failed_rules = int(record.classification_status == ClassificationStatus.FAILED)
        self.db.add(record)
        # Product planning is a separate human decision. Ensure every
        # successfully classified rule appears in the product workspace as
        # NOT_EVALUATED, without auto-promoting it to CANDIDATE.
        if record.classification_status != ClassificationStatus.FAILED and not self.db.scalar(
            select(RuleProductDecision).where(RuleProductDecision.rule_id == rule.id)
        ):
            self.db.add(RuleProductDecision(rule_id=rule.id, status=ProductStatus.NOT_EVALUATED))
        self.db.commit()
        self.db.refresh(record)
        # Latest-classification aggregates are cached for the catalogue UI;
        # a new provider result must be visible immediately after this commit.
        try:
            from app.api.catalog import clear_catalog_facets_cache
            clear_catalog_facets_cache()
        except Exception:
            pass
        # Family enrichment is a separate deterministic catalogue projection.
        # Classification has already been durably committed; enrichment failure
        # must never turn a valid provider result into a failed classification.
        if record.classification_status != ClassificationStatus.FAILED:
            try:
                from app.services.detection_families import assign_if_unassigned
                assign_if_unassigned(self.db, rule, record)
                self.db.commit()
            except Exception:
                self.db.rollback()
        record._cache_hit = False
        record._token_usage = usage if "usage" in locals() else TokenUsage()
        return record
