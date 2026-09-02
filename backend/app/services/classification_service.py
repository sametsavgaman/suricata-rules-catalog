from sqlalchemy import select
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4
from sqlalchemy.orm import Session

from app.agent.classifier import ClassificationProvider
from app.agent.context import build_classification_context
from app.agent.schemas import ProviderResult, TokenUsage
from app.config import Settings
from app.database.models import Classification, ClassificationRun, ClassificationStatus, Rule
from app.enrichment.deterministic_enrichment import enrich_rule
from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule
from app.validation.classification_validator import ClassificationValidator
from app.knowledge.taxonomy import SUBCATEGORIES
from app.v2.tools import entity_candidates, extract_cves, search_mitre, search_similar_rules
from app.v2.pipeline import finalize
from app.v2.state import build_field_decisions
from pathlib import Path


class ClassificationService:
    def __init__(
        self,
        db: Session,
        provider: ClassificationProvider,
        settings: Settings,
        mitre_repository: MitreRepository,
    ):
        self.db = db
        self.provider = provider
        self.settings = settings
        self.mitre_repository = mitre_repository
        self.validator = ClassificationValidator(mitre_repository)

    async def classify(self, rule: Rule, force: bool = False) -> Classification:
        provider_name = self.provider.__class__.__name__.replace("ClassificationProvider", "").lower() or "unknown"
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
                )
                .order_by(Classification.created_at.desc())
            )
            if cached:
                cached._cache_hit = True
                cached._token_usage = TokenUsage()
                return cached

        run_id = f"{provider_name}-{self.settings.classifier_version}-{uuid4().hex[:12]}"
        display_name = {"gemini-3.5-flash-lite": "Gemini 3.5 Flash Lite", "qwen3:8b": "Qwen3 8B"}.get(model_name, model_name)
        run = ClassificationRun(run_id=run_id, provider=provider_name, model_name=model_name,
                                model_display_name=display_name, classifier_version=self.settings.classifier_version,
                                inference_mode="API" if provider_name == "gemini" else "LOCAL",
                                started_at=datetime.now(timezone.utc), total_rules=1, configuration_json={}, rule_id=rule.id)
        self.db.add(run); self.db.flush(); started = perf_counter()
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
        v2_data=None; tool_names=[]; v2_entity=[]; v2_mitre=[]; similar=[]
        if self.settings.classifier_version.casefold().startswith("v2"):
            v2_entity=entity_candidates(parsed); tool_names.append("entity_candidates")
            v2_mitre=search_mitre(parsed,self.mitre_repository); tool_names.append("search_mitre")
            cves=extract_cves(parsed)
            if cves: tool_names.append("lookup_cve")
            elif len(tool_names)<self.settings.max_tool_calls_per_rule:
                similar=search_similar_rules(parsed,Path(__file__).resolve().parents[3]/"data/evaluation/golden_dataset.jsonl"); tool_names.append("search_similar_rules")
            tool_names=tool_names[:self.settings.max_tool_calls_per_rule]
            v2_data={"classifier_version":"v2","controlled_subcategories":{k.value:list(v) for k,v in SUBCATEGORIES.items()},"entity_candidates":v2_entity,"mitre_candidates":v2_mitre,"cve_context":cves,"similar_rules":similar}
        context = build_classification_context(
            parsed, self.mitre_repository, max_contents=self.settings.max_agent_contents,
            max_content_chars=self.settings.max_agent_content_chars, hints=hints, v2_data=v2_data,
        )
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
            if self.settings.classifier_version.casefold().startswith("v2"): output,activity_obj=finalize(output,rule=parsed,entity_candidates=v2_entity,mitre_candidates=v2_mitre,tool_names=tool_names,similar_count=len(similar)); activity=activity_obj.as_dict()
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
                inference_mode=run.inference_mode, model_config_json={},
                inference_duration_ms=round((perf_counter() - started) * 1000, 2),
            )
        except Exception as exc:
            record = Classification(
                rule_id=rule.id,
                model_name=model_name,
                provider=provider_name,
                run_id=run_id, classification_run_id=run.id, model_display_name=display_name,
                inference_mode=run.inference_mode, model_config_json={},
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
        self.db.commit()
        self.db.refresh(record)
        record._cache_hit = False
        record._token_usage = usage if "usage" in locals() else TokenUsage()
        return record
