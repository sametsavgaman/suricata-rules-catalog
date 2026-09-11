from app.agent.schemas import ClassificationContext
from app.enrichment.deterministic_enrichment import EnrichmentHints, enrich_rule
from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule


def build_classification_context(
    rule: ParsedRule,
    repository: MitreRepository,
    *,
    max_contents: int = 20,
    max_content_chars: int = 12000,
    max_pcre: int = 10,
    max_app_layer: int = 20,
    hints: EnrichmentHints | None = None,
    v2_data: dict | None = None,
) -> ClassificationContext:
    hints = hints or enrich_rule(rule)
    remaining = max_content_chars
    contents: list[str] = []
    for item in rule.contents[:max_contents]:
        if remaining <= 0:
            break
        value = item[:remaining]
        contents.append(value)
        remaining -= len(value)
    extra = dict(v2_data or {})
    mitre_candidates = extra.pop("mitre_candidates", repository.compact_context())
    return ClassificationContext(
        sid=rule.sid, msg=rule.msg, protocol=rule.protocol, classtype=rule.classtype,
        metadata=rule.metadata, references=rule.references, flow=rule.flow,
        flowbits=rule.flowbits, content=contents, pcre=rule.pcre[:max_pcre],
        app_layer=rule.app_layer[:max_app_layer], entity_hint=hints.entity_hint,
        category_hint=hints.category_hint, mitre_candidates=mitre_candidates,
        **extra,
    )
