from app.enrichment.deterministic_enrichment import EnrichmentHints
from app.evaluation.schemas import AnnotationProposal, EvidenceItem
from app.parser.models import ParsedRule


def generate_evidence(rule: ParsedRule, proposal: AnnotationProposal, hints: EnrichmentHints) -> list[EvidenceItem]:
    """Return short, auditable evidence snippets; never expose hidden reasoning."""
    items: list[EvidenceItem] = []
    if rule.msg:
        items.append(EvidenceItem(field="detected_behavior", source="msg", value=rule.msg))
    if rule.protocol:
        items.append(EvidenceItem(field="protocol", source="parsed.protocol", value=rule.protocol))
    if rule.source_port or rule.destination_port:
        items.append(EvidenceItem(field="ports", source="parsed.ports", value=f"src={rule.source_port or 'any'} dst={rule.destination_port or 'any'}"))
    if rule.contents:
        items.append(EvidenceItem(field="content", source="parsed.contents", value="; ".join(rule.contents[:3])))
    if rule.pcre:
        items.append(EvidenceItem(field="pcre", source="parsed.pcre", value="; ".join(rule.pcre[:2])))
    if rule.app_layer:
        items.append(EvidenceItem(field="app_layer", source="parsed.app_layer", value=", ".join(str(x) for x in rule.app_layer[:3])))
    if rule.classtype:
        items.append(EvidenceItem(field="classtype", source="rule.classtype", value=rule.classtype))
    if rule.metadata:
        items.append(EvidenceItem(field="metadata", source="rule.metadata", value="; ".join(rule.metadata[:4])))
    if hints.entity_hint:
        items.append(EvidenceItem(field="detected_entity", source="deterministic_hint", value=hints.entity_hint))
    if proposal.mitre_technique_id:
        items.append(EvidenceItem(field="mitre_technique_id", source="proposal_mapping", value=proposal.mitre_technique_id))
    return items
