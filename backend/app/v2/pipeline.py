from dataclasses import dataclass, field
from app.agent.schemas import ClassificationOutput
from app.knowledge.taxonomy import Category, SUBCATEGORIES, canonical_subcategory
from app.parser.models import ParsedRule
from app.v2.tools import source_mitre_mapping
from app.v2.state import build_field_decisions

@dataclass
class V2Activity:
    tools_used:list[str]; mitre_candidates:list[dict]; entity_candidates:list[dict]; similar_rules_count:int; abstained_fields:list[str]; validator_result:str; verifier_verdict:str; tool_calls:int
    metadata: dict = field(default_factory=dict)
    def as_dict(self):
        data = {k: v for k, v in self.__dict__.items() if k != "metadata"}
        data.update(self.metadata)
        return data

def infer_subcategory(rule: ParsedRule, category) -> str | None:
    text=(rule.msg or "").casefold(); protocol=rule.protocol.casefold()
    if category==Category.REMOTE_ACCESS: return "Remote Access Software" if any(x in text for x in ("anydesk","teamviewer","screenconnect","remote access")) else "Remote Desktop" if "rdp" in text else None
    if category==Category.COMMAND_AND_CONTROL:
        if protocol=="dns" or "dns lookup" in text:return "DNS C2 Communication"
        if protocol=="tls" or "tls sni" in text:return "TLS C2 Communication"
        if protocol.startswith("http"):return "HTTP C2 Communication"
        return "C2 Communication"
    if category==Category.CREDENTIAL_ACCESS:
        if "brute" in text or "login failure" in text:return "Brute Force"
        if "pwdump" in text or "credential dump" in text:return "Credential Dumping"
        return "Credential Activity"
    if category==Category.WEB_ATTACK:
        if "sql injection" in text or "union select" in text:return "SQL Injection"
        if "cross site scripting" in text or "xss" in text:return "Cross-Site Scripting"
        if "webshell" in text or "backdoor" in text:return "Web Shell"
        if "command injection" in text:return "Command Injection"
        if "path traversal" in text or "directory traversal" in text:return "Path Traversal"
        # Generic web exploit/scan labels are not members of the controlled
        # Web Attack taxonomy. Abstain instead of manufacturing a review item.
        return None
    if category==Category.RECONNAISSANCE:
        if "user-agent" in text or "scanner" in text or "census" in text:return "Web Scan"
        if "port" in text:return "Service Scan"
    if category==Category.NETWORK_ABUSE and "phish" in text:return "Phishing Infrastructure"
    if category==Category.SUSPICIOUS_DNS:return "Unusual DNS Query"
    if category==Category.POLICY_VIOLATION:return "Prohibited Application or Protocol"
    if category==Category.OTHER:return "Informational Activity"
    if category==Category.MALWARE:return "Malware Network Activity"
    if category==Category.EXPLOITATION:return "Exploit Attempt"
    return None

def finalize(output: ClassificationOutput, *, rule:ParsedRule, entity_candidates:list[dict], mitre_candidates:list[dict], tool_names:list[str], similar_count:int):
    data=output.model_dump(); abstained=[]; issues=[]
    sub=infer_subcategory(rule,output.category) or canonical_subcategory(output.category,output.subcategory)
    if output.subcategory and sub is None: issues.append("subcategory_not_allowlisted"); abstained.append("subcategory")
    data["subcategory"]=sub
    strong=[x for x in entity_candidates if not x.get("weak")]
    matched=next((x for x in strong if output.detected_entity and x["candidate"].casefold() in output.detected_entity.casefold()),None)
    if output.detected_entity and not matched:
        data["detected_entity"]=None; data["entity_type"]=None; abstained += ["detected_entity","entity_type"]; issues.append("entity_evidence_insufficient")
    elif matched:
        data["detected_entity"]=matched["candidate"]; data["entity_type"]=matched["entity_type"]
    elif len(strong) == 1 and strong[0].get("deterministic"):
        # A single explicit name in rule evidence is safer than preserving an
        # unnecessary model abstention. Ambiguous multi-candidate rules still
        # require the model (or a reviewer) to select the detected subject.
        data["detected_entity"]=strong[0]["candidate"]
        data["entity_type"]=strong[0]["entity_type"]
        data["evidence"] = list(dict.fromkeys(output.evidence + [
            f"entity_candidate:{strong[0]['candidate']}:{strong[0]['evidence_type']}"
        ]))[:10]
        data["explanation"] = (
            output.explanation.rstrip()
            + f" Entity was deterministically resolved as {strong[0]['candidate']} from explicit rule evidence."
        )[:800]
    allowed={x["id"]:x for x in mitre_candidates}
    candidate=allowed.get(output.mitre_technique_id)
    if output.mitre_technique_id and (not candidate or candidate["score"]<.5):
        data.update(mitre_tactic=None,mitre_technique=None,mitre_technique_id=None); abstained += ["mitre_tactic","mitre_technique","mitre_technique_id"]; issues.append("mitre_not_grounded")
    elif candidate:
        data["mitre_technique"]=candidate["name"]; data["mitre_tactic"]=candidate["tactics"][0] if candidate["tactics"] else None
    if data["cyber_kill_chain_phase"] and data["category"] in {Category.OTHER,Category.POLICY_VIOLATION,Category.SUSPICIOUS_DNS}:
        data["cyber_kill_chain_phase"]=None; abstained.append("cyber_kill_chain_phase"); issues.append("kill_chain_evidence_insufficient")
    # Preserve provider evidence but add explicit operational evidence without hidden reasoning.
    data["evidence"]=list(dict.fromkeys(output.evidence + [f"entity_candidate:{x['candidate']}:{x['evidence_type']}" for x in strong][:3] + [f"mitre_candidate:{x['id']}:{x['score']:.2f}" for x in mitre_candidates][:3]))[:10]
    final=ClassificationOutput.model_validate(data)
    repository = __import__("app.knowledge.mitre_repository", fromlist=["MitreRepository"]).MitreRepository()
    source_obj = source_mitre_mapping(rule, repository)
    source_id = source_obj.get("technique_id") if source_obj else None
    final_id = final.mitre_technique_id
    if not final_id: method = "NO_SUPPORTED_MAPPING"; reason = "No supported final MITRE mapping survived canonical validation."
    elif source_id and source_id == final_id: method = "EXACT_SOURCE_MAPPING"; reason = "Final mapping matches the technique ID explicitly present in Suricata metadata."
    elif source_id and repository.get(final_id) and repository.get(final_id).parent_id == source_id: method = "DERIVED_SUBTECHNIQUE"; reason = f"Source metadata identifies {source_id}; canonical child relation supports {final_id}."
    elif source_id: method = "SOURCE_MAPPING_OVERRIDDEN"; reason = f"Source metadata mapping {source_id} differs from the final retrieved mapping {final_id}; review is recommended."
    else: method = "INFERRED_MAPPING"; reason = "No MITRE ID was present in metadata; final mapping came from behavior and retrieval evidence."
    retrieval_score = next((float(x.get("score", 0.0)) for x in mitre_candidates if x.get("id") == final_id), None)
    evidence_strength = "STRONG" if source_id and source_id == final_id else "MEDIUM" if final_id else "NONE"
    verdict="PASS" if not issues else ("REVIEW" if len(issues)<3 else "FAIL")
    activity=V2Activity(tool_names,mitre_candidates,entity_candidates,similar_count,abstained,"PASS" if not issues else "WARN",verdict,len(tool_names))
    activity.metadata.update(source_mitre_mapping=source_obj, final_mitre_mapping=({"technique_id": final_id, "technique_name": final.mitre_technique, "tactic": final.mitre_tactic} if final_id else None), mitre_mapping_method=method, mapping_reason=reason, mitre_retrieval_score=retrieval_score, evidence_strength=evidence_strength, model_confidence=final.confidence, validator_mitre_status={"EXACT_SOURCE_MAPPING":"PASS_EXACT","DERIVED_SUBTECHNIQUE":"PASS_WITH_ENRICHMENT","INFERRED_MAPPING":"PASS_INFERRED","SOURCE_MAPPING_OVERRIDDEN":"REVIEW_OVERRIDE","NO_SUPPORTED_MAPPING":"NO_MAPPING"}[method])
    activity.metadata["field_decisions"] = build_field_decisions(data, abstained, legacy=False)
    activity.metadata["abstained_fields"] = [k for k, v in activity.metadata["field_decisions"].items() if v["status"] == "ABSTAINED"]
    return final,activity
