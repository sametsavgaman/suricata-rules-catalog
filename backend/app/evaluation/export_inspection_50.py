"""Export raw/parsed/input/output/final views for a completed 50-rule run."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from sqlalchemy import select
from app.agent.context import build_classification_context
from app.agent.schemas import ClassificationContext
from app.config import get_settings
from app.database.models import Rule
from app.database.session import SessionLocal
from app.enrichment.deterministic_enrichment import enrich_rule
from app.knowledge.mitre_repository import MitreRepository
from app.knowledge.taxonomy import SUBCATEGORIES
from app.parser.models import ParsedRule
from app.v2.qwen_hardening import build_semantic_context, qwen_entity_candidates
from app.v2.tools import entity_candidates, extract_cves, search_mitre, search_similar_rules

ROOT=Path(__file__).resolve().parents[3]

def parsed(rule: Rule) -> ParsedRule:
    return ParsedRule(raw_rule=rule.raw_rule, action=rule.action, protocol=rule.protocol, source=rule.source,
        source_port=rule.source_port, direction=rule.direction, destination=rule.destination,
        destination_port=rule.destination_port, sid=rule.sid, rev=rule.rev, msg=rule.msg,
        classtype=rule.classtype, metadata=rule.rule_metadata, references=rule.references,
        flow=rule.flow, flowbits=rule.flowbits, contents=rule.contents, pcre=rule.pcre, app_layer=rule.app_layer)

def agent_input(pr: ParsedRule, provider: str, version: str, repo: MitreRepository) -> dict:
    hints=enrich_rule(pr); ent=entity_candidates(pr); mitre=search_mitre(pr,repo); cves=extract_cves(pr); similar=[]
    if provider == "ollama" and version in {"qwen-v2.2","v2.2-qwen"}:
        ent=qwen_entity_candidates(pr,ent); mitre=__import__("app.v2.mitre_decision",fromlist=["retrieve_candidates"]).retrieve_candidates(pr,repo)
        if not cves: similar=search_similar_rules(pr,ROOT/"data/evaluation/golden_dataset.jsonl")
        controlled={k.value:list(v) for k,v in SUBCATEGORIES.items()}
        controlled["__qwen_semantic_context__"]=[json.dumps(build_semantic_context(pr,hints=hints,entity_candidates=ent,mitre_candidates=mitre,cves=cves,similar_rules=similar,controlled_subcategories={k.value:list(v) for k,v in SUBCATEGORIES.items()}),ensure_ascii=False)]
        ctx=build_classification_context(pr,repo,hints=hints,v2_data={"classifier_version":version,"controlled_subcategories":controlled,"entity_candidates":ent,"mitre_candidates":mitre,"cve_context":cves,"similar_rules":similar})
        data=ctx.model_dump(mode="json"); semantic=json.loads(data["controlled_subcategories"]["__qwen_semantic_context__"][0]); data["qwen_semantic_context"]=semantic; data["controlled_subcategories"].pop("__qwen_semantic_context__",None); return data
    ctx=build_classification_context(pr,repo,hints=hints,v2_data={"classifier_version":"v2","controlled_subcategories":{k.value:list(v) for k,v in SUBCATEGORIES.items()},"entity_candidates":ent,"mitre_candidates":mitre,"cve_context":cves,"similar_rules":similar})
    return ctx.model_dump(mode="json")

def main():
    p=argparse.ArgumentParser(); p.add_argument("run",type=Path); args=p.parse_args()
    rows=[json.loads(x) for x in (args.run/"results.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    grouped={}
    for row in rows: grouped.setdefault((row["sid"],row["rev"]),{})[row["provider"]]=row
    repo=MitreRepository(); records=[]
    with SessionLocal() as db:
        for (sid,rev), pair in sorted(grouped.items()):
            rule=db.scalar(select(Rule).where(Rule.sid==sid,Rule.rev==rev))
            if not rule: continue
            pr=parsed(rule); item={"sid":sid,"rev":rev,"raw_rule":rule.raw_rule,"parsed_rule":pr.model_dump(mode="json"),"source_file":rule.source_file,"models":{}}
            for provider,row in pair.items():
                version=row.get("classifier_version") or ("qwen-v2.2" if provider=="ollama" else "v2.1")
                item["models"][provider]={"model":row.get("model"),"classifier_version":version,"agent_input":agent_input(pr,provider,version,repo),"agent_output":row.get("final_classification"),"agent_activity":row.get("agent_activity",{}),"final_system_response":{"classification":row.get("final_classification"),"validator":row.get("validator"),"status":"SUCCEEDED" if row.get("succeeded") else "FAILED","normalization_and_provenance":{"source_mitre_mapping":row.get("source_mitre_mapping"),"final_mitre_mapping":row.get("final_mitre_mapping"),"mitre_mapping_method":row.get("mitre_mapping_method"),"validator_mitre_status":row.get("validator_mitre_status")},"note":"Raw provider output is not persisted; agent_output is the persisted post-normalization classification."}}
            records.append(item)
    out={"sample_id":"operational-250-random-20260903-v1","source_run":str(args.run),"total_rules":len(records),"records":records}
    (args.run/"inspection-export-50.json").write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding="utf-8")
    with (args.run/"inspection-export-50.jsonl").open("w",encoding="utf-8") as f:
        for item in records: f.write(json.dumps(item,ensure_ascii=False)+"\n")
    print(f"Exported {len(records)} rules")

if __name__=="__main__": main()
