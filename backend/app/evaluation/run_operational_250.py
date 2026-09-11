"""Run the immutable operational-250 cohort against the existing V2 pipeline."""
import asyncio, json, random, re, time
from collections import Counter
from pathlib import Path

from sqlalchemy import select

from app.agent.factory import create_classification_provider, provider_config_error
from app.config import get_settings
from app.database.models import Classification, ClassificationStatus, Rule
from app.database.session import Base, SessionLocal, engine, ensure_schema_extensions
from app.evaluation.evaluator import evaluate_records
from app.evaluation.golden_dataset import read_jsonl, reviewed_records, write_jsonl
from app.evaluation.metrics import calculate_metrics, confidence_bucket
from app.evaluation.schemas import EVALUATED_FIELDS, GoldenRecord, RuleSample
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser
from app.ingestion.rule_loader import RuleLoader
from app.services.classification_service import ClassificationService

ROOT = Path(__file__).resolve().parents[3]
BATCH = "operational-250"
SEED = 42

def _family(path: Path) -> str:
    name = path.stem.lower().replace("emerging-", "")
    for token in ("scan", "malware", "trojan", "web_server", "web_client", "exploit", "remote", "dns", "dyn_dns", "phishing", "policy", "info", "mobile", "c2", "attack_response", "user_agents", "sql", "ftp", "smb", "rdp", "tls", "http"):
        if token in name: return token.upper()
    return name.upper()

def choose_sample(audited: list[GoldenRecord]) -> tuple[list[GoldenRecord], list[RuleSample]]:
    audited_keys = {(r.sid, r.rev) for r in audited}
    sample_keys = {(r.sid, r.rev) for r in read_jsonl(ROOT / "data/evaluation/sample.jsonl", GoldenRecord)}
    parser, loader = SuricataRuleParser(), RuleLoader()
    groups: dict[str, list[RuleSample]] = {}
    for path in sorted((ROOT / "data/rules/et-open").rglob("*.rules")):
        try: loaded = loader.load_file(path)
        except Exception: continue
        family = _family(path)
        for raw in loaded.rules:
            try:
                parsed = parser.parse(raw); key = (parsed.sid, parsed.rev)
                if key in audited_keys or key in sample_keys: continue
                groups.setdefault(family, []).append(RuleSample(sid=parsed.sid, rev=parsed.rev, msg=parsed.msg, source_file=str(path.relative_to(ROOT)), raw_rule=raw, stratum=family))
            except Exception: continue
    rng = random.Random(SEED)
    for rows in groups.values(): rng.shuffle(rows)
    fresh=[]; names=sorted(groups)
    while len(fresh) < 153 and names:
        progressed=False
        for name in list(names):
            if groups[name]: fresh.append(groups[name].pop()); progressed=True
            if len(fresh) >= 153: break
            if not groups[name]: names.remove(name)
        if not progressed: break
    if len(fresh) != 153: raise RuntimeError(f"Only selected {len(fresh)} fresh rules")
    return audited, fresh

def _classification_payload(rule: Rule, c: Classification | None) -> dict:
    final = {field: getattr(c, field, None) for field in EVALUATED_FIELDS}
    final["confidence"] = float(getattr(c, "confidence", 0.0) or 0.0)
    status = "FAILED" if c is None or c.classification_status == ClassificationStatus.FAILED else ("REVIEW" if c.classification_status == ClassificationStatus.REVIEW_REQUIRED else "PASS" if not c.validation_issues else "REVIEW")
    return {"sid": rule.sid, "rev": rule.rev, "raw_rule": rule.raw_rule, "rule_message": rule.msg, "source_file": rule.source_file,
            "final_classification": final, "evidence": getattr(c, "evidence", []) if c else [], "agent_activity": getattr(c, "agent_activity", {}) if c else {},
            "validator": {"status": status, "issues": getattr(c, "validation_issues", []) if c else ["CLASSIFICATION_FAILED"]},
            "provider": getattr(c, "provider", None) if c else None, "model": getattr(c, "model_name", None) if c else None,
            "classifier_version": getattr(c, "classifier_version", "v2.1") if c else "v2.1", "inspection_batch": BATCH,
            "source_mitre_mapping": getattr(c, "source_mitre_mapping", None) if c else None,
            "final_mitre_mapping": getattr(c, "final_mitre_mapping", None) if c else None,
            "mitre_mapping_method": getattr(c, "mitre_mapping_method", None) if c else None,
            "model_confidence": getattr(c, "model_confidence", None) if c else None,
            "mitre_retrieval_score": getattr(c, "mitre_retrieval_score", None) if c else None,
            "evidence_strength": getattr(c, "evidence_strength", None) if c else None,
            "validator_mitre_status": getattr(c, "validator_mitre_status", None) if c else None}

async def main() -> int:
    settings=get_settings(); settings.classifier_version="v2.1"; error=provider_config_error(settings)
    if error: print(error); return 2
    audited, fresh = choose_sample(reviewed_records(ROOT / "data/evaluation/golden_dataset.jsonl"))
    outdir=ROOT / "data/evaluation/operational-250"; outdir.mkdir(parents=True, exist_ok=True)
    cohort=[{"sid":r.sid,"rev":r.rev,"source_file":r.source_file,"cohort":"AUDITED_BENCHMARK"} for r in audited] + [{"sid":r.sid,"rev":r.rev,"source_file":r.source_file,"cohort":"FRESH_OPERATIONAL","stratum":r.stratum} for r in fresh]
    (outdir / "sample-250.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in cohort)+"\n", encoding="utf-8")
    Base.metadata.create_all(bind=engine); ensure_schema_extensions(); provider=create_classification_provider(settings)
    started=time.perf_counter(); audited_results=[]; output=[]; retries=0; cache_hits=0
    with SessionLocal() as db:
        service=ClassificationService(db, provider, settings, MitreRepository())
        audited_results=await evaluate_records(db, service, audited, force=False)
        for i, r in enumerate(audited, 1):
            rule=db.scalar(select(Rule).where(Rule.sid==r.sid, Rule.rev==r.rev)); c=db.scalar(select(Classification).where(Classification.rule_id==rule.id).order_by(Classification.created_at.desc())) if rule else None
            if c: c.inspection_batch=BATCH; db.commit(); output.append({"cohort":"AUDITED_BENCHMARK", **_classification_payload(rule,c)})
            print(f"[{i}/250] [AUDITED] SID {r.sid}", flush=True)
        for i, r in enumerate(fresh, 98):
            parsed=SuricataRuleParser().parse(r.raw_rule); rule, _ = __import__("app.database.repository", fromlist=["RuleRepository"]).RuleRepository(db).upsert(parsed, r.source_file); db.commit()
            c=await service.classify(rule, force=True); c.inspection_batch=BATCH; db.commit(); db.refresh(c)
            output.append({"cohort":"FRESH_OPERATIONAL", **_classification_payload(rule,c)})
            print(f"[{i}/250] [FRESH] SID {r.sid}", flush=True)
            if getattr(c,"_cache_hit",False): cache_hits += 1
    duration=time.perf_counter()-started
    write_jsonl(outdir / "results-250.jsonl", [type("Row", (), {"model_dump_json": lambda self, x=x: json.dumps(x, ensure_ascii=False)})() for x in output])
    fresh_rows=[x for x in output if x["cohort"]=="FRESH_OPERATIONAL"]; audited_metrics=calculate_metrics(audited_results)
    def assigned(rows, field): return sum(x["final_classification"].get(field) is not None for x in rows)
    fresh_stats={"total":len(fresh_rows),"succeeded":sum(x["validator"]["status"]!="FAILED" for x in fresh_rows),"failed":sum(x["validator"]["status"]=="FAILED" for x in fresh_rows),"entity_assigned":assigned(fresh_rows,"detected_entity"),"mitre_assigned":assigned(fresh_rows,"mitre_technique_id"),"kill_chain_assigned":assigned(fresh_rows,"cyber_kill_chain_phase"),"validator":Counter(x["validator"]["status"] for x in fresh_rows),"average_confidence":sum(x["final_classification"]["confidence"] for x in fresh_rows)/len(fresh_rows),"category_distribution":dict(Counter(x["final_classification"].get("category") or "<null>" for x in fresh_rows))}
    buckets=Counter(confidence_bucket(x["final_classification"]["confidence"]) for x in output)
    queues={"lowest_confidence":[[x["sid"],x["rev"]] for x in sorted(fresh_rows,key=lambda x:x["final_classification"]["confidence"])[:20]],"validator_warnings":[[x["sid"],x["rev"]] for x in fresh_rows if x["validator"]["status"]!="PASS"],"entity_assigned":[[x["sid"],x["rev"]] for x in fresh_rows if x["final_classification"].get("detected_entity")],"mitre_assigned":[[x["sid"],x["rev"]] for x in fresh_rows if x["final_classification"].get("mitre_technique_id")],"abstained":[[x["sid"],x["rev"]] for x in fresh_rows if not x["final_classification"].get("detected_entity") and not x["final_classification"].get("mitre_technique_id") and not x["final_classification"].get("cyber_kill_chain_phase")],"cve_rules":[[x["sid"],x["rev"]] for x in fresh_rows if re.search(r"cve[-_]?(?:19|20)\d{2}", x["raw_rule"], re.I)],"high_confidence_rich":[[x["sid"],x["rev"]] for x in fresh_rows if x["final_classification"]["confidence"]>=.9 and (x["final_classification"].get("detected_entity") or x["final_classification"].get("mitre_technique_id"))]}
    manifest={"sample_id":"operational-250-seed42-v1","seed":SEED,"queues":queues}; (outdir/"inspection-manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    report={"sample_id":manifest["sample_id"],"run_configuration":{"provider":settings.ai_provider,"model":provider.model_name,"classifier_version":settings.classifier_version,"seed":SEED,"total":250,"duration_seconds":duration,"cache_hits":cache_hits},"cohorts":{"audited":97,"fresh":153},"audited_metrics":audited_metrics,"fresh_summary":{**fresh_stats,"validator":dict(fresh_stats["validator"])},"confidence_distribution":dict(buckets),"tool_usage":audited_metrics.get("tool_usage",{}),"token_usage":{"status":"NOT_PERSISTED_IN_CLASSIFICATION_SCHEMA","note":"Provider usage metadata is not stored in the current Classification table."},"important_notice":"The 153 fresh operational rules do not have independently verified ground-truth labels. Accuracy metrics apply only to the 97 audited benchmark records."}
    (outdir/"operational-250-report.json").write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
    md=f"# Operational 250 Test\n\n## Run Configuration\n\n- Provider: `{settings.ai_provider}`\n- Model: `{provider.model_name}`\n- Classifier version: `{settings.classifier_version}`\n- Seed: `{SEED}`\n- Total: 250\n- Duration: {duration:.1f}s\n\n## Cohorts\n\n- Audited benchmark: 97\n- Fresh operational: 153\n\n## Audited Benchmark Accuracy\n\nEvaluated: **{audited_metrics['evaluated']}**.\n\n```json\n{json.dumps(audited_metrics['field_metrics'],indent=2)}\n```\n\n## Fresh Operational Summary\n\n- Succeeded: {fresh_stats['succeeded']}\n- Failed: {fresh_stats['failed']}\n- Entity assigned: {fresh_stats['entity_assigned']}\n- MITRE assigned: {fresh_stats['mitre_assigned']}\n- Kill Chain assigned: {fresh_stats['kill_chain_assigned']}\n- Average confidence: {fresh_stats['average_confidence']:.3f}\n\n## Category Distribution\n\n```json\n{json.dumps(fresh_stats['category_distribution'],indent=2)}\n```\n\n## Confidence Distribution\n\n```json\n{json.dumps(dict(buckets),indent=2)}\n```\n\n## Tool / Token Usage\n\n```json\n{json.dumps(audited_metrics.get('tool_usage',{}),indent=2)}\n```\n\n## Important Notice\n\n> The 153 fresh operational rules do not have independently verified ground-truth labels. Their correctness must be assessed through manual inspection. Accuracy metrics apply only to the 97 audited benchmark records.\n"
    (outdir/"operational-250-report.md").write_text(md,encoding="utf-8"); print(f"Completed operational-250: {len(output)} records; audited evaluated={audited_metrics['evaluated']}; fresh failed={fresh_stats['failed']}"); return 0

if __name__ == "__main__": raise SystemExit(asyncio.run(main()))
