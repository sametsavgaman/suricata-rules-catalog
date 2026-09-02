import asyncio,json
from pathlib import Path
from app.agent.factory import create_classification_provider,provider_config_error
from app.config import get_settings
from app.database.session import Base,SessionLocal,engine,ensure_schema_extensions
from app.evaluation.cost_analysis import calculate_costs
from app.evaluation.evaluator import evaluate_records
from app.evaluation.golden_dataset import reviewed_records,write_jsonl
from app.evaluation.metrics import calculate_metrics
from app.evaluation.report import build_report_payload,write_reports
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService

async def main():
    root=Path(__file__).resolve().parents[3]; s=get_settings(); s.classifier_version="v2.1"
    error=provider_config_error(s)
    if error: print(error); return 2
    records=reviewed_records(root/"data/evaluation/golden_dataset.jsonl"); Base.metadata.create_all(bind=engine); ensure_schema_extensions()
    provider=create_classification_provider(s); results=[]
    with SessionLocal() as db:
        service=ClassificationService(db,provider,s,MitreRepository())
        for i,r in enumerate(records,1):
            results.extend(await evaluate_records(db,service,[r],force=False)); print(f"[{i}/{len(records)}] SID {r.sid}",flush=True)
    output=root/"data/evaluation/evaluation-results-v2.jsonl"; write_jsonl(output,results); metrics=calculate_metrics(results)
    costs=calculate_costs(results,s.gemini_input_cost_per_million,s.gemini_output_cost_per_million)
    payload=build_report_payload(results,metrics,costs,status="COMPLETED",golden_records=records,provider=s.ai_provider,model=f"v2:{provider.model_name}")
    tmp=root/"data/evaluation/reports/v2"; md,js=write_reports(tmp,payload); reports=root/"data/evaluation/reports"
    (reports/"evaluation-report-v2.md").write_text(md.read_text(encoding="utf-8"),encoding="utf-8"); (reports/"evaluation-report-v2.json").write_text(js.read_text(encoding="utf-8"),encoding="utf-8")
    before=json.loads((reports/"evaluation-report-audited.json").read_text(encoding="utf-8"))["metrics"]
    fields=["detected_entity","entity_type","category","subcategory","mitre_tactic","mitre_technique","mitre_technique_id","cyber_kill_chain_phase"]
    lines=["# V1 Audited vs V2","","| Metric | V1 Audited | V2 | Delta |","|---|---:|---:|---:|"]
    for f in fields:
        b=before["field_metrics"][f]["normalized_accuracy"]; a=metrics["field_metrics"][f]["normalized_accuracy"]; lines.append(f"| {f} | {b:.1%} | {a:.1%} | {a-b:+.1%} |")
    lines += [f"| behavior semantic normalized | {before.get('behavior_semantic_normalized_accuracy',0):.1%} | {metrics['behavior_semantic_normalized_accuracy']:.1%} | {metrics['behavior_semantic_normalized_accuracy']-before.get('behavior_semantic_normalized_accuracy',0):+.1%} |",f"| entity null hallucination | {before['null_metrics']['detected_entity']['null_hallucination_rate']:.1%} | {metrics['null_metrics']['detected_entity']['null_hallucination_rate']:.1%} | {metrics['null_metrics']['detected_entity']['null_hallucination_rate']-before['null_metrics']['detected_entity']['null_hallucination_rate']:+.1%} |","","## Tool Usage","",json.dumps(metrics["tool_usage"],indent=2)]
    (reports/"v1-vs-v2.md").write_text("\n".join(lines),encoding="utf-8"); print(f"Evaluated {metrics['evaluated']}/{metrics['golden_samples']}"); return 0
if __name__=="__main__": raise SystemExit(asyncio.run(main()))
