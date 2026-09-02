import argparse, json
from datetime import datetime, timezone
from pathlib import Path
from app.agent.context import build_classification_context
from app.enrichment.deterministic_enrichment import enrich_rule
from app.evaluation.golden_dataset import read_jsonl, write_jsonl
from app.evaluation.schemas import AgreementStatus, AnnotationStatus, EVALUATED_FIELDS, GoldenRecord
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser

def ordered_records(records):
    rank={AgreementStatus.HIGH_CONFIDENCE_AGREEMENT:0, AgreementStatus.PARTIAL_AGREEMENT:1, AgreementStatus.DISAGREEMENT:2, None:3}
    return sorted(records,key=lambda r:(rank.get(r.agreement_status,3), r.sid))

def apply_approve(record, annotator):
    if record.proposal is None: raise ValueError("record has no proposal")
    record.expected=record.expected.model_validate({k:getattr(record.proposal,k) for k in EVALUATED_FIELDS})
    record.annotation.status=AnnotationStatus.REVIEWED; record.annotation.annotator=annotator; record.annotation.review_method="AI_ASSISTED_HUMAN_REVIEW"; record.annotation.reviewed_at=datetime.now(timezone.utc); record.annotation.notes=None; return record

def apply_dispute(record, annotator, notes=None):
    record.annotation.status=AnnotationStatus.DISPUTED; record.annotation.annotator=annotator; record.annotation.notes=notes; record.annotation.review_method="HUMAN_DISPUTE"; record.annotation.reviewed_at=datetime.now(timezone.utc); return record

def _bar(title, source): print("\n"+"="*80+f"\n{title}\nSOURCE: {source}\n"+"="*80)
def render_full(record, parsed, hints, context):
    _bar("SOURCE / RAW RULE","ET OPEN RULESET"); print(f"Source File: {record.source_file}\nSID: {record.sid}\nREV: {record.rev}\n\n{record.raw_rule}")
    _bar("DETERMINISTIC PARSER OUTPUT","DETERMINISTIC SURICATA PARSER"); print(json.dumps(parsed.model_dump(mode="json"),indent=2,ensure_ascii=False))
    _bar("DETERMINISTIC ENRICHMENT / HINTS","APPLICATION CODE — NO LLM"); print(json.dumps(hints.__dict__,indent=2,ensure_ascii=False))
    _bar("ACTUAL CLASSIFICATION AI INPUT","STRUCTURED RULE CONTEXT SENT TO CLASSIFICATION MODEL"); print(json.dumps(context.model_dump(mode="json"),indent=2,ensure_ascii=False))
    if record.proposal:
        _bar("AI CLASSIFICATION PROPOSAL","CLASSIFICATION LLM"); print(record.proposal.model_dump_json(indent=2)); print("\nAI EVIDENCE SUMMARY")
        for e in record.evidence: print(f"- [{e.source}] {e.field}: {e.value}")
    if record.verification:
        _bar("INDEPENDENT VERIFIER","VERIFICATION CRITIC"); v=record.verification; print(f"Verdict: {v.verdict.value}\nVerifier confidence: {v.verifier_confidence:.2f}")
        for field, verdict in v.field_verdicts.items(): print(f"{field:28} {verdict.value}")
        print("Issues: None" if not v.issues else "Issues:\n"+"\n".join(f"- {i.field}: {i.reason}" for i in v.issues))
def render_compact(record, parsed):
    print("\n"+"="*80+f"\nRULE | SID {record.sid} rev {record.rev}\n"+"="*80); print(record.msg or "(no message)")
    print(f"\n[ET DATA] RAW RULE SUMMARY\nprotocol={parsed.protocol} direction={parsed.direction} contents={len(parsed.contents)} pcre={len(parsed.pcre)} app_layer={len(parsed.app_layer)}")
    print(f"\n[REVIEW] STATUS={record.annotation.status.value} AGREEMENT={record.agreement_status or 'N/A'}")
    if record.proposal:
        p=record.proposal; print(f"\n[AI OUTPUT] PROPOSAL\nBehavior: {p.detected_behavior}\nEntity: {p.detected_entity}\nCategory: {p.category}\nMITRE: {p.mitre_technique_id or 'null'}\nConfidence: {p.proposal_confidence:.2f}")
    if record.verification: print(f"\n[VERIFIER] {record.verification.verdict.value} | confidence={record.verification.verifier_confidence:.2f}")
def _edit(record, annotator):
    if not record.proposal: return
    field=input("Field (blank cancels): ").strip()
    if field not in EVALUATED_FIELDS: return
    values={k:getattr(record.proposal,k) for k in EVALUATED_FIELDS}; values[field]=input("Value (blank = null): ").strip() or None; record.expected=record.expected.model_validate(values)
    if input("Save as REVIEWED? [Y/n] ").strip().lower()!="n": record.annotation.status=AnnotationStatus.REVIEWED; record.annotation.annotator=annotator; record.annotation.review_method="AI_ASSISTED_HUMAN_REVIEW"; record.annotation.reviewed_at=datetime.now(timezone.utc)
def main():
    root=Path(__file__).resolve().parents[3]; ap=argparse.ArgumentParser(); ap.add_argument("--golden",type=Path,default=root/"data/evaluation/golden_dataset.jsonl"); ap.add_argument("--annotator",required=True); ap.add_argument("--show-proposals",action="store_true"); ap.add_argument("--verbose",action="store_true"); ap.add_argument("--only",choices=["high-confidence","disagreement","unreviewed"]); args=ap.parse_args()
    all_records=read_jsonl(args.golden,GoldenRecord); records=ordered_records(all_records); parser,repo=SuricataRuleParser(),MitreRepository()
    if args.only=="high-confidence": records=[r for r in records if r.agreement_status==AgreementStatus.HIGH_CONFIDENCE_AGREEMENT]
    elif args.only=="disagreement": records=[r for r in records if r.agreement_status==AgreementStatus.DISAGREEMENT]
    elif args.only=="unreviewed": records=[r for r in records if r.annotation.status==AnnotationStatus.UNREVIEWED]
    for r in records:
        parsed=parser.parse(r.raw_rule); hints=enrich_rule(parsed); context=build_classification_context(parsed,repo,hints=hints); render_compact(r,parsed)
        action=input("\n[V] Full details  [A]pprove [E]dit [D]ispute [S]kip [Q]uit: ").strip().lower()
        if action=="v" or args.verbose or args.show_proposals: render_full(r,parsed,hints,context); action=input("\n[A]pprove [E]dit [D]ispute [S]kip [Q]uit: ").strip().lower()
        if action=="a": apply_approve(r,args.annotator)
        elif action=="e": _edit(r,args.annotator)
        elif action=="d": apply_dispute(r,args.annotator,input("Dispute note: ").strip() or None)
        elif action=="q": break
    write_jsonl(args.golden,all_records)
if __name__=="__main__": main()
