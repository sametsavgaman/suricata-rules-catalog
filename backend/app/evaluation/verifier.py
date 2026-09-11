import argparse, json
from pathlib import Path
from app.evaluation.golden_dataset import read_jsonl, write_jsonl
from app.evaluation.schemas import AgreementStatus, GoldenRecord, Verification, VerificationIssue, VerificationVerdict, EVALUATED_FIELDS
from app.knowledge.mitre_repository import MitreRepository
from app.parser.suricata_parser import SuricataRuleParser

def verify_record(record: GoldenRecord, repo: MitreRepository) -> Verification:
    p = record.proposal
    if p is None:
        return Verification(verdict=VerificationVerdict.DISAGREE, verifier_confidence=0.99, issues=[VerificationIssue(field="proposal", reason="No AI proposal present")])
    vals = p.model_dump()
    fv = {f: VerificationVerdict.AGREE for f in EVALUATED_FIELDS}
    issues: list[VerificationIssue] = []
    text = ((record.msg or "") + " " + record.raw_rule).casefold()
    if p.detected_entity and p.detected_entity.casefold() not in text:
        fv["detected_entity"] = VerificationVerdict.DISAGREE; issues.append(VerificationIssue(field="detected_entity", reason="Entity is not present in raw rule evidence"))
    if p.detected_entity is None and p.entity_type is not None:
        fv["entity_type"] = VerificationVerdict.DISAGREE; issues.append(VerificationIssue(field="entity_type", reason="Entity type set while entity is null"))
    if p.mitre_technique_id:
        t = repo.get(p.mitre_technique_id)
        if not t or t.name != p.mitre_technique or (t.tactics and p.mitre_tactic not in t.tactics):
            fv["mitre_technique_id"] = VerificationVerdict.DISAGREE; issues.append(VerificationIssue(field="mitre_technique_id", reason="MITRE fields are not canonical in local repository"))
    elif any((p.mitre_tactic, p.mitre_technique)):
        fv["mitre_technique_id"] = VerificationVerdict.DISAGREE; issues.append(VerificationIssue(field="mitre_technique_id", reason="MITRE name/tactic supplied without a technique ID"))
    if not p.detected_behavior or not p.category:
        fv["detected_behavior"] = VerificationVerdict.PARTIAL
    if p.category == "Reconnaissance" and not any(x in text for x in ("scan", "port", "probe", "discovery", "1433")):
        fv["category"] = VerificationVerdict.PARTIAL
    counts = {v: list(fv.values()).count(v) for v in VerificationVerdict}
    ratio = counts[VerificationVerdict.AGREE] / len(EVALUATED_FIELDS)
    if any(fv[f] == VerificationVerdict.DISAGREE for f in ("detected_behavior", "category", "mitre_technique_id")) or counts[VerificationVerdict.DISAGREE]:
        verdict = VerificationVerdict.DISAGREE
    elif ratio >= .8: verdict = VerificationVerdict.AGREE
    elif ratio >= .5: verdict = VerificationVerdict.PARTIAL
    else: verdict = VerificationVerdict.DISAGREE
    return Verification(verdict=verdict, field_verdicts=fv, issues=issues, verifier_confidence=round(.95 if verdict == VerificationVerdict.AGREE else .78, 2))

def calculate_agreement(proposal_confidence: float, verification: Verification) -> AgreementStatus:
    if verification.verdict == VerificationVerdict.DISAGREE or any(v == VerificationVerdict.DISAGREE for v in verification.field_verdicts.values()): return AgreementStatus.DISAGREEMENT
    if verification.verdict == VerificationVerdict.AGREE and proposal_confidence >= .90: return AgreementStatus.HIGH_CONFIDENCE_AGREEMENT
    return AgreementStatus.PARTIAL_AGREEMENT

def main() -> int:
    root=Path(__file__).resolve().parents[3]; ap=argparse.ArgumentParser(); ap.add_argument("--golden",type=Path,default=root/"data/evaluation/golden_dataset.jsonl"); args=ap.parse_args()
    records=read_jsonl(args.golden, GoldenRecord); repo=MitreRepository(); out=[]
    for r in records:
        r.verification=verify_record(r,repo); r.agreement_status=calculate_agreement(r.proposal.proposal_confidence if r.proposal else 0, r.verification); out.append(r)
    write_jsonl(args.golden,out)
    write_jsonl(root/"data/evaluation/verification_results.jsonl", out)
    summary={"total":len(out),"high_confidence_agreement":sum(r.agreement_status==AgreementStatus.HIGH_CONFIDENCE_AGREEMENT for r in out),"partial_agreement":sum(r.agreement_status==AgreementStatus.PARTIAL_AGREEMENT for r in out),"disagreement":sum(r.agreement_status==AgreementStatus.DISAGREEMENT for r in out),"human_reviewed":sum(r.annotation.status.value=="REVIEWED" for r in out)}
    (root/"data/evaluation/verification_summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8"); print(json.dumps(summary,indent=2)); return 0
if __name__ == "__main__": raise SystemExit(main())
