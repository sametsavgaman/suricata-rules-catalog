import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

from app.evaluation.golden_dataset import read_jsonl, write_jsonl
from app.evaluation.metrics import calculate_metrics, compare_fields
from app.evaluation.report import build_report_payload, write_reports
from app.evaluation.schemas import AnnotationStatus, EVALUATED_FIELDS, EvaluationResult, GoldenRecord

# Only corrections supported directly by raw signature evidence and canonical project taxonomy.
OVERRIDES = {
    2019842: dict(detected_behavior="Internet Explorer VBScript CVE-2014-6332 exploit attempt", detected_entity="Internet Explorer", entity_type="Product", category="Web Attack", subcategory="Web Exploit Attempt", mitre_tactic="Initial Access", mitre_technique="Drive-by Compromise", mitre_technique_id="T1189", cyber_kill_chain_phase="Exploitation"),
    2045262: dict(detected_behavior="HTTP request to a dynamic DNS domain", detected_entity=None, entity_type=None, category="Suspicious DNS", subcategory="Unusual DNS Query", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2048071: dict(detected_behavior="TLS SNI observation of credential-phishing infrastructure", detected_entity=None, entity_type=None, category="Network Abuse", subcategory="Phishing Infrastructure", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase="Delivery"),
    2046259: dict(detected_behavior="ReconShark HTTP command-and-control communication", detected_entity="ReconShark", entity_type="Malware", category="Command and Control", subcategory="HTTP C2 Communication", mitre_tactic="Command and Control", mitre_technique="Web Protocols", mitre_technique_id="T1071.001", cyber_kill_chain_phase="Command and Control"),
    2002383: dict(detected_behavior="Possible FTP brute-force activity", detected_entity=None, entity_type=None, category="Credential Access", subcategory="Credential Activity", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2010494: dict(detected_behavior="Possible MySQL brute-force login activity", detected_entity=None, entity_type=None, category="Credential Access", subcategory="Credential Activity", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2000564: dict(detected_behavior="Pwdump3e credential-dumping activity over SMB", detected_entity="Pwdump3e", entity_type="Attack Tool", category="Credential Access", subcategory="Credential Dumping", mitre_tactic="Credential Access", mitre_technique="OS Credential Dumping", mitre_technique_id="T1003", cyber_kill_chain_phase=None),
    2011286: dict(detected_behavior="Remote file inclusion scan against a web server", detected_entity=None, entity_type=None, category="Web Attack", subcategory="Web Scan", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase="Reconnaissance"),
    2005279: dict(detected_behavior="SQL injection attempt against Easebay Resources Login Manager", detected_entity="Easebay Resources Login Manager", entity_type="Product", category="Web Attack", subcategory="SQL Injection", mitre_tactic="Initial Access", mitre_technique="Exploit Public-Facing Application", mitre_technique_id="T1190", cyber_kill_chain_phase="Exploitation"),
    2013682: dict(detected_behavior="Local file inclusion attempt against Simplis CMS", detected_entity="Simplis CMS", entity_type="Product", category="Web Attack", subcategory="Web Exploit Attempt", mitre_tactic="Initial Access", mitre_technique="Exploit Public-Facing Application", mitre_technique_id="T1190", cyber_kill_chain_phase="Exploitation"),
    2103271: dict(detected_behavior="SMB IrotIsRunning request attempt", detected_entity=None, entity_type=None, category="Network Abuse", subcategory="Suspicious TCP Activity", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2103162: dict(detected_behavior="SMB msqueue bind attempt", detected_entity=None, entity_type=None, category="Network Abuse", subcategory="Suspicious TCP Activity", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2103120: dict(detected_behavior="SMB llsrconnect overflow attempt", detected_entity=None, entity_type=None, category="Exploitation", subcategory="Exploit Attempt", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase="Exploitation"),
    2063279: dict(detected_behavior="Observation of a revoked ScreenConnect code-signing certificate", detected_entity="ScreenConnect", entity_type="Remote Access Tool", category="Remote Access", subcategory="Remote Administration Tool", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase=None),
    2049581: dict(detected_behavior="TLS SNI observation of phishing infrastructure", detected_entity=None, entity_type=None, category="Network Abuse", subcategory="Phishing Infrastructure", mitre_tactic=None, mitre_technique=None, mitre_technique_id=None, cyber_kill_chain_phase="Delivery"),
}

AMBIGUOUS = {2014385, 2100652, 2102994}

def audit(golden, result):
    preserved=(golden.benchmark_audit or {}).get("original_expected")
    original=deepcopy(preserved or golden.expected.model_dump()); actual=result.actual or {}; final=deepcopy(original)
    if golden.sid in AMBIGUOUS:
        decision="AMBIGUOUS"; reason="The signature label and packet evidence do not support a single stable behavioral interpretation."
    elif golden.sid in OVERRIDES:
        final.update(OVERRIDES[golden.sid]); decision="BOTH_INCORRECT" if golden.sid in {2045262,2048071,2010494,2063279,2049581} else "ACTUAL_CORRECT"
        reason="Raw protocol/content/metadata supports the audited values; the model output was used only as a comparison candidate."
    elif original.get("category")==actual.get("category") and original.get("mitre_technique_id")==actual.get("mitre_technique_id"):
        decision="BOTH_ACCEPTABLE"; reason="Core behavior category and canonical MITRE mapping agree; differences are wording or subcategory vocabulary."
    elif actual.get("mitre_technique_id") and not original.get("mitre_technique_id"):
        decision="EXPECTED_CORRECT"; reason="Gemini introduced a MITRE mapping not sufficiently supported by the network signature alone."
    elif actual.get("detected_entity") and actual.get("entity_type")=="Other":
        decision="EXPECTED_CORRECT"; reason="A domain/label was promoted to an entity without a supported tool, malware, or product identity."
    else:
        decision="EXPECTED_CORRECT"; reason="The conservative Claude expected remains more defensible than the more specific Gemini interpretation."
    field_decisions={f:("UNCHANGED" if original.get(f)==final.get(f) else "CORRECTED") for f in EVALUATED_FIELDS}
    return decision,reason,original,final,field_decisions

def main():
    root=Path(__file__).resolve().parents[3]; reports=root/"data/evaluation/reports"
    golden=read_jsonl(root/"data/evaluation/golden_dataset.jsonl",GoldenRecord)
    actuals={r["sid"]:r for r in map(json.loads,(root/"data/evaluation/evaluation_results.jsonl").open(encoding="utf-8"))}
    audit_rows=[]; audited_results=[]; decisions=Counter(); corrections=Counter()
    for record in golden:
        raw=actuals[record.sid]; result=EvaluationResult.model_validate(raw)
        decision,reason,original,final,field_decisions=audit(record,result); decisions[decision]+=1
        for f,v in field_decisions.items(): corrections[f]+=v=="CORRECTED"
        record.benchmark_audit={"initial_review":"CLAUDE_INDEPENDENT_REVIEW","secondary_audit":"CODEX_BENCHMARK_AUDIT","original_expected":original,"audited_expected":final,"audit_decision":decision,"audit_reason":reason}
        if decision=="AMBIGUOUS": record.annotation.status=AnnotationStatus.DISPUTED
        else: record.expected=record.expected.model_validate(final)
        audit_rows.append({"sid":record.sid,"msg":record.msg,"raw_rule":record.raw_rule,"decision":decision,"field_decisions":field_decisions,"reason":reason,"original_expected":original,"gemini_actual":result.actual,"final_expected":final})
        if decision!="AMBIGUOUS":
            matches,norm,errors=compare_fields(final,result.actual)
            audited_results.append(result.model_copy(update={"expected":final,"matches":matches,"normalized_matches":norm,"errors":errors}))
    write_jsonl(root/"data/evaluation/golden_dataset.jsonl",golden)
    write_jsonl(root/"data/evaluation/evaluation-results-audited.jsonl",audited_results)
    (reports/"benchmark-audit.json").write_text(json.dumps(audit_rows,indent=2,ensure_ascii=False),encoding="utf-8")
    before=json.loads((reports/"evaluation-report.json").read_text(encoding="utf-8"))["metrics"]
    after=calculate_metrics(audited_results)
    payload=build_report_payload(audited_results,after,{"cost_status":"COST_NOT_CALCULATED","total_tokens":0,"average_total_tokens_per_rule":0},status="COMPLETED",golden_records=[r for r in golden if r.annotation.status==AnnotationStatus.REVIEWED],provider="gemini",model="gemini-flash-lite-latest")
    tmp=reports/"audited"; md,js=write_reports(tmp,payload)
    (reports/"evaluation-report-audited.md").write_text(md.read_text(encoding="utf-8"),encoding="utf-8"); (reports/"evaluation-report-audited.json").write_text(js.read_text(encoding="utf-8"),encoding="utf-8")
    lines=["# Benchmark Audit Summary","",f"- Total: {len(audit_rows)}"]+[f"- {k}: {decisions[k]}" for k in ("EXPECTED_CORRECT","ACTUAL_CORRECT","BOTH_ACCEPTABLE","BOTH_INCORRECT","AMBIGUOUS")]
    lines += ["","## Field Corrections",""]+[f"- {k}: {v}" for k,v in corrections.items()]
    lines += ["","## Benchmark Problems Found","","- Behavior exact matching penalizes semantically equivalent wording.","- Subcategory is not consistently controlled between benchmark and classifier.","- Domain strings are frequently promoted to entities.","- DNS/TLS observation is sometimes over-mapped to C2 MITRE techniques.","- Several phishing signatures were incorrectly mapped to Spearphishing Attachment."]
    exp_sub=Counter(r["original_expected"].get("subcategory") for r in audit_rows); act_sub=Counter(r["gemini_actual"].get("subcategory") for r in audit_rows)
    pairs=Counter((r["original_expected"].get("subcategory"),r["gemini_actual"].get("subcategory")) for r in audit_rows if r["original_expected"].get("subcategory")!=r["gemini_actual"].get("subcategory"))
    lines += ["","## Evaluation Metric Problems","","Behavior exact-match is lexical, not semantic. Subcategory accuracy is dominated by vocabulary mismatch.","",f"- Expected unique subcategories: {len(exp_sub)}",f"- Actual unique subcategories: {len(act_sub)}","- Most common mismatches:"]+[f"  - {e} ↔ {a}: {n}" for (e,a),n in pairs.most_common(10)]
    lines += ["","## Most Important Corrections",""]
    for row in [r for r in audit_rows if any(v=="CORRECTED" for v in r["field_decisions"].values())][:15]:
        lines += [f"### SID {row['sid']}","",f"- MSG: {row['msg']}",f"- RAW evidence: `{row['raw_rule'][:500]}`",f"- Decision: {row['decision']}",f"- Reason: {row['reason']}","","Original Claude expected:","```json",json.dumps(row["original_expected"],indent=2,ensure_ascii=False),"```","Gemini actual:","```json",json.dumps(row["gemini_actual"],indent=2,ensure_ascii=False),"```","Final audited expected:","```json",json.dumps(row["final_expected"],indent=2,ensure_ascii=False),"```",""]
    lines += ["## Before vs After Evaluation","","| Metric | Before | After | Delta |","|---|---:|---:|---:|"]
    for f in EVALUATED_FIELDS:
        bv=before["field_metrics"][f]["normalized_accuracy"]; av=after["field_metrics"][f]["normalized_accuracy"]; lines.append(f"| {f} | {bv:.1%} | {av:.1%} | {av-bv:+.1%} |")
    bn=before["null_metrics"]["detected_entity"]["null_hallucination_rate"]; an=after["null_metrics"]["detected_entity"]["null_hallucination_rate"]
    lines += [f"| entity null hallucination | {bn:.1%} | {an:.1%} | {an-bn:+.1%} |","",f"- Before evaluated: {before['evaluated']}",f"- After evaluated: {after['evaluated']}","","> This remains an AI-assisted benchmark (Claude initial review + Codex secondary audit), not expert-human ground truth."]
    (reports/"benchmark-audit-report.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps({"decisions":decisions,"corrections":corrections,"before":before["evaluated"],"after":after["evaluated"]},default=dict,indent=2))
if __name__=="__main__": main()
