"""Create a rule-by-rule Gemini/Qwen comparison from a completed run."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from app.evaluation.metrics import compare_fields

FIELDS = ("detected_behavior", "detected_entity", "entity_type", "category", "subcategory", "mitre_tactic", "mitre_technique", "mitre_technique_id", "cyber_kill_chain_phase")

def main():
    p=argparse.ArgumentParser(); p.add_argument("run", type=Path); args=p.parse_args()
    rows=[json.loads(x) for x in (args.run/"results.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    golden={}
    root=Path(__file__).resolve().parents[3]
    for line in (root/"data/evaluation/golden_dataset.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            item=json.loads(line); golden[(item["sid"],item["rev"])]=item["expected"]
    grouped={}
    for row in rows: grouped.setdefault((row["sid"],row["rev"]),{})[row["provider"]]=row
    details=[]; audited_scores={"gemini":[],"ollama":[]}; wins={"gemini":0,"qwen":0,"tie":0}
    for (sid,rev), pair in grouped.items():
        g,q=pair.get("gemini"),pair.get("ollama"); expected=golden.get((sid,rev)); item={"sid":sid,"rev":rev,"cohort":"AUDITED_BENCHMARK" if expected else "FRESH_OPERATIONAL","gemini_ok":bool(g and g["succeeded"]),"qwen_ok":bool(q and q["succeeded"])}
        if expected and g and q and g["succeeded"] and q["succeeded"]:
            gm,_,_=compare_fields(expected,g["final_classification"]); qm,_,_=compare_fields(expected,q["final_classification"])
            gs=sum(bool(gm.get(f)) for f in FIELDS)/len(FIELDS); qs=sum(bool(qm.get(f)) for f in FIELDS)/len(FIELDS)
            item.update(gemini_expected_pct=round(gs*100,1),qwen_expected_pct=round(qs*100,1),winner="gemini" if gs>qs else "qwen" if qs>gs else "tie")
            audited_scores["gemini"].append(gs); audited_scores["ollama"].append(qs)
            wins["qwen" if item["winner"] == "qwen" else item["winner"]]+=1
        elif g and q and g["succeeded"] and q["succeeded"]:
            same=sum(g["final_classification"].get(f)==q["final_classification"].get(f) for f in FIELDS)/len(FIELDS)
            item.update(model_agreement_pct=round(same*100,1),winner="not_determinable_without_ground_truth")
        else:
            item["winner"]="not_determinable"
        details.append(item)
    out={"run":str(args.run),"total_rules":len(details),"audited_rules":sum(x["cohort"]=="AUDITED_BENCHMARK" for x in details),"fresh_rules":sum(x["cohort"]=="FRESH_OPERATIONAL" for x in details),"audited":{"gemini_mean_expected_pct":round(sum(audited_scores["gemini"])/len(audited_scores["gemini"])*100,2) if audited_scores["gemini"] else None,"qwen_mean_expected_pct":round(sum(audited_scores["ollama"])/len(audited_scores["ollama"])*100,2) if audited_scores["ollama"] else None,"wins":wins},"rules":sorted(details,key=lambda x:(x["cohort"],x["sid"]))}
    (args.run/"rule-by-rule-comparison.json").write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["# Rule-by-rule Gemini vs Qwen comparison","",f"Total rules: **{out['total_rules']}**",f"Audited rules: **{out['audited_rules']}**",f"Fresh rules: **{out['fresh_rules']}**","","## Audited benchmark","",f"Gemini mean closeness to expected: **{out['audited']['gemini_mean_expected_pct']}%**",f"Qwen mean closeness to expected: **{out['audited']['qwen_mean_expected_pct']}%**",f"Rule wins — Gemini: {wins['gemini']}, Qwen: {wins['qwen']}, Tie: {wins['tie']}","","Fresh rules have no ground truth; their winner is not asserted.","","## Rule results","","| SID/REV | Cohort | Gemini | Qwen | Result |","|---|---|---:|---:|---|"]
    for x in out["rules"]:
        g=x.get("gemini_expected_pct",x.get("model_agreement_pct","—")); q=x.get("qwen_expected_pct","—"); lines.append(f"| {x['sid']}/{x['rev']} | {x['cohort']} | {g}{'%' if isinstance(g,(int,float)) else ''} | {q}{'%' if isinstance(q,(int,float)) else ''} | {x['winner']} |")
    (args.run/"rule-by-rule-comparison.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(out["audited"],ensure_ascii=False))

if __name__ == "__main__": main()
