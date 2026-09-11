"""Read-only analysis of saved paired runs; no model calls or dataset mutations."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from statistics import median

from app.evaluation.compare_models import GOLDEN, SAMPLE, digest, frozen_sample, summarize
from app.evaluation.golden_dataset import reviewed_records
from app.evaluation.schemas import EVALUATED_FIELDS


def paired_analysis(rows):
    grouped = defaultdict(dict)
    for r in rows:
        key = r['sid'], r['rev']
        if r['provider'] in grouped[key]:
            raise ValueError('Duplicate provider/SID/REV result.')
        grouped[key][r['provider']] = r
    complete = [pair for pair in grouped.values() if set(pair) == {'gemini','ollama'}]
    comparable = [p for p in complete if all(r['succeeded'] for r in p.values())]
    fingerprints = ('context_sha256', 'prompt_sha256')
    context_mismatches = []
    for pair in complete:
        g, q = pair['gemini'], pair['ollama']
        if any(not g['configuration'].get(k) or g['configuration'].get(k) != q['configuration'].get(k) for k in fingerprints):
            context_mismatches.append([g['sid'],g['rev']])
    mismatches = []
    for pair in comparable:
        g, q = pair['gemini'], pair['ollama']
        fields = [f for f in EVALUATED_FIELDS if g['final_classification'].get(f) != q['final_classification'].get(f)]
        if fields:
            mismatches.append({'sid':g['sid'],'rev':g['rev'],'cohort':g['cohort'],'fields':fields,
                'gemini_classification_id':g['classification_id'],'qwen_classification_id':q['classification_id']})
    return {'complete_pairs':len(complete),'successful_pairs':len(comparable),
        'context_or_prompt_mismatches':context_mismatches,
        'agreement_not_accuracy': {f: sum(p['gemini']['final_classification'].get(f)==p['ollama']['final_classification'].get(f) for p in comparable)/len(comparable) if comparable else None for f in EVALUATED_FIELDS},
        'inspection_disagreements':mismatches}


def main(directory):
    rows = [json.loads(line) for line in (directory/'results.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    sample_hash = digest(SAMPLE)
    valid = {(r['sid'],r['rev']):r['cohort'] for r in frozen_sample()}
    for r in rows:
        if r['sample_sha256'] != sample_hash or valid.get((r['sid'],r['rev'])) != r['cohort']:
            raise ValueError('Sample identity or cohort mismatch.')
    golden = {(r.sid,r.rev):r for r in reviewed_records(GOLDEN)}
    models = {}
    for name in ('gemini','ollama'):
        subset = [r for r in rows if r['provider']==name]
        if len({r['model'] for r in subset}) > 1:
            raise ValueError('Mixed models in the same provider run.')
        models[name] = summarize(subset,golden)
        timings = sorted(r['wall_seconds'] for r in subset)
        models[name].update(model=subset[0]['model'] if subset else None,
            p50_seconds=median(timings) if timings else None,
            p95_seconds=timings[max(0, int(len(timings)*.95+.999)-1)] if timings else None)
    paired = paired_analysis(rows)
    report = {'sample_id':'operational-250-seed42-v1','sample_sha256':sample_hash,
        'status':'COMPLETE' if all(m['total']==250 for m in models.values()) else 'PARTIAL',
        'models':models, **paired,
        'limitations':['Accuracy applies only to the reviewed audited cohort; fresh agreement is not accuracy.',
            'Existing similar-rule retrieval can use other reviewed benchmark examples; not a fully held-out benchmark.',
            'Token counts use different tokenizers. Local hardware/electricity and API cost not calculated.',
            'Reported latency is end-to-end per-rule wall time, including provider retries and any cold loading.',
            'No fine-tuning was performed. Model confidence is uncalibrated.']}
    (directory/'comparison-summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    lines = ['# Gemini / Qwen3-8B comparison', '', f"Status: **{report['status']}** · successful pairs: {paired['successful_pairs']}/250", '',
        '| Model | Succeeded | Failed | Average sec/rule | P50 | P95 | Input tokens | Output tokens |', '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name,m in models.items():
        lines.append(f"| {m['model']} | {m['succeeded']} | {m['failed']} | {m['average_seconds'] or 0:.2f} | {m['p50_seconds'] or 0:.2f} | {m['p95_seconds'] or 0:.2f} | {m['usage']['input_tokens']} | {m['usage']['output_tokens']} |")
    lines += ['', '## Reviewed audited records only', '', '| Field | Gemini exact accuracy | Qwen exact accuracy |', '|---|---:|---:|']
    for field in EVALUATED_FIELDS:
        cells=[]
        for name in ('gemini','ollama'):
            metrics = models[name]['audited_metrics']
            cells.append(f"{metrics['field_metrics'][field]['exact_accuracy']:.1%} (n={metrics['evaluated']})" if metrics else 'Unavailable')
        lines.append(f"| {field} | {cells[0]} | {cells[1]} |")
    behavior = [models[name]['audited_metrics'] for name in ('gemini','ollama')]
    if all(behavior):
        lines.append(f"| Behavior normalized by existing heuristic | {behavior[0]['behavior_semantic_normalized_accuracy']:.1%} | {behavior[1]['behavior_semantic_normalized_accuracy']:.1%} |")
    lines += ['', 'Behavior exact match is text equality; normalized behavior uses the existing project heuristic, not an independent semantic judge.', '', '## Fresh operational rules (no accuracy)', '', '| Model | Total | Successful | Entity assigned | MITRE assigned |', '|---|---:|---:|---:|---:|']
    for name,m in models.items():
        f=m['fresh_operational']
        lines.append(f"| {name} | {f['total']} | {f['succeeded']} | {f['entity_assigned']} | {f['mitre_assigned']} |")
    lines += ['', '## Inspect disagreements', '', '| SID / REV | Cohort | Different fields |', '|---|---|---|']
    for r in sorted(paired['inspection_disagreements'],key=lambda r:-sum(f!='detected_behavior' for f in r['fields']))[:20]:
        lines.append(f"| {r['sid']} / {r['rev']} | {r['cohort']} | {', '.join(r['fields'])} |")
    lines += ['', '## Interpretation limits', ''] + ['- '+x for x in report['limitations']]
    lines += ['', f"Prompt/context mismatched pairs: {len(paired['context_or_prompt_mismatches'])}", '', 'Cost: COST_NOT_CALCULATED.']
    (directory/'comparison-summary.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('status','complete_pairs','successful_pairs','context_or_prompt_mismatches')}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    main(parser.parse_args().directory.resolve())
