"""Paired production-pipeline runs using the frozen operational sample, never resampling it."""
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from time import perf_counter

from sqlalchemy import select

from app.agent.factory import create_classification_provider, provider_config_error
from app.config import get_settings
from app.database.models import Rule, ClassificationStatus
from app.database.session import Base, engine, SessionLocal, ensure_schema_extensions
from app.evaluation.golden_dataset import reviewed_records
from app.evaluation.metrics import calculate_metrics, compare_fields
from app.evaluation.schemas import EVALUATED_FIELDS, EvaluationResult
from app.evaluation.run_operational_250 import _classification_payload
from app.knowledge.mitre_repository import MitreRepository
from app.services.classification_service import ClassificationService

ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "data/evaluation/operational-250/sample-250.jsonl"
GOLDEN = ROOT / "data/evaluation/golden_dataset.jsonl"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_sample(path=SAMPLE):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 250 or len({(r['sid'], r['rev']) for r in rows}) != 250:
        raise ValueError("Frozen sample must contain exactly 250 unique SID/REV pairs.")
    if Counter(r['cohort'] for r in rows) != {"AUDITED_BENCHMARK": 97, "FRESH_OPERATIONAL": 153}:
        raise ValueError("Frozen sample cohort counts are invalid.")
    return rows


def summarize(rows, golden):
    audited = []
    for row in rows:
        key = row['sid'], row['rev']
        if row['cohort'] != 'AUDITED_BENCHMARK' or key not in golden:
            continue
        expected = golden[key].expected.model_dump()
        actual = row['final_classification'] if row['succeeded'] else None
        matches, normalized, errors = compare_fields(expected, actual)
        audited.append(EvaluationResult(sid=row['sid'], rev=row['rev'], msg=row['rule_message'],
            source_file=row['source_file'] or '', expected=expected, actual=actual,
            matches=matches, normalized_matches=normalized, errors=errors,
            confidence=row['final_classification']['confidence'], status=row['validator']['status'],
            usage=row['usage'], agent_activity=row['agent_activity']))
    fresh = [r for r in rows if r['cohort'] == 'FRESH_OPERATIONAL']
    successful = [r for r in fresh if r['succeeded']]
    return {
        "total": len(rows), "succeeded": sum(r['succeeded'] for r in rows),
        "failed": sum(not r['succeeded'] for r in rows),
        "audited_metrics": calculate_metrics(audited) if audited else None,
        "fresh_operational": {"total": len(fresh), "succeeded": len(successful),
            "category_distribution": dict(Counter(r['final_classification'].get('category') for r in successful)),
            "entity_assigned": sum(r['final_classification'].get('detected_entity') is not None for r in successful),
            "mitre_assigned": sum(r['final_classification'].get('mitre_technique_id') is not None for r in successful),
            "validator_distribution": dict(Counter(r['validator']['status'] for r in fresh))},
        "usage": {k: sum(r['usage'][k] for r in rows) for k in ('input_tokens', 'output_tokens', 'total_tokens')},
        "usage_coverage": "SUCCESSFUL_RESPONSES_ONLY; usage on failed or retried requests may be unavailable",
        "retry_count": "NOT_RECORDED",
        "average_seconds": sum(r['wall_seconds'] for r in rows) / len(rows) if rows else None,
        "tool_usage": dict(Counter(t for r in rows for t in r['agent_activity'].get('tools_used', []))),
        "cost": "COST_NOT_CALCULATED",
    }


async def run(args):
    frozen = frozen_sample()
    sample_hash, golden_hash = digest(SAMPLE), digest(GOLDEN)
    if args.limit == 250:
        selected = frozen
    else:
        # A smoke test covers both cohorts while retaining exact frozen rules.
        n = (args.limit + 1) // 2
        selected = [r for r in frozen if r['cohort'] == 'AUDITED_BENCHMARK'][:n] + [r for r in frozen if r['cohort'] == 'FRESH_OPERATIONAL'][:args.limit-n]
    settings = get_settings()
    providers = args.providers.split(',')
    services_settings = {}
    for name in providers:
        s = settings.model_copy(update={"ai_provider": name, "classifier_version": "v2.1"})
        if error := provider_config_error(s):
            raise ValueError(error)
        services_settings[name] = (s, create_classification_provider(s))
    golden = {(r.sid, r.rev): r for r in reviewed_records(GOLDEN)}
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    outdir = args.resume.resolve() if args.resume else ROOT / 'data/evaluation/model-comparison' / stamp
    output = []
    if args.resume:
        output = [json.loads(line) for line in (outdir / 'results.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
        wanted = {(r['sid'], r['rev']) for r in selected}
        for row in output:
            if row['sample_sha256'] != sample_hash or (row['sid'], row['rev']) not in wanted:
                raise ValueError('Resume sample mismatch.')
            if row['provider'] not in services_settings or row['model'] != services_settings[row['provider']][1].model_name or row['classifier_version'] != 'v2.1':
                raise ValueError('Resume model/version mismatch.')
    else:
        outdir.mkdir(parents=True, exist_ok=False)
    completed = {(r['provider'], r['sid'], r['rev']) for r in output}
    if len(completed) != len(output):
        raise ValueError('Duplicate results in resume file.')
    print(f"REPORT_DIRECTORY={outdir}", flush=True)
    Base.metadata.create_all(engine)
    ensure_schema_extensions()
    repo = MitreRepository()
    with SessionLocal() as db, (outdir / 'results.jsonl').open('a' if args.resume else 'x', encoding='utf-8') as stream:
        rules = []
        for row in selected:
            rule = db.scalar(select(Rule).where(Rule.sid == row['sid'], Rule.rev == row['rev']))
            if rule is None:
                raise ValueError(f"Frozen rule missing from database: {row['sid']}/{row['rev']}; import its exact revision first.")
            rules.append((row, rule))
        for index, (cohort, rule) in enumerate(rules, 1):
            for name, (s, provider) in services_settings.items():
                if (name, rule.sid, rule.rev) in completed:
                    continue
                started = perf_counter()
                c = await ClassificationService(db, provider, s, repo).classify(rule, force=True)
                c.inspection_batch = 'operational-250'
                db.commit()
                payload = {**_classification_payload(rule, c), "cohort": cohort['cohort'],
                    "sample_id": "operational-250-seed42-v1", "sample_sha256": sample_hash,
                    "classification_id": c.id, "run_id": c.run_id,
                    "succeeded": c.classification_status != ClassificationStatus.FAILED,
                    "wall_seconds": round(perf_counter() - started, 3),
                    "usage": c._token_usage.model_dump(), "cache_hit": False,
                    "configuration": c.model_config_json,
                    "raw_rule_sha256": hashlib.sha256(rule.raw_rule.encode()).hexdigest()}
                if not payload['succeeded']:
                    # Do not serialize provider exception text, which may contain request data.
                    payload['failure'] = list(c.validation_issues)
                stream.write(json.dumps(payload, ensure_ascii=False) + '\n')
                stream.flush()
                output.append(payload)
                print(f"[{index}/{len(selected)}] [{name}] SID {rule.sid} {'OK' if payload['succeeded'] else 'FAILED'} {payload['wall_seconds']}s", flush=True)
                if name == 'gemini' and args.pace:
                    await asyncio.sleep(args.pace)
    if digest(SAMPLE) != sample_hash or digest(GOLDEN) != golden_hash:
        raise RuntimeError('Sample or golden dataset changed during the run.')
    report = {
        "sample_id": "operational-250-seed42-v1", "sample_sha256": sample_hash,
        "golden_sha256": golden_hash, "selected_count": len(selected),
        "classifier_version": 'v2.1', "cache_policy": 'FRESH_CALLS_BOTH_PROVIDERS',
        "notice": "Accuracy applies only to reviewed audited records. Fresh cohort has no ground truth. Smoke metrics are not representative. Similar-rule retrieval uses other reviewed benchmark examples (existing V2 policy); this is not a fully held-out benchmark. Model confidence is uncalibrated. Token counts use different tokenizers.",
        "models": {name: {"model": p.model_name, **summarize([r for r in output if r['provider'] == name], golden)} for name, (s, p) in services_settings.items()},
    }
    (outdir / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = ['# Gemini / Qwen production pipeline comparison', '', report['notice'], '', f"Rules: {len(selected)}; sample SHA256: `{sample_hash}`", '', '| Provider | Model | Succeeded | Failed | Mean seconds | Input tokens | Output tokens |', '|---|---|---:|---:|---:|---:|---:|']
    for name, r in report['models'].items():
        lines.append(f"| {name} | {r['model']} | {r['succeeded']} | {r['failed']} | {r['average_seconds']:.2f} | {r['usage']['input_tokens']} | {r['usage']['output_tokens']} |")
    lines += ['', '## Audited metrics / fresh descriptive results', '', 'See report.json. No accuracy is calculated for fresh rules.', '', 'Cost: COST_NOT_CALCULATED. Local electricity and hardware costs have not been measured.']
    (outdir / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(report['models'], ensure_ascii=False), flush=True)
    return int(any(not r['succeeded'] for r in output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, choices=range(1, 251), default=5)
    parser.add_argument('--providers', default='ollama,gemini', choices=['ollama', 'gemini', 'ollama,gemini'])
    parser.add_argument('--pace', type=float, default=4, help='Seconds between Gemini calls; local inference is sequential.')
    parser.add_argument('--resume', type=Path, help='Continue an interrupted result directory without repeating recorded attempts.')
    raise SystemExit(asyncio.run(run(parser.parse_args())))
