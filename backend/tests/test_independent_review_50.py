"""Artifact integrity checks; never call providers or mutate the classification DB."""
import json
import random

import pytest

from app.evaluation.independent_review_50 import (
    BASE, OUT, ROOT, FIELDS, canonical_check, digest, lines, read, verify_inputs, verify_database,
)


def test_sample_reproducibility_and_cohorts():
    sample=read(OUT/'sample-50.json')
    packet=read(OUT/'blind-packet.json')
    pairs=sorted({(r['sid'],r['rev']) for r in lines(BASE/'results.jsonl')})
    assert [(r['sid'],r['rev']) for r in packet] == random.Random(42).sample(pairs,50)
    assert sample['cohorts']=={'AUDITED_BENCHMARK':16,'FRESH_OPERATIONAL':34}


def test_inputs_and_original_files_unchanged():
    assert all(verify_inputs(read(OUT/'blind-packet.json'),
        read(OUT/'adjudicated-blind-review.json'),read(OUT/'sample-50.json')).values())


def test_review_decisions_were_locked():
    lock=read(OUT/'review-lock.json')
    assert lock['judgment_sha256']==digest(OUT/'adjudicated-blind-review.json')
    assert lock['packet_sha256']==digest(OUT/'blind-packet.json')
    assert lock['identity_key_sha256']==digest(OUT/'identity-key.json')


def test_database_read_only_snapshot_matches_all_100_outputs():
    assert verify_database(lines(OUT/'review-50.jsonl'))


def test_all_100_sides_have_nine_fields_and_no_ground_truth():
    results=lines(OUT/'review-50.jsonl')
    assert len(results)==50
    for r in results:
        assert r['ground_truth'] is False
        assert r['annotation']=={'status':'UNREVIEWED','human_approved':False}
        assert 'expected' not in r
        assert len(r['models'])==2
        for m in r['models'].values():
            assert set(m['field_assessments'])==set(FIELDS)


def test_report_models_and_values_match_saved_run():
    baseline={r['classification_id']:r for r in lines(BASE/'results.jsonl')}
    for r in lines(OUT/'review-50.jsonl'):
        for provider,m in r['models'].items():
            saved=baseline[m['classification_id']]
            assert (saved['sid'],saved['rev'])==(r['sid'],r['rev'])
            assert saved['provider']==provider
            assert saved['model']==m['model']
            assert saved['final_classification']==m['final_classification']


@pytest.mark.parametrize('final,expected',[
    ({'mitre_technique_id':None,'mitre_technique':None,'mitre_tactic':None},[]),
    ({'mitre_technique_id':None,'mitre_technique':'Web Shell','mitre_tactic':'Web Attack'},['PARTIAL_MITRE_WITHOUT_ID']),
    ({'mitre_technique_id':'T0','mitre_technique':'Anything','mitre_tactic':'Anything'},['UNKNOWN_MITRE_ID']),
    ({'mitre_technique_id':'T1219','mitre_technique':'Remote Access Tools','mitre_tactic':'Command And Control'},[]),
])
def test_mitre_tuple_check(final,expected):
    techniques={t['technique_id']:t for t in read(ROOT/'data/mitre/enterprise-techniques.json')}
    assert canonical_check(final,techniques)==expected


def test_summary_aggregates_and_no_fake_accuracy():
    summary=read(OUT/'review-50-summary.json')
    results=lines(OUT/'review-50.jsonl')
    for axis in ('semantic','catalogue'):
        for side in ('gemini','ollama','TIE'):
            assert summary['preferences'][axis][side]==sum(r[axis+'_preference']==side for r in results)
    for provider,s in summary['models'].items():
        assert s['records_with_material_findings']==sum(bool(r['models'][provider]['material_finding_fields']) for r in results)
        assert s['canonical_mitre_tuple_errors']==sum(bool(r['models'][provider]['canonical_mitre_errors']) for r in results)
    assert summary['new_model_calls']==summary['database_writes']==0
    assert 'accuracy' not in summary
    assert all(summary['checks'].values())
