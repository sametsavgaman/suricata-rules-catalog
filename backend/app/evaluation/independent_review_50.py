"""Reproducible, blinded evidence review of saved results; no model calls or DB writes."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random
import sqlite3
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'data/evaluation/model-comparison/20260903T060724303787Z'
OUT = BASE / 'independent-review-50'
FIELDS = ['detected_behavior','detected_entity','entity_type','category','subcategory','mitre_tactic','mitre_technique','mitre_technique_id','cyber_kill_chain_phase']

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def lines(path):
    return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x.strip()]

def write(name, value):
    (OUT/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def prepare():
    if (OUT/'blind-packet.json').exists():
        return
    OUT.mkdir(parents=True, exist_ok=True)
    sample = ROOT/'data/evaluation/operational-250/sample-250.jsonl'
    source = BASE/'results.jsonl'
    golden = ROOT/'data/evaluation/golden_dataset.jsonl'
    rows = lines(source)
    groups = defaultdict(dict)
    for row in rows:
        key = row['sid'],row['rev']
        assert row['provider'] not in groups[key]
        groups[key][row['provider']] = row
    assert len(groups)==250 and all(set(p)=={'gemini','ollama'} for p in groups.values())
    selected = random.Random(42).sample(sorted(groups), 50)
    rng = random.Random(20260903)
    packet, keymap = [], []
    db = sqlite3.connect(f'file:{(ROOT/"suricata_rules.db").as_posix()}?mode=ro', uri=True)
    for index,key in enumerate(selected, 1):
        pair = groups[key]
        assert pair['gemini']['raw_rule']==pair['ollama']['raw_rule']
        assert pair['gemini']['configuration']['context_sha256']==pair['ollama']['configuration']['context_sha256']
        names = ['gemini','ollama']; rng.shuffle(names)
        first = pair[names[0]]
        record = {'index':index,'sid':key[0],'rev':key[1],'raw_rule':first['raw_rule'],'source_file':first['source_file'],'cohort':first['cohort']}
        identity = {'index':index,'sid':key[0],'rev':key[1]}
        for label,name in zip(('A','B'),names):
            row = pair[name]
            actual = db.execute('select provider,model_name,rule_id from classifications where id=?',(row['classification_id'],)).fetchone()
            assert actual and actual[:2]==(name,row['model'])
            assert db.execute('select sid,rev from rules where id=?',(actual[2],)).fetchone()==key
            record[label] = {'final':row['final_classification'],'evidence':row['evidence'],
                             'validator':row['validator'], 'mitre_mapping_method':row.get('mitre_mapping_method')}
            identity[label] = {k:row[k] for k in ('provider','model','classification_id','run_id','wall_seconds','usage')}
        packet.append(record); keymap.append(identity)
    db.close()
    write('blind-packet.json',packet); write('identity-key.json',keymap)
    write('sample-50.json',{'seed':42,'sampling':'random.Random(42).sample(sorted SID/REV pairs,50); no disagreement/confidence selection',
          'sample_id':'operational-250-seed42-v1','total':50,'cohorts':dict(Counter(r['cohort'] for r in packet)),
          'records':[{k:r[k] for k in ('index','sid','rev','cohort','source_file')} for r in packet],
          'source_hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (sample,source,golden,ROOT/'data/mitre/enterprise-techniques.json')}})

def show(start,end):
    techniques = {x['technique_id']:x for x in read(ROOT/'data/mitre/enterprise-techniques.json')}
    for row in read(OUT/'blind-packet.json')[start-1:end]:
        print(json.dumps(row,ensure_ascii=False))
        ids = {row[label]['final'].get('mitre_technique_id') for label in ('A','B')} - {None}
        for tid in sorted(ids):
            t=techniques.get(tid)
            print('CANONICAL',json.dumps({k:t.get(k) for k in ('technique_id','name','tactics','parent_id','description')} if t else {'missing':tid},ensure_ascii=False))

SOURCES = {
    'RFC1833': ('RFC 1833: Port Mapper GETPORT / DUMP', 'https://www.rfc-editor.org/rfc/rfc1833.html'),
    'RFC3261': ('RFC 3261: SIP 401 authentication', 'https://www.rfc-editor.org/info/rfc3261/'),
    'SURICATA_THRESHOLD': ('Suricata threshold semantics', 'https://docs.suricata.io/en/latest/rules/thresholding.html'),
    'SURICATA_FLOWBITS': ('Suricata flowbits / noalert', 'https://docs.suricata.io/en/latest/rules/flow-keywords.html'),
    'CLOUDFLARE_SLOPPYLEMMING': ('Cloudflare: SloppyLemming threat actor', 'https://www.cloudflare.com/cloudforce-one/research/unraveling-sloppylemmings-operations-across-south-asia/'),
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical_check(final, techniques):
    tid, name, tactic = (final.get(k) for k in ('mitre_technique_id','mitre_technique','mitre_tactic'))
    if tid is None:
        return ['PARTIAL_MITRE_WITHOUT_ID'] if name is not None or tactic is not None else []
    if tid not in techniques:
        return ['UNKNOWN_MITRE_ID']
    t = techniques[tid]
    issues = []
    if name != t['name']: issues.append('NON_CANONICAL_MITRE_NAME')
    if tactic not in t['tactics']: issues.append('NON_CANONICAL_MITRE_TACTIC')
    return issues

def verify_inputs(packet, judgments, sample):
    assert len(packet) == len(judgments) == 50
    assert [r['index'] for r in judgments] == list(range(1,51))
    assert len({(r['sid'],r['rev']) for r in packet}) == 50
    pairs = sorted({(r['sid'],r['rev']) for r in lines(BASE/'results.jsonl')})
    assert [(r['sid'],r['rev']) for r in packet] == random.Random(42).sample(pairs,50)
    for path,expected in sample['source_hashes'].items():
        assert digest(ROOT/path) == expected, f'Source changed: {path}'
    for row in judgments:
        assert row['semantic'] in ('A','B','TIE') and row['catalogue'] in ('A','B','TIE')
        assert len(row['note']) > 80
        for side in ('A','B'):
            assert set(row['material_'+side]) <= set(FIELDS)
    return {'sample_exactly_50':True, 'unique_pairs_50':True, 'seed42_reproducible':True,
            'all_50_judgments_complete':True, 'original_source_hashes_unchanged':True}

def verify_database(results):
    db=sqlite3.connect(f'file:{(ROOT/"suricata_rules.db").as_posix()}?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    count=0
    try:
        for r in results:
            for p,m in r['models'].items():
                row=db.execute('SELECT * FROM classifications WHERE id=?',(m['classification_id'],)).fetchone()
                assert row is not None and row['provider']==p and row['model_name']==m['model']
                for field in FIELDS+['confidence']:
                    assert row[field]==m['final_classification'].get(field), (r['sid'],p,field)
                count+=1
    finally:
        db.close()
    return count==100

def report():
    packet = read(OUT/'blind-packet.json')
    judgments = read(OUT/'adjudicated-blind-review.json')
    sample = read(OUT/'sample-50.json')
    checks = verify_inputs(packet,judgments,sample)
    # Freeze the evidence-based decisions BEFORE revealing which model is A/B.
    lock_data = {'judgment_sha256':digest(OUT/'adjudicated-blind-review.json'),
                 'packet_sha256':digest(OUT/'blind-packet.json'),
                 'identity_key_sha256':digest(OUT/'identity-key.json')}
    lock_path = OUT/'review-lock.json'
    if lock_path.exists():
        old = read(lock_path)
        assert all(old[k] == v for k,v in lock_data.items()), 'Locked review changed'
    else:
        write('review-lock.json',{**lock_data,'locked_at_utc':datetime.now(timezone.utc).isoformat()})
    identities = read(OUT/'identity-key.json')
    techniques = {x['technique_id']:x for x in read(ROOT/'data/mitre/enterprise-techniques.json')}
    counts = {axis:Counter({'gemini':0,'ollama':0,'TIE':0}) for axis in ('semantic','catalogue')}
    stats = {p:{'model':None,'reviewed':0,'records_with_material_findings':0,
                'canonical_mitre_tuple_errors':0,'material_fields':Counter(),'validator_statuses':Counter(),
                'material_findings_despite_validator_pass':0,'entity_assigned':0,'mitre_assigned':0,
                'kill_chain_assigned':0,'saved_wall_seconds':[], 'flagged_sids':[], 'invalid_mitre_sids':[]}
             for p in ('gemini','ollama')}
    results=[]
    for row,j,identity in zip(packet,judgments,identities):
        assert row['index']==j['index']==identity['index'] and row['sid']==identity['sid']
        decisions={axis:(identity[j[axis]]['provider'] if j[axis]!='TIE' else 'TIE') for axis in counts}
        for axis,value in decisions.items(): counts[axis][value]+=1
        reviewed={}
        for label in ('A','B'):
            ident=identity[label]; provider=ident['provider']; final=row[label]['final']; s=stats[provider]
            s['model']=ident['model']; s['reviewed']+=1
            material=j['material_'+label]; structural=canonical_check(final,techniques)
            s['material_fields'].update(material)
            s['records_with_material_findings']+=bool(material)
            s['canonical_mitre_tuple_errors']+=bool(structural)
            status=row[label]['validator']['status']; s['validator_statuses'][status]+=1
            s['material_findings_despite_validator_pass']+=bool(material) and status=='PASS'
            s['entity_assigned']+=final.get('detected_entity') is not None
            s['mitre_assigned']+=final.get('mitre_technique_id') is not None
            s['kill_chain_assigned']+=final.get('cyber_kill_chain_phase') is not None
            s['saved_wall_seconds'].append(ident['wall_seconds'])
            if material: s['flagged_sids'].append(row['sid'])
            if structural: s['invalid_mitre_sids'].append(row['sid'])
            reviewed[provider]={'blind_label':label,**ident,'final_classification':final,
                'evidence':row[label]['evidence'],'saved_validator':row[label]['validator'],
                'mitre_mapping_method':row[label]['mitre_mapping_method'],
                'material_finding_fields':material,'canonical_mitre_errors':structural,
                'field_assessments':{field:{'value':final.get(field),
                    'assessment':'MATERIAL_FINDING' if field in material else 'NO_MATERIAL_FINDING_ASSERTED',
                    'note_reference':'independent_analysis'} for field in FIELDS}}
        results.append({k:row[k] for k in ('index','sid','rev','cohort','source_file','raw_rule')} | {
            'review_method':'CODEX_INDEPENDENT_ANALYSIS','annotation':{'status':'UNREVIEWED','human_approved':False},
            'ground_truth':False,'independent_analysis':j['note'],'sources':[SOURCES[k] for k in j.get('sources',[])],
            'semantic_preference':decisions['semantic'],'catalogue_preference':decisions['catalogue'],
            'models':reviewed})
    shared=[r['sid'] for r in results if all(r['models'][p]['material_finding_fields'] for p in stats)]
    equal_with_shared=[r['sid'] for r in results if r['semantic_preference']=='TIE' and r['sid'] in shared]
    for s in stats.values():
        s['average_saved_wall_seconds']=sum(s.pop('saved_wall_seconds'))/s['reviewed']
    checks.update({'database_100_outputs_match_snapshot':verify_database(results),
                   'side_assessments_100':sum(s['reviewed'] for s in stats.values())==100,
                   'nine_fields_per_side':all(len(m['field_assessments'])==9 for r in results for m in r['models'].values()),
                   'all_unreviewed':all(r['annotation']['status']=='UNREVIEWED' for r in results),
                   'review_lock_matches':read(lock_path)['judgment_sha256']==digest(OUT/'adjudicated-blind-review.json')})
    assert all(checks.values())
    summary={'sample':sample,'source_run':BASE.name,'review_method':'CODEX_INDEPENDENT_ANALYSIS',
        'ground_truth':False,'new_model_calls':0,'database_writes':0,'preferences':counts,'models':stats,
        'both_models_have_material_findings_sids':shared,'tied_with_shared_material_findings_sids':equal_with_shared,
        'checks':checks,'review_lock':read(lock_path),
        'limitations':['Single AI reviewer, not independent human ground truth.',
            'A/B identities masked during review, but output style can still reveal model characteristics.',
            'Same saved context hash, existing final pipeline outputs; shared gates may cause some errors.',
            '16 audited and 34 fresh; existing expected labels were not used to decide these preferences.',
            'No accuracy inferred from null rates, model agreement, confidence or validator PASS.',
            'One random 50-rule sample and one saved run; no significance or 52k generalization claim.',
            'Material finding counts are reviewer findings, not calibrated error rates; unflagged does not mean verified correct.',
            'Saved timings are from original run, not measurements of this review or pure model latency.']}
    write('review-50-summary.json',summary)
    (OUT/'review-50.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in results),encoding='utf-8')
    def cell(value):
        return ('null' if value is None else str(value)).replace('|','\\|').replace('\n',' ')
    names={p:s['model'] for p,s in stats.items()} | {'TIE':'Eşit / kesin üstünlük yok'}
    md=['# 50 Rule — Gemini / Qwen Bağımsız İnceleme','',
        'Bu rapor AI incelemesidir; human-reviewed ground truth veya accuracy raporu değildir. Hiçbir kayıt otomatik onaylanmadı.',
        '', '## Yöntem','',
        '250 sabit SID/REV çifti sıralandı, Python random.Random(42).sample(..., 50) ile seçildi. '
        '16 audited + 34 fresh. Disagreement/confidence oranına göre örnek seçilmedi. '
        'Aynı raw rule ve context hash kullanan tamamlanmış run sonuçları incelendi; 100 classification ID SQLite ile read-only doğrulandı. '
        'Model adları A/B olarak maskelendi, kanıt incelemesi ve kaynak doğrulaması sonrasında karar dosyası hash ile kilitlenip kimlikler açıldı. '
        'Bu iki bağımsız insan hakemi anlamına gelmez; tek AI reviewer iki çıktıyı da rule evidence ve local MITRE ile kontrol etti.',
        '', 'Dokuz alan birlikte incelendi: behavior, entity, entity type, category, subcategory, tactic, technique, technique ID, Kill Chain. '
        'Semantik tercih: belirgin yanlış/kanıtsız iddia veya geçersiz MITRE tuple açısından göreli üstünlük. '
        'Katalog tercihi: güvenliği gözeterek daha somut, filtrelenebilir ve denetlenebilir anlatım. '
        'Null alan tek başına hata değildir; daha dolu/uzun çıktı otomatik daha doğru değildir. '
        'Source ATT&CK association gözlenmiş saldırı başarısı değildir. Model confidence ve validator PASS hakem olarak kullanılmadı.',
        '', '## Sonuç','', '| Ölçüm | Gemini | Qwen | Eşit |','|---|---:|---:|---:|',
        f"| Kanıta göre belirgin doğruluk üstünlüğü | {counts['semantic']['gemini']} | {counts['semantic']['ollama']} | {counts['semantic']['TIE']} |",
        f"| Katalog kullanılabilirliği tercihi | {counts['catalogue']['gemini']} | {counts['catalogue']['ollama']} | {counts['catalogue']['TIE']} |",'',
        '| Kontrol (her model 50 kayıt) | Gemini | Qwen |','|---|---:|---:|']
    for label,key in [('En az bir önemli bulgu taşıyan kayıt','records_with_material_findings'),
        ('Canonical MITRE tuple hatası','canonical_mitre_tuple_errors'),
        ('Validator PASS olmasına rağmen önemli bulgu','material_findings_despite_validator_pass'),
        ('Entity atanmış (kalite puanı değil)','entity_assigned'),('MITRE ID atanmış (kalite puanı değil)','mitre_assigned'),
        ('Kill Chain atanmış (kalite puanı değil)','kill_chain_assigned')]:
        md.append(f"| {label} | {stats['gemini'][key]} | {stats['ollama'][key]} |")
    md += ['',f"Modeller: `{names['gemini']}` ve `{names['ollama']}`. Her ikisi mevcut V2.1 pipeline sonucu; raw model performansı izole edilmedi.",
        '', 'Bu 50 kural ve mevcut konfigürasyonda Gemini daha güçlü katalog baseline adayıdır: '
        'hem belirgin doğruluk farkı olan karşılaştırmalarda hem somut davranış açıklamalarında öndedir. '
        'Qwen bazı örneklerde daha temkinli/doğru ve kullanılabilir bir local alternatiftir; sonuç genel model ailesine değil bu kaydedilmiş run’a aittir. '
        'Qwen’in sekiz partial MITRE problemi kaydedilmiş validator tarafından REVIEW olarak yakalanmıştır; '
        'buna karşılık iki tarafta da PASS alıp bu incelemede önemli bulgu taşıyan yedişer kayıt vardır.',
        '',f"İki modelde de önemli bulgu: {', '.join(map(str,shared))}. Eşitlik içinde ortak hata: {', '.join(map(str,equal_with_shared))}.",
        '', '**Bu sayılardan 50−bulgu = doğru sayısı veya accuracy üretilmemelidir.** Belirsiz/contextual kararlar notlarda açıklandı. '
        'Generic ama savunulabilir açıklamaları semantik hata saymamak çok sayıda eşitlik üretir; katalog tercihi bu farkı ayrıca görünür kılar.',
        '', '## Operasyonel çıkarım','',
        'Öncelik sırası: (1) ATT&CK ID/name/tactic alanlarının atomik tutarlılığı; (2) HTTP host, DNS lookup ve DNS C2 ayrımı; '
        '(3) source IOC association ile doğrudan ürün/tool fingerprint ayrımı; (4) noalert/helper kurallarının katalog rolü; '
        '(5) protocol, method, CVE ve olasılık niteliğini kaybetmeyen behavior açıklamaları. '
        'Önce bu somut bulgular insan tarafından karara bağlanmalı. Fine-tuning gerekliliği bu 50 kayıttan tek başına çıkarılamaz. '
        'Classifier, prompt, taxonomy, model ayarları, DB, golden dataset ve benchmark değiştirilmedi.',
        '', '## Kural bazlı kısa indeks','', '| # | SID/REV | Doğruluk tercihi | Katalog tercihi |', '|---:|---|---|---|']
    for r in results:
        md.append(f"| {r['index']} | {r['sid']}/{r['rev']} | {names[r['semantic_preference']]} | {names[r['catalogue_preference']]} |")
    md += ['', '## 50 kuralın ayrıntılı incelemesi','']
    for r in results:
        md += [f"### {r['index']}. SID {r['sid']} / REV {r['rev']}",'',f"Cohort: {r['cohort']} — Source: `{r['source_file']}`",'',
            '```text',r['raw_rule'],'```','', '| Alan | Gemini | Qwen |','|---|---|---|']
        for field in FIELDS+['confidence']:
            label='model_confidence (hakem puanı değil)' if field=='confidence' else field
            md.append(f"| {label} | {cell(r['models']['gemini']['final_classification'].get(field))} | {cell(r['models']['ollama']['final_classification'].get(field))} |")
        md += ['']
        for p in stats:
            m=r['models'][p]
            md += [f"**{names[p]} — kör etiket {m['blind_label']}, classification ID {m['classification_id']}**",'',
                f"Kaydedilmiş validator: {m['saved_validator']['status']}; MITRE provenance: {m['mitre_mapping_method']}; "
                f"önemli bulgu alanları: {', '.join(m['material_finding_fields']) or 'belirli önemli hata ileri sürülmedi'}.",
                '', 'Evidence: '+cell(json.dumps(m['evidence'],ensure_ascii=False)), '']
        md += ['**Bağımsız inceleme (A/B kimliği açılmadan yazıldı)**','',r['independent_analysis'],'',
            f"Doğruluk tercihi: **{names[r['semantic_preference']]}**. Katalog tercihi: **{names[r['catalogue_preference']]}**.",'']
        if r['sources']:
            md += ['Teknik kaynak: '+', '.join(f'[{title}]({url})' for title,url in r['sources']), '']
    md += ['## Doğrulama ve sınırlar','']
    md += [f'- {k}: {v}' for k,v in checks.items()]
    md += ['', 'Golden dataset, sample-250, baseline results ve local MITRE SHA256 değerleri başlangıçla aynı. '
        'Yeni API çağrısı: 0. DB mutation: 0. AI review statüsü: UNREVIEWED. '
        'Kaynak/prompt/candidate ortaklıkları nedeniyle bu test salt model yeteneği değil mevcut iki provider pipeline konfigürasyonunun karşılaştırmasıdır. '
        '50 kural tek seed ve tek run ile seçildi; 52 bin kurala kesin genelleme veya istatistiksel anlamlılık iddiası yapılmadı. '
        '16 audited kaydın önceki expected etiketleri bu tercih kararlarında hakem olarak kullanılmadı.', '']
    (OUT/'review-50-report.md').write_text('\n'.join(md),encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ('preferences','models','checks','both_models_have_material_findings_sids')},ensure_ascii=False,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('action', choices=['prepare','show','report']); parser.add_argument('--start', type=int, default=1); parser.add_argument('--end',type=int,default=10)
    args=parser.parse_args()
    if args.action=='prepare': prepare()
    elif args.action=='show': show(args.start,args.end)
    else: report()
