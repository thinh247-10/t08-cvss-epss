"""N1 independent artifact checks: fixed cohorts, pair statuses and real figure tables."""
from pathlib import Path
import hashlib
import itertools
import json
import math
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

def check(root=ROOT):
    n2 = root/'data/processed/p3_n2'
    n3 = root/'data/processed/p3_n3'
    rank = pd.read_csv(n2/'rankings.csv')
    cohort = pd.read_parquet(root/'data/processed/phase1_v1_20261010/ranking_cohort.parquet')
    assert len(rank)==396 and not rank.cve_id.duplicated().any()
    assert set(rank.cve_id)==set(cohort.cve_id) and rank.is_kev.sum()==3
    assert hashlib.sha256((n2/'rankings.csv').read_bytes()).hexdigest()=='4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67'
    # Pairwise definition, independent of scipy and production ranking metrics.
    concordant=discordant=ties_x=ties_y=0
    values=list(rank[['cvss_base_score','epss']].itertuples(index=False,name=None))
    for (x1,y1),(x2,y2) in itertools.combinations(values,2):
        x,y=x1-x2,y1-y2
        if x==0 and y==0: continue
        if x==0: ties_x+=1
        elif y==0: ties_y+=1
        elif x*y>0: concordant+=1
        else: discordant+=1
    tau=(concordant-discordant)/math.sqrt((concordant+discordant+ties_x)*(concordant+discordant+ties_y))
    metrics=json.loads((n2/'ranking_metrics.json').read_text())
    assert abs(tau-metrics['kendall_tau_b']['value'])<1e-12
    for row in pd.read_csv(n2/'overlap.csv').itertuples():
        a=set(rank.loc[rank[row.policy_a+'_rank']<=row.k,'cve_id'])
        b=set(rank.loc[rank[row.policy_b+'_rank']<=row.k,'cve_id'])
        assert row.intersection==len(a&b) and row.union==len(a|b)
        assert abs(row.jaccard-len(a&b)/len(a|b))<1e-12
    for row in pd.read_csv(n2/'topk_metrics.csv').itertuples():
        selected=rank.loc[rank[row.policy+'_rank']<=row.k]
        assert row.kev_hits==selected.is_kev.sum()
        if row.policy=='kev_first': assert pd.isna(row.kev_recall)
        else: assert abs(row.kev_recall-row.kev_hits/3)<1e-12
    top=pd.read_csv(n3/'top50_long.csv')
    for policy,group in top.groupby('policy'):
        expected=rank.sort_values(policy+'_rank').head(50)
        assert group.sort_values('rank').cve_id.tolist()==expected.cve_id.tolist()
    mapping=pd.read_csv(n2/'cve_asset_mapping.csv')
    queue=pd.read_csv(n2/'priority_queue.csv')
    env=pd.read_csv(n2/'environmental_scores.csv')
    pairs=lambda f:set(zip(f.cve_id,f.asset_id))
    assert len(mapping)==15 and len(queue)==15 and pairs(mapping)==pairs(queue)
    assert not mapping.duplicated(['cve_id','asset_id']).any()
    assert len(env)==10 and pairs(env)==pairs(mapping.loc[mapping.applicability.eq('affected')])
    assert queue.queue_status.value_counts().to_dict()=={'patch':8,'review_required':7}
    patch=queue.loc[queue.queue_status.eq('patch')]
    assert sorted(patch.priority_rank)==list(range(1,9))
    assert queue.loc[~queue.queue_status.eq('patch'),'priority_rank'].isna().all()
    clients=queue.loc[queue.exposure.eq('client')]
    assert len(clients)==2 and clients.queue_status.eq('review_required').all()
    context=pd.read_csv(n3/'context_plot.csv')
    assert pairs(context)==pairs(patch) and context.context_version.eq('phase3-context-v2').all()
    figures=json.loads((n3/'figures_manifest.json').read_text())
    assert figures['status']=='complete' and not figures['pending']
    assert figures['context']['context_version']=='phase3-context-v2'
    for name in ['figures_manifest.json','prediction_rank_metrics.json']:
        manifest=json.loads((n3/name).read_text())
        for rec in manifest['inputs']+manifest['outputs']+[manifest['code']]:
            p=root/rec['path']
            assert p.stat().st_size==rec['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==rec['sha256'],p
    result={'status':'pass','dataset_version':'t08-v1.0-20261010','context_version':'phase3-context-v2',
            'ranking_cves':396,'kev':3,'independent_tau_b':tau,'top50_rows':len(top),
            'mapping_pairs':15,'environmental_pairs':10,'patch_pairs':8,'review_pairs':7,
            'client_review_pairs':2,'source':'N1 rerun from merged peer code; original N2 r2/N3 ZIPs not received',
            'checks':['ranking hash and cohort','pairwise tau-b','all Jaccard/recall entries','all top50 IDs',
                      'mapping/queue completeness','client null ranks','context-v2 plot cohort','manifest inputs/outputs/code']}
    return result

if __name__=='__main__':
    result=check()
    (ROOT/'reports/p3_integration_verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
