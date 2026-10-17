"""Validate completed Phase 2 artifacts and create a portable handoff.

Reads recorded metrics only; never retrains or reevaluates final-test predictions.
"""
from pathlib import Path
import json
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
from src.model.run_phase2 import sha256, write_json
from src.model.verify_handoff import verify_handoff
from src.model.predict_distilbert import verify_bundle
from src.model.reporting import summary_table
from src.model.data_validation import TARGET_METRICS


def markdown_table(frame):
    def value(x):
        return f'{x:.6f}' if isinstance(x, float) else str(x).replace('|','/')
    return '\n'.join(['| '+' | '.join(frame.columns)+' |',
                       '| '+' | '.join(['---']*len(frame.columns))+' |']+
                      ['| '+' | '.join(value(v) for v in row)+' |' for row in frame.itertuples(index=False, name=None)])


def main():
    baseline = ROOT/'data/processed/p2_n1_reproduction_20261017'
    distil = ROOT/'data/processed/p2_distilbert_20261017'
    release = ROOT/'data/processed/phase1_v1_20261010'
    rankings = ROOT/'data/raw/handoffs/n2_phase2_received_20261017/rankings.csv'
    output = ROOT/'data/processed/phase2_handoff_20261017'
    if output.exists():
        raise FileExistsError('Preserve the previous handoff; do not overwrite')
    b_verify = verify_handoff(repo_root=baseline)
    d_manifest = verify_bundle(distil)
    b = json.loads((baseline/'reports/model_metrics.json').read_text())
    d = json.loads((distil/'metrics.json').read_text())
    lock = json.loads((distil/'lock.json').read_text())
    if d['status'] != 'complete' or lock['test_status'] != 'complete':
        raise ValueError('DistilBERT has not completed final evaluation')
    if sha256(distil/'model/model.safetensors') != lock['model_sha256']:
        raise ValueError('Locked model hash differs')
    if sha256(release/'ml_cohort.parquet') != lock['dataset_sha256']:
        raise ValueError('Frozen dataset hash differs')
    if sha256(ROOT/'config/distilbert.yaml') != lock['config_sha256']:
        raise ValueError('Configuration changed after lock')
    bp = pd.read_csv(baseline/'data/processed/predictions.csv')
    dp = pd.read_csv(distil/'predictions.csv')
    truth = pd.read_parquet(release/'ml_cohort.parquet')
    heldout = truth.loc[truth.split.ne('train')]
    for prediction in (bp, dp):
        if prediction.duplicated(['cve_id','model_version']).any():
            raise ValueError('Duplicate prediction key')
        for _, group in prediction.groupby('model_version'):
            if set(group.cve_id) != set(heldout.cve_id):
                raise ValueError('Prediction IDs differ from frozen held-out IDs')
            joined = heldout[['cve_id','split','dataset_version']].merge(group, on='cve_id', validate='one_to_one')
            if not joined.split_x.eq(joined.split_y).all() or not joined.dataset_version_x.eq(joined.dataset_version_y).all():
                raise ValueError('Prediction split/version mismatch')
    ranking = pd.read_csv(rankings)
    cohort = pd.read_parquet(release/'ranking_cohort.parquet')
    if len(ranking) != 396 or ranking.cve_id.duplicated().any() or set(ranking.cve_id) != set(cohort.cve_id):
        raise ValueError('Ranking cohort mismatch')
    if sha256(rankings) != '4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67':
        raise ValueError('Reviewed ranking bytes changed')
    rows = []
    for split in ('validation','test'):
        for metrics in (b,d):
            table = summary_table(metrics, split)
            table.insert(0,'split',split)
            rows.append(table)
    comparison = pd.concat(rows, ignore_index=True)
    comparison.to_csv(ROOT/'reports/p2_model_comparison.csv',index=False)
    # Export validation errors only. Never inspect test cases to change a model.
    validation = truth.loc[truth.split.eq('validation')].merge(dp, on=['cve_id','split','dataset_version'],validate='one_to_one')
    wrong = pd.Series(False,index=validation.index)
    for metric in TARGET_METRICS:
        wrong |= validation[metric].ne(validation[f'pred_{metric}'])
    error_sample = validation.loc[wrong].sort_values('cve_id').head(10)
    columns = ['cve_id','description',*TARGET_METRICS,*[f'pred_{m}' for m in TARGET_METRICS],
               'cvss_base_score','predicted_base_score']
    error_sample[columns].to_csv(ROOT/'reports/p2_distilbert_validation_errors.csv',index=False)
    write_json(ROOT/'reports/p2_distilbert_results.json',d)
    write_json(ROOT/'reports/p2_distilbert_lock.json',lock)
    # Portable handoff: original baseline ZIP is unchanged; DistilBERT files keep exact bytes.
    output.mkdir(parents=True)
    baseline_zip = baseline.with_suffix('.zip')
    expected = json.loads((baseline/'archive_receipt.json').read_text())
    if sha256(baseline_zip) != expected['sha256']:
        raise ValueError('Baseline ZIP hash mismatch')
    shutil.copyfile(baseline_zip,output/'baseline.zip')
    shutil.copytree(distil,output/'distilbert')
    shutil.copyfile(rankings,output/'rankings.csv')
    shutil.copytree(ROOT/'src',output/'src',ignore=shutil.ignore_patterns('__pycache__'))
    for name in ['requirements-data.txt','requirements-model.txt','requirements-distilbert.txt']:
        shutil.copyfile(ROOT/name,output/name)
    for name in ['reports/p2_model_comparison.csv','reports/p2_distilbert_results.json',
                 'reports/p2_distilbert_validation_errors.csv','reports/p2_validation_security_review.md',
                 'notebooks/02_model_eval_n1.ipynb','config/distilbert.yaml']:
        destination = output/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,destination)
    (output/'README.txt').write_text(
        'Phase 2 handoff: dataset t08-v1.0-20261010\n'
        'Baseline is inside baseline.zip: extract into baseline/ and use its verify_handoff CLI.\n'
        'DistilBERT: python -m src.model.predict_distilbert --bundle distilbert --description "A remote attacker can execute arbitrary code."\n'
        'Install requirements-distilbert.txt for the optional CUDA run. Inference defaults to CPU.\n'
        'rankings.csv uses observed CVSS, NOT predicted severity.\n'
        'The notebook refers to the full repository layout and Phase 1 release; retain those to rerun it.\n'
        'This ZIP has no API keys or .env. Phase 1 dataset is delivered separately.\n',encoding='utf-8')
    files = {p.relative_to(output).as_posix():{'bytes':p.stat().st_size,'sha256':sha256(p)}
             for p in output.rglob('*') if p.is_file()}
    manifest = {'status':'complete','dataset_version':b['dataset_version'],
                'baseline_model_versions':b_verify['model_versions'],
                'distilbert_model_version':d_manifest['model_version'],
                'baseline_prediction_rows':len(bp),'distilbert_prediction_rows':len(dp),
                'ranking_rows':len(ranking),'files':files}
    write_json(output/'manifest.json',manifest)
    archive = output.with_suffix('.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for path in sorted(output.rglob('*')):
            if path.is_file():
                z.write(path,path.relative_to(output).as_posix())
    receipt = {'archive':archive.relative_to(ROOT).as_posix(),'bytes':archive.stat().st_size,
               'sha256':sha256(archive),'dataset_version':b['dataset_version'],
               'baseline_model_versions':b_verify['model_versions'],
               'distilbert_model_version':d_manifest['model_version'],
               'baseline_prediction_rows':len(bp),'distilbert_prediction_rows':len(dp),
               'ranking_rows':len(ranking)}
    write_json(ROOT/'docs/handoffs/phase-2-complete-20261017.json',receipt)
    print(comparison.to_string(index=False))
    print(json.dumps(receipt,indent=2))


if __name__ == '__main__':
    main()
