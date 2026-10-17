"""Verify fresh archive extraction and replay five validation cases only."""
from pathlib import Path
import json
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.model.run_phase2 import sha256, write_json
from src.model.predict_distilbert import verify_bundle

def main():
    receipt = json.loads((ROOT/'docs/handoffs/phase-2-complete-20261017.json').read_text())
    archive = ROOT/receipt['archive']
    assert archive.stat().st_size == receipt['bytes']
    assert sha256(archive) == receipt['sha256']
    dest = ROOT/'data/processed/reviews/phase2_handoff_verified_20261017'
    dest.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            assert (dest/name).resolve().is_relative_to(dest.resolve())
        z.extractall(dest)
    manifest = json.loads((dest/'manifest.json').read_text())
    for name, entry in manifest['files'].items():
        p = dest/name
        assert p.stat().st_size == entry['bytes'] and sha256(p) == entry['sha256'], name
    notebook = 'notebooks/02_model_eval_n1.ipynb'
    assert sha256(dest/notebook) == sha256(ROOT/notebook)
    cells = json.loads((dest/notebook).read_text(encoding='utf-8'))['cells']
    executed = [c for c in cells if c['cell_type']=='code' and c.get('execution_count') is not None]
    assert len(executed) == 13
    verify_bundle(dest/'distilbert')
    import pandas as pd
    import torch
    from src.model.distilbert_multihead import load_model, tokenize_descriptions, infer_tokens, contract_predictions
    torch.set_num_threads(4)
    model, tokenizer, metadata = load_model(dest/'distilbert/model', 'cpu')
    cohort = pd.read_parquet(ROOT/'data/processed/phase1_v1_20261010/ml_cohort.parquet')
    sample = cohort.loc[cohort.split.eq('validation')].sort_values('cve_id').head(5)
    tokens, _ = tokenize_descriptions(tokenizer, sample.description, metadata['config']['max_length'])
    actual = contract_predictions(sample, infer_tokens(model, tokens, 5, 'cpu'), metadata)
    expected = pd.read_csv(dest/'distilbert/predictions.csv').set_index('cve_id').loc[actual.cve_id].reset_index()
    columns = [c for c in actual.columns if c.startswith('pred_') or c == 'predicted_base_score']
    for col in columns:
        assert actual[col].reset_index(drop=True).equals(expected[col].reset_index(drop=True)), col
    result = {'status':'passed','archive_sha256':receipt['sha256'], 'verified_files':len(manifest['files']),
              'executed_notebook_cells':len(executed),'validation_ids':sample.cve_id.tolist(),
              'reloaded_device':'cpu','matched_prediction_columns':columns,
              'validation_predictions_match':True,'final_test_reevaluated':False,
              'limitation':'Fresh extraction and new process on N1 machine; not an independent second-machine receipt.'}
    write_json(ROOT/'reports/p2_final_handoff_verification.json',result)
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    main()
