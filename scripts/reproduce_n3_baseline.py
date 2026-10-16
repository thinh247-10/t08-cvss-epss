"""Reproduce N3's already selected C=1 baseline; never search parameters again.

Run with --source pointing to the reviewed N3+N2 source tree. Outputs are new,
separate artifacts; the original N3 model cannot be verified without its bytes.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists():
        raise FileExistsError('Use a new output folder; existing runs are immutable.')
    sys.path.insert(0, str(source))
    import pandas as pd
    import yaml
    from src.model.baseline import train_baseline, save_artifact, load_artifact
    from src.model.predict import predict_frame
    from src.model.run_phase2 import (load_release, sha256, write_json,
                                     final_evaluation, _export_validation_errors)
    from src.model.verify_handoff import verify_handoff
    config = yaml.safe_load((source / 'config/model.yaml').read_text(encoding='utf-8'))
    for key in ('dataset', 'metadata', 'project_config', 'split_source'):
        config['data'][key] = (root / config['data'][key]).as_posix()
    config['parameter_selection'] = {
        'status': 'fixed_reproduction_of_N3_selected_candidate',
        'selected_C': 1.0, 'new_parameter_search': False,
        'original_source_commit': 'a5c0c16d862059819c2b10f973e91827796ac30e',
    }
    output.mkdir(parents=True)
    for folder in ('config', 'reports', 'docs/handoffs', 'models'):
        (output / folder).mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / 'src', output / 'src', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(source / 'requirements-model.txt', output / 'requirements-model.txt')
    config_path = output / 'config/model.yaml'
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding='utf-8')
    os.chdir(output)
    manifest = root / 'docs/handoffs/phase-1-v1.json'
    config, frame, metadata = load_release(config_path, manifest)
    print('Phase 1 verified. Training fixed C=1 on train rows only.', flush=True)
    artifact = train_baseline(frame.loc[frame.split.eq('train')].copy(), config,
                              baseline_overrides={'C': 1.0},
                              model_version='tfidf-v1-n1-reproduction-20261017')
    artifact['selection'] = config['parameter_selection']
    model_path = Path(config['artifacts']['baseline'])
    save_artifact(artifact, model_path)
    loaded = load_artifact(model_path)
    validation = frame.loc[frame.split.eq('validation')].copy()
    pd.testing.assert_frame_equal(predict_frame(artifact, validation.head(5)),
                                  predict_frame(loaded, validation.head(5)))
    lock = {'schema_version': '1.0', 'locked_at': datetime.now(timezone.utc).isoformat(),
            'artifact': model_path.as_posix(), 'artifact_sha256': sha256(model_path),
            'config_sha256': sha256(config_path),
            'dataset_sha256': sha256(config['data']['dataset']),
            'dataset_version': metadata['dataset_version'],
            'model_versions': artifact['model_versions'], 'chosen_candidate': 1,
            'test_status': 'not_run', 'purpose': 'fixed_config_reproduction_not_new_selection'}
    write_json('models/phase2_lock.json', lock)
    write_json('reports/model_selection.json', artifact['selection'])
    val_predictions = pd.concat([predict_frame(loaded, validation, model_kind=kind)
                                 for kind in ('dummy', 'tfidf')], ignore_index=True)
    _export_validation_errors(validation, val_predictions, loaded)
    print(f"Training complete in {artifact['training_seconds']:.2f}s; artifact locked. Evaluating.", flush=True)
    result = final_evaluation(config_path, manifest)
    handoff_path = Path('docs/handoffs/phase-2-model.json')
    handoff = json.loads(handoff_path.read_text(encoding='utf-8'))
    handoff['provenance'] = {'type': 'N1_retraining_of_fixed_N3_configuration',
                             'original_N3_artifact_received': False,
                             'original_model_hash_not_expected_to_match': True}
    handoff['n1_second_machine_reproduction'] = 'retrained_locally_original_artifact_unavailable'
    # Cover exact config/code bytes as well; ZIP preserves them across Git newline settings.
    extra = [config_path, Path('models/phase2_lock.json'), *Path('src').rglob('*.py')]
    for path in extra:
        relative = path.resolve().relative_to(output).as_posix()
        handoff['files'][relative] = {'bytes': path.stat().st_size, 'sha256': sha256(path)}
    write_json(handoff_path, handoff)
    verification = verify_handoff(repo_root=output)
    write_json('reports/reproduction_verification.json', verification)
    original = json.loads((source / 'reports/model_metrics.json').read_text(encoding='utf-8'))
    actual = json.loads(Path('reports/model_metrics.json').read_text(encoding='utf-8'))
    comparison = {}
    for kind in ('dummy', 'tfidf'):
        comparison[kind] = {
            'all_scope_metrics_exactly_equal': actual['models'][kind]['scopes'] == original['models'][kind]['scopes'],
            'training_seconds': artifact['training_seconds'],
        }
    write_json('reports/comparison_to_N3.json', comparison)
    archive = output.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
        for name in sorted(handoff['files']):
            package.write(output / name, name)
        for name in ('docs/handoffs/phase-2-model.json', 'reports/reproduction_verification.json',
                     'reports/comparison_to_N3.json'):
            package.write(output / name, name)
    write_json(output / 'archive_receipt.json', {'archive': str(archive),
               'bytes': archive.stat().st_size, 'sha256': sha256(archive)})
    print(json.dumps({'result': result, 'verification': verification,
                      'comparison': comparison, 'zip': str(archive)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
