"""Verify N3 outputs and create a new handoff ZIP; never overwrite a sent archive."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TABLES = ROOT / 'data/processed/p3_n3'


def info(path):
    path = Path(path)
    return {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    if args.archive.exists():
        parser.error('Archive exists; choose a new revision, never overwrite a delivered ZIP')
    plots = json.loads((TABLES / 'figures_manifest.json').read_text(encoding='utf-8'))
    impact = json.loads((TABLES / 'prediction_rank_metrics.json').read_text(encoding='utf-8'))
    crosscheck = json.loads((TABLES / 'environmental_crosscheck_n3.json').read_text(encoding='utf-8'))
    if plots['status'] != 'complete' or plots['pending'] or crosscheck['status'] != 'pass':
        raise ValueError('Required plot/context/crosscheck scope incomplete')
    sources = set()
    for manifest in (plots, impact):
        for rec in manifest['inputs'] + manifest['outputs'] + [manifest['code']]:
            path = ROOT / rec['path']
            if info(path) != {k: rec[k] for k in ('sha256', 'bytes')}:
                raise ValueError(f'Artifact changed since analysis: {path}')
        sources.update(ROOT / rec['path'] for rec in manifest['outputs'])
    if info(ROOT / crosscheck['input']['path']) != {k: crosscheck['input'][k] for k in ('sha256','bytes')}:
        raise ValueError('Crosscheck input changed')
    sources.update(TABLES / name for name in ('figures_manifest.json', 'prediction_rank_metrics.json',
        'environmental_crosscheck_n3.json'))
    documents = ['reports/p3_figures.md', 'reports/p3_figures_check.md',
        'reports/p3_prediction_rank_impact.md', 'reports/p3_environmental_crosscheck_n3.md',
        'reports/p3_n3_completion.md', 'docs/cases/p3-mobile-n3.md',
        'docs/phase-4-ui-contract.md', 'notebooks/03_priority_analysis.ipynb']
    sources.update(ROOT / name for name in documents)
    notebook = json.loads((ROOT / documents[-1]).read_text(encoding='utf-8'))
    code_cells = [c for c in notebook['cells'] if c['cell_type']=='code']
    if [c['execution_count'] for c in code_cells] != list(range(1, len(code_cells)+1)):
        raise ValueError('Notebook not executed in order')
    if any(o['output_type']=='error' for c in code_cells for o in c['outputs']):
        raise ValueError('Notebook contains errors')
    images = sum('image/png' in o.get('data',{}) for c in code_cells for o in c['outputs'])
    if images != 7:
        raise ValueError('Notebook must embed the seven actual figures')
    members = {}
    for path in sorted(sources):
        if path.is_relative_to(TABLES):
            name = 'p3_n3/' + path.relative_to(TABLES).as_posix()
        elif path.is_relative_to(ROOT / 'reports/figures/phase3'):
            name = 'phase3/' + path.name
        else:
            name = 'p3_n3/review/' + path.relative_to(ROOT).as_posix()
        members[name] = {'source_path': path.relative_to(ROOT).as_posix(), **info(path)}
    head = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    metadata = {'schema_version': 'p3-n3-handoff-v1', 'status': 'n3_scope_complete',
        'dataset_version': plots['dataset_version'], 'cohort_id': plots['cohort_id'],
        'ranking_policy_version': plots['policy_version'], 'context_version': plots['context']['context_version'],
        'queue_policy_version': plots['context']['queue_policy_version'], 'model_versions': impact['models'],
        'packaging_commit': head, 'branch': subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip(),
        'analysis_provenance': 'Original plot/prediction manifests preserve their own command, code hash and run provenance.',
        'source_dates': plots['source_dates'], 'dependencies': plots['dependencies'],
        'python_packaging': platform.python_version(), 'commands': [plots['command'], impact['command'],
            ['python','scripts/check_phase3_environmental_n3.py'], ['python','scripts/execute_phase3_notebook.py']],
        'coverage': {'ranking_n':plots['n'], 'kev':plots['kev'], 'context':plots['context'],
            'prediction_splits': impact['splits']}, 'notebook_execution': notebook['metadata']['n3_execution'],
        'files': members, 'metadata_self_hash': 'Excluded to avoid recursion; entire metadata is covered by external ZIP SHA-256.',
        'unresolved_n3_artifacts': [], 'group_integration': 'N1/N2 integration is not asserted complete',
        'required_external_inputs': 'Verified Phase 1, Phase 2 and user-pinned N2 context r1; not bundled again.'}
    metadata_path = TABLES / 'metadata.json'
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for name, rec in members.items():
            z.write(ROOT / rec['source_path'], name)
        z.write(metadata_path, 'p3_n3/metadata.json')
    with zipfile.ZipFile(args.archive) as z:
        assert z.testzip() is None
        for name, rec in members.items():
            data=z.read(name)
            assert len(data)==rec['bytes'] and hashlib.sha256(data).hexdigest()==rec['sha256'], name
        assert z.read('p3_n3/metadata.json')==metadata_path.read_bytes()
    receipt = {'archive': args.archive.as_posix(), **info(args.archive), 'packaging_commit':head,
               'files':len(members)+1, 'zip_crc_and_member_hashes':'pass'}
    args.archive.with_suffix('.receipt.json').write_text(json.dumps(receipt, indent=2)+'\n',encoding='utf-8')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
