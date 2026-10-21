"""Package the integrated Phase 3 artifacts; verify a fresh extraction without ML dependencies."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]

def info(p):
    return {'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

def verify(folder):
    folder=Path(folder).resolve()
    manifest=json.loads((folder/'phase3_manifest.json').read_text(encoding='utf-8'))
    if manifest.get('status')!='complete' or manifest.get('context_version')!='phase3-context-v2':
        raise ValueError('Wrong release status/context')
    for name,record in manifest['files'].items():
        p=(folder/name).resolve()
        if not p.is_relative_to(folder) or not p.is_file() or info(p)!=record:
            raise ValueError(f'Missing/unsafe/changed release file: {name}')
    return {'status':'pass','files':len(manifest['files']),'context_version':manifest['context_version']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify',type=Path)
    args=parser.parse_args()
    if args.verify:
        print(json.dumps(verify(args.verify),indent=2)); return
    sys.path.insert(0,str(ROOT))
    from scripts.verify_phase3_integration import check
    check()
    archive=ROOT/'data/processed/phase3_handoff_20261021.zip'
    if archive.exists(): raise FileExistsError('Use a new revision; never overwrite a delivered archive')
    files=set()
    for relative in ['data/processed/p3_n2','data/processed/p3_n3',
                     'data/processed/p3_n1_context_verified_20261021','reports/figures/phase3']:
        files.update(p for p in (ROOT/relative).rglob('*') if p.is_file())
    for pattern in ['reports/p3*.md','reports/p3*.json','docs/phase-3-completion.md',
                    'docs/phase-4-*.md','docs/cases/p3-*.md','config/phase3*.yaml']:
        files.update(ROOT.glob(pattern))
    files.update(ROOT/name for name in ['docs/analysis-results.md','docs/03-environmental-context.md',
        'docs/04-patch-playbook.md','docs/phase-3-artifact-contract.md','config/assets.yaml',
        'notebooks/03_priority_analysis.ipynb','requirements-analysis.txt','requirements-data.txt',
        'requirements-model.txt'])
    records={p.relative_to(ROOT).as_posix():info(p) for p in sorted(files)}
    manifest={'status':'complete','release_version':'phase3-n1-integrated-20261021',
        'dataset_version':'t08-v1.0-20261010','context_version':'phase3-context-v2',
        'created_at_utc':datetime.now(timezone.utc).isoformat(), 'files':records,
        'provenance':'Reproduced by N1 from merged N2/N3 code; not a receipt of their original final ZIPs.',
        'external_inputs':'Phase 1 and Phase 2 bundles remain separate; code is obtained from Git.',
        'layout':'Repository-relative paths; extract into a NEW staging directory, verify before using.',
        'historical_manifests':'Producer manifests retain original input paths and code hashes; outer manifest covers distributed bytes.'}
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for name in records: z.write(ROOT/name,name)
        z.writestr('phase3_manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    destination=ROOT/'data/processed/reviews/phase3_handoff_verified_20261021'
    destination.mkdir(parents=True,exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None: raise ValueError('Archive CRC failed')
        for name in z.namelist():
            if not (destination/name).resolve().is_relative_to(destination.resolve()): raise ValueError('Unsafe ZIP')
        z.extractall(destination)
    verified=verify(destination)
    receipt={'archive':archive.relative_to(ROOT).as_posix(),**info(archive),
        'release_version':manifest['release_version'],'dataset_version':manifest['dataset_version'],
        'context_version':manifest['context_version'],'fresh_extraction':verified,
        'original_peer_zips_received':False}
    (ROOT/'docs/handoffs/phase-3-complete-20261021.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf8')
    print(json.dumps(receipt,indent=2))

if __name__=='__main__': main()
