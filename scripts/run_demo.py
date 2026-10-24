"""Run the existing demo using repository-relative paths from YAML."""
import argparse
from pathlib import Path
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/demo.yaml')
    parser.add_argument('--mode', choices=['live', 'saved', 'no-ai'], default='saved')
    parser.add_argument('--cli', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    config = yaml.safe_load(args.config.read_text(encoding='utf-8'))
    if config.get('dataset_version') != 't08-v1.0-20261010' or config.get('context_version') != 'phase3-context-v2':
        parser.error('Dataset/context version does not match the frozen release')
    paths = []
    for key in ['phase1', 'phase2', 'phase3']:
        paths.extend(['--' + key, str((ROOT / config[key]).resolve())])
    if args.cli is not None:
        command = [sys.executable, '-X', 'utf8', '-m', 'src.demo.cli', *paths]
        if args.mode == 'no-ai':
            command.append('--no-ai')
        command.extend(args.cli)
    else:
        command = [sys.executable, '-X', 'utf8', str(ROOT / 'scripts/execute_demo_notebook.py'), *paths,
                   '--output', str(ROOT / f'data/processed/p4_demo_n1/{args.mode}.ipynb'),
                   '--report', str(ROOT / f'reports/p4_n1_{args.mode}.json')]
        if args.mode == 'saved':
            command.append('--saved-only')
        elif args.mode == 'no-ai':
            command.append('--no-ai')
    return subprocess.call(command, cwd=ROOT)

if __name__ == '__main__':
    raise SystemExit(main())
