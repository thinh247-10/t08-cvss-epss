"""Read-only N3 content checks against N2's published narration; no peer sign-off."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.demo.data_loader import DemoError, file_info, load_release, records
from scripts.execute_demo_notebook import block_network


def check():
    sys.addaudithook(block_network)
    start = time.perf_counter()
    release = load_release()
    checks = []

    def expect(name, actual, expected):
        checks.append({'name': name, 'expected': expected, 'actual': actual, 'pass': actual == expected})

    summary = release.summary()
    expect('population', [summary[k] for k in ['n', 'total_kev', 'mapping', 'scored']], [396, 3, 15, 10])
    expect('queue', summary['queue'], {'patch': 8, 'review_required': 7})
    row = release.lookup_cve('CVE-2023-23752')
    expect('N2 lower Base/high EPSS', [row[k] for k in ['cvss_base_score', 'epss', 'is_kev', 'epss_rank', 'kev_first_rank']], [5.3, 0.99827, True, 3, 3])
    pairs = records(release.lookup_asset_pairs('CVE-2023-22626'))
    admin = next(p for p in pairs if p['asset_id'] == 'ADMIN-01')
    api = next(p for p in pairs if p['asset_id'] == 'API-02')
    expect('PgHero context', [admin[k] for k in ['base_score', 'environmental_score', 'priority_rank']], [7.5, 9.3, 8])
    expect('API-02 retained', [api[k] for k in ['queue_status', 'environmental_score', 'priority_rank']], ['review_required', None, None])
    context = records(release.lookup_context_comparison('CVE-2023-22626'))[0]
    expect('PgHero severity/context/sensitivity', [context[k] for k in ['base_rank', 'environmental_rank', 'context_rank', 'sensitivity_rank']], [2, 1, 8, 2])
    discourse = records(release.lookup_asset_pairs('CVE-2022-46177'))[0]
    expect('Discourse', [discourse[k] for k in ['base_score', 'environmental_score', 'priority_rank']], [8.1, 8.8, 2])
    mobile = records(release.lookup_asset_pairs('CVE-2023-41387'))[0]
    expect('MOB-02', [mobile[k] for k in ['environmental_score', 'exposure', 'queue_status', 'priority_rank']], [9.8, 'client', 'review_required', None])
    expect('client count', int(release.pairs.exposure.eq('client').sum()), 2)
    expect('AI common cohort', [release.compare_predictions(s)['common_n'] for s in ['validation', 'test']], [69, 108])
    prediction = release.lookup_prediction('CVE-2023-38709')
    expect('AI saved mode', prediction['mode'], 'saved')
    expect('AI observed/predicted', [release.lookup_cve('CVE-2023-38709')['cvss_base_score'], prediction['predicted_base_score']], [7.3, 9.1])
    expect('AI error metrics', [prediction['pred_' + m] for m in ['C', 'I', 'A']], ['N', 'H', 'H'])
    for path, expected in release.verified_files.items():
        if file_info(path) != expected:
            raise DemoError(f'Input changed: {path}')
    report = {'status': 'pass' if all(c['pass'] for c in checks) else 'fail',
              'scope': 'N3 self-check against received N2 narration; NOT N2 acceptance',
              'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'python': platform.python_version(),
              'os': platform.platform(), 'seconds': time.perf_counter()-start,
              'n2_source_commit': '43ce98028a817eff7643581a26e48cd9fd233408',
              'dataset_version': summary['dataset_version'], 'context_version': summary['context_version'],
              'network': 'socket audit blocked', 'input_files_unchanged': len(release.verified_files), 'checks': checks}
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'reports/p4_n3_content_checks.json')
    args = parser.parse_args()
    report = check()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'seconds': report['seconds']}))
    raise SystemExit(0 if report['status'] == 'pass' else 1)
