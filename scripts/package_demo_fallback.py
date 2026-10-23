"""Package a verified, already executed demo for viewing without Python or network."""
import argparse
import base64
import hashlib
import html
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.demo.data_loader import DemoError, file_info, load_release, read_json


def notebook_html(notebook):
    parts = ['<!doctype html><html lang="vi"><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<title>Demo CVSS/EPSS — kết quả đã lưu</title>',
             '<style>body{font:16px/1.6 system-ui;margin:32px auto;padding:0 20px;max-width:1200px;color:#182235}'
             'section{margin:36px 0}img{max-width:100%;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:16px}'
             'table{border-collapse:collapse;font-size:14px}td,th{border:1px solid #ccd3df;padding:8px}th{background:#edf2f8}'
             '.notice{background:#fff4ce;padding:18px;border-left:5px solid #ac7900}</style>',
             '<div class="notice"><b>Bản dự phòng — kết quả đã lưu.</b> Không có inference khi mở trang này. '
             'Nhãn live trong output chỉ lần chạy notebook đã ghi thời gian, không phải lúc xem HTML.</div>']
    for cell in notebook['cells']:
        parts.append('<section>')
        if cell['cell_type'] == 'markdown':
            for paragraph in ''.join(cell['source']).split('\n\n'):
                escaped = html.escape(paragraph.strip())
                escaped = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', escaped)
                escaped = re.sub(r'`(.+?)`', r'<code>\1</code>', escaped)
                if escaped.startswith('## '):
                    parts.append('<h2>' + escaped[3:] + '</h2>')
                elif escaped.startswith('# '):
                    parts.append('<h1>' + escaped[2:] + '</h1>')
                else:
                    parts.append('<p>' + escaped + '</p>')
        else:
            for output in cell.get('outputs', []):
                data = output.get('data', {})
                if output['output_type'] == 'stream':
                    parts.append('<pre>' + html.escape(''.join(output['text'])) + '</pre>')
                elif 'image/png' in data:
                    encoded = ''.join(data['image/png'])
                    base64.b64decode(encoded, validate=True)
                    parts.append('<img alt="Hình Phase 3 đã xác minh" src="data:image/png;base64,' + encoded + '">')
                elif 'text/html' in data:
                    parts.append(''.join(data['text/html']))
        parts.append('</section>')
    parts.append('</html>')
    return '\n'.join(parts).encode('utf-8')


def package(output, receipt):
    output, receipt = Path(output).resolve(), Path(receipt).resolve()
    if output.exists() or receipt.exists():
        raise DemoError('Output/receipt đã tồn tại; chọn revision mới, không ghi đè gói đã giao.')
    release = load_release()
    if release.predictions.empty:
        raise DemoError('Gói dự phòng đầy đủ cần prediction Phase 2 đã xác minh.')
    if any(p.is_relative_to(root) for p in (output, receipt) for root in
           [release.phase3, release.phase2, ROOT / 'data/processed/phase1_v1_20261010']):
        raise DemoError('Không ghi gói/receipt vào release đầu vào.')
    notebook_path = ROOT / 'notebooks/03_demo.ipynb'
    notebook = read_json(notebook_path)
    execution = notebook['metadata']['demo_execution']
    if execution['status'] != 'pass' or execution['embedded_pngs'] != 7:
        raise DemoError('Notebook chưa thực thi đủ hình.')
    for name, expected in execution['code_hashes'].items():
        if file_info(ROOT / name) != expected:
            raise DemoError(f'Notebook output cũ so với code: {name}')
    for key in ['dataset_version', 'context_version', 'n', 'total_kev', 'mapping', 'scored', 'queue']:
        if execution['summary'][key] != release.summary()[key]:
            raise DemoError(f'Notebook khác release: {key}')
    code = [c for c in notebook['cells'] if c['cell_type'] == 'code']
    if len(code) != execution['code_cells'] or any(not c['execution_count'] for c in code):
        raise DemoError('Notebook thiếu output cell.')
    content = {'offline-demo.html': notebook_html(notebook),
               'notebooks/03_demo.ipynb': notebook_path.read_bytes()}
    for name in ['reports/demo-script-security.md', 'reports/demo-script-n3.md',
                 'docs/demo-qa.md', 'docs/demo-commands.md', 'docs/demo-receiver-n3.md',
                 'docs/handoffs/p4-n2-received-by-n3-20261023.json']:
        content[name] = (ROOT / name).read_bytes()
    for path in release.verified_files:
        if path.is_relative_to(release.phase3):
            name = path.relative_to(release.phase3).as_posix()
            if (path.suffix == '.csv' or name.startswith('docs/cases/') or
                    name in {'reports/p3_figures.md', 'reports/p3_prediction_rank_impact.md',
                             'docs/analysis-results.md', 'docs/04-patch-playbook.md', 'docs/03-environmental-context.md',
                             'docs/phase-3-completion.md'} or
                    name.startswith('reports/figures/phase3/') and path.suffix == '.png'):
                content[name] = path.read_bytes()
    content['data/predictions_scoped_saved.csv'] = release.predictions.to_csv(index=False).encode('utf8')
    content['README.txt'] = ('Mo offline-demo.html bang trinh duyet; khong can Python/kernel/mang.\n'
                           'Day la ket qua DA LUU, khong phai inference moi.\n'
                           'Xem reports/demo-script-n3.md de ghep loi thoai N2 va thao tac.\n'
                           'Cac tai lieu N2 duoc nhan tu Git; chua phai phe duyet demo N3.\n'
                           'Khong co model, .env, API key hoac dataset Phase 1/2 day du.\n').encode('utf8')
    manifest = {'dataset_version': execution['summary']['dataset_version'],
                'context_version': execution['summary']['context_version'],
                'mode': 'saved_outputs_only', 'notebook_executed_at': execution['executed_at'],
                'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, data in content.items()}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, data in content.items():
            archive.writestr(name, data)
        archive.writestr('demo_manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise DemoError('ZIP CRC failed')
        for name, record in manifest['files'].items():
            data = archive.read(name)
            if record != {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}:
                raise DemoError(f'ZIP mismatch: {name}')
    receipt.parent.mkdir(parents=True, exist_ok=True)
    result = {'archive': str(output.relative_to(ROOT)), **file_info(output),
              'files': len(content), 'status': 'verified', 'mode': 'saved_outputs_only',
              'notebook_executed_at': execution['executed_at'], 'input_files_unchanged': True}
    for path, expected in release.verified_files.items():
        if file_info(path) != expected:
            raise DemoError(f'Input changed: {path}')
    receipt.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'data/processed/p4_demo_fallback_20261023.zip')
    parser.add_argument('--receipt', type=Path, default=ROOT / 'reports/p4_demo_fallback_receipt.json')
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.output, args.receipt), indent=2))
    except (DemoError, OSError, KeyError) as exc:
        parser.exit(2, f'Demo fallback: {exc}\n')
