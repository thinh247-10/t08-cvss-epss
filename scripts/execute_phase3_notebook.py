"""Execute N3's offline artifact notebook using stdlib; embed actual PNG outputs.

The notebook has no magics and uses print/show_png. No kernel/GPU/model required.
Execution errors abort without replacing the existing executed notebook.
"""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import time


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    sys.path.insert(0, str(root))
    path = root / 'notebooks/03_priority_analysis.ipynb'
    notebook = json.loads(path.read_text(encoding='utf-8'))
    outputs = []

    def emit_png(filename):
        file = Path(filename)
        outputs.append({'output_type': 'display_data', 'metadata': {}, 'data': {
            'image/png': base64.b64encode(file.read_bytes()).decode('ascii'),
            'text/plain': [file.as_posix()]}})

    namespace = {'__name__': '__phase3_notebook__', '_emit_png': emit_png}
    started = time.monotonic()
    count = 0
    for index, cell in enumerate(notebook['cells']):
        if cell['cell_type'] != 'code':
            continue
        outputs = []
        count += 1
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            exec(compile(''.join(cell['source']), f'phase3-cell-{index}', 'exec'), namespace)
        cell['execution_count'] = count
        cell['outputs'] = [{'output_type': 'stream', 'name': 'stdout', 'text': stream.getvalue().splitlines(keepends=True)}] + outputs
    notebook['metadata']['n3_execution'] = {'executor': 'stdlib compile/exec with embedded PNG display_data',
        'python': platform.python_version(), 'code_cells': count, 'seconds': time.monotonic() - started,
        'read_only_artifacts': True, 'training_inference_evaluation': False}
    path.write_text(json.dumps(notebook, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(json.dumps(notebook['metadata']['n3_execution'], indent=2))


if __name__ == '__main__':
    main()
