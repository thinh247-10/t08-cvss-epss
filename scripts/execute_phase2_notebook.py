"""Execute the read-only N1 artifact notebook with stdlib, preserving stdout.

No IPython magics, model fitting or final-test evaluation. Errors stop execution.
"""
import contextlib
import io
import json
from pathlib import Path
import platform
import time


def main():
    root = Path(__file__).resolve().parents[1]
    original = root / 'notebooks/02_model_eval.ipynb'
    output = root / 'notebooks/02_model_eval_n1.ipynb'
    notebook = json.loads(original.read_text(encoding='utf-8'))
    def replace(index, text):
        notebook['cells'][index]['source'] = text.splitlines(keepends=True)
    replace(0, '# Phase 2 — N1 kiểm tra gói baseline tái lập\n\n'
            'Notebook được thực thi thật trên Python ' + platform.python_version() +
            ' bằng compile/exec, cùng namespace và lưu stdout.\n'
            'Chỉ đọc báo cáo đã khóa và kiểm inference validation; không train, '
            'không đánh giá lại test.\n')
    first = ''.join(notebook['cells'][1]['source'])
    first = first.replace('metrics = read_metrics(ROOT /',
        'import os\nRUN = Path(os.environ.get("T08_MODEL_RUN", '
        'str(ROOT / "data/processed/p2_n1_reproduction_20261017"))).resolve()\n'
        'metrics = read_metrics(RUN /')
    first = first.replace('(ROOT / "docs/handoffs/phase-2-model.json")',
                          '(RUN / "docs/handoffs/phase-2-model.json")')
    replace(1, first)
    cell = ''.join(notebook['cells'][3]['source']).replace('repo_root=ROOT', 'repo_root=RUN')
    cell = cell.replace('ROOT / "reports/phase2_local_reproduction.json"',
                        'RUN / "reports/reproduction_verification.json"')
    cell = cell.replace('artifact_path = ROOT /', 'artifact_path = RUN /')
    replace(3, cell)
    replace(5, '''selection = json.loads((ROOT / "reports/model_selection.json").read_text(encoding="utf-8"))
assert selection["status"] == "locked" and selection["chosen_candidate"] == 1
assert artifact["selection"]["selected_C"] == 1.0
assert artifact["selection"]["new_parameter_search"] is False
selection_rows = pd.DataFrame([
    {"candidate": r["candidate"], "C": r["overrides"]["C"],
     "validation_mean_macro_f1": r["validation_mean_macro_f1"]}
    for r in selection["candidates"]])
print("N3 historical selection, not a new search:")
print(selection_rows.to_string(index=False))
print("N1 fixed configuration:", artifact["selection"])
print("Locked:", manifest["lock"]["locked_at"])
print("Test started:", manifest["lock"]["test_started_at"])
''')
    replace(19, '''release_folder = ROOT / "data/processed/phase1_v1_20261010"
label_support = pd.read_csv(release_folder / "label_support.csv")
print(label_support.loc[label_support["split"].eq("train")].to_string(index=False))
print("Preprocessing policy:", artifact["preprocessing"]["policy_version"])
from src.model.baseline import preprocess_descriptions
descriptions = pd.read_parquet(release_folder / "ml_cohort.parquet", columns=["split", "description"])
audits = {split: preprocess_descriptions(descriptions.loc[descriptions.split.eq(split), "description"])[1]
          for split in ("train", "validation", "test")}
print(pd.DataFrame(audits).T.to_string())
print("Structural text audit only; no prediction or test error inspection.")
''')
    cell = ''.join(notebook['cells'][21]['source']).replace('ROOT / "reports/validation_errors_n2.csv"',
                                                          'RUN / "reports/validation_errors_n2.csv"')
    cell += '\nprint("N2 completed review: reports/p2_validation_security_review.md (13 CVEs)")\n'
    replace(21, cell)
    replace(20, '## Mẫu lỗi validation\n\nN2 đã phân tích 13 CVE trong báo cáo review. '
            'Manifest ZIP giữ trạng thái lúc đóng gói; nhật ký tích hợp cập nhật riêng.\n')
    distil_metrics = root / 'data/processed/p2_distilbert_20261017/metrics.json'
    if distil_metrics.is_file():
        notebook['cells'].append({'cell_type':'markdown', 'metadata':{}, 'source':[
            '## DistilBERT — thử nghiệm bổ sung một epoch cố định\n',
            'Đọc báo cáo đã khóa, không chọn lại cấu hình từ điểm test.\n']})
        notebook['cells'].append({'cell_type':'code','metadata':{},'source':[
            'from src.model.predict_distilbert import verify_bundle\n',
            'DISTIL = ROOT / "data/processed/p2_distilbert_20261017"\n',
            'distil_manifest = verify_bundle(DISTIL)\n',
            'distil_metrics = read_metrics(DISTIL / "metrics.json")\n',
            'for split in ("validation", "test"):\n',
            '    print(split)\n',
            '    print(summary_table(distil_metrics, split).to_string(index=False))\n',
            '    print(component_table(distil_metrics, split, model_kind="distilbert").to_string(index=False))\n',
            '    print(per_class_table(distil_metrics, split, model_kind="distilbert").to_string(index=False))\n',
            'print("Truncation:", distil_metrics["token_audit"])\n',
            'print("Training:", distil_metrics["training"])\n'], 'execution_count':None,'outputs':[]})
    namespace = {'__name__': '__phase2_notebook__'}
    count = 0
    started = time.monotonic()
    for index, cell in enumerate(notebook['cells']):
        if cell['cell_type'] != 'code':
            continue
        count += 1
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            exec(compile(''.join(cell['source']), f'notebook-cell-{index}', 'exec'), namespace)
        cell['execution_count'] = count
        cell['outputs'] = [{'output_type': 'stream', 'name': 'stdout',
                            'text': stream.getvalue().splitlines(keepends=True)}]
    notebook['metadata']['n1_execution'] = {
        'python': platform.python_version(), 'executor': 'stdlib compile/exec',
        'code_cells': count, 'seconds': time.monotonic()-started,
        'no_training_or_final_test_reevaluation': True}
    output.write_text(json.dumps(notebook, ensure_ascii=False, indent=1)+'\n', encoding='utf-8')
    print(json.dumps(notebook['metadata']['n1_execution'], indent=2))


if __name__ == '__main__':
    main()
