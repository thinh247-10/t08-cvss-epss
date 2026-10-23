"""Execute every demo cell in a fresh process, block sockets, save real outputs.

The stdlib runner uses the same cells as Jupyter and embeds verified PNGs.
Failure preserves the previous notebook. Input hashes must remain unchanged.
"""
import argparse
import base64
import contextlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def block_network(event, args):
    if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.sendto", "socket.bind"}:
        raise RuntimeError("Offline demo: network access blocked")


def main(argv=None):
    from src.demo.data_loader import DEFAULT_P1, DEFAULT_P2, DEFAULT_P3, file_info
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase1", type=Path, default=DEFAULT_P1)
    p.add_argument("--phase2", type=Path, default=DEFAULT_P2)
    p.add_argument("--phase3", type=Path, default=DEFAULT_P3)
    p.add_argument("--saved-only", action="store_true", help="Không chạy inference; dùng prediction đã lưu")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--output", type=Path, default=ROOT / "notebooks/03_demo.ipynb")
    p.add_argument("--report", type=Path, default=ROOT / "reports/p4_demo_execution.json")
    args = p.parse_args(argv)
    for output in (args.output, args.report):
        if any(output.resolve().is_relative_to(x.resolve()) for x in (args.phase1, args.phase2, args.phase3)):
            p.error("Output/report không được nằm trong release đầu vào.")
    os.chdir(ROOT)
    os.environ.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    sys.dont_write_bytecode = True
    sys.addaudithook(block_network)
    # Demonstrate the guard really rejects network attempts; no request is sent.
    import socket
    try:
        socket.getaddrinfo("offline.invalid", 443)
    except RuntimeError:
        guard_verified = True
    else:
        raise RuntimeError("Offline guard did not block DNS")
    notebook = json.loads((ROOT / "notebooks/03_demo.ipynb").read_text(encoding="utf-8"))
    outputs = []

    def emit_png(path):
        outputs.append({"output_type": "display_data", "metadata": {}, "data": {
            "image/png": base64.b64encode(Path(path).read_bytes()).decode("ascii"),
            "text/plain": [Path(path).name]}})

    def emit_table(markup, plain):
        outputs.append({"output_type": "display_data", "metadata": {},
                        "data": {"text/html": [markup], "text/plain": [plain]}})

    from src.demo import presentation
    presentation.TABLE_SINK = emit_table

    namespace = {"__name__": "__demo__", "_emit_png": emit_png,
                 "DEMO_PATHS": {"phase1": args.phase1, "phase2": None if args.no_ai else args.phase2, "phase3": args.phase3},
                 "RUN_LIVE": not args.saved_only and not args.no_ai}
    started = time.perf_counter()
    count, figures = 0, 0
    timings = []
    try:
        for index, cell in enumerate(notebook["cells"]):
            if cell["cell_type"] != "code":
                continue
            count += 1
            outputs = []
            stream = io.StringIO()
            cell_started = time.perf_counter()
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                exec(compile("".join(cell["source"]), f"demo-cell-{index}", "exec"), namespace)
            figures += sum("image/png" in out.get("data", {}) for out in outputs)
            timings.append({"cell": index, "seconds": time.perf_counter() - cell_started})
            cell["execution_count"] = count
            cell["outputs"] = [{"output_type": "stream", "name": "stdout", "text": stream.getvalue().splitlines(keepends=True)}] + outputs
        release = namespace["release"]
        for path, expected in release.verified_files.items():
            if file_info(path) != expected:
                raise RuntimeError(f"Input was changed: {path}")
    except Exception as exc:
        p.exit(2, f"Demo chưa hoàn tất ở cell {count}: {type(exc).__name__}: {exc}\n")
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--", "src/demo",
                    "scripts/execute_demo_notebook.py", "notebooks/03_demo.ipynb"], cwd=ROOT, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        commit = "unavailable"
        dirty = None
    report = {"status": "pass", "executed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
              "python": platform.python_version(), "os": platform.platform(), "commit": commit,
              "working_tree_has_uncommitted_demo": dirty,
              "code_hashes": {str(path.relative_to(ROOT)): file_info(path) for path in
                              [*sorted((ROOT / "src/demo").glob("*.py")), Path(__file__).resolve()]},
              "dependencies": {name: importlib.metadata.version(name) for name in ["pandas", "numpy", "pyarrow", "PyYAML"]},
              "paths": {k: str(v) if v else None for k, v in namespace["DEMO_PATHS"].items()},
              "code_cells": count, "embedded_pngs": figures, "seconds": time.perf_counter() - started,
              "cell_timings": timings, "summary": release.summary(),
              "offline": "Python socket audit guard active; DNS guard probe blocked; OS adapter was not disabled",
              "guard_verified": guard_verified, "input_hashes_unchanged": len(release.verified_files),
              "model": release.model_record, "ai_result": namespace.get("ai_result"),
              "rehearsal_six_minutes": "pending human rehearsal; execution timing is not narration timing",
              "n2_content_acceptance": "pending", "n1_runbook_second_machine": "pending"}
    notebook["metadata"]["demo_execution"] = report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(notebook, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("status", "code_cells", "embedded_pngs", "seconds", "guard_verified", "input_hashes_unchanged")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
