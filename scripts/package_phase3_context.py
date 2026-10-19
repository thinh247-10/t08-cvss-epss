"""Build a new non-overwriting A-D handoff ZIP after verifying artifact hashes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

from src.analysis.compare_rankings import digest

DATA_FILES = ("rankings.csv", "ranking_metrics.json", "topk_metrics.csv", "overlap.csv",
              "rank_deltas.csv", "metadata.json", "cve_asset_mapping.csv", "environmental_scores.csv",
              "priority_queue.csv", "priority_queue_env_first.csv", "context_comparison.csv",
              "context_sensitivity.json", "context_metadata.json", "environmental_first_check.json")
SUPPORT = ("config/phase3.yaml", "config/phase3_mapping.yaml", "config/assets.yaml",
           "docs/phase-3-artifact-contract.md", "reports/p3_ranking_results.md",
           "reports/p3_environmental_check.md", "reports/p3_context_results.md")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("ZIP exists; select a new revision, never overwrite a sent package")
    root = Path(__file__).resolve().parents[1]
    for meta_name in ("metadata.json", "context_metadata.json"):
        meta = json.loads((args.source_dir / meta_name).read_text(encoding="utf-8"))
        if meta["dataset_version"] != "t08-v1.0-20261010" or meta["tracked_dirty"]:
            raise ValueError("Unexpected dataset or uncommitted production run")
        for name, info in meta["outputs"].items():
            if Path(name).name != name:
                raise ValueError("Unsafe output filename")
            path = args.source_dir / name
            if digest(path) != info["sha256"] or path.stat().st_size != info["bytes"]:
                raise ValueError(f"Output differs from metadata: {name}")
        for info in meta["inputs"].values():
            path = Path(info["path"])
            if digest(path) != info["sha256"] or path.stat().st_size != info["bytes"]:
                raise ValueError(f"Input changed since run: {path}")
    entries = {"p3_n2/" + name: (args.source_dir / name).read_bytes() for name in DATA_FILES}
    entries.update({name: (root / name).read_bytes() for name in SUPPORT})
    manifest = dict(schema_version="p3-n2-handoff-manifest-v1", dataset_version="t08-v1.0-20261010",
                    context_version="phase3-context-v1", status="A-D implemented with explicit limits; E pending",
                    limits=["6 mapping pairs, target 15 not met", "N3 independent check/mobile case pending"],
                    files={name: dict(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
                           for name, content in entries.items()})
    entries["handoff_manifest.json"] = (json.dumps(manifest, indent=2, allow_nan=False) + "\n").encode("utf-8")
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    with ZipFile(buffer) as archive:
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC failure")
        for name, entry in manifest["files"].items():
            if hashlib.sha256(archive.read(name)).hexdigest() != entry["sha256"]:
                raise ValueError("ZIP entry hash mismatch")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as target:
        target.write(buffer.getvalue())
    print(json.dumps(dict(zip=str(args.output), bytes=args.output.stat().st_size,
                          sha256=digest(args.output), files=len(entries)), indent=2))


if __name__ == "__main__":
    main()
