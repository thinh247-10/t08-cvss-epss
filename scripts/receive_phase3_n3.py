"""Verify and extract N3's received archives without inference or source overwrite."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def verify(path, entry):
    path = Path(path)
    actual = {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if any(actual[k] != entry[k] for k in actual):
        raise ValueError(f"Checksum/bytes mismatch: {path}")
    return {"path": path.as_posix(), **actual}


def extract_once(archive, dest):
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest.resolve()):
                raise ValueError("Unsafe ZIP member")
        if z.testzip() is not None:
            raise ValueError("ZIP CRC failed")
        if not dest.exists():
            dest.mkdir(parents=True)
            z.extractall(dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--downloads", type=Path, required=True)
    args = parser.parse_args()
    receipt = json.loads(Path("docs/handoffs/phase-2-complete-20261017.json").read_text(encoding="utf-8"))
    p2 = args.downloads / "phase2_handoff_20261017.zip"
    records = [verify(p2, receipt)]
    dest = Path("data/processed/phase2_received")
    extract_once(p2, dest)
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    for name, entry in manifest["files"].items():
        target = (dest / name).resolve()
        if not target.is_relative_to(dest.resolve()):
            raise ValueError("Unsafe manifest member")
        verify(target, entry)
    extract_once(dest / "baseline.zip", dest / "baseline")
    p3 = args.downloads / "n2_p3_step_b_20261018.zip"
    # Published N2 receipt: origin/feat/p3-ranking-context:docs/handoffs/p3-n2-ranking.md
    records.append(verify(p3, {"bytes": 19198,
        "sha256": "c3aacd4e7b8afddc5950365c929c71358a56e2d794a3d37626feb714d7508945"}))
    received = Path("data/processed/p3_n2_received")
    extract_once(p3, received)
    metadata = json.loads((received / "p3_n2/metadata.json").read_text(encoding="utf-8"))
    for name, entry in metadata["outputs"].items():
        verify(received / "p3_n2" / name, entry)
    verify(received / "p3_n2/rankings.csv", metadata["inputs"]["rankings.csv"])
    verify(received / "phase3.yaml", metadata["inputs"]["phase3.yaml"])
    output = Path("data/processed/p3_n3/input_receipt.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = {"status": "verified", "archives": records, "phase2_files": len(manifest["files"]),
              "n2_schema": metadata["schema_version"], "n2_commit": metadata["commit"],
              "no_inference": True, "source_files_copied_to_repo": False}
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
