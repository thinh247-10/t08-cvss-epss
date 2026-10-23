"""Verify a team ZIP receipt before extracting into a NEW demo staging folder."""
import argparse
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.demo.data_loader import DemoError, file_info, read_json, safe_path, verify_files
from scripts.package_phase3_release import verify


def receive(archive, destination, receipt):
    archive, destination = Path(archive), Path(destination).resolve()
    receipt = read_json(receipt)
    if file_info(archive) != {k: receipt[k] for k in ("bytes", "sha256")}:
        raise DemoError("ZIP không khớp SHA-256/bytes của receipt; chưa giải nén.")
    if destination.exists():
        raise DemoError("Thư mục đích đã tồn tại; chọn thư mục mới, không ghi đè.")
    with zipfile.ZipFile(archive) as bundle:
        names = [i.filename for i in bundle.infolist() if not i.is_dir()]
        paths = [safe_path(destination, n) for n in names]
        if len(set(paths)) != len(paths) or bundle.testzip() is not None:
            raise DemoError("ZIP trùng đường dẫn hoặc sai CRC.")
        destination.mkdir(parents=True)
        # Copy only validated regular members; do not honor ZIP symlink attributes.
        for name, path in zip(names, paths):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bundle.read(name))
    if (destination / "phase3_manifest.json").exists():
        result = verify(destination)
    else:
        result = {"status": "pass", "files": len(verify_files(destination, read_json(destination / "manifest.json")))}
    return {**result, "archive": str(archive), **file_info(archive), "destination": str(destination)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--destination", type=Path, required=True)
    p.add_argument("--receipt", type=Path, default=ROOT / "docs/handoffs/phase-3-complete-20261021.json")
    args = p.parse_args()
    try:
        print(json.dumps(receive(args.archive, args.destination, args.receipt), indent=2))
    except (DemoError, OSError, ValueError) as exc:
        p.exit(2, f"Receive: {exc}\n")


if __name__ == "__main__":
    main()
