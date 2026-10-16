"""Verify a trusted Phase 2 handoff and reproduce validation examples offline.

This checks the current machine only. It never marks N1's independent
second-machine reproduction as complete or changes the handoff manifest.
Only load joblib artifacts received from a trusted team member.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re

import pandas as pd

from src.model.baseline import load_artifact
from src.model.data_validation import LABEL_ORDER
from src.model.predict import predict_frame


DEFAULT_MANIFEST = "docs/handoffs/phase-2-model.json"
EXPECTED_FIELDS = (
    *(f"pred_{metric}" for metric in LABEL_ORDER),
    "predicted_vector", "predicted_base_score", "vector_valid", "prediction_error",
)


def _digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _safe_file(root, name):
    """Accept repository-relative names, including Windows manifest separators."""
    if not isinstance(name, str) or not name or "\x00" in name or ":" in name:
        raise ValueError(f"Unsafe manifest file path: {name!r}")
    windows = PureWindowsPath(name)
    normalized = name.replace("\\", "/")
    portable = PurePosixPath(normalized)
    parts = normalized.split("/")
    if windows.drive or windows.root or portable.is_absolute() or any(
        part in {"", ".", ".."} or part.endswith((".", " ")) for part in parts
    ):
        raise ValueError(f"Unsafe manifest file path: {name!r}")
    path = (root / portable).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Manifest file escapes repository root: {name!r}")
    if not path.is_file():
        raise FileNotFoundError(f"Handoff file missing: {name}")
    return path


def _runtime_versions(expected):
    versions = {}
    for name in expected:
        if name == "python":
            versions[name] = platform.python_version()
            continue
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def _smoke_cases(manifest):
    smoke = manifest.get("reproduction_smoke")
    if not isinstance(smoke, Mapping) or not isinstance(smoke.get("cases"), list) or not smoke["cases"]:
        raise ValueError("Manifest requires nonempty reproduction_smoke.cases")
    cases = smoke["cases"]
    seen = set()
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("Every reproduction case must be an object")
        cve_id = case.get("cve_id")
        if not isinstance(cve_id, str) or re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) is None or cve_id in seen:
            raise ValueError("Reproduction cases require unique validation CVE identifiers")
        seen.add(cve_id)
        if case.get("split") != "validation":
            raise ValueError("Reproduction cases must come from validation")
        if not isinstance(case.get("description"), str) or not case["description"].strip():
            raise ValueError("Reproduction descriptions must be nonblank text")
        expected = case.get("expected")
        if not isinstance(expected, Mapping) or set(expected) != {"dummy", "tfidf"}:
            raise ValueError("Every reproduction case requires expected dummy and tfidf predictions")
        for kind, record in expected.items():
            if not isinstance(record, Mapping) or set(record) != set(EXPECTED_FIELDS):
                raise ValueError(f"Expected {kind} prediction must contain exactly the eight labels, vector, score and validity/error")
            for metric, allowed in LABEL_ORDER.items():
                if record[f"pred_{metric}"] not in allowed:
                    raise ValueError(f"Invalid expected {kind} label for {metric}")
            score = record["predicted_base_score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
                raise ValueError("Expected Base score must be finite and in [0, 10]")
            if record["vector_valid"] is not True or record["prediction_error"] != "":
                raise ValueError("Reproduction cases require successful, valid expected predictions")
            if not isinstance(record["predicted_vector"], str):
                raise ValueError("Expected predicted_vector must be text")
    return cases


def verify_handoff(manifest_path=DEFAULT_MANIFEST, *, artifact_path=None, repo_root=None):
    """Verify file hashes, metadata and exact predictions without modifying files.

    Manifest filenames are relative to ``repo_root`` (the source repository by
    default). ``artifact_path`` may override the artifact location only with a
    file already covered by the manifest. Runtime dependency differences are
    reported; artifact and manifest dependency metadata must agree exactly.
    """
    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[2]
    manifest_file = Path(manifest_path)
    if not manifest_file.is_absolute():
        manifest_file = root / manifest_file
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(manifest, Mapping):
        raise ValueError("Handoff manifest must be an object")
    files = manifest.get("files")
    if not isinstance(files, Mapping) or not files:
        raise ValueError("Handoff manifest requires a nonempty files mapping")
    verified = {}
    seen = set()
    for name, entry in files.items():
        path = _safe_file(root, name)
        canonical = str(path).casefold()
        if canonical in seen:
            raise ValueError(f"Duplicate manifest file path: {name}")
        seen.add(canonical)
        if not isinstance(entry, Mapping):
            raise ValueError(f"Invalid file entry: {name}")
        size, expected_hash = entry.get("bytes"), entry.get("sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"Invalid file byte count: {name}")
        if not isinstance(expected_hash, str) or re.fullmatch(r"[a-fA-F0-9]{64}", expected_hash) is None:
            raise ValueError(f"Invalid file SHA-256: {name}")
        if path.stat().st_size != size or _digest(path) != expected_hash.lower():
            raise ValueError(f"Handoff checksum/size mismatch: {name}")
        verified[path] = {"bytes": size, "sha256": expected_hash.lower()}

    lock = manifest.get("lock", {})
    if not isinstance(lock, Mapping):
        raise ValueError("Manifest lock must be an object")
    artifact_name = artifact_path if artifact_path is not None else lock.get("artifact", "models/baseline.joblib")
    if isinstance(artifact_name, Path):
        if artifact_name.is_absolute():
            try:
                artifact_name = artifact_name.resolve().relative_to(root).as_posix()
            except ValueError as exc:
                raise ValueError("Artifact override must be inside the repository root") from exc
        else:
            artifact_name = str(artifact_name)
    elif isinstance(artifact_name, str) and Path(artifact_name).is_absolute():
        try:
            artifact_name = Path(artifact_name).resolve().relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("Artifact override must be inside the repository root") from exc
    artifact_file = _safe_file(root, artifact_name)
    if artifact_file not in verified:
        raise ValueError("Artifact must be covered by a verified manifest file entry")
    if "artifact_sha256" in lock and lock["artifact_sha256"] != verified[artifact_file]["sha256"]:
        raise ValueError("Manifest lock and artifact file SHA-256 disagree")

    # Hash checks precede joblib deserialization. The manifest and artifact must
    # still come from a trusted source: a hash is integrity, not authentication.
    artifact = load_artifact(artifact_file)
    for key in ("dataset_version", "model_versions", "library_versions"):
        if manifest.get(key) != artifact.get(key):
            raise ValueError(f"Manifest and artifact {key} disagree")
    versions = artifact["library_versions"]
    if not isinstance(versions, Mapping) or not versions or not all(isinstance(key, str) for key in versions):
        raise ValueError("Artifact library_versions must be a nonempty version mapping")
    for key in ("dataset_version", "model_versions"):
        if key in lock and lock[key] != artifact[key]:
            raise ValueError(f"Manifest lock and artifact {key} disagree")
    if artifact["config"].get("data", {}).get("dataset_version") != artifact["dataset_version"]:
        raise ValueError("Artifact config and dataset_version disagree")

    cases = _smoke_cases(manifest)
    frame = pd.DataFrame([{key: case[key] for key in ("cve_id", "split", "description")}
                          for case in cases])
    frame["dataset_version"] = artifact["dataset_version"]
    for kind in ("dummy", "tfidf"):
        predictions = predict_frame(artifact, frame, model_kind=kind, prediction_usage="demo").set_index("cve_id")
        for case in cases:
            actual = predictions.loc[case["cve_id"]]
            expected = case["expected"][kind]
            for field in EXPECTED_FIELDS:
                value = actual[field]
                if pd.isna(value) or value != expected[field]:
                    raise ValueError(f"Reproduction prediction mismatch: {case['cve_id']} {kind} {field}")
    runtime = _runtime_versions(versions)
    return {
        "result": "PHASE2 HANDOFF VERIFIED", "verification_scope": "local_offline_reproduction",
        "dataset_version": artifact["dataset_version"], "model_versions": artifact["model_versions"],
        "artifact_sha256": verified[artifact_file]["sha256"], "files_verified": len(verified),
        "library_versions": dict(versions), "runtime_library_versions": runtime,
        "runtime_versions_match": runtime == dict(versions),
        "reproduction_smoke": {"cases_verified": len(cases), "model_predictions_verified": len(cases) * 2,
                               "prediction_usage": "demo", "all_predictions_match": True},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(DEFAULT_MANIFEST))
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path, help="Optional local verification report; does not update the handoff")
    args = parser.parse_args(argv)
    root = args.repo_root.resolve() if args.repo_root else Path(__file__).resolve().parents[2]
    manifest_file = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        if args.output and args.output.resolve() == manifest_file.resolve():
            raise ValueError("Verification report output must not overwrite the handoff manifest")
        report = verify_handoff(args.manifest, artifact_path=args.artifact, repo_root=root)
        if args.output:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            protected = {_safe_file(root, name) for name in manifest["files"]}
            if args.output.resolve() in protected:
                raise ValueError("Verification report output must not overwrite a handoff file")
        rendered = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
    except (ValueError, OSError) as error:
        parser.exit(2, f"Phase 2 handoff verification failed: {error}\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
