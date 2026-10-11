"""Verify a received Phase 1 release offline; no API key or model dependencies."""
import argparse
import json
from pathlib import Path

import pandas as pd

from src.environmental.cvss_base import calculate_base_score
from src.model.audit_data import digest, proposed_splits
from src.model.data_validation import validate_model_input
from src.model.near_duplicates import normalize


def verify(folder, manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, entry in manifest["files"].items():
        path = folder / name
        if Path(name).name != name or path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"]:
            raise ValueError(f"Manifest checksum/size/path mismatch: {name}")
    meta = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
    if meta["status"] != "complete" or meta["dataset_version"] != manifest["dataset_version"]:
        raise ValueError("Incomplete or incorrect release version")
    for name, entry in meta["files"].items():
        if manifest["files"].get(name) != entry:
            raise ValueError("Internal and independent manifest disagree")
    master = pd.read_parquet(folder / "cves.parquet")
    ml = pd.read_parquet(folder / "ml_cohort.parquet")
    ranking = pd.read_parquet(folder / "ranking_cohort.parquet")
    for table in (master, ml, ranking):
        if table.cve_id.duplicated().any() or not table.dataset_version.eq(meta["dataset_version"]).all():
            raise ValueError("Duplicate CVE or wrong dataset version")
    if len(master) != meta["statistics"]["master"] or len(ml) != meta["statistics"]["ml"] or len(ranking) != meta["statistics"]["ranking"]:
        raise ValueError("Release counts mismatch")
    expected_ml = master.loc[master.split.notna()].reset_index(drop=True)
    pd.testing.assert_frame_equal(expected_ml, ml.reset_index(drop=True))
    expected_rank = master.loc[master.in_scope & master.has_cvss31_label & master.vuln_status.ne("Rejected")
                               & master.epss.notna() & master.is_kev.notna()].reset_index(drop=True)
    pd.testing.assert_frame_equal(expected_rank, ranking.reset_index(drop=True))
    validate_model_input(ml, dataset_version=meta["dataset_version"])
    _, proposed = proposed_splits(ml.published, meta["split"])
    if not proposed.eq(ml.split).all():
        raise ValueError("Split violates published boundaries")
    exact = pd.DataFrame({"description": ml.description.map(normalize), "split": ml.split})
    if exact.groupby("description").split.nunique().gt(1).any() or ml.groupby("duplicate_component").split.nunique().gt(1).any():
        raise ValueError("Duplicate leakage across splits")
    scores = master.loc[master.has_cvss31_label, ["cvss_vector", "cvss_base_score"]]
    if not scores.cvss_vector.map(calculate_base_score).sub(scores.cvss_base_score).abs().lt(1e-8).all():
        raise ValueError("Base score mismatch")
    if not ranking.epss_date.astype(str).eq(meta["epss_date"]).all():
        raise ValueError("Ranking mixes EPSS dates")
    print(json.dumps({"result": "PHASE1 RELEASE OK", "dataset_version": meta["dataset_version"],
                      "files_verified": len(manifest["files"]), "statistics": meta["statistics"]}, indent=2))
    return meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, default=Path("data/processed/phase1_v1_20261010"))
    parser.add_argument("--manifest", type=Path, default=Path("docs/handoffs/phase-1-v1.json"))
    args = parser.parse_args()
    verify(args.folder, args.manifest)


if __name__ == "__main__":
    main()
