"""Preliminary observed CVSS/EPSS/KEV-first rankings on a fixed cohort.

No model predictions, cohort filtering, correlation metrics or policy-quality
claims are produced here. The CLI verifies input against release metadata.
"""

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re

import pandas as pd
from pandas.api.types import is_bool_dtype, is_numeric_dtype


POLICY_VERSION = "cvss-epss-kev-first-v1"
INPUT_COLUMNS = ("cve_id", "cvss_base_score", "epss", "is_kev",
                 "dataset_version", "epss_date")
OUTPUT_COLUMNS = ("cve_id", "cvss_base_score", "epss", "is_kev", "cvss_rank",
                  "epss_rank", "kev_first_rank", "dataset_version", "epss_date",
                  "cohort_id", "policy_version")


def build_rankings(cohort, *, dataset_version, cohort_id,
                   policy_version=POLICY_VERSION):
    """Return deterministic 1..N positions without modifying or dropping input.

    The caller supplies an already eligible observed cohort. Missing/invalid
    values are errors, including unknown KEV and mixed EPSS dates/versions.
    """
    for name, value in (("dataset_version", dataset_version),
                        ("cohort_id", cohort_id), ("policy_version", policy_version)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if policy_version != POLICY_VERSION:
        raise ValueError("policy_version does not identify the implemented sort policy")
    if not isinstance(cohort, pd.DataFrame) or cohort.empty:
        raise ValueError("cohort must be a non-empty DataFrame")
    if not cohort.columns.is_unique:
        raise ValueError("cohort has duplicate column names")
    missing = set(INPUT_COLUMNS) - set(cohort.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")
    frame = cohort.loc[:, list(INPUT_COLUMNS)].copy(deep=True)
    if frame.isna().any().any():
        raise ValueError("Missing ranking input; validate the cohort before ranking")
    if not frame.cve_id.map(lambda v: isinstance(v, str) and
                            re.fullmatch(r"CVE-\d{4}-\d{4,}", v) is not None).all():
        raise ValueError("Invalid cve_id")
    if frame.cve_id.duplicated().any():
        raise ValueError("Duplicate cve_id")
    if not frame.dataset_version.eq(dataset_version).all():
        raise ValueError("Dataset version mismatch")
    for column, upper in (("cvss_base_score", 10), ("epss", 1)):
        if (not is_numeric_dtype(frame[column]) or is_bool_dtype(frame[column])
                or not frame[column].between(0, upper).all()):
            raise ValueError(f"{column} must contain finite numbers in [0, {upper}]")
    if not is_bool_dtype(frame.is_kev):
        raise ValueError("is_kev must be boolean, not strings or numbers")
    if frame.epss_date.nunique() != 1:
        raise ValueError("Mixed EPSS dates")
    day = frame.epss_date.iloc[0]
    try:
        if not isinstance(day, str) or date.fromisoformat(day).isoformat() != day:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("epss_date must be an ISO YYYY-MM-DD string") from None

    policies = {
        "cvss_rank": (["cvss_base_score", "cve_id"], [False, True]),
        "epss_rank": (["epss", "cve_id"], [False, True]),
        "kev_first_rank": (["is_kev", "epss", "cvss_base_score", "cve_id"],
                           [False, False, False, True]),
    }
    frame = frame.set_index("cve_id", drop=False)
    for rank_column, (keys, ascending) in policies.items():
        ordered = frame.reset_index(drop=True).sort_values(keys, ascending=ascending)
        positions = pd.Series(range(1, len(frame) + 1), index=ordered.cve_id)
        frame[rank_column] = positions.reindex(frame.index).to_numpy()
    frame["cohort_id"] = cohort_id
    frame["policy_version"] = policy_version
    return frame.reset_index(drop=True).sort_values("cve_id").loc[
        :, list(OUTPUT_COLUMNS)].reset_index(drop=True)


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(
        "data/processed/phase1_v1_20261010/ranking_cohort.parquet"))
    parser.add_argument("--metadata", type=Path, default=Path(
        "data/processed/phase1_v1_20261010/metadata.json"))
    parser.add_argument("--output", type=Path,
                        default=Path("data/processed/rankings.csv"))
    args = parser.parse_args(argv)
    if args.output.resolve() in {args.input.resolve(), args.metadata.resolve()}:
        raise ValueError("Output must not overwrite release input or metadata")
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    if metadata.get("status") != "complete" or metadata.get("ranking_ready") is not True:
        raise ValueError("Release is not ready for ranking")
    entry = metadata["files"].get(args.input.name)
    if (entry is None or args.input.stat().st_size != entry["bytes"]
            or digest(args.input) != entry["sha256"]):
        raise ValueError("Input checksum/size differs from release metadata")
    cohort = pd.read_parquet(args.input)
    if (len(cohort) != metadata["statistics"]["ranking"]
            or cohort.is_kev.sum() != metadata["statistics"]["ranking_kev"]
            or not cohort.epss_date.eq(metadata["epss_date"]).all()):
        raise ValueError("Cohort count, KEV count or EPSS date differs from release")
    version = metadata["dataset_version"]
    rankings = build_rankings(cohort, dataset_version=version,
                              cohort_id=f"{version}:ranking")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rankings.to_csv(args.output, index=False, encoding="utf-8", lineterminator="\n")
    print(json.dumps({"rows": len(rankings), "kev": int(rankings.is_kev.sum()),
                      "dataset_version": version,
                      "cohort_id": f"{version}:ranking",
                      "policy_version": POLICY_VERSION,
                      "epss_date": metadata["epss_date"],
                      "output": str(args.output), "sha256": digest(args.output)}, indent=2))


if __name__ == "__main__":
    main()
