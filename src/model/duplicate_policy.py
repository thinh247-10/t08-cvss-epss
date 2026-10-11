"""Preview exact-description exclusions; never edit master or authorize training."""
import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd
import yaml

from src.model.audit_data import (
    NORMALIZATION, SPLITS, audit_frame, digest, proposed_splits, verify_inputs,
)
from src.model.data_validation import LABEL_ORDER, validate_model_input

POLICY_VERSION = "exact-earliest-period-v1"


def plan_duplicates(frame, *, dataset_version, split_config):
    """Accept already eligible rows; return metadata-only decisions and counts.

    Keep all occurrences in their earliest chronological period, including rows
    with differing targets. Exclude only later-period occurrences. Decisions use
    descriptions/dates, never target labels, EPSS, KEV or model performance.
    This is a preview before scope filtering, not an official split assignment.
    """
    validate_model_input(frame, dataset_version=dataset_version)
    data = frame.reset_index(drop=True)
    if "published" not in data:
        raise ValueError("published is required")
    dates, proposed = proposed_splits(data.published, split_config)
    if dates.isna().any() or proposed.isna().any():
        raise ValueError("Every submitted candidate needs a date inside the split intervals")
    normalized = data.description.str.normalize("NFKC").str.replace(
        r"\s+", " ", regex=True).str.strip().str.casefold()
    first_date = dates.groupby(normalized).transform("min")
    _, earliest = proposed_splits(first_date, split_config)
    keep = proposed.eq(earliest)
    decisions = pd.DataFrame({
        "cve_id": data.cve_id,
        "source_dataset_version": dataset_version,
        "duplicate_policy_version": POLICY_VERSION,
        "description_sha256": normalized.map(lambda x: hashlib.sha256(x.encode("utf-8")).hexdigest()),
        "proposed_split": proposed,
        "earliest_split": earliest,
        "keep_in_preview": keep,
        "reason": keep.map({True: "earliest_period", False: "duplicate_in_earlier_period"}),
    })
    # Invariant: after exclusions each normalized description belongs to one period.
    remaining = decisions.loc[keep]
    if remaining.groupby("description_sha256").proposed_split.nunique().gt(1).any():
        raise RuntimeError("Cross-split duplicates remain")
    counts = []
    for stage, active in (("before", pd.Series(True, index=data.index)), ("after", keep)):
        for split in SPLITS:
            mask = active & proposed.eq(split)
            for metric, labels in LABEL_ORDER.items():
                for label in labels:
                    counts.append({"stage": stage, "split": split, "metric": metric,
                                   "label": label, "support": int((mask & data[metric].eq(label)).sum()),
                                   "cohort_size": int(mask.sum())})
    summary = {
        "policy_version": POLICY_VERSION,
        "normalization": NORMALIZATION,
        "status": "preview_before_scope_not_training_ready",
        "input_candidates": len(data), "kept_candidates": int(keep.sum()),
        "excluded_candidates": int((~keep).sum()),
        "by_split": {name: {"before": int(proposed.eq(name).sum()),
                            "kept": int((proposed.eq(name) & keep).sum()),
                            "excluded": int((proposed.eq(name) & ~keep).sum())} for name in SPLITS},
        "cross_split_groups_after": 0,
        "limitations": ["Scope and shared Base scorer still need verification.",
                        "Near duplicates and product groups have not been resolved.",
                        "Within-period duplicates and differing source labels are retained.",
                        "Recompute on the final scoped cohort; this does not lock split."],
    }
    return decisions.sort_values("cve_id").reset_index(drop=True), pd.DataFrame(counts), summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("config/project.yaml"))
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.table.suffix.lower() != ".parquet":
        parser.error("--table must be Parquet")
    if args.out_dir.exists() or args.out_dir.resolve().is_relative_to(args.table.parent.resolve()):
        parser.error("Use a new output directory outside the source package")
    meta, _, paths, provenance = verify_inputs(
        args.table, args.metadata, args.config, args.manifest)
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    if meta.get("status") != "complete" or meta.get("schema_version") != config["project"]["schema_version"]:
        raise ValueError("Incomplete dataset or schema version mismatch")
    frame = pd.read_parquet(args.table)
    audit = audit_frame(frame, dataset_version=meta["dataset_version"], split_config=config["split"])
    errors = [f for f in audit["findings"] if f["severity"] == "error"]
    if errors:
        raise ValueError(f"Fix source audit errors before preview: {errors[:5]}")
    # audit_frame rejects inconsistent flags/labels; validator rechecks selected rows.
    eligible = frame.vuln_status.ne("Rejected") & frame.has_cvss31_label.fillna(False)
    eligible &= frame.description.astype("string").str.strip().fillna("").ne("")
    decisions, counts, summary = plan_duplicates(
        frame.loc[eligible], dataset_version=meta["dataset_version"], split_config=config["split"])
    summary["source_dataset_version"] = meta["dataset_version"]
    summary["input_hashes"] = provenance["hashes"]
    summary["split_config"] = config["split"]
    summary["cross_split_groups_before"] = audit["description_duplicates"]["cross_split_groups"]
    summary["module_sha256"] = digest(Path(__file__))
    for path in paths:
        if digest(path) != provenance["hashes"][str(path)]:
            raise ValueError(f"Input changed during preview: {path}")
    args.out_dir.mkdir(parents=True, exist_ok=False)
    decisions.to_csv(args.out_dir / "decisions.csv", index=False, lineterminator="\n")
    counts.to_csv(args.out_dir / "label_counts.csv", index=False, lineterminator="\n")
    summary["output_hashes"] = {name: digest(args.out_dir / name)
                                for name in ("decisions.csv", "label_counts.csv")}
    (args.out_dir / "metadata.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in (
        "status", "input_candidates", "kept_candidates", "excluded_candidates", "by_split",
        "cross_split_groups_before", "cross_split_groups_after")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
