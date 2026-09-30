"""Prepare a small, reproducible NVD-only handoff without network requests.

Existing handoff files are never overwritten, particularly manual scope reviews.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

from src.collect.collect_pilot import ROOT, candidate_mask, summarize_records
from src.collect.nvd_collector import ALLOWED_LABELS, parse_base_vector


METRICS = list(ALLOWED_LABELS)
SAMPLE_COLUMNS = [
    "cve_id", "published", "last_modified", "vuln_status", "description",
    "cvss_version", "cvss_vector", "cvss_base_score", "cvss_source", "cvss_type",
    *METRICS, "has_cvss31_label", "epss", "epss_percentile", "epss_date",
    "is_kev", "kev_date_added", "kev_known_ransomware", "domain_tags", "in_scope",
    "scope_reason", "scope_evidence", "scope_status", "split", "dataset_version",
    "retrieved_at",
]
SAMPLE_DTYPES = {name: "string" for name in SAMPLE_COLUMNS}
SAMPLE_DTYPES.update({
    "cvss_base_score": "Float64", "epss": "Float64", "epss_percentile": "Float64",
    "has_cvss31_label": "boolean", "in_scope": "boolean", "is_kev": "boolean",
})


def workspace_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Duong dan phai nam trong repo")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_rows(frame, size, seed):
    """Deterministic hash ordering, independent of input row order."""
    if size < 0 or size > len(frame):
        raise ValueError(f"Khong the lay {size} dong tu tap {len(frame)} dong")
    ranked = frame.assign(_order=frame["cve_id"].map(
        lambda cve_id: hashlib.sha256(f"{seed}:{cve_id}".encode()).hexdigest()
    ))
    return ranked.sort_values(["_order", "cve_id"]).head(size).drop(columns="_order")


def make_sample(selected, version, built_at):
    sample = selected.copy().reset_index(drop=True)
    valid = []
    for _, row in sample.iterrows():
        labels = parse_base_vector(row["cvss_vector"])
        if labels is not None:
            if any(pd.isna(row[name]) or row[name] != labels[name] for name in METRICS):
                raise ValueError(f"Nhan khong khop vector: {row['cve_id']}")
            score = row["cvss_base_score"]
            if pd.isna(score) or not 0 <= score <= 10:
                raise ValueError(f"Diem CVSS ngoai khoang hoac thieu: {row['cve_id']}")
        valid.append(labels is not None)
    sample["has_cvss31_label"] = pd.array(valid, dtype="boolean")
    for name in ("epss", "epss_percentile"):
        sample[name] = pd.Series(pd.NA, index=sample.index, dtype="Float64")
    sample["is_kev"] = pd.Series(pd.NA, index=sample.index, dtype="boolean")
    for name in ("epss_date", "kev_date_added", "kev_known_ransomware", "split"):
        sample[name] = pd.Series(pd.NA, index=sample.index, dtype="string")
    sample["domain_tags"] = "[]"
    sample["scope_evidence"] = "[]"
    sample["in_scope"] = False
    sample["scope_status"] = "needs_review"
    sample["scope_reason"] = "Chua duoc danh gia pham vi Web/mobile"
    sample["dataset_version"] = version
    sample["retrieved_at"] = built_at
    for name in ("published", "last_modified"):
        sample[name] = sample[name].map(lambda value: value.isoformat() if pd.notna(value) else None)
    return sample[SAMPLE_COLUMNS]


def label_counts(frame):
    return {
        name: {value: int(frame[name].eq(value).fillna(False).sum())
               for value in sorted(ALLOWED_LABELS[name])}
        for name in METRICS
    }


def make_annotations(candidates, raw_by_id, version, policy_version):
    rows = []
    for _, row in candidates.sort_values("cve_id").iterrows():
        raw = raw_by_id[row["cve_id"]]
        # These are unreviewed source links, not confirmed scope evidence.
        urls = sorted({ref["url"] for ref in raw.get("references", [])
                       if isinstance(ref.get("url"), str) and ref["url"].startswith(("https://", "http://"))})
        rows.append({
            "cve_id": row["cve_id"],
            "proposed_domain_tags": "[]", "final_domain_tags": "[]",
            "scope_status": "needs_review", "reason": "Chua danh gia",
            "evidence_url": "", "reviewer": "", "reviewed_at": "",
            "scope_policy_version": policy_version,
            "description": row["description"], "cvss_vector": row["cvss_vector"],
            "cvss_source": row["cvss_source"],
            "reference_urls": json.dumps(urls, ensure_ascii=False),
            "dataset_version": version,
        })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(description="Tao mau ban giao NVD-only cho N2/N3")
    parser.add_argument("--metadata", required=True, help="Metadata cua lan tai pilot")
    parser.add_argument("--size", type=int, default=30, help="So ung vien co nhan")
    parser.add_argument("--rejected-size", type=int, default=5, help="So dong Rejected de thu missing")
    args = parser.parse_args()
    if args.size < 1 or args.rejected_size < 0:
        parser.error("--size phai >= 1, --rejected-size phai >= 0")

    config = yaml.safe_load((ROOT / "config/project.yaml").read_text(encoding="utf-8"))
    source_metadata_path = workspace_path(args.metadata)
    source = json.loads(source_metadata_path.read_text(encoding="utf-8"))
    raw_path = workspace_path(source["raw_file"])
    table_path = workspace_path(source["table_file"])
    if digest(raw_path) != source["raw_sha256"] or digest(table_path) != source["table_sha256"]:
        raise ValueError("Checksum nguon khong khop metadata")
    frame = pd.read_parquet(table_path)
    if not frame["cve_id"].is_unique or len(frame) != source["downloaded_records"]:
        raise ValueError("So dong/ID khong hop le")
    if set(frame["dataset_version"].dropna()) != {source["dataset_version"]}:
        raise ValueError("Phien ban bang khong khop metadata")
    raw = json.loads(raw_path.read_bytes())
    raw_by_id = {entry["cve"]["id"]: entry["cve"] for entry in raw["vulnerabilities"]}
    if set(raw_by_id) != set(frame["cve_id"]):
        raise ValueError("ID cua raw va bang khong khop")

    candidates = frame.loc[candidate_mask(frame)].copy()
    rejected = frame.loc[frame["vuln_status"].eq("Rejected").fillna(False)].copy()
    seed = int(config["project"]["seed"])
    chosen = select_rows(candidates, args.size, seed)
    missing_examples = select_rows(rejected, args.rejected_size, seed)
    selected = pd.concat([chosen, missing_examples]).sort_values("cve_id")
    signature = json.dumps({
        "preparation_version": 1, "seed": seed, "ids": selected["cve_id"].tolist(),
        "source_sha256": source["table_sha256"], "scope_policy": config["scope"]["policy_version"],
    }, sort_keys=True).encode()
    version = f"{source['dataset_version']}-handoff-{hashlib.sha256(signature).hexdigest()[:12]}"
    built_at = datetime.now(timezone.utc).isoformat()
    sample = make_sample(selected, version, built_at)
    annotations = make_annotations(chosen, raw_by_id, version, config["scope"]["policy_version"])

    outputs = {
        "sample": workspace_path(config["paths"]["sample"]),
        "metadata": workspace_path(config["paths"]["sample_metadata"]),
        "annotations": workspace_path(config["paths"]["scope_annotations"]),
        "labels": workspace_path(Path(config["paths"]["reports_dir"]) / "pilot_label_distribution.json"),
    }
    if len(set(outputs.values())) != len(outputs):
        raise ValueError("Duong dan dau ra bi trung nhau")
    existing = [str(path.relative_to(ROOT)) for path in outputs.values() if path.exists()]
    if existing:
        raise FileExistsError(f"Da co file ban giao; dung de bao ve phan review: {existing}")
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    sample.to_csv(outputs["sample"], index=False, encoding="utf-8", lineterminator="\n")
    annotations.to_csv(outputs["annotations"], index=False, encoding="utf-8", lineterminator="\n")
    report = {
        "source_dataset_version": source["dataset_version"], "sample_dataset_version": version,
        "source_summary": summarize_records(frame), "candidate_pool_size": len(candidates),
        "candidate_label_counts": label_counts(candidates),
        "sample_candidate_size": len(chosen), "sample_candidate_label_counts": label_counts(chosen),
        "sample_rejected_size": len(missing_examples),
        "limitations": "One-week NVD snapshot; no Web/mobile review, final split, or model evaluation.",
    }
    outputs["labels"].write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    metadata = {
        "schema_version": config["project"]["schema_version"], "dataset_version": version,
        "created_at": built_at, "purpose": "NVD-only integration handoff; not a training/evaluation cohort",
        "source_metadata": source_metadata_path.relative_to(ROOT).as_posix(),
        "source_dataset_version": source["dataset_version"], "source_retrieved_at": source["retrieved_at"],
        "source_params": source["params"], "source_complete_for_window": source["complete_for_requested_window"],
        "source_raw_sha256": source["raw_sha256"], "source_table_sha256": source["table_sha256"],
        "seed": seed, "selection_method": "Lowest SHA256(seed:CVE ID) within each of two separate groups",
        "sample_size": len(sample), "labelled_candidates": len(chosen), "rejected_examples": len(missing_examples),
        "sample_ids": sample["cve_id"].tolist(), "scope_policy_version": config["scope"]["policy_version"],
        "epss_date": None, "kev_retrieved_at": None,
        "sample_sha256": digest(outputs["sample"]),
        "annotations_initial_sha256": digest(outputs["annotations"]),
        "label_report_sha256": digest(outputs["labels"]),
        "limitations": [
            "All scope decisions are pending; in_scope=false means not admitted yet, not confirmed excluded.",
            "EPSS/KEV are unknown, not zero/false. No train/validation/test assignments.",
            "has_cvss31_label checks the vector and matching labels; Base score recalculation is pending.",
            "Reference URLs are supplied for review, not verified scope evidence.",
            "The sample deliberately includes Rejected examples; do not infer population proportions.",
            "Annotation checksum records initial handoff only; N2 edits and versions reviews through Git.",
        ],
    }
    outputs["metadata"].write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Da tao {len(sample)} dong mau: {len(chosen)} ung vien + {len(missing_examples)} Rejected")
    print(f"Bang scope: {len(annotations)} dong needs_review")
    print(f"Thong ke nhan tren {len(candidates)} ung vien trong pilot")
    for name, path in outputs.items():
        print(f"{name}: {path.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
