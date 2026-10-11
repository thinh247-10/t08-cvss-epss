"""Build the versioned Phase 1 release offline from verified immutable sources."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import zipfile

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from src.collect.build_dataset import read_source, check_epss_raw, check_kev_raw, join_pilot
from src.collect.collect_nvd import replay_pages
from src.collect.filter_scope import classify_scope, vulnerable_cpes
from src.environmental.asset_inventory import load_inventory
from src.environmental.cvss_base import calculate_base_score
from src.model.audit_data import audit_frame, digest, verify_inputs, SPLITS
from src.model.data_validation import LABEL_ORDER, validate_model_input
from src.model.duplicate_policy import plan_duplicates
from src.model.near_duplicates import plan_near_duplicates


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_table(frame, path):
    table = pa.Table.from_pandas(frame, preserve_index=False)
    for name in ("domain_tags", "scope_evidence", "product_groups", "reference_urls"):
        if name in table.column_names:
            idx = table.column_names.index(name)
            table = table.set_column(idx, name, table.column(idx).cast(pa.list_(pa.string())))
    for name in ("epss_date", "kev_date_added"):
        if name in table.column_names:
            idx = table.column_names.index(name)
            table = table.set_column(idx, name, pa.array(pd.to_datetime(frame[name]).dt.date, type=pa.date32()))
    pq.write_table(table, path)


def label_support(frame):
    rows = []
    for scope, scoped in (("all_ml", frame), ("web_mobile_ml", frame.loc[frame.in_scope])):
        for split in SPLITS:
            part = scoped.loc[scoped.split.eq(split)]
            for metric, labels in LABEL_ORDER.items():
                for label in labels:
                    rows.append({"cohort": scope, "split": split, "metric": metric,
                                 "label": label, "support": int(part[metric].eq(label).sum()), "size": len(part)})
    return pd.DataFrame(rows)


def apply_annotations(master, raw_by_id, annotations, policy):
    result = master.set_index("cve_id", drop=False).copy()
    audit = []
    if annotations.cve_id.duplicated().any():
        raise ValueError("Duplicate annotation CVE ID")
    for _, row in annotations.iterrows():
        cve_id = row.cve_id
        if cve_id not in result.index or result.at[cve_id, "description"] != row.description:
            raise ValueError(f"Annotation snapshot description mismatch: {cve_id}")
        if result.at[cve_id, "vuln_status"] == "Rejected":
            raise ValueError(f"Cannot transfer annotation to Rejected CVE: {cve_id}")
        refs = set(json.loads(row.reference_urls))
        current_refs = {r["url"] for r in raw_by_id[cve_id].get("references", [])}
        if not refs.intersection(current_refs):
            raise ValueError(f"Annotation raw references no longer match: {cve_id}")
        tags = json.loads(row.final_domain_tags)
        status, reason = row.scope_status, row.reason
        if status not in {"included", "excluded", "needs_review"}:
            raise ValueError(f"Invalid annotation status: {cve_id}")
        if status == "included" and (not tags or not set(tags) <= {"web", "mobile"}):
            raise ValueError(f"Invalid included tags: {cve_id}")
        if status != "included" and tags:
            raise ValueError(f"Non-included annotation must not assign domains: {cve_id}")
        if not isinstance(row.evidence_url, str) or not row.evidence_url.startswith("https://"):
            raise ValueError(f"Missing evidence URL: {cve_id}")
        override = policy.get("annotation_overrides", {}).get(cve_id)
        if override:
            status, reason, tags = override["status"], override["reason"], []
        for column, value in {"scope_status": status, "in_scope": status == "included",
                              "domain_tags": tags, "scope_reason": reason,
                              "scope_evidence": [row.evidence_url]}.items():
            result.at[cve_id, column] = value
        audit.append({"cve_id": cve_id, "old_status": row.scope_status, "new_status": status,
                      "source_annotation_version": row.dataset_version, "description_equal": True,
                      "reference_overlap": True, "overridden": bool(override), "reason": reason})
    return result.reset_index(drop=True), pd.DataFrame(audit)


def build(config_path):
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    output = Path(cfg["output"])
    if output.exists():
        raise ValueError("Release directory exists; choose a new version/output, never overwrite")
    paths = {key: Path(cfg[key]) for key in ("scope_policy", "inventory", "annotations", "joined_table",
                                            "joined_metadata", "handoff_manifest", "source_project_config")}
    meta, _, protected, provenance = verify_inputs(paths["joined_table"], paths["joined_metadata"],
                                                  paths["source_project_config"], paths["handoff_manifest"])
    inputs = {**provenance["hashes"], str(config_path): digest(config_path),
              **{str(p): digest(p) for p in paths.values()}}
    frame = pd.read_parquet(paths["joined_table"])
    project = yaml.safe_load(paths["source_project_config"].read_text(encoding="utf-8"))
    check = audit_frame(frame, dataset_version=meta["dataset_version"], split_config=cfg["split"])
    errors = [f for f in check["findings"] if f["severity"] == "error"]
    if meta["status"] != "complete" or errors:
        raise ValueError(f"Joined source failed audit: {errors[:4]}")
    sources = {}
    for kind in ("nvd", "epss", "kev"):
        entry = meta["sources"][kind]
        if digest(Path(entry["metadata_file"])) != entry["metadata_sha256"]:
            raise ValueError(f"Source metadata changed: {kind}")
        sources[kind] = read_source(entry["metadata_file"], kind)
        inputs[entry["metadata_file"]] = entry["metadata_sha256"]
    nm, nvd, _ = sources["nvd"]
    em, epss, _ = sources["epss"]
    km, kev, _ = sources["kev"]
    raw, progress = replay_pages(nm)
    if not all(p["complete"] for p in progress):
        raise ValueError("Incomplete NVD raw pages")
    raw_by_id = {c["id"]: c for c in raw}
    if len(raw) != len(raw_by_id) or set(raw_by_id) != set(frame.cve_id):
        raise ValueError("Raw IDs do not match joined master")
    check_epss_raw(em, epss, set(raw_by_id))
    check_kev_raw(km, kev)
    rebuilt = join_pilot(nvd, epss, kev, meta["dataset_version"], meta["built_at"], kev_complete=True)
    # Compare original source content, including nulls, against a fresh offline join.
    for col in ("description", "cvss_vector", "cvss_base_score", "epss", "epss_date", "is_kev"):
        pd.testing.assert_series_equal(frame.set_index("cve_id")[col].sort_index(),
                                       rebuilt.set_index("cve_id")[col].sort_index(), check_dtype=False)
    print("Verified NVD/EPSS/KEV raw and joined source", flush=True)
    policy = yaml.safe_load(paths["scope_policy"].read_text(encoding="utf-8"))
    scope_rows = []
    for cve_id in frame.cve_id:
        c = raw_by_id[cve_id]
        scope_rows.append(classify_scope(cve_id, list(vulnerable_cpes(c.get("configurations", []))),
                                         [r["url"] for r in c.get("references", [])], policy))
    master = frame.copy(deep=True)
    for column in scope_rows[0]:
        master[column] = [row[column] for row in scope_rows]
    master, annotations_audit = apply_annotations(master, raw_by_id,
                                                  pd.read_csv(paths["annotations"]), policy)
    rejected = master.vuln_status.eq("Rejected")
    master.loc[rejected, "in_scope"] = False
    master.loc[rejected, "scope_status"] = "excluded"
    master.loc[rejected, "scope_reason"] = "Rejected CVE; retained in master only"
    for idx in master.index[rejected]:
        master.at[idx, "domain_tags"] = []
    master["source_dataset_version"] = meta["dataset_version"]
    master["dataset_version"] = cfg["dataset_version"]
    candidate = master.has_cvss31_label & ~rejected & master.description.astype("string").str.strip().ne("")
    eligible = master.loc[candidate].copy()
    validate_model_input(eligible, dataset_version=cfg["dataset_version"])
    scored = eligible.cvss_vector.map(calculate_base_score)
    if not (scored.sub(eligible.cvss_base_score).abs() < 1e-8).all():
        raise ValueError("Source Base Score mismatch; inspect before release")
    exact, _, _ = plan_duplicates(eligible, dataset_version=cfg["dataset_version"], split_config=cfg["split"])
    print("Scope and Base verified; auditing near duplicates", flush=True)
    decisions, edges, near = plan_near_duplicates(eligible, exact,
        threshold=cfg["ml"]["near_jaccard"], max_bucket=cfg["ml"]["near_max_bucket"])
    decisions = decisions.rename(columns={"keep_in_preview": "ml_selected"})
    decisions["dataset_version"] = cfg["dataset_version"]
    kept = decisions.loc[decisions.ml_selected].set_index("cve_id")
    master["split"] = master.cve_id.map(kept.proposed_split).astype("string")
    master["ml_exclusion_reason"] = master.cve_id.map(decisions.set_index("cve_id").reason).fillna("missing_description_or_label_or_rejected")
    master.loc[master.split.notna(), "ml_exclusion_reason"] = pd.NA
    master["duplicate_component"] = master.cve_id.map(decisions.set_index("cve_id").component_id).astype("string")
    for metric, labels in LABEL_ORDER.items():
        master[metric] = pd.Categorical(master[metric], categories=labels)
    master["in_scope"] = master.in_scope.astype("boolean")
    ml = master.loc[master.split.notna()].copy()
    ranking = master.loc[master.in_scope & candidate & master.epss.notna() & master.is_kev.notna()].copy()
    if len(ranking) < cfg["ranking"]["minimum_cohort"]:
        raise ValueError("Ranking cohort too small for planned top-50 comparison")
    if ml.groupby("duplicate_component").split.nunique().gt(1).any():
        raise ValueError("Duplicate components overlap splits")
    validate_model_input(ml, dataset_version=cfg["dataset_version"])
    support = label_support(ml)
    asset_inventory = load_inventory(paths["inventory"])
    assets = {a.asset_id: a for a in asset_inventory.assets}
    mappings = []
    for case in cfg["case_mappings"]:
        asset = assets[case["asset_id"]]
        if case["cve_id"] not in raw_by_id or case["evidence_url"] not in master.set_index("cve_id").at[case["cve_id"], "reference_urls"]:
            raise ValueError("Case evidence is not in snapshot references")
        mappings.append({**case, "product": asset.product, "assumed_version": asset.version,
                         "reviewer": "N1 integration assisted review 2026-10-10",
                         "dataset_version": cfg["dataset_version"], "context_version": asset_inventory.inventory_version})
    products = ml[["cve_id", "split", "product_groups"]].explode("product_groups").dropna()
    overlap = products.groupby("product_groups").agg(rows=("cve_id", "nunique"), splits=("split", lambda s: "|".join(sorted(set(s)))))
    overlap = overlap.loc[overlap.splits.str.contains("\\|")].reset_index()
    now = datetime.now(timezone.utc).isoformat()
    statistics = {"master": len(master), "unique_cve_ids": int(master.cve_id.nunique()),
        "rejected": int(rejected.sum()), "missing_epss": int(master.epss.isna().sum()),
        "scope_status": master.scope_status.value_counts().to_dict(),
        "web": sum("web" in t for t in master.domain_tags), "mobile": sum("mobile" in t for t in master.domain_tags),
        "ranking": len(ranking), "ranking_kev": int(ranking.is_kev.sum()),
        "ml_before_duplicates": len(eligible), "ml": len(ml),
        "excluded_duplicate_rows": len(eligible)-len(ml), "splits": ml.split.value_counts().to_dict(),
        "scoped_ml_splits": ml.loc[ml.in_scope].split.value_counts().to_dict(),
        "base_scores_checked": len(scored), "base_score_mismatches": 0,
        "shared_product_groups": len(overlap), "case_pairs": len(mappings)}
    print(json.dumps(statistics, indent=2), flush=True)
    for path, checksum in inputs.items():
        if digest(Path(path)) != checksum:
            raise ValueError(f"Input changed during build: {path}")
    output.mkdir(parents=True, exist_ok=False)
    for name, table in (("cves", master), ("ranking_cohort", ranking), ("ml_cohort", ml)):
        write_table(table, output / f"{name}.parquet")
    decisions.to_csv(output / "ml_decisions.csv", index=False)
    edges.to_csv(output / "near_duplicate_edges.csv", index=False)
    support.to_csv(output / "label_support.csv", index=False)
    annotations_audit.to_csv(output / "annotation_transfer.csv", index=False)
    overlap.to_csv(output / "product_overlap.csv", index=False)
    pd.DataFrame(mappings).to_csv(output / "cve_asset_mapping.csv", index=False)
    for name, content in (("phase1.yaml", cfg), ("scope.yaml", policy),
                          ("assets.yaml", yaml.safe_load(paths["inventory"].read_text(encoding="utf-8")))):
        (output / name).write_text(yaml.safe_dump(content, sort_keys=False, allow_unicode=True), encoding="utf-8")
    write_json(output / "source_manifests.json", {kind: values[0] for kind, values in sources.items()})
    release = {"status": "complete", "dataset_version": cfg["dataset_version"], "schema_version": cfg["schema_version"],
        "built_at": now, "training_ready": True, "ranking_ready": True,
        "readiness_meaning": "Technical gates passed for the declared cohort/protocol; no model trained. Teammate receipt of this new package remains external.",
        "statistics": statistics, "near_duplicate_audit": near, "split": cfg["split"], "ml_protocol": cfg["ml"],
        "scope_policy_version": policy["policy_version"], "epss_date": meta["epss_date"],
        "kev_date_released": meta["kev_date_released"], "kev_retrieved_at": meta["kev_retrieved_at"],
        "input_hashes": inputs, "module_hashes": {str(p): digest(p) for p in
            [Path(__file__), Path("src/model/near_duplicates.py"), Path("src/collect/filter_scope.py"), Path("src/environmental/cvss_base.py")]},
        "limitations": ["Bounded product cohort, not a census of Web/mobile CVEs; unmatched rows remain needs_review.",
            "ML training domain is broad; separately report Web/mobile validation and test, including absent classes.",
            "Approximate near-duplicate retrieval can miss similar text; product overlap is allowed and reported.",
            "Temporal split of current NVD snapshot is not an as-of historical forecast.",
            "EPSS and KEV snapshot dates differ; KEV is not complete exploitation ground truth.",
            "Assets are hypothetical; applicability is conditional, not a real-system assessment."]}
    release["files"] = {p.name: {"sha256": digest(p), "bytes": p.stat().st_size} for p in sorted(output.iterdir())}
    write_json(output / "metadata.json", release)
    archive = output.parent / f"{output.name}.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.iterdir()):
            z.write(p, f"{output.name}/{p.name}")
    handoff = {"dataset_version": cfg["dataset_version"], "archive": str(archive),
               "archive_sha256": digest(archive), "archive_bytes": archive.stat().st_size,
               "files": {p.name: {"sha256": digest(p), "bytes": p.stat().st_size} for p in sorted(output.iterdir())}}
    write_json(Path("docs/handoffs/phase-1-v1.json"), handoff)
    print(f"Release: {output}\nArchive: {archive}", flush=True)
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config/phase1.yaml"))
    args = parser.parse_args()
    build(args.config)


if __name__ == "__main__":
    main()
