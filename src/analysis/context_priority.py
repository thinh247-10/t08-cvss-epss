"""Applicability-first context policy; no inference of Modified CVSS controls.

CLI creates a new context artifact set beside (not over) frozen release files.
"""
import argparse
from dataclasses import asdict
from datetime import date, datetime, timezone
import json
from importlib.metadata import version as package_version
import math
from numbers import Real
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

import pandas as pd
import yaml

from src.analysis.compare_rankings import digest
from src.analysis.ranking_metrics import file_record, git_output, validate_k
from src.environmental.asset_inventory import load_inventory
from src.environmental.cvss_base import calculate_base_score
from src.environmental.cvss_environmental import environmental_score, score_environmental_vector

PAIR = ["cve_id", "asset_id"]
MAP_COLUMNS = ("cve_id", "asset_id", "applicability", "affected_version_evidence", "evidence_url",
               "mapping_reason", "product", "assumed_version", "reviewer", "dataset_version",
               "context_version", "evidence_read_at", "exploit_conditions", "evidence_limitations")
ENV_COLUMNS = ("cve_id", "asset_id", "base_vector", "base_score", "environmental_vector",
               "environmental_score", "CR", "IR", "AR", "modification_reason", "score_source",
               "dataset_version", "context_version")
QUEUE_COLUMNS = ("cve_id", "asset_id", "applicability", "is_kev", "epss", "environmental_score",
                 "exposure", "queue_status", "priority_rank", "priority_reason", "recommended_action",
                 "policy_version", "context_version", "dataset_version")


def unique(frame, key, name):
    if not frame.columns.is_unique or not set(key).issubset(frame.columns):
        raise ValueError(f"{name}: duplicate columns or missing key")
    if frame[key].isna().any().any() or frame.duplicated(key).any():
        raise ValueError(f"{name}: missing or duplicate key")


def validate_mapping(mapping, assets, dataset_version, context_version):
    unique(mapping, PAIR, "mapping")
    unique(assets, ["asset_id"], "inventory")
    if not set(MAP_COLUMNS).issubset(mapping.columns):
        raise ValueError("Mapping lacks contract/evidence columns")
    for column in MAP_COLUMNS:
        if not mapping[column].map(lambda v: isinstance(v, str) and bool(v.strip())).all():
            raise ValueError(f"Mapping missing text: {column}")
    if not mapping.cve_id.map(lambda v: re.fullmatch(r"CVE-\d{4}-\d{4,}", v) is not None).all():
        raise ValueError("Invalid mapping CVE ID")
    if (not mapping.dataset_version.eq(dataset_version).all()
            or not mapping.context_version.eq(context_version).all()):
        raise ValueError("Mapping version mismatch")
    if not mapping.applicability.isin(["affected", "unaffected", "needs_review"]).all():
        raise ValueError("Invalid applicability")
    for value in mapping.evidence_read_at:
        if date.fromisoformat(value).isoformat() != value:
            raise ValueError("Invalid evidence date")
    for value in mapping.evidence_url:
        if urlparse(value).scheme != "https" or not urlparse(value).netloc:
            raise ValueError("Evidence requires HTTPS URL")
    joined = mapping.merge(assets, on="asset_id", how="left", validate="many_to_one",
                           suffixes=("", "_asset"), indicator=True)
    if not joined._merge.eq("both").all():
        raise ValueError("Mapping references unknown asset")
    affected = joined.applicability.eq("affected")
    if (joined.loc[affected, ["product_asset", "version"]].isna().any().any()
            or not joined.loc[affected, "product"].eq(joined.loc[affected, "product_asset"]).all()
            or not joined.loc[affected, "assumed_version"].eq(joined.loc[affected, "version"]).all()):
        raise ValueError("Affected mapping must match explicit inventory product/version")
    return mapping.sort_values(PAIR).reset_index(drop=True)


def validate_master(master, dataset_version):
    unique(master, ["cve_id"], "master")
    required = {"cvss_vector", "cvss_base_score", "epss", "is_kev", "dataset_version"}
    if not required.issubset(master.columns) or not master.dataset_version.eq(dataset_version).all():
        raise ValueError("Master schema/version mismatch")
    for column, upper in (("epss", 1), ("cvss_base_score", 10)):
        values = master[column].dropna()
        if not values.map(lambda v: isinstance(v, Real) and not isinstance(v, bool)
                          and math.isfinite(v) and 0 <= v <= upper).all():
            raise ValueError(f"Invalid master {column}")
    if not master.is_kev.dropna().map(lambda v: isinstance(v, (bool, type(pd.NA))) or type(v).__name__ == "bool").all():
        raise ValueError("KEV must be boolean or missing, never strings/numeric imputation")


def build_environmental(master, mapping, assets, *, dataset_version, context_version):
    mapping = validate_mapping(mapping, assets, dataset_version, context_version)
    validate_master(master, dataset_version)
    joined = mapping.merge(master[["cve_id", "cvss_vector", "cvss_base_score"]],
                           on="cve_id", how="left", validate="many_to_one")
    joined = joined.merge(assets, on="asset_id", how="left", validate="many_to_one", suffixes=("", "_asset"))
    rows, excluded = [], []
    for _, row in joined.iterrows():
        key = dict(cve_id=row.cve_id, asset_id=row.asset_id)
        if row.applicability != "affected":
            excluded.append(dict(**key, reason="applicability_" + row.applicability))
            continue
        try:
            base = calculate_base_score(row.cvss_vector)
            if pd.isna(row.cvss_base_score) or abs(base - float(row.cvss_base_score)) > 1e-8:
                raise ValueError("observed Base score/vector mismatch")
            requirements = {k: row[k] for k in ("CR", "IR", "AR")}
            full, score = environmental_score(row.cvss_vector, requirements)
        except ValueError as error:
            excluded.append(dict(**key, reason=str(error)))
            continue
        rows.append(dict(**key, base_vector=row.cvss_vector, base_score=base,
                         environmental_vector=full, environmental_score=score, **requirements,
                         modification_reason="CR/IR/AR from hypothetical inventory: " + row.rationale
                         + " Temporal E/RL/RC and all Modified metrics remain X: no verified controls; "
                         + "internal/client exposure does not change MAV. " + row.exploit_conditions,
                         score_source="observed", dataset_version=dataset_version,
                         context_version=context_version))
    return pd.DataFrame(rows, columns=ENV_COLUMNS), excluded


def build_queue(master, mapping, assets, environmental, *, dataset_version, context_version,
                policy_version="context-v1"):
    if policy_version not in ("context-v1", "context-v1-env-first"):
        raise ValueError("Unknown context policy")
    mapping = validate_mapping(mapping, assets, dataset_version, context_version)
    validate_master(master, dataset_version)
    unique(environmental, PAIR, "environmental")
    if not set(ENV_COLUMNS).issubset(environmental.columns):
        raise ValueError("Environmental schema mismatch")
    if (not environmental.dataset_version.eq(dataset_version).all()
            or not environmental.context_version.eq(context_version).all()
            or not environmental.score_source.eq("observed").all()):
        raise ValueError("Environmental source/version mismatch")
    # Reject stale/forged vectors and orphan scores, including unaffected pairs.
    eligible = set(map(tuple, mapping.loc[mapping.applicability.eq("affected"), PAIR].to_numpy()))
    for _, row in environmental.iterrows():
        if (row.cve_id, row.asset_id) not in eligible:
            raise ValueError("Environmental pair is not affected mapping")
        _, calculated = score_environmental_vector(row.environmental_vector)
        expected_base = master.loc[master.cve_id.eq(row.cve_id)]
        if expected_base.empty or row.base_vector != expected_base.iloc[0].cvss_vector:
            raise ValueError("Environmental must use observed vector")
        if (pd.isna(expected_base.iloc[0].cvss_base_score)
                or float(row.base_score) != float(expected_base.iloc[0].cvss_base_score)):
            raise ValueError("Environmental Base score differs from observed source")
        requirements = {k: row[k] for k in ("CR", "IR", "AR")}
        expected_vector, expected_score = environmental_score(row.base_vector, requirements)
        if (row.environmental_vector != expected_vector or calculated != float(row.environmental_score)
                or expected_score != calculated or float(row.base_score) != calculate_base_score(row.base_vector)):
            raise ValueError("Stale or inconsistent Environmental row")
        asset = assets.loc[assets.asset_id.eq(row.asset_id)].iloc[0]
        if any(row[k] != asset[k] for k in requirements):
            raise ValueError("Environmental requirements differ from inventory")
    joined = mapping.merge(master[["cve_id", "is_kev", "epss"]], on="cve_id", how="left", validate="many_to_one")
    joined = joined.merge(assets[["asset_id", "exposure"]], on="asset_id", how="left", validate="many_to_one")
    joined = joined.merge(environmental[PAIR + ["environmental_score"]], on=PAIR,
                           how="left", validate="one_to_one")
    rows = []
    exposure_weights = {"internet": 2, "internal": 1, "isolated": 0}
    for _, row in joined.iterrows():
        reasons = []
        if row.applicability == "unaffected":
            status, action = "not_applicable", "Retain evidence; reassess on deployment/version change."
            reasons.append("Unaffected: " + row.mapping_reason)
        else:
            if row.applicability != "affected":
                reasons.append("Applicability not established: " + row.mapping_reason)
            if row.exposure not in exposure_weights:
                reasons.append("Exposure client/unknown has no numeric rule; verify attack path.")
            for column in ("environmental_score", "epss", "is_kev"):
                if pd.isna(row[column]):
                    reasons.append("Missing " + column + "; not imputed.")
            status = "review_required" if reasons else "patch"
            action = ("Verify promptly: KEV present; establish version, attack path and missing signals."
                      if status == "review_required" and pd.notna(row.is_kev) and bool(row.is_kev) else
                      "Verify applicability, client attack path and missing signals before numeric ranking."
                      if status == "review_required" else
                      "Plan vendor patch; verify version, compatibility, backup/rollback and post-patch checks.")
            if not reasons:
                reasons.append(f"Affected under stated assumptions; KEV={row.is_kev}; exposure={row.exposure}; "
                               f"Environmental={row.environmental_score}; EPSS={row.epss}; policy={policy_version}.")
        rows.append(dict(cve_id=row.cve_id, asset_id=row.asset_id, applicability=row.applicability,
                         is_kev=row.is_kev, epss=row.epss, environmental_score=row.environmental_score,
                         exposure=row.exposure, queue_status=status, priority_rank=None,
                         priority_reason=" ".join(reasons), recommended_action=action,
                         policy_version=policy_version, context_version=context_version,
                         dataset_version=dataset_version))
    queue = pd.DataFrame(rows, columns=QUEUE_COLUMNS)
    queue["priority_rank"] = pd.array([pd.NA] * len(queue), dtype="Int64")
    patch = queue.loc[queue.queue_status.eq("patch")].copy()
    patch["exposure_weight"] = patch.exposure.map(exposure_weights)
    middle = (["environmental_score", "exposure_weight"] if policy_version.endswith("env-first")
              else ["exposure_weight", "environmental_score"])
    patch = patch.sort_values(["is_kev"] + middle + ["epss"] + PAIR,
                             ascending=[False] * 4 + [True, True])
    queue.loc[patch.index, "priority_rank"] = list(range(1, len(patch) + 1))
    return queue.sort_values(PAIR).reset_index(drop=True)


def compare_context(primary, sensitivity, environmental, *, ks=(1, 2)):
    ks = validate_k(ks)
    a = primary.loc[primary.queue_status.eq("patch")]
    b = sensitivity.loc[sensitivity.queue_status.eq("patch")]
    if set(map(tuple, a[PAIR].to_numpy())) != set(map(tuple, b[PAIR].to_numpy())):
        raise ValueError("Sensitivity must use identical eligible patch pairs")
    combined = a[PAIR + ["priority_rank", "dataset_version", "context_version"]].rename(columns={"priority_rank": "context_rank"})
    combined = combined.merge(b[PAIR + ["priority_rank"]].rename(columns={"priority_rank": "sensitivity_rank"}),
                              on=PAIR, validate="one_to_one")
    combined = combined.merge(environmental[PAIR + ["base_score", "environmental_score"]], on=PAIR, validate="one_to_one")
    if len(combined) != len(a):
        raise ValueError("Comparison cannot drop patch pairs missing Environmental")
    for column, rank_name in (("base_score", "base_rank"), ("environmental_score", "environmental_rank")):
        ordered = combined.sort_values([column] + PAIR, ascending=[False, True, True])
        combined[rank_name] = pd.Series(range(1, len(ordered) + 1), index=ordered.index)
    combined["rank_delta_base_environmental"] = combined.base_rank - combined.environmental_rank
    combined["rank_delta_context_sensitivity"] = combined.context_rank - combined.sensitivity_rank
    combined["primary_policy_version"] = "context-v1"
    combined["sensitivity_policy_version"] = "context-v1-env-first"
    m = len(combined)
    overlap = []
    for label, left, right in (("context_vs_env_first", "context_rank", "sensitivity_rank"),
                                ("base_vs_environmental", "base_rank", "environmental_rank")):
        for k in ks:
            valid = m >= 2 and k < m
            left_set = set(map(tuple, combined.loc[combined[left].le(k), PAIR].to_numpy()))
            right_set = set(map(tuple, combined.loc[combined[right].le(k), PAIR].to_numpy()))
            intersection, union = len(left_set & right_set), len(left_set | right_set)
            overlap.append(dict(comparison=label, k=k, m=m, intersection=intersection, union=union,
                                jaccard=intersection / union if valid else None,
                                reason=None if valid else "m_lt_2_or_k_at_least_m_no_discriminating_topk"))
    summary = dict(patch_pairs=m, identical_pair_set=True,
                   context_order_changed=bool(combined.rank_delta_context_sensitivity.ne(0).any()),
                   base_environmental_order_changed=bool(combined.rank_delta_base_environmental.ne(0).any()),
                   rank_delta_base_environmental="base_rank - environmental_rank; positive means Environmental earlier",
                   rank_delta_context_sensitivity="context_rank - sensitivity_rank; positive means env-first earlier",
                   topk=overlap)
    return combined.sort_values(PAIR).reset_index(drop=True), summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True, help="Reviewed mapping YAML")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    root = Path(__file__).resolve().parents[2]
    release = (root / config["release_folder"]).resolve()
    if args.output_dir.resolve() == release or release in args.output_dir.resolve().parents:
        raise ValueError("Cannot write into frozen release")
    meta_path = release / "metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    entry = meta["files"].get(args.master.name)
    if (args.master.resolve() != release / "cves.parquet" or entry is None
            or digest(args.master) != entry["sha256"] or args.master.stat().st_size != entry["bytes"]
            or meta["dataset_version"] != config["dataset_version"]):
        raise ValueError("Master must match frozen release metadata")
    dates = config["source_dates"]
    if any(meta.get(k) != v for k, v in dates.items()):
        raise ValueError("Source date mismatch")
    inventory = load_inventory(args.inventory)
    assets = pd.DataFrame([asdict(asset) for asset in inventory.assets])
    raw = yaml.safe_load(args.mapping.read_text(encoding="utf-8"))
    mapping = pd.DataFrame(raw["mappings"])
    version, context = config["dataset_version"], config["context_version"]
    extension_path = None
    if config.get("context_mapping_extension"):
        extension_path = root / config["context_mapping_extension"]
        extension = yaml.safe_load(extension_path.read_text(encoding="utf-8"))
        additions = []
        for entry in extension["mappings"]:
            additions.append(dict(asset_id="API-01", product="Discourse", assumed_version="2.8.13",
                                  evidence_read_at="2026-10-19", dataset_version=version,
                                  context_version=context,
                                  reviewer="Codex-assisted source review for N2; no independent human approval claimed",
                                  **entry))
        mapping = pd.concat([mapping, pd.DataFrame(additions)], ignore_index=True)
        raw["limitations"] = extension.get("limitations", []) + [
            "Five original affected pairs remain conditional on the hypothetical inventory.",
            "API-02 has unknown product/version; candidate does not establish PgHero installation."]
    # New artifact revision, while preserving historical evidence fields in r1 source.
    mapping["context_version"] = context
    mapping = validate_mapping(mapping, assets, version, context)
    master = pd.read_parquet(args.master)
    env, excluded = build_environmental(master, mapping, assets, dataset_version=version, context_version=context)
    queues = [build_queue(master, mapping, assets, env, dataset_version=version, context_version=context,
                          policy_version=policy) for policy in ("context-v1", "context-v1-env-first")]
    comparison, summary = compare_context(*queues, env, ks=config.get("context_sensitivity_k", [1, 2]))
    summary.update(dataset_version=version, context_version=context, inventory_version=inventory.inventory_version,
                   mapped_pairs=len(mapping), environmental_pairs=len(env), environmental_exclusions=excluded,
                   queue_counts=queues[0].queue_status.value_counts().to_dict(), source_dates=dates,
                   mapping_target=15, mapping_target_met=len(mapping) >= 15,
                   limitations=raw.get("limitations", []))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tables = {"cve_asset_mapping.csv": mapping.loc[:, list(MAP_COLUMNS)],
              "environmental_scores.csv": env, "priority_queue.csv": queues[0],
              "priority_queue_env_first.csv": queues[1], "context_comparison.csv": comparison}
    protected = {p.resolve() for p in (args.master, args.mapping, args.inventory, args.config, meta_path)}
    if any((args.output_dir / name).resolve() in protected for name in list(tables) + ["context_sensitivity.json", "context_metadata.json"]):
        raise ValueError("Output collision with input")
    for name, table in tables.items():
        table.to_csv(args.output_dir / name, index=False, encoding="utf-8", lineterminator="\n")
    summary_path = args.output_dir / "context_sensitivity.json"
    summary_path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    inputs = (args.master, args.mapping, args.inventory, args.config, meta_path)
    if extension_path is not None:
        inputs += (extension_path,)
    provenance = dict(schema_version="p3-context-artifacts-v1", dataset_version=version,
                      context_version=context, inventory_version=inventory.inventory_version,
                      policy_versions=["context-v1", "context-v1-env-first"], source_dates=dates,
                      created_at=datetime.now(timezone.utc).isoformat(), commit=git_output(root, "rev-parse", "HEAD"),
                      tracked_dirty=bool(git_output(root, "status", "--porcelain", "--untracked-files=no")),
                      command=[sys.executable, "-m", "src.analysis.context_priority",
                               *(sys.argv[1:] if argv is None else argv)],
                      python=sys.version,
                      packages={p: package_version(p) for p in ("pandas", "pyarrow", "PyYAML", "numpy", "scipy")},
                      inputs={str(p): file_record(p) for p in inputs},
                      code={name: file_record(root / name) for name in
                            ("src/analysis/context_priority.py", "src/environmental/cvss_environmental.py",
                             "src/environmental/cvss_base.py", "src/environmental/asset_inventory.py")},
                      outputs={name: file_record(args.output_dir / name, len(table)) for name, table in tables.items()},
                      metadata_self_hash="excluded; package manifest/ZIP hashes all metadata")
    provenance["outputs"][summary_path.name] = file_record(summary_path)
    (args.output_dir / "context_metadata.json").write_text(json.dumps(provenance, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
