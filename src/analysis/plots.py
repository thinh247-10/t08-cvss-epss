"""Export Phase 3 figures from frozen artifacts, without collection or ranking."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import textwrap
import zipfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "t08-matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import yaml
from src.analysis.ranking_metrics import git_output

POLICIES = ("cvss", "epss", "kev_first")
LABELS = {"cvss": "CVSS Base", "epss": "EPSS", "kev_first": "KEV-first"}
DATES = "EPSS 2026-09-29 | KEV released 2026-09-30; retrieved 2026-10-01 UTC"
PAIR = ["cve_id", "asset_id"]


def verify_record(path, record):
    actual = file_info(path)
    if not isinstance(record, dict) or any(record.get(k) != actual[k] for k in ("sha256", "bytes")):
        raise ValueError(f"Missing or mismatched checksum/bytes: {path}")
    return actual


def verify_received_archive(archive, folder, expected):
    """Check an externally recorded ZIP receipt and its exact extracted members."""
    record = verify_record(archive, expected)
    root = Path(folder).parent.resolve()
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError("N2 ZIP CRC failure")
        for member in bundle.infolist():
            if member.is_dir():
                continue
            target = (root / member.filename).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Unsafe archive member")
            if not target.is_file() or hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(bundle.read(member)).digest():
                raise ValueError(f"Received artifact differs from verified ZIP: {member.filename}")
    return record


def verify_handoff(root):
    """Verify the delivered package envelope, including both metadata files."""
    root = Path(root).resolve()
    path = root / "handoff_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "p3-n2-handoff-manifest-v1":
        raise ValueError("Unsupported N2 handoff schema")
    for name, record in manifest["files"].items():
        target = (root / name).resolve()
        if not target.is_relative_to(root):
            raise ValueError("Unsafe handoff path")
        verify_record(target, record)
    return manifest


def numeric_column(frame, column, upper=None, *, nullable=False, integer=False):
    values = frame[column]
    if pd.api.types.is_bool_dtype(values):
        raise ValueError(f"{column} must be numeric, not boolean")
    try:
        converted = pd.to_numeric(values, errors="raise")
    except (ValueError, TypeError):
        raise ValueError(f"Invalid numeric {column}") from None
    present = converted.dropna()
    if (not nullable and converted.isna().any()) or not np.isfinite(present).all():
        raise ValueError(f"Missing/nonfinite {column}")
    if (present < 0).any() or (upper is not None and (present > upper).any()):
        raise ValueError(f"{column} outside permitted range")
    if integer and not present.mod(1).eq(0).all():
        raise ValueError(f"{column} must be integer")
    return converted


def file_info(path):
    path = Path(path)
    return {"path": path.as_posix(), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def require(frame, columns, keys=()):
    missing = set(columns) - set(frame.columns)
    if not frame.columns.is_unique or missing:
        raise ValueError(f"Duplicate columns or missing columns: {sorted(missing)}")
    if keys and (frame[list(keys)].isna().any().any() or frame.duplicated(list(keys)).any()):
        raise ValueError(f"Missing or duplicate key: {list(keys)}")
    for key in keys:
        if frame[key].map(lambda value: not isinstance(value, str) or not value.strip()).any():
            # Numeric keys such as K are checked by their numeric validators.
            if key not in {"k"}:
                raise ValueError(f"Missing/blank key: {key}")
    if "cve_id" in keys and not frame.cve_id.str.fullmatch(r"CVE-\d{4}-\d{4,}").all():
        raise ValueError("Invalid CVE ID")


def validate_rankings(frame):
    cols = ["cve_id", "cvss_base_score", "epss", "is_kev", "dataset_version",
            "cohort_id", "policy_version", "epss_date"] + [p + "_rank" for p in POLICIES]
    require(frame, cols, ["cve_id"])
    if len(frame) < 2 or frame[cols].isna().any().any():
        raise ValueError("Ranking requires N>=2 and no missing values")
    if not frame.cve_id.str.fullmatch(r"CVE-\d{4}-\d{4,}").all():
        raise ValueError("Invalid CVE ID")
    for col, upper in (("cvss_base_score", 10), ("epss", 1)):
        if (not pd.api.types.is_numeric_dtype(frame[col]) or pd.api.types.is_bool_dtype(frame[col])
                or not frame[col].between(0, upper).all()):
            raise ValueError(f"Invalid {col}")
    if not pd.api.types.is_bool_dtype(frame.is_kev):
        raise ValueError("is_kev must be boolean, not strings or unknown")
    for col in ("dataset_version", "cohort_id", "policy_version", "epss_date"):
        if frame[col].nunique() != 1 or not str(frame[col].iloc[0]).strip():
            raise ValueError(f"Mixed/empty {col}")
    for p in POLICIES:
        if sorted(frame[p + "_rank"].tolist()) != list(range(1, len(frame) + 1)):
            raise ValueError(f"{p}_rank must contain positions 1..N exactly once")
    return frame.copy(deep=True)


def topk_table(frame, k=50):
    frame = validate_rankings(frame)
    if not isinstance(k, int) or not 0 < k < len(frame):
        raise ValueError("Selective top-K requires 0 < K < N")
    cols = ["cve_id", "cvss_base_score", "epss", "is_kev", "dataset_version",
            "cohort_id", "policy_version", "epss_date"]
    parts = []
    for policy in POLICIES:
        selected = frame.loc[frame[policy + "_rank"].le(k), cols + [policy + "_rank"]].copy()
        selected = selected.rename(columns={policy + "_rank": "rank"}).sort_values("rank")
        selected.insert(0, "policy", policy)
        parts.append(selected)
    return pd.concat(parts, ignore_index=True)[["policy", "rank"] + cols]


def save_figure(fig, folder, name, dpi=160):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for suffix in ("png", "svg"):
        path = folder / f"{name}.{suffix}"
        fig.savefig(path, dpi=dpi, bbox_inches="tight", facecolor="white")
        paths.append(path)
    plt.close(fig)
    return paths


def scatter_figure(frame, config):
    frame = validate_rankings(frame)
    fig, ax = plt.subplots(figsize=config["sizes"]["scatter"])
    regular, kev = frame.loc[~frame.is_kev], frame.loc[frame.is_kev]
    ax.scatter(regular.cvss_base_score, regular.epss, s=23, alpha=.48,
               color=config["colors"]["regular"], label=f"Not in KEV ({len(regular)})", clip_on=False)
    ax.scatter(kev.cvss_base_score, kev.epss, s=120, marker="D", edgecolor="black",
               color=config["colors"]["kev"], label=f"KEV ({len(kev)})", zorder=5, clip_on=False)
    for row in kev.itertuples():
        near_top = row.epss > .9
        ax.annotate(row.cve_id, (row.cvss_base_score, row.epss),
                    xytext=(-8, -15 if near_top else 8), textcoords="offset points",
                    ha="right", va="top" if near_top else "bottom", fontsize=8,
                    bbox={"facecolor": "white", "edgecolor": "none", "alpha": .85, "pad": 1})
    ax.axvline(config["thresholds"]["cvss"], color="#666666", ls="--", lw=.8)
    ax.axhline(config["thresholds"]["epss"], color="#666666", ls="--", lw=.8)
    ax.set(xlim=(0, 10), ylim=(0, 1), xlabel="Observed CVSS v3.1 Base (0–10)",
           ylabel="EPSS probability (0–1)", title=f"Observed severity and EPSS | N={len(frame)} CVEs")
    ax.set_title(f"Observed severity and EPSS | N={len(frame)} CVEs", pad=18)
    ax.legend(loc="upper left")
    ax.grid(alpha=.15)
    fig.text(.5, -.01, DATES + "\nIllustrative thresholds; coincident CVEs can overlap.", ha="center", fontsize=8)
    fig.tight_layout()
    return fig


def top50_figure(table, page, config):
    if page not in (1, 2):
        raise ValueError("Top-50 page must be 1 or 2")
    start, end = (1, 25) if page == 1 else (26, 50)
    fig, axes = plt.subplots(1, 3, figsize=config["sizes"]["top50"])
    for ax, policy in zip(axes, POLICIES):
        rows = table.loc[table.policy.eq(policy) & table["rank"].between(start, end)]
        ax.set(xlim=(0, 1), ylim=(end + 1, start - 1))
        ax.axis("off")
        ax.set_title(LABELS[policy], fontsize=14, pad=18)
        for row in rows.itertuples():
            if row.rank % 2 == 0:
                ax.axhspan(row.rank - .46, row.rank + .46, color="#f0f3f6", zorder=0)
            ax.text(.01, row.rank, f"{row.rank:02d}", va="center", color="#525d6b", fontsize=10)
            ax.text(.12, row.rank, row.cve_id, va="center", fontsize=10, family="DejaVu Sans Mono")
            if row.is_kev:
                ax.text(.99, row.rank, "KEV", ha="right", va="center", fontsize=8, color="white",
                        bbox={"facecolor": config["colors"]["kev"], "edgecolor": "none", "pad": 2})
    fig.suptitle(f"Top 50 observed CVEs | positions {start}–{end}", fontsize=17, y=.99)
    fig.text(.5, .015, DATES + "\nPositions from the full ranking; KEV-first is a policy, not a score.", ha="center", fontsize=8)
    fig.subplots_adjust(top=.92, bottom=.075, wspace=.17)
    return fig


def recall_table(frame):
    require(frame, ["policy", "k", "n", "kev_total", "kev_hits", "kev_recall"], ["policy", "k"])
    selected = frame.loc[frame.policy.isin(["cvss", "epss"])].copy(deep=True)
    if selected.empty:
        raise ValueError("No CVSS/EPSS recall rows")
    for column in ("n", "k", "kev_total", "kev_hits"):
        selected[column] = numeric_column(selected, column, integer=True)
    selected["kev_recall"] = numeric_column(selected, "kev_recall", 1, nullable=True)
    if (selected.k.le(0) | selected.k.ge(selected.n)).any():
        raise ValueError("Recall plot requires 0 < K < N")
    if (selected.kev_total.gt(selected.n) | selected.kev_hits.gt(selected.kev_total)
            | selected.kev_hits.gt(selected.k)).any():
        raise ValueError("Invalid KEV count/denominator")
    if (selected.kev_total.eq(0) & selected.kev_recall.notna()).any():
        raise ValueError("No KEV denominator: recall must remain N/A")
    if "undefined_reason" not in selected:
        selected["undefined_reason"] = selected.get("kev_recall_reason", "")
    nulls = selected.kev_recall.isna()
    missing_reason = selected.undefined_reason.fillna("").astype(str).str.strip().eq("")
    selected.loc[nulls & selected.kev_total.eq(0) & missing_reason, "undefined_reason"] = "No KEV in cohort"
    if (nulls & selected.undefined_reason.fillna("").astype(str).str.strip().eq("")).any():
        raise ValueError("Null recall requires undefined_reason")
    if not selected.loc[~nulls, "kev_recall"].between(0, 1).all():
        raise ValueError("Recall outside [0,1]")
    defined = ~nulls
    if not np.allclose(selected.loc[defined, "kev_recall"],
                       selected.loc[defined, "kev_hits"] / selected.loc[defined, "kev_total"]):
        raise ValueError("Supplied recall disagrees with hits/KEV denominator")
    selected["display"] = [f"N/A: {r.undefined_reason}" if pd.isna(r.kev_recall)
                           else f"{int(r.kev_hits)}/{int(r.kev_total)} ({r.kev_recall:.1%})"
                           for r in selected.itertuples()]
    return selected


def context_table(comparison, scores, columns):
    keys = ["cve_id", "asset_id"]
    require(comparison, keys + list(columns.values()), keys)
    require(scores, keys + ["base_score", "environmental_score"], keys)
    comparison = comparison.rename(columns={v: k for k, v in columns.items()}).copy()
    scores = scores.copy(deep=True)
    for column in ("base_score", "environmental_score"):
        scores[column] = numeric_column(scores, column, 10, nullable=True)
        comparison[column] = numeric_column(comparison, column, 10, nullable=True)
    complete = scores.dropna(subset=["base_score", "environmental_score"])
    # Caller supplies the producer's declared cohort (C/D: complete patch pairs).
    if set(map(tuple, comparison[keys].to_numpy())) != set(map(tuple, complete[keys].to_numpy())):
        raise ValueError("Context comparison must use the same complete CVE/asset pairs")
    joined = comparison.merge(complete, on=keys, validate="one_to_one", suffixes=("", "_source"))
    for col in ("base_score", "environmental_score"):
        if not np.allclose(joined[col], joined[col + "_source"], equal_nan=False):
            raise ValueError(f"Context {col} mismatch")
    for col in ("base_rank", "environmental_rank"):
        joined[col] = numeric_column(joined, col, nullable=len(joined) < 2, integer=True)
        if len(joined) >= 2 and sorted(joined[col]) != list(range(1, len(joined) + 1)):
            raise ValueError(f"Invalid context {col}")
    return joined


def queue_tables(queue, *, policy_version="context-v1"):
    """Validate supplied decisions; never derive status or sort priority ourselves."""
    columns = PAIR + ["applicability", "is_kev", "epss", "environmental_score", "exposure",
                      "queue_status", "priority_rank", "priority_reason", "recommended_action",
                      "dataset_version", "context_version", "policy_version"]
    require(queue, columns, PAIR)
    frame = queue.copy(deep=True)
    allowed = ("patch", "review_required", "not_applicable")
    if not frame.queue_status.isin(allowed).all():
        raise ValueError("Unknown/missing queue_status")
    if not frame.policy_version.eq(policy_version).all():
        raise ValueError("Queue policy_version mismatch")
    for column in ("priority_reason", "recommended_action"):
        if frame[column].fillna("").astype(str).str.strip().eq("").any():
            raise ValueError(f"Missing queue {column}")
    for column, upper in (("epss", 1), ("environmental_score", 10)):
        frame[column] = numeric_column(frame, column, upper, nullable=True)
    frame["priority_rank"] = numeric_column(frame, "priority_rank", nullable=True, integer=True)
    if not frame.is_kev.dropna().map(lambda v: isinstance(v, (bool, np.bool_))).all():
        raise ValueError("Queue is_kev must be boolean or unknown")
    patch = frame.queue_status.eq("patch")
    if frame.loc[~patch, "priority_rank"].notna().any():
        raise ValueError("Review/not_applicable must keep priority_rank null")
    if sorted(frame.loc[patch, "priority_rank"].dropna()) != list(range(1, int(patch.sum()) + 1)):
        raise ValueError("Patch ranks must be a complete 1..M permutation")
    if (~frame.loc[patch, "applicability"].eq("affected")).any():
        raise ValueError("Patch row must be affected")
    if frame.loc[patch, ["is_kev", "epss", "environmental_score"]].isna().any().any():
        raise ValueError("Patch row has missing signals")
    if not frame.loc[patch, "exposure"].isin(["internet", "internal", "isolated"]).all():
        raise ValueError("Client/unknown exposure must remain review_required")
    if (frame.applicability.eq("unaffected") != frame.queue_status.eq("not_applicable")).any():
        raise ValueError("Unaffected rows must remain not_applicable")
    unknown = ~frame.applicability.isin(["affected", "unaffected"])
    client_or_unknown = ~frame.exposure.isin(["internet", "internal", "isolated"])
    review_needed = unknown | (frame.applicability.eq("affected") & client_or_unknown)
    if not frame.loc[review_needed, "queue_status"].eq("review_required").all():
        raise ValueError("Client/unknown rows must remain review_required")
    counts = frame.groupby("queue_status").size().reindex(allowed, fill_value=0).rename("pairs").reset_index()
    return {"queue_source.csv": frame, "queue_status_counts.csv": counts,
            "queue_review.csv": frame.loc[frame.queue_status.eq("review_required")].copy()}


def context_figure(frame, config):
    if len(frame) < 2:
        return None
    frame = frame.sort_values("base_rank")
    fig, ax = plt.subplots(figsize=(config["sizes"].get("context_width", 12), max(4.5, .36 * len(frame))))
    positions = np.arange(len(frame))
    ax.hlines(positions, frame.base_rank, frame.environmental_rank, color="#a0a8b0", lw=2)
    ax.scatter(frame.base_rank, positions, facecolors="none", edgecolors="#246b94", s=90, label="Base rank", zorder=3)
    ax.scatter(frame.environmental_rank, positions, marker="D", color="#b44224", s=25, label="Environmental rank", zorder=4)
    ax.set_yticks(positions, frame.cve_id + " / " + frame.asset_id, fontsize=9)
    ax.invert_yaxis()
    ax.set(xlabel="Supplied severity rank (1 = highest)", xlim=(.5, len(frame)+.5),
           title=f"Base → Environmental | {len(frame)} identical CVE/asset pairs")
    ax.xaxis.get_major_locator().set_params(integer=True)
    fig.legend(*ax.get_legend_handles_labels(), loc="lower center", bbox_to_anchor=(.5, .07), ncol=2)
    fig.text(.5, .01, "Severity comparison only; action queue and client review are reported separately.", ha="center", fontsize=8)
    fig.tight_layout(rect=(0, .21, 1, 1))
    return fig


def read_context(folder, contract, schema, config):
    """Read C/D: compare complete patch pairs, retain every mapping/queue pair."""
    folder, contract = Path(folder), Path(contract)
    names = ["environmental_scores.csv", "context_comparison.csv", "priority_queue.csv"]
    metadata_path = folder / "context_metadata.json"
    for path in [metadata_path, contract, folder / "cve_asset_mapping.csv"] + [folder / n for n in names]:
        if not path.is_file():
            raise FileNotFoundError(f"Required context input missing: {path}")
    if not schema or schema == "p3-ranking-metrics-v1":
        raise ValueError("A supplemental N2 context schema is required; A+B does not define context")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = {"schema_version": schema, "dataset_version": config["expected"]["dataset_version"],
                "context_version": config["context"]["version"]}
    for column, value in expected.items():
        if metadata.get(column) != value:
            raise ValueError(f"Context {column} mismatch")
    inputs = [file_info(metadata_path), file_info(contract)]
    handoff_path = folder.parent / "handoff_manifest.json"
    if handoff_path.is_file():
        handoff = verify_handoff(folder.parent)
        for column in ("dataset_version", "context_version"):
            if handoff.get(column) != expected[column]:
                raise ValueError(f"Handoff {column} mismatch")
        if contract.resolve() != (folder.parent / "docs/phase-3-artifact-contract.md").resolve():
            raise ValueError("Context contract must be the verified package contract")
        for name in ["p3_n2/context_metadata.json", "docs/phase-3-artifact-contract.md"]:
            verify_record(folder.parent / name, handoff["files"].get(name))
        inputs.append(file_info(handoff_path))
    # Require manifest coverage of every artifact we consume, not just listed entries.
    for name in names + ["cve_asset_mapping.csv"]:
        inputs.append(verify_record(folder / name, metadata.get("outputs", {}).get(name)))
    scores, comparison, queue = [pd.read_csv(folder / n) for n in names]
    mapping = pd.read_csv(folder / "cve_asset_mapping.csv")
    for name, frame in zip(names + ["cve_asset_mapping.csv"], (scores, comparison, queue, mapping)):
        require(frame, PAIR + ["dataset_version", "context_version"], PAIR)
        if metadata["outputs"][name].get("rows", len(frame)) != len(frame):
            raise ValueError(f"Context row count mismatch: {name}")
        for column in ("dataset_version", "context_version"):
            if not frame[column].eq(expected[column]).all():
                raise ValueError(f"Mixed/wrong context {column}")
    require(scores, ["base_vector", "environmental_vector", "CR", "IR", "AR",
                     "modification_reason", "score_source"])
    if not scores.score_source.eq("observed").all():
        raise ValueError("Context must use observed scores, not predictions")
    tables = queue_tables(queue, policy_version=config["context"]["queue_policy_version"])
    require(mapping, ["applicability"])
    queue_keys = set(map(tuple, queue[PAIR].to_numpy()))
    if queue_keys != set(map(tuple, mapping[PAIR].to_numpy())):
        raise ValueError("Queue must preserve every mapping pair exactly once")
    mapping_check = mapping[PAIR + ["applicability"]].merge(queue[PAIR + ["applicability"]],
        on=PAIR, validate="one_to_one", suffixes=("_mapping", "_queue"))
    if not mapping_check.applicability_mapping.eq(mapping_check.applicability_queue).all():
        raise ValueError("Mapping/queue applicability mismatch")
    if not set(map(tuple, scores[PAIR].to_numpy())).issubset(queue_keys):
        raise ValueError("Scored CVE/asset pair disappeared from queue")
    # Check common signals by pair, preserving missing values instead of imputing.
    check = scores[PAIR + ["environmental_score"]].merge(queue[PAIR + ["environmental_score"]],
        on=PAIR, validate="one_to_one", suffixes=("_score", "_queue"))
    if not np.allclose(check.environmental_score_score, check.environmental_score_queue, equal_nan=True):
        raise ValueError("Queue/Environmental score mismatch for same CVE/asset")
    score_queue = scores.merge(queue[PAIR + ["queue_status"]], on=PAIR, validate="one_to_one")
    eligible = score_queue.loc[score_queue.queue_status.eq("patch")].drop(columns="queue_status")
    paired = context_table(comparison, eligible, config["context_columns"])
    excluded = score_queue.loc[~score_queue.queue_status.eq("patch") |
                              score_queue[["base_score", "environmental_score"]].isna().any(axis=1)].copy()
    excluded["plot_exclusion_reason"] = np.where(excluded.queue_status.ne("patch"),
        "outside N2 patch comparison population; retained in queue", "missing Base or Environmental")
    # Keep queue-only pairs (e.g. unknown applicability) alongside scored exclusions.
    missing_scores = queue.loc[~pd.MultiIndex.from_frame(queue[PAIR]).isin(pd.MultiIndex.from_frame(scores[PAIR]))].copy()
    missing_scores["plot_exclusion_reason"] = "no Environmental score row; retained in queue"
    excluded = pd.concat([excluded, missing_scores], ignore_index=True, sort=False)
    tables.update({"context_plot.csv": paired, "context_excluded.csv": excluded,
                   "environmental_source.csv": scores})
    summary = {"schema_version": schema, "context_version": expected["context_version"],
        "queue_policy_version": config["context"]["queue_policy_version"], "unit": "CVE/asset pair",
        "score_rows": len(scores), "complete_pairs": len(paired),
        "excluded_score_rows": len(scores) - len(paired), "excluded_mapping_pairs": len(excluded),
        "population": "N2 patch pairs with complete Base and Environmental scores",
        "mapping_rows": len(mapping),
        "queue_rows": len(queue), "queue_without_score_rows": len(queue_keys - set(map(tuple, scores[PAIR].to_numpy()))),
        "client_review_pairs": int(((queue.exposure == "client") & (queue.queue_status == "review_required")).sum()),
        "figure_status": "ready" if len(paired) >= 2 else "insufficient_data",
        "undefined_reason": None if len(paired) >= 2 else "N<2 complete pairs; no rank-change line drawn",
        "mapping_completeness": "verified: all mapping pairs retained in queue",
        "producer_commit": metadata.get("commit"), "source_dates": metadata.get("source_dates"),
        "adapter_status": "validated_against_explicit_supplemental_schema_and_versions"}
    figure = context_figure(paired, config)
    return figure, tables, summary, inputs


def queue_status_figure(tables, summary, config):
    """Show supplied decisions and retain review counts without deriving a policy."""
    counts = tables["queue_status_counts.csv"]
    fig, ax = plt.subplots(figsize=config["sizes"]["metrics"])
    bars = ax.bar(counts.queue_status, counts.pairs, color=["#246b94", "#b44224", "#8a9199"])
    ax.bar_label(bars, padding=5)
    ax.set(ylim=(0, max(1, counts.pairs.max()) * 1.25), ylabel="CVE/asset pairs",
           title=f"Supplied action queue | {summary['queue_rows']} pairs")
    ax.yaxis.get_major_locator().set_params(integer=True)
    fig.text(.5, .015, f"Client review retained: {summary['client_review_pairs']} pairs. "
             "Null priority_rank remains N/A; this is not a severity ranking.", ha="center", fontsize=8)
    fig.tight_layout(rect=(0, .07, 1, 1))
    return fig


def protect_outputs(args, config=None):
    """Reject all destinations inside producer packages before any output write."""
    protected = {args.rankings.resolve(), args.config.resolve()}
    if config and config.get("n2_archive"):
        protected.add(Path(config["n2_archive"]["path"]).resolve())
    roots = []
    if args.n2_dir:
        roots.append(args.n2_dir.parent.resolve())
    if args.context_dir:
        roots.append(args.context_dir.parent.resolve())
    if args.context_contract:
        protected.add(args.context_contract.resolve())
    if args.context_archive:
        protected.add(args.context_archive.resolve())
    for path in (args.report, args.output_dir, args.tables_dir):
        resolved = path.resolve()
        if resolved in protected or any(resolved.is_relative_to(root) for root in roots):
            raise ValueError(f"Output must not overwrite N2/input files: {path}")
    names = ("top50_long.csv", "scatter_source.csv", "figures_manifest.json", "kev_recall_plot.csv",
             "overlap_plot.csv", "context_plot.csv", "context_excluded.csv", "queue_source.csv",
             "queue_status_counts.csv", "queue_review.csv", "environmental_source.csv")
    figures = ("cvss_epss_scatter", "top50_three_policies_p1", "top50_three_policies_p2",
               "topk_overlap", "kev_recall_at_k", "context_rank_changes", "priority_queue_status")
    destinations = [args.tables_dir / name for name in names]
    destinations += [args.output_dir / (name + suffix) for name in figures for suffix in (".png", ".svg")]
    if any(path.resolve() in protected for path in destinations):
        raise ValueError("Output must not overwrite ranking input, config or contract")


def write_captions(args, cfg, frame, inputs, pending, n2_metrics, context_summary, tables):
    expected = cfg["expected"]
    lines = ["# Phase 3 — N3 figure captions", "", f"Run status: {'partial' if pending else 'complete'}; "
             f"N={len(frame)} CVEs; KEV={int(frame.is_kev.sum())}; K=10/20/50 for metrics, K=50 for top lists.",
             "", DATES + ".", "", "Dataset/cohort/policy: " + " / ".join(str(expected[k]) for k in
             ("dataset_version", "cohort_id", "policy_version")) + ".",
             "", "Observed CVSS only. Ranks, overlaps, recall and context decisions are read from N2 artifacts. "
             "No policy is recalculated; ID is only the producer's tie-break.",
             "", "CVSS: Base descending → ID ascending. EPSS: probability descending → ID ascending. "
             "KEV-first: KEV descending → EPSS descending → Base descending → ID ascending.",
             "", f"Illustrative thresholds CVSS≥{cfg['thresholds']['cvss']} / EPSS≥{cfg['thresholds']['epss']}; "
             f"status={cfg['thresholds']['status']}. {cfg['thresholds']['reason']}",
             "", "Three KEVs are a small denominator. These are snapshot comparisons, not evidence of future "
             "prediction accuracy. Absence from KEV does not prove no exploitation.",
             "", "| Figure (PNG + SVG) | Caption |", "|---|---|",
             f"| cvss_epss_scatter | N={len(frame)} CVEs, K=N/A. Observed Base 0–10 versus EPSS probability 0–1; "
             f"KEV diamonds={int(frame.is_kev.sum())}. Coincident points can overlap; every ID/zero retained in scatter_source.csv. |",
             "| top50_three_policies_p1 | K=50 per policy, positions 1–25 from the full supplied ranks; KEV badges follow source booleans. |",
             "| top50_three_policies_p2 | Same N/K, positions 26–50. No KEV-first score is invented. Exact rows: top50_long.csv. |"]
    if n2_metrics is not None:
        lines += ["| topk_overlap | N=396 CVEs, K=10/20/50; supplied Jaccard in [0,1] from overlap.csv. "
                  "CVSS/EPSS and CVSS/KEV-first coincide; differing markers/styles expose both. "
                  "EPSS/KEV-first set overlap=1 does not establish identical order. |",
                  "| kev_recall_at_k | N=396, denominator=3 KEV; CVSS/EPSS only, K=10/20/50. "
                  "Supplied hits/denominator and rate; null is N/A with reason and has no marker at a numeric value. "
                  "KEV-first recall stays null in source and is excluded from this figure. |",
                  "", "N2 Kendall tau-b on raw CVSS/EPSS scores (ties retained), copied without recomputing: `" +
                  json.dumps(n2_metrics["kendall_tau_b"], ensure_ascii=False, allow_nan=False) + "`.",
                  "", "CVSS cutoff at K=10/20 spans 28 tied CVEs; 10/20 chosen by N2's ID tie-break. "
                  "See the verified topk_metrics.csv; thresholds do not alter this choice."]
    lines += ["", "## Context severity and action queue", ""]
    if context_summary["figure_status"] == "pending_inputs":
        lines += ["**Pending real N2 context inputs.** The received p3-ranking-metrics-v1 contract explicitly "
                  "excludes Environmental/queue. No context figure/count is inferred from Phase 1 or synthetic tests.",
                  "", "Required: supplemental contract/schema, environmental_scores.csv, context_comparison.csv, "
                  "priority_queue.csv and checksummed metadata. Client review count is N/A until those rows arrive."]
    else:
        lines += [f"Unit=CVE/asset pair; context={context_summary['context_version']}; "
                  f"queue policy={context_summary['queue_policy_version']}. "
                  f"Complete identical pairs={context_summary['complete_pairs']}; "
                  f"comparison population={context_summary['population']}; "
                  f"scored pairs outside comparison={context_summary['excluded_score_rows']}; "
                  f"all mapping pairs outside comparison={context_summary['excluded_mapping_pairs']} "
                  "(retained with reasons in context_excluded.csv).",
                  "", "Base→Environmental severity ranks and patch/review decisions are different views. "
                  "No ranks are derived from queue position, and no missing value is converted to zero."]
        if context_summary["figure_status"] == "ready":
            lines += ["", "`context_rank_changes.png/.svg`: supplied Base→Environmental rank on the exact same "
                      "complete patch CVE/asset pairs declared by N2; labels identify both keys. "
                      "Rank 1 is highest severity. Both axes use the same population; client review is outside both. "
                      "Base/Environmental ties follow score descending → CVE/asset ascending, as supplied by N2."]
        else:
            lines += ["", "Context severity figure: N/A — " + context_summary["undefined_reason"] + "."]
        lines += ["", "`priority_queue_status.png/.svg`: counts of supplied patch/review_required/not_applicable "
                  "decisions, without rerunning the action policy.", "", "| Queue status | Pairs |", "|---|---:|"]
        lines += [f"| {row.queue_status} | {row.pairs} |" for row in tables["queue_status_counts.csv"].itertuples()]
        lines += ["", "Client/unknown review rows retain null priority_rank=N/A, plus the producer's reason/action.",
                  "", "| CVE | Asset | Exposure | Rank | Supplied review reason | Supplied action |", "|---|---|---|---|---|---|"]
        for row in tables["queue_review.csv"].itertuples():
            reason = str(row.priority_reason).replace("|", "\\|").replace("\n", " ")
            action = str(row.recommended_action).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {row.cve_id} | {row.asset_id} | {row.exposure} | N/A | {reason} | {action} |")
        lines += ["", f"Source version is {context_summary['context_version']} from the supplied package; "
                  "it is not automatically replaced by newer revisions on N2's branch. "
                  "Queue counts include every mapping pair; the Environmental table retains all scored client pairs. "
                  "Plot completion is not completion of the independent Environmental crosscheck or all Phase 3 tasks."]
    lines += ["", "## Input integrity", "", "| Input | Bytes | SHA-256 |", "|---|---:|---|"]
    lines += [f"| {item['path']} | {item['bytes']} | `{item['sha256']}` |" for item in inputs]
    lines += ["", f"Output hashes/bytes and exact command: `{(args.tables_dir / 'figures_manifest.json').as_posix()}`.",
              "", "Only the files listed in this run's manifest are certified. "
              "Synthetic fixture outputs are confined to temporary test directories.", "", "Pending:"]
    lines += [f"- {item}" for item in pending] or ["- None for the supplied artifact scope."]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def metric_figures(overlap, metrics, config):
    require(overlap, ["policy_a", "policy_b", "k", "jaccard"], ["policy_a", "policy_b", "k"])
    overlap = overlap.copy(deep=True)
    overlap["jaccard"] = numeric_column(overlap, "jaccard", 1, nullable=True)
    overlap["k"] = numeric_column(overlap, "k", integer=True)
    if not overlap.policy_a.isin(POLICIES).all() or not overlap.policy_b.isin(POLICIES).all():
        raise ValueError("Unknown overlap policy")
    missing = overlap.jaccard.isna()
    reasons = overlap.get("undefined_reason", overlap.get("jaccard_reason", pd.Series("", index=overlap.index)))
    if (missing & reasons.fillna("").astype(str).str.strip().eq("")).any():
        raise ValueError("Null Jaccard requires undefined_reason")
    fig, ax = plt.subplots(figsize=config["sizes"]["metrics"])
    for index, ((a, b), group) in enumerate(overlap.groupby(["policy_a", "policy_b"])):
        group = group.sort_values("k")
        ax.plot(group.k, group.jaccard, marker=("o", "x", "s")[index % 3],
                linestyle=("-", "--", ":")[index % 3], markersize=8,
                label=f"{LABELS[a]} / {LABELS[b]}")
        for row in group.loc[group.jaccard.isna()].itertuples():
            ax.annotate(f"N/A: {reasons.loc[row.Index]}", (row.k, .08 + .10 * index),
                        xycoords=("data", "axes fraction"), ha="center", fontsize=8)
    ax.set(ylim=(0, 1.05), xlabel="K (CVEs)", ylabel="Jaccard", title="Top-K overlap (N2 artifact)")
    ax.set_xticks(sorted(overlap.k.unique()))
    ax.legend()
    fig.tight_layout()
    recall = recall_table(metrics)
    fig2, ax2 = plt.subplots(figsize=config["sizes"]["metrics"])
    for policy, group in recall.groupby("policy"):
        group = group.sort_values("k")
        ax2.plot(group.k, group.kev_recall, marker="o", label=LABELS[policy])
        for row in group.itertuples():
            if pd.isna(row.kev_recall):
                ax2.annotate(row.display, (row.k, .12 if policy == "cvss" else .25),
                             xycoords=("data", "axes fraction"), ha="center", fontsize=8)
            else:
                ax2.annotate(row.display, (row.k, row.kev_recall),
                             xytext=(0, 10 if policy == "cvss" else -18),
                             textcoords="offset points", ha="center", fontsize=8)
    ax2.set(ylim=(-.1, 1.15), xlabel="K (CVEs)", ylabel="KEV Recall@K", title="Observed KEV coverage | CVSS / EPSS only")
    ax2.set_xticks(sorted(recall.k.unique()))
    ax2.legend()
    fig2.tight_layout()
    return [("topk_overlap", fig), ("kev_recall_at_k", fig2)], recall


def read_n2(folder, frame, config):
    """Consume the received p3-ranking-metrics-v1 contract, fail on hash/schema drift."""
    folder = Path(folder)
    packaged = (folder.parent / "handoff_manifest.json").is_file()
    handoff = verify_handoff(folder.parent) if packaged else None
    contract = folder.parent / ("docs/phase-3-artifact-contract.md" if packaged else "phase-3-artifact-contract.md")
    source_config = folder.parent / ("config/phase3.yaml" if packaged else "phase3.yaml")
    names = ["metadata.json", "rankings.csv", "ranking_metrics.json", "topk_metrics.csv", "overlap.csv", "rank_deltas.csv"]
    for path in [folder / n for n in names] + [contract, source_config]:
        if not path.is_file():
            raise FileNotFoundError(f"Required N2 input missing: {path}")
    metadata = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
    metrics = json.loads((folder / "ranking_metrics.json").read_text(encoding="utf-8"))
    n2config = yaml.safe_load(source_config.read_text(encoding="utf-8"))
    receipt = None if packaged else config.get("n2_archive")
    if receipt:
        verify_received_archive(receipt["path"], folder, receipt)
    if metadata["schema_version"] != "p3-ranking-metrics-v1" or metrics["schema_version"] != metadata["schema_version"]:
        raise ValueError("Unsupported N2 schema; consult final contract")
    for key in ("dataset_version", "cohort_id", "policy_version"):
        if metadata[key] != frame[key].iloc[0] or metrics[key] != metadata[key]:
            raise ValueError(f"N2 {key} mismatch")
    if metadata["n"] != len(frame) or metadata["total_kev"] != int(frame.is_kev.sum()):
        raise ValueError("N2 cohort count mismatch")
    # Every consumed file must be covered, even if an entry was removed from metadata.
    for name in names[2:]:
        if name not in metadata.get("outputs", {}):
            raise ValueError(f"Required N2 manifest checksum missing: {name}")
    paths = {name: folder / name for name in metadata["outputs"]}
    paths.update({"rankings.csv": folder / "rankings.csv"})
    config_entry = handoff["files"].get("config/phase3.yaml") if packaged else metadata["inputs"].get("phase3.yaml")
    verify_record(source_config, config_entry)
    for name, path in paths.items():
        if path.parent.resolve() not in (folder.resolve(), folder.parent.resolve()):
            raise ValueError("Unsafe N2 manifest path")
        entry = metadata["outputs"].get(name, metadata["inputs"].get(name))
        actual = file_info(path)
        if any(entry[k] != actual[k] for k in ("bytes", "sha256")):
            raise ValueError(f"N2 checksum/bytes mismatch: {name}")
    pd.testing.assert_frame_equal(validate_rankings(pd.read_csv(folder / "rankings.csv")).sort_values("cve_id").reset_index(drop=True),
                                  frame.sort_values("cve_id").reset_index(drop=True))
    if n2config["illustrative_thresholds"] != {k: config["thresholds"][k] for k in ("cvss", "epss")}:
        raise ValueError("Plot thresholds differ from locked N2 config")
    for key in ("schema_version", "dataset_version", "cohort_id", "policy_version", "context_version"):
        if n2config.get(key) != metadata.get(key):
            raise ValueError(f"N2 config/metadata {key} mismatch")
    if metrics.get("source_dates") != metadata.get("source_dates") or n2config.get("source_dates") != metadata.get("source_dates"):
        raise ValueError("N2 source dates mismatch")
    overlap = pd.read_csv(folder / "overlap.csv")
    topk = pd.read_csv(folder / "topk_metrics.csv")
    expected_topk = {(p, k) for p in POLICIES for k in n2config["k"]}
    if set(zip(topk.policy, topk.k)) != expected_topk or len(topk) != len(expected_topk):
        raise ValueError("N2 missing/duplicate top-K policy rows")
    expected_pairs = {(a, b, k) for i, a in enumerate(POLICIES) for b in POLICIES[i+1:] for k in n2config["k"]}
    if set(zip(overlap.policy_a, overlap.policy_b, overlap.k)) != expected_pairs or len(overlap) != len(expected_pairs):
        raise ValueError("N2 missing/duplicate overlap rows")
    if not topk.n.eq(len(frame)).all() or not topk.kev_total.eq(int(frame.is_kev.sum())).all():
        raise ValueError("N2 topk denominators mismatch")
    if not pd.api.types.is_bool_dtype(topk.selection_is_discriminating) or not topk.selection_is_discriminating.all():
        raise ValueError("Nonselective K must not be plotted as selective ranking")
    more, recall = metric_figures(overlap, topk, config)
    inputs = [file_info(folder / n) for n in names] + [file_info(contract), file_info(source_config)]
    if packaged:
        for name in ("docs/phase-3-artifact-contract.md", "p3_n2/metadata.json"):
            verify_record(folder.parent / name, handoff["files"].get(name))
        inputs.append(file_info(folder.parent / "handoff_manifest.json"))
    if receipt:
        inputs.append(file_info(receipt["path"]))
    return more, recall, metrics, inputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rankings", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tables-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("config/phase3_plots.yaml"))
    parser.add_argument("--report", type=Path, default=Path("reports/p3_figures.md"))
    parser.add_argument("--n2-dir", type=Path, help="Received p3_n2 folder; requires sibling contract and phase3.yaml")
    parser.add_argument("--context-dir", type=Path, help="Received supplemental N2 context folder")
    parser.add_argument("--context-contract", type=Path, help="Explicit supplemental contract, never the A+B contract")
    parser.add_argument("--context-schema", help="Reviewed exact schema_version from supplemental contract")
    parser.add_argument("--context-version", help="Reviewed context_version; defaults to N3 plot config")
    parser.add_argument("--queue-policy-version", help="Exact supplied queue policy_version")
    parser.add_argument("--context-archive", type=Path, help="Optional received ZIP with external receipt below")
    parser.add_argument("--context-archive-sha256")
    parser.add_argument("--context-archive-bytes", type=int)
    args = parser.parse_args(argv)
    context_requested = any((args.context_dir, args.context_contract, args.context_schema,
                             args.context_version, args.queue_policy_version))
    if context_requested and not all((args.context_dir, args.context_contract, args.context_schema, args.queue_policy_version)):
        parser.error("Context requires --context-dir, --context-contract, --context-schema and --queue-policy-version")
    archive_requested = any((args.context_archive, args.context_archive_sha256, args.context_archive_bytes))
    if archive_requested and (not context_requested or not all((args.context_archive, args.context_archive_sha256, args.context_archive_bytes))):
        parser.error("Context archive requires context inputs and all archive receipt fields")
    for path in [args.rankings, args.config]:
        if not path.is_file():
            parser.error(f"Required input missing: {path}")
    protected = {args.rankings.resolve(), args.config.resolve()}
    destinations = [args.report, args.tables_dir / "top50_long.csv",
                    args.tables_dir / "scatter_source.csv", args.tables_dir / "figures_manifest.json"]
    destinations += [args.output_dir / (name + suffix) for name in
                     ("cvss_epss_scatter", "top50_three_policies_p1", "top50_three_policies_p2")
                     for suffix in (".png", ".svg")]
    if any(path.resolve() in protected for path in destinations):
        parser.error("Output must not overwrite ranking input or config")
    try:
        protect_outputs(args)
    except ValueError as error:
        parser.error(str(error))
    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    try:
        protect_outputs(args, cfg)
    except ValueError as error:
        parser.error(str(error))
    frame = validate_rankings(pd.read_csv(args.rankings))
    expected = cfg["expected"]
    for key in ("dataset_version", "cohort_id", "policy_version", "epss_date"):
        if frame[key].iloc[0] != expected[key]:
            raise ValueError(f"Unexpected {key}")
    if len(frame) != expected["n"] or int(frame.is_kev.sum()) != expected["kev"]:
        raise ValueError("Cohort/KEV count differs from frozen config")
    if expected["rankings_sha256"] != file_info(args.rankings)["sha256"]:
        raise ValueError("Ranking checksum differs from approved snapshot; review with N2")
    plt.rcParams.update({"font.family": cfg["font"], "font.size": cfg["font_size"],
                         "svg.fonttype": cfg.get("svg_fonttype", "path")})
    top = topk_table(frame)
    inputs = [file_info(args.rankings), file_info(args.config)]
    figures = [("cvss_epss_scatter", scatter_figure(frame, cfg))]
    figures += [(f"top50_three_policies_p{p}", top50_figure(top, p, cfg)) for p in (1, 2)]
    pending = ["Metric figures not requested for this Part A run; supply --n2-dir for the verified N2 package",
               "N2 environmental_scores/context_comparison/priority_queue not delivered"]
    if cfg["thresholds"]["status"] != "locked":
        pending.append("N2 threshold lock pending: current thresholds are draft")
    tables = {"top50_long.csv": top, "scatter_source.csv": frame}
    n2_metrics = None
    context_summary = {"figure_status": "pending_inputs", "client_review_pairs": None,
                       "undefined_reason": "Supplemental N2 context contract/artifacts not received"}
    if args.n2_dir:
        more, recall, n2_metrics, n2_inputs = read_n2(args.n2_dir, frame, cfg)
        figures += more
        inputs += n2_inputs
        tables["kev_recall_plot.csv"] = recall
        tables["overlap_plot.csv"] = pd.read_csv(args.n2_dir / "overlap.csv")
        pending = ["N2 Environmental/context/queue and their final schema have not been delivered"]
    if context_requested:
        cfg["context"]["version"] = args.context_version or cfg["context"]["version"]
        cfg["context"]["queue_policy_version"] = args.queue_policy_version
        if args.context_archive:
            receipt = {"sha256": args.context_archive_sha256, "bytes": args.context_archive_bytes}
            inputs.append(verify_received_archive(args.context_archive, args.context_dir, receipt))
        context_fig, context_tables, context_summary, context_inputs = read_context(
            args.context_dir, args.context_contract, args.context_schema, cfg)
        inputs += context_inputs
        tables.update(context_tables)
        if context_fig is not None:
            figures.append(("context_rank_changes", context_fig))
        figures.append(("priority_queue_status", queue_status_figure(context_tables, context_summary, cfg)))
        pending = [item for item in pending if "context" not in item.lower() and "environmental" not in item.lower()]
        if context_fig is None:
            pending.append(context_summary["undefined_reason"])
    args.tables_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for name, table in tables.items():
        path = args.tables_dir / name
        table.to_csv(path, index=False, lineterminator="\n")
        outputs.append(file_info(path))
    for name, fig in figures:
        outputs.extend(file_info(p) for p in save_figure(fig, args.output_dir, name, cfg["dpi"]))
    manifest = {"schema_version": "p3-n3-plots-v1", "status": "partial" if pending else "complete",
                "inputs": inputs, "outputs": outputs, "pending": pending,
                "n": len(frame), "kev": int(frame.is_kev.sum()), "k": 50, "thresholds": cfg["thresholds"],
                "n2_ranking_metrics": n2_metrics, "context": context_summary,
                "part_b_metrics_status": "complete" if n2_metrics is not None else "not_requested",
                "part_b_context_status": context_summary["figure_status"]}
    manifest.update({
        "part_a_status": "complete", "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_version": expected["dataset_version"], "cohort_id": expected["cohort_id"],
        "policy_version": expected["policy_version"],
        "source_dates": {"epss_date": expected["epss_date"],
                         "kev_date_released": "2026-09-30", "kev_retrieved_date_utc": "2026-10-01"},
        "units": {"scatter": "CVE", "top50": "CVE per policy", "context": "CVE/asset pair",
                  "queue": "CVE/asset pair; supplied decisions"},
        "command": [sys.executable, "-m", "src.analysis.plots"] + (list(argv) if argv is not None else sys.argv[1:]),
        "dependencies": {"python": platform.python_version(), "matplotlib": matplotlib.__version__,
                         "pandas": pd.__version__, "numpy": np.__version__, "PyYAML": yaml.__version__},
        "code": file_info(Path(__file__)),
        "commit": git_output(Path(__file__).resolve().parents[2], 'rev-parse', 'HEAD'),
        "plot_code_may_be_uncommitted": True,
        "scope": "Only files listed in outputs belong to this run; pre-existing files are not certified."})
    (args.tables_dir / "figures_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_captions(args, cfg, frame, inputs, pending, n2_metrics, context_summary, tables)
    print(json.dumps({"status": manifest["status"], "figures": len(figures), "n": len(frame),
                      "context_status": context_summary["figure_status"], "pending": pending}, indent=2))


if __name__ == "__main__":
    main()
