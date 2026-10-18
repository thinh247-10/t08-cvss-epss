"""Descriptive ranking metrics on one verified, observed release cohort.

Paths in config are repository-root relative. No API calls or model predictions.
"""

import argparse
from datetime import datetime, timezone
from importlib.metadata import version
from itertools import combinations
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pandas as pd
from pandas.testing import assert_frame_equal
from scipy.stats import kendalltau
import yaml

from src.analysis.compare_rankings import (
    build_rankings, digest, OUTPUT_COLUMNS, POLICY_VERSION,
)

SCHEMA_VERSION = "p3-ranking-metrics-v1"
POLICIES = ("cvss", "epss", "kev_first")
TOPK_COLUMNS = ("policy", "k", "n", "kev_total", "kev_hits", "kev_recall",
                "cutoff_tie_count", "selected_from_cutoff_tie",
                "selected_n", "effective_k", "selection_is_discriminating",
                "selection_reason", "kev_recall_reason")
OVERLAP_COLUMNS = ("policy_a", "policy_b", "k", "intersection", "union", "jaccard")
DELTA_COLUMNS = ("cve_id", "cvss_rank", "epss_rank", "kev_first_rank",
                 "rank_delta_cvss_epss")


def validate_k(ks):
    if (not isinstance(ks, (list, tuple)) or not ks
            or any(type(k) is not int or k <= 0 for k in ks)
            or len(set(ks)) != len(ks)):
        raise ValueError("K must be a non-empty list of unique positive integers")
    return sorted(ks)


def validate_rankings(rankings, *, dataset_version, cohort_id,
                      policy_version=POLICY_VERSION, reference_cohort=None):
    if tuple(rankings.columns) != OUTPUT_COLUMNS:
        raise ValueError("Ranking schema must be exactly the 11-column contract")
    expected = build_rankings(rankings, dataset_version=dataset_version,
                              cohort_id=cohort_id, policy_version=policy_version)
    if (not rankings.cohort_id.eq(cohort_id).all()
            or not rankings.policy_version.eq(policy_version).all()):
        raise ValueError("Cohort or policy version mismatch")
    for col in ("cvss_rank", "epss_rank", "kev_first_rank"):
        if (not pd.api.types.is_integer_dtype(rankings[col])
                or pd.api.types.is_bool_dtype(rankings[col])):
            raise ValueError(f"{col} must contain integer positions")
    try:
        assert_frame_equal(rankings.sort_values("cve_id").reset_index(drop=True),
                           expected, check_dtype=False)
        if reference_cohort is not None:
            reference = build_rankings(reference_cohort, dataset_version=dataset_version,
                                       cohort_id=cohort_id, policy_version=policy_version)
            assert_frame_equal(expected, reference, check_dtype=False)
    except AssertionError as error:
        raise ValueError("Ranking positions, IDs or scores differ from fixed cohort/policy") from error
    return expected


def compute_metrics(rankings, *, ks, dataset_version, cohort_id,
                    policy_version=POLICY_VERSION, reference_cohort=None):
    """Return summary + three dataframes; reject invalid inputs, never drop IDs."""
    ks = validate_k(ks)
    frame = validate_rankings(rankings, dataset_version=dataset_version,
                             cohort_id=cohort_id, policy_version=policy_version,
                             reference_cohort=reference_cohort)
    n, kev_total = len(frame), int(frame.is_kev.sum())
    reason = None
    if n < 2:
        reason = "fewer_than_two_rows"
    elif frame.cvss_base_score.nunique() < 2 or frame.epss.nunique() < 2:
        reason = "constant_score_column"
    tau = None if reason else float(kendalltau(
        frame.cvss_base_score, frame.epss, variant="b", nan_policy="raise").statistic)
    if tau is not None and not math.isfinite(tau):
        tau, reason = None, "undefined_tau_b"
    top_rows, overlap_rows = [], []
    tie_keys = {"cvss": ["cvss_base_score"], "epss": ["epss"],
                "kev_first": ["is_kev", "epss", "cvss_base_score"]}
    for k in ks:
        selected_sets = {}
        for policy in POLICIES:
            selected = frame.sort_values(f"{policy}_rank").head(k)
            selected_sets[policy] = set(selected.cve_id)
            cutoff = selected.iloc[-1]
            tie_mask = pd.Series(True, index=frame.index)
            selected_tie = pd.Series(True, index=selected.index)
            for key in tie_keys[policy]:
                tie_mask &= frame[key].eq(cutoff[key])
                selected_tie &= selected[key].eq(cutoff[key])
            hits = int(selected.is_kev.sum())
            recall_reason = ("policy_uses_kev_directly" if policy == "kev_first" else
                             "no_kev_in_cohort" if kev_total == 0 else None)
            top_rows.append(dict(policy=policy, k=k, n=n, kev_total=kev_total,
                                 kev_hits=hits, kev_recall=None if recall_reason else hits / kev_total,
                                 cutoff_tie_count=int(tie_mask.sum()),
                                 selected_from_cutoff_tie=int(selected_tie.sum()),
                                 selected_n=len(selected), effective_k=min(k, n),
                                 selection_is_discriminating=k < n,
                                 selection_reason=None if k < n else "k_at_least_n_selects_whole_cohort",
                                 kev_recall_reason=recall_reason))
        for left, right in combinations(POLICIES, 2):
            intersection = len(selected_sets[left] & selected_sets[right])
            union = len(selected_sets[left] | selected_sets[right])
            overlap_rows.append(dict(policy_a=left, policy_b=right, k=k,
                                     intersection=intersection, union=union,
                                     jaccard=intersection / union))
    deltas = frame.loc[:, list(DELTA_COLUMNS[:-1])].copy()
    deltas[DELTA_COLUMNS[-1]] = deltas.cvss_rank - deltas.epss_rank
    summary = dict(schema_version=SCHEMA_VERSION, dataset_version=dataset_version,
                   cohort_id=cohort_id, policy_version=policy_version, n=n,
                   total_kev=kev_total, k=ks,
                   kendall_tau_b=dict(value=tau, reason=reason,
                                      inputs=["cvss_base_score", "epss"], variant="b"),
                   rank_delta_definition="cvss_rank - epss_rank; positive means EPSS ranks earlier",
                   topk=top_rows, overlap=overlap_rows)
    return (summary, pd.DataFrame(top_rows, columns=TOPK_COLUMNS),
            pd.DataFrame(overlap_rows, columns=OVERLAP_COLUMNS), deltas)


def file_record(path, rows=None):
    info = dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path))
    if rows is not None:
        info["rows"] = rows
    return info


def git_executable():
    # Match Git for Windows used by the project terminal, not MSYS2 git with
    # a different global autocrlf config (which can report spurious dirty files).
    candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/cmd/git.exe"
    if os.name == "nt" and candidate.is_file():
        return str(candidate)
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git is required to record provenance")
    return executable


def git_output(root, *args):
    result = subprocess.run([git_executable(), "-C", str(root), *args], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", check=True)
    return result.stdout.strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rankings", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    args.rankings, args.config, args.output_dir = (
        (root / p).resolve() for p in (args.rankings, args.config, args.output_dir))
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    if config.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported config schema")
    validate_k(config["k"])
    if config.get("missing_policy") != "reject_ranking_inputs_null_undefined_metrics_with_reason":
        raise ValueError("Unsupported missing policy")
    thresholds = config["illustrative_thresholds"]
    if thresholds != {"cvss": 7.0, "epss": 0.10}:
        raise ValueError("Illustrative thresholds differ from predeclared Phase 3 proposal")
    if args.rankings != (root / config["rankings_path"]).resolve():
        raise ValueError("Ranking path differs from config")
    if args.output_dir != (root / config["output_dir"]).resolve():
        raise ValueError("Output directory differs from config")
    release = (root / config["release_folder"]).resolve()
    if args.output_dir == release or release in args.output_dir.parents:
        raise ValueError("Never write into frozen release")
    meta_path = release / "metadata.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if (meta.get("status") != "complete" or meta.get("ranking_ready") is not True
            or meta["dataset_version"] != config["dataset_version"]):
        raise ValueError("Release status/version mismatch")
    dates = config["source_dates"]
    if any(meta.get(key) != value for key, value in dates.items()):
        raise ValueError("Source dates differ from release metadata")
    source_path = release / "ranking_cohort.parquet"
    entry = meta["files"][source_path.name]
    if digest(source_path) != entry["sha256"] or source_path.stat().st_size != entry["bytes"]:
        raise ValueError("Release cohort checksum/bytes mismatch")
    source = pd.read_parquet(source_path)
    if (len(source) != meta["statistics"]["ranking"]
            or int(source.is_kev.sum()) != meta["statistics"]["ranking_kev"]
            or not source.epss_date.eq(dates["epss_date"]).all()):
        raise ValueError("Release cohort statistics/date mismatch")
    frame = pd.read_csv(args.rankings)
    summary, topk, overlap, deltas = compute_metrics(
        frame, ks=config["k"], dataset_version=config["dataset_version"],
        cohort_id=config["cohort_id"], policy_version=config["policy_version"],
        reference_cohort=source)
    summary.update(source_dates=dates, context_version=config["context_version"],
                   illustrative_thresholds=thresholds,
                   limitations=["descriptive snapshot, not a 30-day forecast validation",
                                "KEV absence is not evidence of no exploitation",
                                "KEV-first is not independently evaluated using KEV recall"])
    # Record the fixed, illustrative 2x2 split; no threshold tuning or false-positive claim.
    high_cvss = frame.cvss_base_score.ge(thresholds["cvss"])
    high_epss = frame.epss.ge(thresholds["epss"])
    summary["illustrative_threshold_counts"] = {
        "high_cvss_high_epss": int((high_cvss & high_epss).sum()),
        "high_cvss_low_epss": int((high_cvss & ~high_epss).sum()),
        "low_cvss_high_epss": int((~high_cvss & high_epss).sum()),
        "low_cvss_low_epss": int((~high_cvss & ~high_epss).sum())}
    names = ("ranking_metrics.json", "topk_metrics.csv", "overlap.csv", "rank_deltas.csv", "metadata.json")
    outputs = [args.output_dir / name for name in names]
    protected = {args.rankings, args.config, meta_path, source_path}
    if any(p in protected for p in outputs):
        raise ValueError("Output would overwrite an input")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    outputs[0].write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for path, table in zip(outputs[1:4], (topk, overlap, deltas)):
        table.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
    metadata = dict(schema_version=SCHEMA_VERSION, created_at=datetime.now(timezone.utc).isoformat(),
                    dataset_version=config["dataset_version"], cohort_id=config["cohort_id"],
                    policy_version=config["policy_version"], context_version=config["context_version"],
                    source_dates=dates, n=len(frame), total_kev=int(frame.is_kev.sum()),
                    command=[sys.executable, "-m", "src.analysis.ranking_metrics",
                             "--rankings", str(args.rankings), "--config", str(args.config),
                             "--output-dir", str(args.output_dir)],
                    commit=git_output(root, "rev-parse", "HEAD"), git_executable=git_executable(),
                    tracked_dirty=bool(git_output(root, "status", "--porcelain", "--untracked-files=no")),
                    python=sys.version, packages={p: version(p) for p in ("pandas", "pyarrow", "scipy", "PyYAML", "numpy")},
                    inputs={p.name: file_record(p) for p in (args.rankings, args.config, source_path, meta_path)},
                    code={str(Path(__file__).relative_to(root)): file_record(Path(__file__)),
                          "src/analysis/compare_rankings.py": file_record(root / "src/analysis/compare_rankings.py")},
                    outputs={p.name: file_record(p, count) for p, count in
                             zip(outputs[:4], (None, len(topk), len(overlap), len(deltas)))},
                    metadata_self_hash="excluded to avoid recursive hash; hash enclosing ZIP separately")
    outputs[4].write_text(json.dumps(metadata, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(dict(n=summary["n"], total_kev=summary["total_kev"],
                          tau_b=summary["kendall_tau_b"], output_dir=str(args.output_dir)), indent=2))


if __name__ == "__main__":
    main()
