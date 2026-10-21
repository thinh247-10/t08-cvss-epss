"""Auxiliary RQ1: observed versus frozen predicted Base ranks on common held-out IDs.

Predeclared policy: separate validation/test; common valid IDs across BOTH models;
score descending then CVE ID ascending; delta=observed_rank-predicted_rank;
Jaccard only for K<N; tau-b on raw scores. No training, inference or model selection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import subprocess
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from scipy.stats import kendalltau
from src.environmental.cvss_base import calculate_base_score

VERSIONS = {"tfidf": "tfidf-v1-n1-reproduction-20261017", "distilbert": "distilbert-v1-n1-20261017"}
DATASET = "t08-v1.0-20261010"
SPLITS = ("validation", "test")
POLICY = "common-valid-heldout-base-desc-id-asc-v1"


def file_info(path):
    p = Path(path)
    return {"path": p.as_posix(), "bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def check_table(frame, columns, keys):
    missing = set(columns) - set(frame.columns)
    if missing or not frame.columns.is_unique:
        raise ValueError(f"Missing/duplicate columns: {sorted(missing)}")
    if frame[keys].isna().any().any() or frame.duplicated(keys).any():
        raise ValueError(f"Missing or duplicate key: {keys}")
    for key in keys:
        if not frame[key].map(lambda v: isinstance(v, str) and bool(v.strip())).all():
            raise ValueError(f"Blank/non-string key: {key}")


def heldout_cohort(ranking, ml, dataset=DATASET):
    cols = ["cve_id", "cvss_base_score", "dataset_version"]
    check_table(ranking, cols, ["cve_id"])
    check_table(ml, cols + ["split", "domain_tags"], ["cve_id"])
    for frame in (ranking, ml):
        if not frame.dataset_version.eq(dataset).all():
            raise ValueError("dataset_version mismatch")
    if not ml.split.isin(("train", *SPLITS)).all():
        raise ValueError("Invalid ML split; expected train/validation/test")
    joined = ranking[cols].merge(ml[["cve_id", "split", "domain_tags", "cvss_base_score"]],
                                on="cve_id", validate="one_to_one", suffixes=("", "_ml"))
    if not np.allclose(pd.to_numeric(joined.cvss_base_score, errors="coerce"),
                       pd.to_numeric(joined.cvss_base_score_ml, errors="coerce"),
                       rtol=0, atol=1e-8, equal_nan=True):
        raise ValueError("Observed Base differs between ranking and ML release")
    return joined.loc[joined.split.isin(SPLITS)].drop(columns="cvss_base_score_ml").copy()


def select_model(predictions, version, ml, dataset=DATASET):
    cols = ["cve_id", "model_version", "dataset_version", "split", "prediction_usage",
            "predicted_vector", "predicted_base_score", "vector_valid", "prediction_error"]
    check_table(predictions, cols, ["cve_id", "model_version"])
    chosen = predictions.loc[predictions.model_version.eq(version)].copy(deep=True)
    if chosen.empty:
        raise ValueError(f"Required model_version not present: {version}")
    if not chosen.dataset_version.eq(dataset).all():
        raise ValueError("Prediction dataset_version mismatch")
    if not chosen.prediction_usage.eq("evaluation").all() or not chosen.split.isin(SPLITS).all():
        raise ValueError("Only evaluation predictions from validation/test are allowed")
    checked = chosen.merge(ml[["cve_id", "split"]], on="cve_id", how="left",
                           validate="one_to_one", suffixes=("", "_source"))
    if not checked.split.eq(checked.split_source).all():
        raise ValueError("Prediction ID/split disagrees with ML release")
    return chosen


def prediction_reason(row):
    if pd.isna(row.get("model_version")):
        return "missing_prediction"
    valid = row.get("vector_valid")
    if not isinstance(valid, (bool, np.bool_)) or not valid:
        return "invalid_vector_flag"
    error = row.get("prediction_error")
    if pd.notna(error) and str(error).strip():
        return "prediction_error"
    score = row.get("predicted_base_score")
    if isinstance(score, (bool, np.bool_)) or not isinstance(score, (int, float, np.number)) or not np.isfinite(score) or not 0 <= score <= 10:
        return "invalid_predicted_score"
    try:
        computed = calculate_base_score(row.get("predicted_vector"))
    except (ValueError, TypeError):
        return "invalid_predicted_vector"
    if not np.isclose(computed, score, rtol=0, atol=1e-8):
        return "vector_score_mismatch"
    return "valid"


def rank_scores(frame, column):
    order = frame.sort_values([column, "cve_id"], ascending=[False, True])
    return pd.Series(range(1, len(order) + 1), index=order.cve_id)


def analyze(ranking, ml, predictions, versions=VERSIONS, ks=(10, 20, 50), dataset=DATASET):
    if set(predictions) != set(versions) or len(versions) != 2:
        raise ValueError("Both configured models are required")
    if not ks or len(set(ks)) != len(ks) or any(not isinstance(k, int) or k <= 0 for k in ks):
        raise ValueError("K must be distinct positive integers")
    cohort = heldout_cohort(ranking, ml, dataset)
    membership = ranking[["cve_id"]].merge(ml[["cve_id", "split"]], on="cve_id", how="left", validate="one_to_one")
    join_audit = {"ranking_ids": len(ranking), "ml_ids": len(ml),
                  "ranking_missing_from_ml": int(membership.split.isna().sum()),
                  "ranking_missing_from_ml_ids": sorted(membership.loc[membership.split.isna(), "cve_id"]),
                  "train_excluded": int(membership.split.eq("train").sum()),
                  "heldout_ids": len(cohort)}
    chosen = {name: select_model(predictions[name], version, ml, dataset) for name, version in versions.items()}
    rows, exclusions, results = [], [], []
    for split in SPLITS:
        source = cohort.loc[cohort.split.eq(split)].copy()
        observed_valid = pd.to_numeric(source.cvss_base_score, errors="coerce").between(0, 10)
        observed_valid &= ~source.cvss_base_score.map(lambda v: isinstance(v, (bool, np.bool_)))
        common = set(source.loc[observed_valid, "cve_id"])
        coverage, aligned = {}, {}
        for name, pred in chosen.items():
            joined = source[["cve_id"]].merge(pred, on="cve_id", how="left", validate="one_to_one")
            joined["validity"] = joined.apply(prediction_reason, axis=1) if len(joined) else pd.Series(dtype=str)
            valid_ids = set(joined.loc[joined.validity.eq("valid"), "cve_id"])
            common &= valid_ids
            counts = joined.validity.value_counts().to_dict()
            coverage[name] = {"model_version": versions[name], "eligible": len(source),
                              "valid": len(valid_ids), "missing": counts.get("missing_prediction", 0),
                              "invalid": len(source) - len(valid_ids) - counts.get("missing_prediction", 0),
                              "coverage": len(valid_ids) / len(source) if len(source) else None,
                              "reason_counts": counts}
            aligned[name] = joined.set_index("cve_id")
        for item in source.itertuples():
            if item.cve_id not in common:
                for name in versions:
                    reason = aligned[name].loc[item.cve_id, "validity"]
                    exclusions.append({"split": split, "cve_id": item.cve_id, "model": name,
                                       "reason": reason if reason != "valid" else (
                                           "invalid_observed_score" if not observed_valid.loc[item.Index] else "excluded_by_common_cohort"),
                                       "observed_valid": bool(observed_valid.loc[item.Index])})
        common_frame = source.loc[source.cve_id.isin(common)].sort_values("cve_id").copy()
        common_frame["cvss_base_score"] = pd.to_numeric(common_frame.cvss_base_score)
        n = len(common_frame)
        for name in versions:
            coverage[name]["common_valid"] = n
            coverage[name]["lost_to_common_cohort"] = coverage[name]["valid"] - n
            coverage[name]["common_coverage"] = n / len(source) if len(source) else None
        split_result = {"split": split, "eligible": len(source), "common_n": n,
                        "common_ids": common_frame.cve_id.tolist(),
                        "invalid_observed": int((~observed_valid).sum()), "coverage": coverage,
                        "domain_counts": {tag: int(source.domain_tags.map(lambda tags: tag in tags).sum())
                                          for tag in ("web", "mobile")}, "models": []}
        for name, version in versions.items():
            result = {"model": name, "model_version": version, "n": n, "jaccard": []}
            compared = common_frame[["cve_id", "cvss_base_score"]].copy()
            compared["predicted_base_score"] = compared.cve_id.map(aligned[name].predicted_base_score)
            compared["split"], compared["model"], compared["model_version"] = split, name, version
            compared["dataset_version"], compared["policy_version"], compared["n"] = dataset, POLICY, n
            compared["eligible"], compared["common_coverage"] = len(source), n / len(source) if len(source) else None
            if n < 2:
                # Retain a valid singleton for audit, without inventing selective ranks.
                compared[["observed_rank", "predicted_rank", "rank_delta"]] = np.nan
                rows.append(compared)
                result.update(kendall_tau_b=None, undefined_reason="N<2 common valid IDs")
                result["jaccard"] = [{"k": k, "value": None, "reason": "N<2"} for k in ks]
                split_result["models"].append(result)
                continue
            compared["observed_rank"] = compared.cve_id.map(rank_scores(compared, "cvss_base_score"))
            compared["predicted_rank"] = compared.cve_id.map(rank_scores(compared, "predicted_base_score"))
            compared["rank_delta"] = compared.observed_rank - compared.predicted_rank
            rows.append(compared)
            constant = compared.cvss_base_score.nunique() < 2 or compared.predicted_base_score.nunique() < 2
            result["kendall_tau_b"] = None if constant else float(kendalltau(
                compared.cvss_base_score, compared.predicted_base_score, variant="b").statistic)
            result["undefined_reason"] = "constant raw score" if constant else None
            result["mean_absolute_rank_delta"] = float(compared.rank_delta.abs().mean())
            for k in ks:
                a = set(compared.loc[compared.observed_rank.le(k), "cve_id"])
                b = set(compared.loc[compared.predicted_rank.le(k), "cve_id"])
                result["jaccard"].append({"k": k, "value": len(a & b) / len(a | b) if k < n else None,
                                          "reason": None if k < n else "K>=N is not selective"})
            split_result["models"].append(result)
        results.append(split_result)
    columns = ["cve_id", "cvss_base_score", "predicted_base_score", "observed_rank", "predicted_rank",
               "rank_delta", "split", "model", "model_version", "dataset_version", "policy_version",
               "n", "eligible", "common_coverage"]
    return (pd.concat(rows, ignore_index=True) if rows else pd.DataFrame(columns=columns),
            {"schema_version": "p3-n3-prediction-impact-v1", "dataset_version": dataset,
             "policy_version": POLICY, "rank_delta_definition": "observed_rank - predicted_rank; positive = predicted earlier",
             "tie_break": "Base score descending, CVE ID ascending; same rule for observed and predicted",
             "ks": list(ks), "join_audit": join_audit,
             "models": versions, "splits": results, "training_or_inference": False},
            pd.DataFrame(exclusions, columns=["split", "cve_id", "model", "reason", "observed_valid"]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    release = Path("data/processed/phase1_v1_20261010")
    received = Path("data/processed/phase2_received")
    parser.add_argument("--ranking-cohort", type=Path, default=release / "ranking_cohort.parquet")
    parser.add_argument("--ml-cohort", type=Path, default=release / "ml_cohort.parquet")
    parser.add_argument("--tfidf", type=Path, default=received / "baseline/data/processed/predictions.csv")
    parser.add_argument("--distilbert", type=Path, default=received / "distilbert/predictions.csv")
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed/p3_n3"))
    parser.add_argument("--report", type=Path, default=Path("reports/p3_prediction_rank_impact.md"))
    args = parser.parse_args(argv)
    paths = [args.ranking_cohort, args.ml_cohort, args.tfidf, args.distilbert]
    for path in paths:
        if not path.is_file():
            parser.error(f"Required input missing: {path}")
    output_names = ("predicted_rank_comparison.csv", "prediction_rank_exclusions.csv", "prediction_rank_metrics.json")
    destinations = [args.output_dir / name for name in output_names] + [args.report]
    if len({p.resolve() for p in destinations}) != len(destinations):
        parser.error("Output/report paths must be distinct")
    protected = {p.resolve() for p in paths} | {Path(__file__).resolve()}
    roots = [release.resolve(), received.resolve()]
    if any(p.resolve() in protected or any(p.resolve().is_relative_to(root) for root in roots) for p in destinations):
        parser.error("Output must not overwrite frozen inputs or producer release directories")
    try:
        comparison, metrics, excluded = analyze(pd.read_parquet(args.ranking_cohort), pd.read_parquet(args.ml_cohort),
                                              {"tfidf": pd.read_csv(args.tfidf), "distilbert": pd.read_csv(args.distilbert)})
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    metrics["inputs"] = [file_info(p) for p in paths]
    metrics["code"] = file_info(__file__)
    metrics["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    metrics["command"] = [sys.executable, "-m", "src.analysis.prediction_rank_impact"] + (list(argv) if argv is not None else sys.argv[1:])
    metrics["expected_counts"] = {"validation": 69, "test": 108}
    metrics["count_warnings"] = [f"{s['split']}: join found {s['eligible']}, expected {metrics['expected_counts'][s['split']]}"
                                 for s in metrics["splits"] if s["eligible"] != metrics["expected_counts"][s["split"]]]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    comparison.to_csv(args.output_dir / "predicted_rank_comparison.csv", index=False, lineterminator="\n")
    excluded.to_csv(args.output_dir / "prediction_rank_exclusions.csv", index=False, lineterminator="\n")
    metrics["outputs"] = [file_info(args.output_dir / name) for name in output_names[:2]]
    (args.output_dir / "prediction_rank_metrics.json").write_text(json.dumps(metrics, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    lines = ["# Phase 3 — N3: tác động sai số AI lên thứ hạng severity", "",
             "Phân tích phụ RQ1; không trộn với RQ2 (396 CVE quan sát). Quy tắc được chốt trong module trước khi chạy: "
             "validation/test riêng, giao ID ranking–ML; cùng tập có observation và prediction hợp lệ của cả hai model. "
             "Base giảm rồi CVE ID tăng; delta=observed_rank−predicted_rank (dương: dự đoán xếp sớm hơn). "
             "Tau-b trên điểm gốc, không phải rank đã phá hòa. Chỉ tính Jaccard khi K<N.", "",
             "K chốt trước chạy: 10, 20, 50. Coverage từng model = prediction hợp lệ / ID giao đủ điều kiện; "
             "common coverage = ID có observation và cả hai prediction hợp lệ / ID giao đủ điều kiện. "
             "Không bù giá trị thiếu bằng 0. N<2: giữ dòng hợp lệ để truy vết nhưng rank/tau/Jaccard là N/A.", "",
             "```powershell", r".\.venv\Scripts\python.exe -m src.analysis.prediction_rank_impact --help",
             "& " + subprocess.list2cmdline(metrics["command"]), "```", "",
             "Join audit: `" + json.dumps(metrics["join_audit"], ensure_ascii=False) + "`.", "",
             "| Split | Model/version | Eligible | Common N | Valid/missing/invalid | Model coverage | Common coverage | Lost to common | Tau-b | J@10 | J@20 | J@50 |",
             "|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda value: "N/A" if value is None else f"{value:.6f}"
    for split in metrics["splits"]:
        for model in split["models"]:
            c = split["coverage"][model["model"]]
            js = " | ".join(fmt(v["value"]) for v in model["jaccard"])
            lines.append(f"| {split['split']} | {model['model_version']} | {split['eligible']} | {split['common_n']} | "
                         f"{c['valid']}/{c['missing']}/{c['invalid']} | {fmt(c['coverage'])} | {fmt(c['common_coverage'])} | "
                         f"{c['lost_to_common_cohort']} | {fmt(model['kendall_tau_b'])} | {js} |")
    lines += ["", "Chi tiết coverage, miền dữ liệu và lý do N/A:"]
    for split in metrics["splits"]:
        lines += ["", f"- {split['split']}: invalid observed={split['invalid_observed']}; "
                  f"domain counts={split['domain_counts']}; common IDs được lưu đầy đủ trong JSON."]
        for model in split["models"]:
            c = split["coverage"][model["model"]]
            reasons = {str(j['k']): j['reason'] for j in model['jaccard'] if j['reason']}
            lines.append(f"- {split['split']}/{model['model']}: validity={c['reason_counts']}; "
                         f"tau N/A reason={model['undefined_reason']}; Jaccard N/A reasons={reasons}; "
                         f"mean absolute rank delta={fmt(model.get('mean_absolute_rank_delta'))}.")
    lines += ["", "Coverage và lý do loại từng dòng: [metrics](../data/processed/p3_n3/prediction_rank_metrics.json), "
              "[exclusions](../data/processed/p3_n3/prediction_rank_exclusions.csv). "
              "[Bảng đối chiếu](../data/processed/p3_n3/predicted_rank_comparison.csv) giữ rank/score/version từng CVE.",
              "", "Domain counts ở trên được đếm từ ML cohort, không suy diễn nhãn mobile từ backend. Không thêm train để đủ 396. "
              "Đây là độ thay đổi thứ tự severity do ước lượng Base; không đo hiệu quả vá, xác suất khai thác hay tác động vận hành. "
              "Không chọn model thắng, chỉnh cấu hình từ test, retrain hoặc chạy lại inference. "
              "Dùng artifact N1; không tuyên bố byte-identical với model N3 cũ. Ties phụ thuộc ID ở cutoff.", "",
              "Input/hash/bytes và command thực tế được lưu trong JSON. Counts khác dự kiến (nếu có): " + str(metrics["count_warnings"]),
              "Nếu số join khác 69/108, xem join audit (ranking không có trong ML, train bị loại) và hash/version đầu vào; "
              "không bổ sung ID để ép đạt số dự kiến.", "",
              "Chỉ dùng score prediction đã lưu; kiểm vector/score là kiểm tính hợp lệ artifact bằng Base scorer hiện có, "
              "không gọi src.model.evaluate, train hoặc inference. Dummy bị loại theo model_version chính xác.", "",
              "| Input | Bytes | SHA-256 |", "|---|---:|---|"]
    lines += [f"| {p['path']} | {p['bytes']} | `{p['sha256']}` |" for p in metrics['inputs']]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(comparison), "excluded_model_rows": len(excluded),
                      "counts": {s["split"]: s["common_n"] for s in metrics["splits"]}}, indent=2))


if __name__ == "__main__":
    main()
