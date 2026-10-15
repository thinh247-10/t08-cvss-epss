"""Evaluate fixed CVSS labels by CVE ID, retaining failed prediction rows.

No model fitting, threshold selection or test-driven configuration occurs here.
MAE/RMSE use the team's shared scorer, never an independent CVSS formula.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

import numpy as np
import pandas as pd

from src.collect.nvd_collector import parse_base_vector
from src.environmental.cvss_base import calculate_base_score
from src.model.data_validation import LABEL_ORDER, TARGET_METRICS, checked_boolean
from src.model.predict import PREDICTION_COLUMNS


def _require_frame(frame, required, name):
    if not isinstance(frame, pd.DataFrame) or not frame.columns.is_unique:
        raise ValueError(f"{name} must be a DataFrame with unique columns")
    missing = set(required) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing {name} columns: {sorted(missing)}")


def _validate_ids(frame, name):
    valid = frame.cve_id.map(lambda value: isinstance(value, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", value) is not None).astype(bool)
    if not valid.all():
        raise ValueError(f"{name} contains invalid or missing cve_id")
    if frame.cve_id.duplicated().any():
        raise ValueError(f"{name} contains duplicate cve_id")


def _error_text(value):
    if value is None or value is pd.NA:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return not pd.isna(value)


def _numeric_score(value):
    if isinstance(value, (bool, np.bool_)) or not isinstance(value, (int, float, np.number)):
        return None
    return float(value) if math.isfinite(value) and 0 <= value <= 10 else None


def _analyze_target(row):
    parsed = parse_base_vector(row["cvss_vector"])
    if parsed is None or any(not isinstance(row[metric], str) or row[metric] not in allowed or row[metric] != parsed[metric]
                             for metric, allowed in LABEL_ORDER.items()):
        return None, "invalid_target_vector_or_labels"
    if "cvss_version" in row and (not isinstance(row["cvss_version"], str) or row["cvss_version"] != "3.1"):
        return None, "invalid_target_cvss_version"
    try:
        score = calculate_base_score(row["cvss_vector"])
    except Exception:
        return None, "target_scorer_failed"
    if "cvss_base_score" in row:
        observed = _numeric_score(row["cvss_base_score"])
        if observed is None or not math.isclose(observed, score, abs_tol=1e-8):
            return None, "target_base_score_mismatch"
    return score, None


def _analyze_prediction(row):
    reasons = []
    parsed = parse_base_vector(row["predicted_vector"])
    if parsed is None:
        reasons.append("invalid_vector")
    else:
        for metric, allowed in LABEL_ORDER.items():
            value = row[f"pred_{metric}"]
            if not isinstance(value, str) or value not in allowed or value != parsed[metric]:
                reasons.append("vector_label_mismatch")
                break
    if not pd.api.types.is_bool(row["vector_valid"]) or not row["vector_valid"]:
        reasons.append("vector_valid_false_or_missing")
    if _error_text(row["prediction_error"]):
        reasons.append("reported_prediction_error")
    score = None
    if parsed is not None:
        try:
            score = calculate_base_score(row["predicted_vector"])
        except Exception:
            reasons.append("prediction_scorer_failed")
    reported = _numeric_score(row["predicted_base_score"])
    if score is not None and (reported is None or not math.isclose(reported, score, abs_tol=1e-8)):
        reasons.append("predicted_base_score_mismatch")
    return (score if not reasons else None), list(dict.fromkeys(reasons))


def _component_metrics(truth, predictions, metric):
    labels = list(LABEL_ORDER[metric])
    matrix = [[0] * len(labels) for _ in labels]
    invalid_by_true = [0] * len(labels)
    for actual, predicted in zip(truth[metric], predictions[f"pred_{metric}"]):
        actual_index = labels.index(actual)
        if isinstance(predicted, str) and predicted in labels:
            matrix[actual_index][labels.index(predicted)] += 1
        else:
            invalid_by_true[actual_index] += 1
    classes = {}
    for index, label in enumerate(labels):
        tp = matrix[index][index]
        support = sum(matrix[index]) + invalid_by_true[index]
        predicted_count = sum(row[index] for row in matrix)
        precision = tp / predicted_count if predicted_count else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        classes[label] = {"precision": precision, "recall": recall, "f1": f1, "support": support}
    count = len(truth)
    covered = count - sum(invalid_by_true)
    return {
        "sample_count": count,
        "accuracy": sum(matrix[i][i] for i in range(len(labels))) / count if count else None,
        "macro_f1": sum(value["f1"] for value in classes.values()) / len(labels) if count else None,
        "per_class": classes, "label_order": labels,
        "confusion_matrix": matrix,
        "confusion_matrix_orientation": "rows=true, columns=predicted",
        "invalid_predictions_by_true_label": dict(zip(labels, invalid_by_true)),
        "coverage": {"numerator": covered, "denominator": count, "fraction": covered / count if count else None},
        "status": "complete" if covered == count else "incomplete",
    }


def _split_report(truth, predictions):
    if truth.empty:
        return None
    truth_rows = truth.to_dict(orient="records")
    prediction_rows = predictions.to_dict(orient="records")
    target = [_analyze_target(row) for row in truth_rows]
    predicted = [_analyze_prediction(row) for row in prediction_rows]
    valid_target = np.array([reason is None for _, reason in target], dtype=bool)
    target_truth = truth.loc[valid_target].reset_index(drop=True)
    target_predictions = predictions.loc[valid_target].reset_index(drop=True)
    denominator = int(valid_target.sum())
    exact_count = 0
    differences = []
    for index in range(len(truth)):
        if not valid_target[index]:
            continue
        if not predicted[index][1]:
            exact_count += int(all(truth_rows[index][metric] == prediction_rows[index][f"pred_{metric}"]
                                   for metric in TARGET_METRICS))
            if predicted[index][0] is not None:
                differences.append(predicted[index][0] - target[index][0])
    invalid_predictions = [{"cve_id": prediction_rows[index]["cve_id"], "reasons": reasons}
                           for index, (_, reasons) in enumerate(predicted) if reasons]
    invalid_targets = [{"cve_id": truth_rows[index]["cve_id"], "reason": reason}
                       for index, (_, reason) in enumerate(target) if reason is not None]
    components = {metric: _component_metrics(target_truth, target_predictions, metric) for metric in TARGET_METRICS}
    return {
        "sample_count": len(truth), "valid_target_count": denominator,
        "invalid_target_count": len(invalid_targets), "invalid_targets": invalid_targets,
        "invalid_prediction_count": len(invalid_predictions), "invalid_predictions": invalid_predictions,
        "per_metric": components,
        "mean_macro_f1": (sum(component["macro_f1"] for component in components.values()) / len(TARGET_METRICS)) if denominator else None,
        "exact_vector_accuracy": exact_count / denominator if denominator else None,
        "exact_vector_correct_count": exact_count,
        "exact_vector_denominator": denominator,
        "base_score_mae": float(np.mean(np.abs(differences))) if differences else None,
        "base_score_rmse": float(np.sqrt(np.mean(np.square(differences)))) if differences else None,
        "score_coverage": {"numerator": len(differences), "denominator": denominator,
                           "fraction": len(differences) / denominator if denominator else None},
    }


def evaluate_predictions(truth, predictions, *, model_version, dataset_version):
    """Join one model's predictions by ID and report validation/test separately.

    Missing/extra/duplicate IDs and provenance mismatches are hard errors. Invalid
    inference/vector/score rows remain in every relevant denominator. Bad targets
    are reported separately and excluded from target-based metric denominators.
    """
    if not all(isinstance(value, str) and value.strip() for value in (model_version, dataset_version)):
        raise ValueError("Expected model_version and dataset_version must be nonblank strings")
    _require_frame(truth, ("cve_id", "split", "dataset_version", "in_scope", "cvss_vector", *TARGET_METRICS), "truth")
    _require_frame(predictions, PREDICTION_COLUMNS, "predictions")
    _validate_ids(truth, "truth")
    _validate_ids(predictions, "predictions")
    for name, frame in (("truth", truth), ("predictions", predictions)):
        if not frame.dataset_version.eq(dataset_version).fillna(False).all():
            raise ValueError(f"{name} dataset_version mismatch")
    if not predictions.model_version.eq(model_version).fillna(False).all():
        raise ValueError("Prediction model_version mismatch; submit one requested model at a time")
    if not truth["split"].isin(["train", "validation", "test"]).all():
        raise ValueError("Truth contains missing or invalid split")
    if not predictions["split"].isin(["validation", "test"]).all():
        raise ValueError("Predictions must use validation/test splits")
    if not predictions.prediction_usage.eq("evaluation").fillna(False).all():
        raise ValueError("Only prediction_usage=evaluation can be evaluated")
    scoped, invalid_scope = checked_boolean(truth.in_scope)
    if invalid_scope.any() or scoped.isna().any():
        raise ValueError("Truth in_scope must contain native, nonmissing booleans")
    _, invalid_flag = checked_boolean(predictions.vector_valid)
    if invalid_flag.any():
        raise ValueError("Prediction vector_valid must contain booleans or null")
    evaluation_truth = truth.loc[truth["split"].isin(["validation", "test"])].copy().reset_index(drop=True)
    missing_ids = set(evaluation_truth.cve_id) - set(predictions.cve_id)
    extra_ids = set(predictions.cve_id) - set(evaluation_truth.cve_id)
    if missing_ids or extra_ids:
        raise ValueError(f"Prediction ID mismatch: missing={sorted(missing_ids)[:5]}, extra={sorted(extra_ids)[:5]}")
    ordered = predictions.set_index("cve_id").reindex(evaluation_truth.cve_id).reset_index()
    if not ordered["split"].eq(evaluation_truth["split"]).all():
        raise ValueError("Prediction split mismatch after joining by ID")
    scopes = {}
    for scope_name, scope_mask in (("all_ml", pd.Series(True, index=evaluation_truth.index)),
                                   ("in_scope", evaluation_truth.in_scope)):
        scopes[scope_name] = {}
        for split in ("validation", "test"):
            mask = scope_mask & evaluation_truth["split"].eq(split)
            scopes[scope_name][split] = _split_report(evaluation_truth.loc[mask].reset_index(drop=True),
                                                    ordered.loc[mask].reset_index(drop=True))
    return {
        "schema_version": "1.0", "dataset_version": dataset_version, "model_version": model_version,
        "label_order": {metric: list(labels) for metric, labels in LABEL_ORDER.items()},
        "split_version": "locked_dataset_split", "scopes": scopes,
        "metric_policy": {"macro_f1": "all_declared_labels_zero_division_0",
                          "invalid_predictions": "retained_and_counted_once_per_row",
                          "invalid_targets": "reported_separately_and_excluded_from_metric_denominators",
                          "score_source": "src.environmental.cvss_base.calculate_base_score"},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--dataset-version", required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/model_metrics.json"))
    args = parser.parse_args(argv)
    truth = (pd.read_parquet(args.truth) if args.truth.suffix.lower() == ".parquet" else
             pd.read_csv(args.truth, dtype={"cve_id": "string", "dataset_version": "string",
                                           "split": "string", "cvss_version": "string", "in_scope": "boolean"}))
    predictions = pd.read_csv(args.predictions, dtype={"cve_id": "string", "dataset_version": "string",
                                                     "model_version": "string", "split": "string",
                                                     "vector_valid": "boolean"})
    if "model_version" in predictions:
        predictions = predictions.loc[predictions.model_version.eq(args.model_version)].copy()
    result = evaluate_predictions(truth, predictions, model_version=args.model_version, dataset_version=args.dataset_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Evaluation written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
