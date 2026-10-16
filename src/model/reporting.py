"""Read-only tables for the Phase 2 notebook and model card; never refit a model."""
from pathlib import Path
import json

import pandas as pd


def read_metrics(path="reports/model_metrics.json"):
    metrics = json.loads(Path(path).read_text(encoding="utf-8"))
    if metrics.get("status") != "complete":
        raise ValueError("The final evaluation report is not complete")
    return metrics


def summary_table(metrics, split):
    if split not in {"validation", "test"}:
        raise ValueError("Choose validation or test")
    rows = []
    for kind, model in metrics["models"].items():
        for scope, splits in model["scopes"].items():
            result = splits[split]
            if result is None:
                rows.append({"model": kind, "scope": scope, "n": 0})
                continue
            rows.append({"model": kind, "scope": scope, "n": result["sample_count"],
                         "mean_macro_f1": result["mean_macro_f1"],
                         "exact_vector_accuracy": result["exact_vector_accuracy"],
                         "base_mae": result["base_score_mae"], "base_rmse": result["base_score_rmse"],
                         "score_pairs": result["score_coverage"]["numerator"],
                         "score_denominator": result["score_coverage"]["denominator"],
                         "invalid_predictions": result["invalid_prediction_count"]})
    return pd.DataFrame(rows)


def component_table(metrics, split, *, model_kind="tfidf"):
    rows = []
    for scope, splits in metrics["models"][model_kind]["scopes"].items():
        result = splits[split]
        if result is None:
            continue
        for metric, values in result["per_metric"].items():
            rows.append({"scope": scope, "metric": metric, "n": values["sample_count"],
                         "accuracy": values["accuracy"], "macro_f1": values["macro_f1"]})
    return pd.DataFrame(rows)


def per_class_table(metrics, split, *, model_kind="tfidf"):
    rows = []
    for scope, splits in metrics["models"][model_kind]["scopes"].items():
        result = splits[split]
        if result is None:
            continue
        for metric, values in result["per_metric"].items():
            for label, item in values["per_class"].items():
                rows.append({"scope": scope, "metric": metric, "label": label, **item})
    return pd.DataFrame(rows)
