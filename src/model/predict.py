"""Description-only inference with the shared CVSS 3.1 Base scorer.

Failed rows are kept in the prediction contract so evaluation can count them.
Only load joblib artifacts created by the team from a trusted source.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pandas as pd

from src.collect.nvd_collector import parse_base_vector
from src.environmental.cvss_base import calculate_base_score
from src.model.baseline import load_artifact, predict_labels
from src.model.data_validation import LABEL_ORDER, TARGET_METRICS


PREDICTION_COLUMNS = (
    "cve_id", "split", "dataset_version", "model_version", "prediction_usage",
    *(f"pred_{metric}" for metric in TARGET_METRICS),
    "predicted_vector", "predicted_base_score", "vector_valid", "prediction_error",
)


def labels_to_vector(labels):
    """Build a strict Base vector, refusing missing and out-of-map labels."""
    if any(not isinstance(labels.get(metric), str) or labels[metric] not in allowed
           for metric, allowed in LABEL_ORDER.items()):
        raise ValueError("Missing or invalid predicted Base label")
    return "CVSS:3.1/" + "/".join(f"{metric}:{labels[metric]}" for metric in TARGET_METRICS)


def _nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def _artifact_version(artifact, model_kind):
    if model_kind not in {"dummy", "tfidf"}:
        raise ValueError("model_kind must be dummy or tfidf")
    version = artifact.get("model_versions", {}).get(model_kind)
    if not _nonblank(version) or not _nonblank(artifact.get("dataset_version")):
        raise ValueError("Artifact is missing model/dataset version")
    mapping = artifact.get("label_order", {})
    if set(mapping) != set(LABEL_ORDER) or any(tuple(mapping[k]) != v for k, v in LABEL_ORDER.items()):
        raise ValueError("Artifact label_order does not match the fixed CVSS 3.1 mapping")
    return version


def predict_frame(artifact, frame, *, model_kind="tfidf", prediction_usage="evaluation"):
    """Return one contract row per submitted ID, preserving inference failures.

    Evaluation accepts only validation/test rows of the artifact's dataset.
    Demo rows may omit split/version; they are explicitly excluded by the evaluator.
    Blank descriptions become error rows rather than disappearing.
    """
    model_version = _artifact_version(artifact, model_kind)
    if not isinstance(frame, pd.DataFrame) or not frame.columns.is_unique:
        raise ValueError("Inference input must be a DataFrame with unique columns")
    if prediction_usage not in {"evaluation", "demo"}:
        raise ValueError("prediction_usage must be evaluation or demo")
    required = {"cve_id", "description"}
    if prediction_usage == "evaluation":
        required |= {"split", "dataset_version"}
    if required - set(frame.columns):
        raise ValueError(f"Missing inference columns: {sorted(required - set(frame.columns))}")
    data = frame.reset_index(drop=True).copy()
    if not data.cve_id.map(_nonblank).astype(bool).all() or data.cve_id.duplicated().any():
        raise ValueError("Inference requires nonblank, unique cve_id values")
    if prediction_usage == "evaluation":
        if not data.cve_id.map(lambda value: re.fullmatch(r"CVE-\d{4}-\d{4,}", value) is not None).astype(bool).all():
            raise ValueError("Evaluation requires valid CVE identifiers")
        if not data["split"].isin(["validation", "test"]).all():
            raise ValueError("Evaluation predictions may contain only validation/test splits")
    if "dataset_version" in data and not data.dataset_version.eq(artifact["dataset_version"]).fillna(False).all():
        raise ValueError("Inference dataset_version does not match artifact")
    if "split" not in data:
        data["split"] = pd.NA
    output = pd.DataFrame(index=data.index, columns=PREDICTION_COLUMNS)
    output["cve_id"] = data.cve_id
    output["split"] = data["split"]
    output["dataset_version"] = artifact["dataset_version"]
    output["model_version"] = model_version
    output["prediction_usage"] = prediction_usage
    output["vector_valid"] = False
    output["predicted_base_score"] = float("nan")
    output["prediction_error"] = ""
    good = data.description.map(_nonblank).astype(bool)
    output.loc[~good, "prediction_error"] = "description_missing_or_invalid"

    def store_row(position, labels):
        for metric in TARGET_METRICS:
            output.at[position, f"pred_{metric}"] = labels.get(f"pred_{metric}", pd.NA)
        try:
            vector = labels_to_vector({metric: labels.get(f"pred_{metric}") for metric in TARGET_METRICS})
            output.at[position, "predicted_vector"] = vector
            output.at[position, "vector_valid"] = parse_base_vector(vector) is not None
            output.at[position, "predicted_base_score"] = calculate_base_score(vector)
        except Exception as exc:
            output.at[position, "prediction_error"] = f"prediction_failed: {type(exc).__name__}: {str(exc)[:400]}"

    positions = data.index[good].tolist()
    if positions:
        try:
            labels = predict_labels(artifact, data.loc[good, "description"], model_kind=model_kind)
            if len(labels) != len(positions):
                raise ValueError("Estimator returned an incorrect row count")
            for position, row in zip(positions, labels.to_dict(orient="records")):
                store_row(position, row)
        except Exception:
            # Isolate a bad row without dropping the remainder of the batch.
            for position in positions:
                try:
                    labels = predict_labels(artifact, data.loc[[position], "description"], model_kind=model_kind)
                    if len(labels) != 1:
                        raise ValueError("Estimator returned an incorrect row count")
                    store_row(position, labels.iloc[0].to_dict())
                except Exception as exc:
                    output.at[position, "prediction_error"] = f"inference_failed: {type(exc).__name__}: {str(exc)[:400]}"
    output["vector_valid"] = output.vector_valid.astype(bool)
    return output.loc[:, list(PREDICTION_COLUMNS)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="models/baseline.joblib")
    parser.add_argument("--model-kind", choices=["dummy", "tfidf"], default="tfidf")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="Evaluation CSV/Parquet with ID, split, description and dataset_version")
    source.add_argument("--description", help="A new description, explicitly marked as demo")
    parser.add_argument("--cve-id", default="demo-description", help="Optional identifier for a demo description")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    artifact = load_artifact(args.model)
    if args.description is not None:
        frame = pd.DataFrame({"cve_id": [args.cve_id], "description": [args.description]})
        result = predict_frame(artifact, frame, model_kind=args.model_kind, prediction_usage="demo")
    else:
        frame = pd.read_parquet(args.input) if args.input.suffix.lower() == ".parquet" else pd.read_csv(args.input)
        result = predict_frame(artifact, frame, model_kind=args.model_kind)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        result.to_csv(args.output, index=False)
    else:
        print(json.dumps(json.loads(result.to_json(orient="records")), ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
