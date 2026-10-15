"""Offline, staged Phase 2 workflow: verify -> select on validation -> locked test.

Run from the repository root. No source data, split, or external API is modified.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

import pandas as pd
import yaml

from src.collect.verify_phase1 import verify
from src.model.baseline import (
    load_artifact, predict_labels, preprocess_descriptions, save_artifact, train_baseline,
)
from src.model.data_validation import LABEL_ORDER
from src.model.evaluate import evaluate_predictions
from src.model.predict import predict_frame


SELECTION_RULE = {
    "primary": "mean of eight validation macro-F1 values over all declared labels",
    "tie_tolerance": 1e-6,
    "tie_break": "shorter training_seconds, then declared candidate order",
    "candidates": [{"C": 1.0}, {"C": 0.5}],
    "test_access": "only after artifact and configuration have been locked",
}


def sha256(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def load_release(config_path, manifest_path):
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    dataset = Path(config["data"]["dataset"])
    folder = Path(config["data"]["metadata"]).parent
    if not dataset.is_file() or not (folder / "metadata.json").is_file():
        raise FileNotFoundError(
            f"Locked Phase 1 release missing: {folder}. Receive the original "
            "phase1_v1_20261010.zip; do not substitute the pilot or rebuild the split."
        )
    metadata = verify(folder, Path(manifest_path))
    if metadata["dataset_version"] != config["data"]["dataset_version"]:
        raise ValueError("Config and verified release dataset_version disagree")
    if dataset.resolve() != (folder / "ml_cohort.parquet").resolve():
        raise ValueError("Training input must be the verified release ml_cohort.parquet")
    frame = pd.read_parquet(dataset)
    split_counts = {key: int(frame.split.eq(key).sum()) for key in ("train", "validation", "test")}
    if split_counts != {"train": 28815, "validation": 19606, "test": 18821}:
        raise ValueError(f"Locked v1 split counts disagree: {split_counts}")
    if len(frame) != sum(split_counts.values()):
        raise ValueError("Unknown or missing split in locked cohort")
    return config, frame, metadata


def choose_candidate(candidates):
    if not 1 <= len(candidates) <= 2:
        raise ValueError("Declare one or two candidates before evaluation")
    best = candidates[0]
    for candidate in candidates[1:]:
        delta = candidate["validation_mean_macro_f1"] - best["validation_mean_macro_f1"]
        if delta > SELECTION_RULE["tie_tolerance"] or (
            abs(delta) <= SELECTION_RULE["tie_tolerance"]
            and candidate["training_seconds"] < best["training_seconds"]
        ):
            best = candidate
    return best


def _validate_lock(lock, *, artifact_path, config_path, dataset_path):
    for key, path in (("artifact_sha256", artifact_path), ("config_sha256", config_path),
                      ("dataset_sha256", dataset_path)):
        if lock.get(key) != sha256(path):
            raise ValueError(f"Locked {key} changed; final evaluation refused")
    if lock.get("test_status") != "not_run":
        raise ValueError("Final test has already started; inspect its existing record rather than rerun")


def select(config_path, manifest_path):
    """Fit two train-only candidates and select exclusively from validation."""
    config, frame, metadata = load_release(config_path, manifest_path)
    artifact_path = Path(config["artifacts"]["baseline"])
    lock_path = artifact_path.parent / "phase2_lock.json"
    if artifact_path.exists() or lock_path.exists():
        raise FileExistsError("A model/lock already exists; preserve the recorded experiment")
    if frame.loc[frame.split.eq("validation")].empty:
        raise ValueError("Validation must be nonempty for model selection")
    # Publish the rule before fitting. Only train and validation enter this loop.
    write_json("reports/model_selection.json", {"status": "running", "rule": SELECTION_RULE})
    train = frame.loc[frame.split.eq("train")].copy()
    validation = frame.loc[frame.split.eq("validation")].copy()
    runs, fitted = [], []
    for index, overrides in enumerate(SELECTION_RULE["candidates"]):
        print(f"Training candidate {index + 1}/2 on {len(train)} train rows: {overrides}", flush=True)
        artifact = train_baseline(train, config, baseline_overrides=overrides,
                                  model_version=f"tfidf-v1-candidate-{index + 1}")
        prediction = predict_frame(artifact, validation, model_kind="tfidf")
        metrics = evaluate_predictions(validation, prediction,
                                       model_version=artifact["model_versions"]["tfidf"],
                                       dataset_version=metadata["dataset_version"])
        values = metrics["scopes"]["all_ml"]["validation"]["per_metric"]
        mean_f1 = sum(values[metric]["macro_f1"] for metric in LABEL_ORDER) / len(LABEL_ORDER)
        print(f"Candidate {index + 1}: validation mean macro-F1={mean_f1:.6f}, "
              f"training_seconds={artifact['training_seconds']:.2f}", flush=True)
        runs.append({"candidate": index + 1, "overrides": overrides,
                     "validation_mean_macro_f1": mean_f1,
                     "training_seconds": artifact["training_seconds"], "validation": metrics})
        fitted.append(artifact)
    best = choose_candidate(runs)
    artifact = fitted[best["candidate"] - 1]
    # A fixed structural scan is permitted; no prediction/label error on test is read.
    artifact["preprocessing_audit"] = {"policy_version": "mask_explicit_cvss_v1"}
    for split in ("train", "validation", "test"):
        _, artifact["preprocessing_audit"][split] = preprocess_descriptions(
            frame.loc[frame.split.eq(split), "description"]
        )
    artifact["selection"] = {"rule": SELECTION_RULE, "chosen_candidate": best["candidate"]}
    save_artifact(artifact, artifact_path)
    loaded = load_artifact(artifact_path)
    pd.testing.assert_frame_equal(predict_labels(artifact, validation.description.head(5)),
                                  predict_labels(loaded, validation.description.head(5)))
    lock = {"schema_version": "1.0", "locked_at": datetime.now(timezone.utc).isoformat(),
            "artifact": str(artifact_path), "artifact_sha256": sha256(artifact_path),
            "config_sha256": sha256(config_path),
            "dataset_sha256": sha256(config["data"]["dataset"]),
            "dataset_version": metadata["dataset_version"],
            "model_versions": artifact["model_versions"], "chosen_candidate": best["candidate"],
            "test_status": "not_run"}
    write_json(lock_path, lock)
    write_json("reports/model_selection.json", {"status": "locked", "rule": SELECTION_RULE,
                                               "chosen_candidate": best["candidate"], "candidates": runs})
    validation_predictions = pd.concat([predict_frame(artifact, validation, model_kind=kind)
                                        for kind in ("dummy", "tfidf")], ignore_index=True)
    validation_predictions.to_csv(artifact_path.parent / "validation_predictions.csv", index=False)
    _export_validation_errors(validation, validation_predictions, artifact)
    _write_handoff(artifact, lock, config, final=False)
    return lock


def _export_validation_errors(truth, predictions, artifact):
    selected = predictions.loc[predictions.model_version.eq(artifact["model_versions"]["tfidf"])]
    joined = truth.merge(selected, on=["cve_id", "split", "dataset_version"], validate="one_to_one")
    wrong = pd.Series(False, index=joined.index)
    for metric in LABEL_ORDER:
        wrong |= joined[metric].ne(joined[f"pred_{metric}"])
    errors = joined.loc[wrong | joined.prediction_error.fillna("").ne("")].sort_values("cve_id")
    columns = ["cve_id", "split", "dataset_version", "model_version", "description", *LABEL_ORDER,
               *[f"pred_{metric}" for metric in LABEL_ORDER], "cvss_vector", "predicted_vector",
               "cvss_base_score", "predicted_base_score", "prediction_error"]
    Path("reports").mkdir(exist_ok=True)
    errors.loc[:, columns].to_csv("reports/validation_errors.csv", index=False)
    # A deterministic queue for N2; never claim that exporting it is human review.
    errors.loc[:, columns].head(10).to_csv("reports/validation_errors_n2.csv", index=False)


def _write_handoff(artifact, lock, config, *, final):
    paths = [Path(config["artifacts"]["baseline"]), Path("requirements-model.txt"),
             Path("reports/model_selection.json"), Path("reports/validation_errors_n2.csv")]
    if final:
        paths.extend([Path(config["artifacts"]["predictions"]), Path(config["artifacts"]["metrics"])])
    validation = pd.read_parquet(config["data"]["dataset"],
                                 columns=["cve_id", "split", "description"])
    validation = validation.loc[validation.split.eq("validation")].sort_values("cve_id").head(5)
    smoke_cases = []
    for _, row in validation.iterrows():
        case = {"cve_id": row.cve_id, "split": "validation", "description": row.description, "expected": {}}
        for kind in ("dummy", "tfidf"):
            prediction = predict_frame(artifact, pd.DataFrame([row]), model_kind=kind,
                                       prediction_usage="demo").iloc[0]
            case["expected"][kind] = {
                **{f"pred_{metric}": str(prediction[f"pred_{metric}"]) for metric in LABEL_ORDER},
                "predicted_vector": str(prediction.predicted_vector),
                "predicted_base_score": float(prediction.predicted_base_score),
                "vector_valid": bool(prediction.vector_valid),
                "prediction_error": str(prediction.prediction_error),
            }
        smoke_cases.append(case)
    write_json("docs/handoffs/phase-2-model.json", {
        "status": "final_evaluated" if final else "validation_selected_test_not_run",
        "dataset_version": artifact["dataset_version"], "model_versions": artifact["model_versions"],
        "lock": lock, "files": {str(path): {"bytes": path.stat().st_size, "sha256": sha256(path)}
                                for path in paths},
        "library_versions": artifact["library_versions"],
        "reproduction_smoke": {"usage": "demo_validation_reproduction", "cases": smoke_cases},
        "n2_validation_review": "pending_independent_review",
        "n1_second_machine_reproduction": "not_run",
        "distilbert": {"status": "not_run", "reason": "D05 and backend/time budget not confirmed"},
    })


def final_evaluation(config_path, manifest_path):
    config, frame, _ = load_release(config_path, manifest_path)
    artifact_path = Path(config["artifacts"]["baseline"])
    lock_path = artifact_path.parent / "phase2_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    _validate_lock(lock, artifact_path=artifact_path, config_path=config_path,
                   dataset_path=config["data"]["dataset"])
    artifact = load_artifact(artifact_path)
    # This irreversible audit marker precedes any final-test prediction.
    lock["test_status"] = "running"
    lock["test_started_at"] = datetime.now(timezone.utc).isoformat()
    write_json(lock_path, lock)
    held_out = frame.loc[frame.split.isin(["validation", "test"])].copy()
    tables, reports = [], {}
    for kind in ("dummy", "tfidf"):
        prediction = predict_frame(artifact, held_out, model_kind=kind)
        tables.append(prediction)
        reports[kind] = evaluate_predictions(held_out, prediction,
                                             model_version=artifact["model_versions"][kind],
                                             dataset_version=artifact["dataset_version"])
    predictions = pd.concat(tables, ignore_index=True)
    path = Path(config["artifacts"]["predictions"])
    path.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(path, index=False)
    write_json(config["artifacts"]["metrics"], {
        "status": "complete", "dataset_version": artifact["dataset_version"],
        "python_version": platform.python_version(), "selection": artifact["selection"],
        "artifact_sha256": lock["artifact_sha256"], "models": reports,
        "distilbert": {"status": "not_run", "reason": "D05 pending"},
    })
    lock["test_status"] = "complete"
    lock["test_completed_at"] = datetime.now(timezone.utc).isoformat()
    write_json(lock_path, lock)
    _write_handoff(artifact, lock, config, final=True)
    return {"result": "PHASE2 FINAL EVALUATION COMPLETE", "predictions": len(predictions), "lock": lock}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["select", "final"])
    parser.add_argument("--config", type=Path, default=Path("config/model.yaml"))
    parser.add_argument("--manifest", type=Path, default=Path("docs/handoffs/phase-1-v1.json"))
    args = parser.parse_args()
    try:
        result = (select if args.stage == "select" else final_evaluation)(args.config, args.manifest)
    except (ValueError, FileNotFoundError, FileExistsError) as error:
        parser.exit(2, f"Phase 2 stopped: {error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
