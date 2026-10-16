"""Description-only Dummy and TF-IDF baselines for the frozen Phase 1 cohort.

Only rows already assigned to ``train`` are fitted. No split assignment,
deduplication, model selection, evaluation or network access happens here.
"""

from collections.abc import Mapping
from copy import deepcopy
import importlib.metadata
import logging
import math
from pathlib import Path
import platform
import re
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from src.model.data_validation import (
    LABEL_ORDER, ModelInputs, TARGET_METRICS, validate_model_input,
)


LOGGER = logging.getLogger(__name__)
ARTIFACT_SCHEMA_VERSION = "1.0"
PREPROCESSING_POLICY = "mask_explicit_cvss_v1"

# Mask explicit numerical labels, preserving ordinary vulnerability vocabulary
# such as "remote", "authenticated", "privilege" and "network". This fixed
# policy is applied before the vectorizer in both training and inference.
_VECTOR = re.compile(
    r"\bCVSS:(?:2\.0|3\.[01]|4\.0)(?:/[A-Za-z][A-Za-z0-9]*:[A-Za-z0-9.]+)+",
    re.IGNORECASE,
)
_LEGACY_VECTOR = re.compile(
    r"\bAV:[NALP]/AC:[LMH]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\b",
    re.IGNORECASE,
)
_BARE_VECTOR = re.compile(
    r"\bAV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
    r"(?:/[A-Za-z][A-Za-z0-9]*:[A-Za-z0-9.]+)*\b",
    re.IGNORECASE,
)
_SCORE = re.compile(
    r"\bCVSS(?:\s*(?:v(?:ersion)?\s*)?(?:2\.0|3\.[01]|4\.0))?"
    r"\s*(?:(?:base\s+)?score\s*(?:of\s+|is\s+|[:=]\s*)?|[:=]\s*)"
    r"(?:10(?:\.0)?|[0-9](?:\.[0-9])?)(?!\d|\.\d)(?:\s*/\s*10)?",
    re.IGNORECASE,
)


def prepare_baseline_inputs(frame, *, dataset_version=None) -> ModelInputs:
    """Keep the Phase 1 validation API and expose only description features."""
    return validate_model_input(frame, dataset_version=dataset_version)


def _description_series(descriptions):
    if isinstance(descriptions, pd.DataFrame):
        raise TypeError("Pass description text, not a DataFrame of features")
    if isinstance(descriptions, pd.Series):
        result = descriptions.copy(deep=True)
    elif isinstance(descriptions, str):
        result = pd.Series([descriptions], dtype="object", name="description")
    else:
        try:
            result = pd.Series(list(descriptions), dtype="object", name="description")
        except TypeError as exc:
            raise TypeError("Descriptions must be text or an iterable of text") from exc
    if result.empty:
        return result
    valid = result.map(lambda value: isinstance(value, str) and bool(value.strip()))
    if not valid.all():
        raise ValueError("Every description must be nonblank text")
    return result


def preprocess_descriptions(descriptions):
    """Return masked text and counts under the fixed train/inference policy."""
    series = _description_series(descriptions)
    counts = {"rows": len(series), "changed_rows": 0, "vector_rows": 0,
              "score_rows": 0, "vector_occurrences": 0, "score_occurrences": 0}

    def mask(value):
        text, vector_count = _VECTOR.subn(" CVSS_VECTOR_MASK ", value)
        text, legacy_count = _LEGACY_VECTOR.subn(" CVSS_VECTOR_MASK ", text)
        text, bare_count = _BARE_VECTOR.subn(" CVSS_VECTOR_MASK ", text)
        text, score_count = _SCORE.subn(" CVSS_SCORE_MASK ", text)
        vector_count += legacy_count + bare_count
        counts["vector_occurrences"] += vector_count
        counts["score_occurrences"] += score_count
        counts["vector_rows"] += int(vector_count > 0)
        counts["score_rows"] += int(score_count > 0)
        counts["changed_rows"] += int(vector_count + score_count > 0)
        return text

    return series.map(mask), counts


def _positive_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _resolved_config(config, baseline_overrides):
    if not isinstance(config, Mapping):
        raise TypeError("config must be a mapping loaded from config/model.yaml")
    resolved = deepcopy(dict(config))
    for key in ("data", "label_order", "baseline", "dummy"):
        if not isinstance(resolved.get(key), Mapping):
            raise ValueError(f"config.{key} must be a mapping")
        resolved[key] = dict(resolved[key])
    data = resolved["data"]
    version = data.get("dataset_version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("config.data.dataset_version must be nonblank text")
    if data.get("input_column") != "description":
        raise ValueError("Only description may be used as an input feature")
    if data.get("cvss_version") != "3.1":
        raise ValueError("Only CVSS version 3.1 is supported")
    if data.get("split_key", "split") != "split":
        raise ValueError("Use the frozen split column; do not assign another split")
    if list(data.get("target_metrics", [])) != list(TARGET_METRICS):
        raise ValueError("target_metrics must match the eight canonical metric names in order")
    if list(resolved["label_order"]) != list(LABEL_ORDER) or any(
        list(resolved["label_order"].get(metric, [])) != list(values)
        for metric, values in LABEL_ORDER.items()
    ):
        raise ValueError("label_order must match the complete ordered CVSS 3.1 label map")
    seed = resolved.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**32:
        raise ValueError("seed must be an integer in [0, 2**32)")
    if resolved["dummy"].get("strategy") != "most_frequent":
        raise ValueError("Dummy strategy must be most_frequent")

    allowed = {"vectorizer", "ngram_range", "min_df", "max_features", "classifier",
               "class_weight", "max_iter", "single_class_fallback", "C", "solver",
               "tol", "lowercase", "sublinear_tf", "strip_accents", "preprocessing"}
    if baseline_overrides is not None:
        if not isinstance(baseline_overrides, Mapping):
            raise TypeError("baseline_overrides must be a mapping")
        unknown = set(baseline_overrides) - allowed
        if unknown:
            raise ValueError(f"Unsupported baseline overrides: {sorted(unknown)}")
        resolved["baseline"].update(deepcopy(dict(baseline_overrides)))
    baseline = resolved["baseline"]
    unknown = set(baseline) - allowed
    if unknown:
        raise ValueError(f"Unsupported baseline configuration: {sorted(unknown)}")
    defaults = {"C": 1.0, "solver": "lbfgs", "tol": 1e-4, "preprocessing": PREPROCESSING_POLICY,
                "lowercase": True, "sublinear_tf": False, "strip_accents": None}
    for key, value in defaults.items():
        baseline.setdefault(key, value)
    required = {"vectorizer": "tfidf", "classifier": "logistic_regression",
                "class_weight": "balanced", "single_class_fallback": "dummy"}
    for key, value in required.items():
        if baseline.get(key) != value:
            raise ValueError(f"baseline.{key} must be {value!r}")
    if baseline["preprocessing"] != PREPROCESSING_POLICY:
        raise ValueError(f"baseline.preprocessing must be {PREPROCESSING_POLICY!r}")
    ngrams = baseline.get("ngram_range")
    if not isinstance(ngrams, (list, tuple)) or len(ngrams) != 2:
        raise ValueError("baseline.ngram_range must contain two positive integers")
    for value in ngrams:
        _positive_int(value, "baseline.ngram_range values")
    if ngrams[0] > ngrams[1]:
        raise ValueError("baseline.ngram_range must be increasing")
    min_df = baseline.get("min_df")
    if isinstance(min_df, bool) or not (
        isinstance(min_df, int) and min_df >= 1
        or isinstance(min_df, float) and 0 < min_df <= 1
    ):
        raise ValueError("baseline.min_df must be a positive integer or a fraction in (0, 1]")
    if baseline.get("max_features") is not None:
        _positive_int(baseline["max_features"], "baseline.max_features")
    _positive_int(baseline.get("max_iter"), "baseline.max_iter")
    for key in ("C", "tol"):
        value = baseline[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"baseline.{key} must be finite and positive")
    if baseline["solver"] not in {"lbfgs", "newton-cg", "newton-cholesky", "sag", "saga"}:
        raise ValueError("baseline.solver must support multiclass LogisticRegression")
    for key in ("lowercase", "sublinear_tf"):
        if not isinstance(baseline[key], bool):
            raise ValueError(f"baseline.{key} must be boolean")
    if baseline["strip_accents"] not in {None, "ascii", "unicode"}:
        raise ValueError("baseline.strip_accents must be null, ascii or unicode")
    resolved["preprocessing"] = {"policy_version": PREPROCESSING_POLICY}
    return resolved


def _library_versions():
    versions = {"python": platform.python_version()}
    for package in ("scikit-learn", "joblib", "numpy", "pandas", "scipy", "PyYAML", "pyarrow"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    return versions


def train_baseline(frame, config, *, baseline_overrides=None, model_version=None):
    """Fit Dummy and shared TF-IDF/eight heads on preassigned train rows only.

    The submitted frame is validated without changing it. The resolved config,
    library versions, fixed masking audit and any one-class fallbacks accompany
    the fitted objects. Model selection belongs to the validation orchestrator.
    """
    started = time.perf_counter()
    resolved = _resolved_config(config, baseline_overrides)
    version = resolved["data"]["dataset_version"]
    inputs = prepare_baseline_inputs(frame, dataset_version=version)
    if "split" not in frame or not frame["split"].isin(["train", "validation", "test"]).all():
        raise ValueError("Every submitted row requires a frozen train/validation/test split")
    train_mask = frame["split"].eq("train").to_numpy()
    if not train_mask.any():
        raise ValueError("Training split is empty")
    if model_version is None:
        model_version = "t08-tfidf-lr-v1"
    if not isinstance(model_version, str) or not model_version.strip():
        raise ValueError("model_version must be nonblank text")

    text, audit = preprocess_descriptions(inputs.features)
    preprocessing_audit = {"policy_version": PREPROCESSING_POLICY, "all_submitted": audit}
    for split in ("train", "validation", "test"):
        _, preprocessing_audit[split] = preprocess_descriptions(
            inputs.features.iloc[np.flatnonzero(frame["split"].eq(split).to_numpy())]
        )
    train_positions = np.flatnonzero(train_mask)
    train_text = text.iloc[train_positions]
    targets = inputs.targets.iloc[train_positions]
    params = resolved["baseline"]
    vectorizer = TfidfVectorizer(
        ngram_range=tuple(params["ngram_range"]), min_df=params["min_df"],
        max_features=params.get("max_features"), lowercase=params["lowercase"],
        sublinear_tf=params["sublinear_tf"], strip_accents=params["strip_accents"],
    )
    try:
        matrix = vectorizer.fit_transform(train_text.tolist())
    except ValueError as exc:
        raise ValueError(f"Cannot fit TF-IDF on training descriptions: {exc}") from exc
    classifiers, dummy, fallback_metrics = {}, {}, []
    dummy_matrix = np.zeros((len(targets), 1), dtype=np.uint8)
    for metric in TARGET_METRICS:
        labels = targets[metric].to_numpy(dtype=str)
        dummy[metric] = DummyClassifier(strategy="most_frequent", random_state=resolved["seed"])
        dummy[metric].fit(dummy_matrix, labels)
        if len(np.unique(labels)) == 1:
            classifier = DummyClassifier(strategy="constant", constant=str(labels[0]),
                                         random_state=resolved["seed"])
            fallback_metrics.append(metric)
            LOGGER.warning("Metric %s has one training class %s; using constant Dummy fallback",
                           metric, labels[0])
        else:
            classifier = LogisticRegression(
                C=params["C"], solver=params["solver"], tol=params["tol"],
                class_weight="balanced", max_iter=params["max_iter"],
                random_state=resolved["seed"],
            )
        classifiers[metric] = classifier.fit(matrix, labels)
    elapsed = time.perf_counter() - started
    return {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "dataset_version": version, "model_version": model_version,
        "model_versions": {"dummy": f"{model_version}-dummy", "tfidf": model_version},
        "label_order": {metric: list(values) for metric, values in LABEL_ORDER.items()},
        "config": resolved, "seed": resolved["seed"], "library_versions": _library_versions(),
        "vectorizer": vectorizer, "classifiers": classifiers, "dummy": dummy,
        "preprocessing": {"policy_version": PREPROCESSING_POLICY},
        "preprocessing_audit": preprocessing_audit, "fallback_metrics": fallback_metrics,
        "training_seconds": elapsed,
        "training": {"train_rows": len(targets), "train_features": matrix.shape[1],
                     "fallback_metrics": fallback_metrics.copy(), "training_seconds": elapsed},
    }


def _validate_artifact(artifact):
    if not isinstance(artifact, dict):
        raise ValueError("Baseline artifact must be a dictionary")
    required = {"artifact_schema_version", "dataset_version", "model_versions", "label_order",
                "config", "seed", "library_versions", "vectorizer", "classifiers", "dummy",
                "preprocessing"}
    missing = required - set(artifact)
    if missing:
        raise ValueError(f"Baseline artifact is missing fields: {sorted(missing)}")
    if artifact["artifact_schema_version"] != ARTIFACT_SCHEMA_VERSION:
        raise ValueError("Unsupported baseline artifact schema version")
    if artifact["preprocessing"].get("policy_version") != PREPROCESSING_POLICY:
        raise ValueError("Unsupported artifact preprocessing policy")
    if artifact["label_order"] != {metric: list(values) for metric, values in LABEL_ORDER.items()}:
        raise ValueError("Artifact label_order does not match the CVSS 3.1 label map")
    if not isinstance(artifact["dataset_version"], str) or not artifact["dataset_version"].strip():
        raise ValueError("Artifact requires a dataset version")
    versions = artifact["model_versions"]
    if not isinstance(versions, Mapping) or set(versions) != {"dummy", "tfidf"} or any(
        not isinstance(value, str) or not value.strip() for value in versions.values()
    ) or len(set(versions.values())) != 2:
        raise ValueError("Artifact requires distinct nonblank dummy/tfidf model versions")
    for kind in ("classifiers", "dummy"):
        if not isinstance(artifact[kind], Mapping) or set(artifact[kind]) != set(TARGET_METRICS):
            raise ValueError(f"Artifact {kind} must contain all eight metric heads")


def predict_labels(artifact, descriptions, *, model_kind="tfidf"):
    """Predict eight labels with exactly the preprocessing used in training."""
    _validate_artifact(artifact)
    if model_kind not in {"tfidf", "dummy"}:
        raise ValueError("model_kind must be tfidf or dummy")
    text, _ = preprocess_descriptions(descriptions)
    columns = [f"pred_{metric}" for metric in TARGET_METRICS]
    if text.empty:
        return pd.DataFrame(index=text.index, columns=columns, dtype="object")
    if model_kind == "tfidf":
        matrix = artifact["vectorizer"].transform(text.tolist())
        classifiers = artifact["classifiers"]
    else:
        matrix = np.zeros((len(text), 1), dtype=np.uint8)
        classifiers = artifact["dummy"]
    return pd.DataFrame({f"pred_{metric}": classifiers[metric].predict(matrix)
                         for metric in TARGET_METRICS}, index=text.index)


def save_artifact(artifact, path):
    """Save the fitted model and reproducibility metadata to a joblib file."""
    _validate_artifact(artifact)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, target, compress=3)
    return target


def load_artifact(path):
    """Load and validate a *trusted* team-generated joblib artifact only."""
    artifact = joblib.load(Path(path))
    _validate_artifact(artifact)
    return artifact
