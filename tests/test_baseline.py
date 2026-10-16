"""Small offline training checks; never train or evaluate the release cohort."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

import pandas as pd
from pandas.testing import assert_frame_equal
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
import yaml

from src.model.baseline import (
    PREPROCESSING_POLICY, load_artifact, predict_labels, prepare_baseline_inputs,
    preprocess_descriptions, save_artifact, train_baseline,
)
from src.model.data_validation import LABEL_ORDER, ModelInputError


VERSION = "baseline-unit-v1"
DEFAULT_LABELS = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                  "S": "U", "C": "H", "I": "H", "A": "H"}
ALTERNATIVE_LABELS = {"AV": "L", "AC": "H", "PR": "L", "UI": "R",
                      "S": "C", "C": "N", "I": "N", "A": "N"}


def sample_frame():
    rows = []
    splits = ["train"] * 6 + ["validation", "test"]
    for index, split in enumerate(splits):
        labels = DEFAULT_LABELS if index < 4 else ALTERNATIVE_LABELS
        text = ("remote unauthenticated network overflow" if index < 4
                else "local authenticated complex interactive modification")
        if split != "train":
            text = f"{split}exclusive hiddenword"
        rows.append({
            "cve_id": f"CVE-2024-{1000 + index}", "description": text,
            "vuln_status": "Analyzed", "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/" + "/".join(f"{key}:{value}" for key, value in labels.items()),
            **labels, "split": split, "dataset_version": VERSION,
            "epss": "leakagefromepss", "is_kev": "leakagefromkev",
            "product": "leakagefromproduct",
        })
    return pd.DataFrame(rows)


def sample_config():
    with Path("config/model.yaml").open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    config["data"]["dataset_version"] = VERSION
    config["baseline"]["min_df"] = 1
    config["baseline"]["max_features"] = 100
    return config


class BaselineTests(unittest.TestCase):
    def test_train_only_arrow_strings_keep_empty_audit_splits(self):
        frame = sample_frame().loc[lambda value: value.split.eq("train")].copy()
        frame["description"] = frame.description.astype("string[pyarrow]")
        artifact = train_baseline(frame, sample_config())
        self.assertEqual(artifact["preprocessing_audit"]["validation"]["rows"], 0)
        self.assertEqual(artifact["preprocessing_audit"]["test"]["rows"], 0)
        self.assertTrue(predict_labels(artifact, pd.Series([], dtype="string[pyarrow]")).empty)

    @classmethod
    def setUpClass(cls):
        cls.frame = sample_frame()
        cls.config = sample_config()
        cls.artifact = train_baseline(cls.frame, cls.config, model_version="unit-tfidf-v1")

    def test_description_only_train_vocabulary_and_classifiers(self):
        artifact = self.artifact
        vocabulary = artifact["vectorizer"].vocabulary_
        self.assertIn("authenticated", vocabulary)
        self.assertIn("remote", vocabulary)
        for forbidden in ("validationexclusive", "testexclusive", "hiddenword",
                          "leakagefromepss", "leakagefromkev", "leakagefromproduct", "cve"):
            self.assertNotIn(forbidden, vocabulary)
        self.assertEqual(artifact["training"]["train_rows"], 6)
        self.assertEqual(set(artifact["classifiers"]), set(LABEL_ORDER))
        for classifier in artifact["classifiers"].values():
            self.assertIsInstance(classifier, LogisticRegression)
            self.assertEqual(classifier.class_weight, "balanced")
        inputs = prepare_baseline_inputs(self.frame, dataset_version=VERSION)
        self.assertEqual(inputs.features.name, "description")

    def test_fit_does_not_modify_source_frame_or_config(self):
        frame = self.frame.copy(deep=True)
        config = deepcopy(self.config)
        train_baseline(frame, config, baseline_overrides={"C": 0.5}, model_version="unit-other")
        assert_frame_equal(frame, self.frame)
        self.assertEqual(config, self.config)

    def test_dummy_uses_train_majority(self):
        prediction = predict_labels(self.artifact, ["unseen unknown description"], model_kind="dummy")
        self.assertEqual(prediction.iloc[0].to_dict(),
                         {f"pred_{metric}": label for metric, label in DEFAULT_LABELS.items()})

    def test_single_class_fallback_logs_and_predicts_constant(self):
        frame = self.frame.loc[self.frame.split.eq("train")].copy()
        frame = frame.iloc[:3].copy()
        with self.assertLogs("src.model.baseline", level="WARNING") as logs:
            artifact = train_baseline(frame, self.config)
        self.assertEqual(set(artifact["fallback_metrics"]), set(LABEL_ORDER))
        self.assertEqual(len(logs.output), 8)
        self.assertTrue(all(isinstance(head, DummyClassifier) for head in artifact["classifiers"].values()))
        prediction = predict_labels(artifact, ["never seen local text"])
        self.assertEqual(prediction.iloc[0].to_dict(),
                         {f"pred_{metric}": label for metric, label in DEFAULT_LABELS.items()})

    def test_save_load_preserves_both_models_and_metadata(self):
        descriptions = pd.Series(["remote overflow", "local authenticated"], index=[52, 11])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models" / "baseline.joblib"
            save_artifact(self.artifact, path)
            loaded = load_artifact(path)
            for kind in ("tfidf", "dummy"):
                assert_frame_equal(predict_labels(self.artifact, descriptions, model_kind=kind),
                                   predict_labels(loaded, descriptions, model_kind=kind))
        for key in ("dataset_version", "label_order", "config", "seed", "library_versions",
                    "model_versions", "preprocessing_audit"):
            self.assertEqual(loaded[key], self.artifact[key])
        self.assertNotEqual(loaded["model_versions"]["dummy"], loaded["model_versions"]["tfidf"])

    def test_explicit_cvss_masking_audited_and_business_words_preserved(self):
        vector = self.frame.iloc[0].cvss_vector
        descriptions = pd.Series([
            f"remote authenticated weakness {vector}; CVSS v3.1 base score: 9.8",
            "Local issue; CVSS score of 4.2. CVSS: 7.5.",
            "Only CVSS 3.1 version, no numerical label. network privilege",
        ])
        masked, audit = preprocess_descriptions(descriptions)
        self.assertIn("remote authenticated", masked.iloc[0])
        self.assertIn("network privilege", masked.iloc[2])
        for secret in (vector, "9.8", "4.2", "7.5"):
            self.assertNotIn(secret, " ".join(masked))
        self.assertIn("CVSS 3.1", masked.iloc[2])
        self.assertEqual(audit["changed_rows"], 2)
        self.assertEqual(audit["vector_occurrences"], 1)
        self.assertEqual(audit["score_occurrences"], 3)
        bare_vector = vector.removeprefix("CVSS:3.1/")
        legacy_vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        masked_vectors, vector_audit = preprocess_descriptions([bare_vector, legacy_vector])
        self.assertTrue(all(value.strip() == "CVSS_VECTOR_MASK" for value in masked_vectors))
        self.assertEqual(vector_audit["vector_occurrences"], 2)
        frame = self.frame.copy(deep=True)
        frame.loc[0, "description"] = descriptions.iloc[0]
        artifact = train_baseline(frame, self.config)
        self.assertEqual(artifact["preprocessing_audit"]["train"]["changed_rows"], 1)
        self.assertEqual(artifact["preprocessing"]["policy_version"], PREPROCESSING_POLICY)
        assert_frame_equal(predict_labels(artifact, [descriptions.iloc[0]]),
                           predict_labels(artifact, [masked.iloc[0]]))

    def test_empty_train_wrong_version_and_split_fail(self):
        with self.assertRaises(ModelInputError):
            train_baseline(self.frame.iloc[:0], self.config)
        with self.assertRaisesRegex(ValueError, "Training split is empty"):
            train_baseline(self.frame.loc[self.frame.split.ne("train")], self.config)
        wrong_version = self.frame.assign(dataset_version="different-release")
        with self.assertRaises(ModelInputError) as error:
            train_baseline(wrong_version, self.config)
        self.assertTrue(all(issue["code"] == "dataset_version_mismatch" for issue in error.exception.issues))
        with self.assertRaisesRegex(ValueError, "frozen"):
            train_baseline(self.frame.drop(columns="split"), self.config)
        with self.assertRaisesRegex(ValueError, "frozen"):
            train_baseline(self.frame.assign(split="random"), self.config)

    def test_configuration_errors(self):
        cases = [({"C": 0}, "positive"), ({"class_weight": None}, "balanced"),
                 ({"min_df": True}, "min_df"), ({"ngram_range": [2, 1]}, "increasing"),
                 ({"invented": 4}, "Unsupported")]
        for override, expected in cases:
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, expected):
                train_baseline(self.frame, self.config, baseline_overrides=override)
        config = deepcopy(self.config)
        config["data"]["input_column"] = "epss"
        with self.assertRaisesRegex(ValueError, "Only description"):
            train_baseline(self.frame, config)
        config = deepcopy(self.config)
        config["label_order"]["AV"] = ["N", "L"]
        with self.assertRaisesRegex(ValueError, "label_order"):
            train_baseline(self.frame, config)
        with self.assertRaisesRegex(ValueError, "model_version"):
            train_baseline(self.frame, self.config, model_version=" ")

    def test_inference_empty_invalid_and_duplicate_index(self):
        empty = predict_labels(self.artifact, [])
        self.assertEqual(list(empty), [f"pred_{metric}" for metric in LABEL_ORDER])
        self.assertEqual(len(empty), 0)
        for bad in ([None], ["  "], [3]):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "nonblank"):
                predict_labels(self.artifact, bad)
        with self.assertRaises(TypeError):
            predict_labels(self.artifact, self.frame)
        with self.assertRaisesRegex(ValueError, "model_kind"):
            predict_labels(self.artifact, ["text"], model_kind="other")
        prediction = predict_labels(self.artifact, pd.Series(["remote overflow", "local authenticated"], index=[2, 2]))
        self.assertEqual(prediction.index.tolist(), [2, 2])

    def test_artifact_wrong_schema_or_preprocessing_is_rejected(self):
        artifact = dict(self.artifact)
        artifact["artifact_schema_version"] = "99"
        with self.assertRaisesRegex(ValueError, "schema"):
            predict_labels(artifact, ["text"])
        artifact = dict(self.artifact)
        artifact["preprocessing"] = {"policy_version": "unrecognized"}
        with self.assertRaisesRegex(ValueError, "preprocessing"):
            predict_labels(artifact, ["text"])


if __name__ == "__main__":
    unittest.main()
