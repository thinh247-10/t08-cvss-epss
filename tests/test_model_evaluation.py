"""Adversarial contract/evaluation checks using tiny, offline examples."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from pandas.testing import assert_frame_equal

from src.environmental.cvss_base import calculate_base_score
from src.model.data_validation import LABEL_ORDER
from src.model.evaluate import evaluate_predictions, main as evaluate_main
from src.model.predict import PREDICTION_COLUMNS, labels_to_vector, predict_frame


VERSION = "evaluation-fixture-v1"
MODEL = "fixture-model-v1"
BASE = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}


def truth_frame():
    rows = []
    for index, (split, scoped, changes) in enumerate([
        ("validation", True, {}),
        ("validation", False, {"AV": "A", "C": "N", "I": "N", "A": "N"}),
        ("test", True, {"AV": "P", "AC": "H", "PR": "H", "UI": "R"}),
    ]):
        labels = {**BASE, **changes}
        vector = labels_to_vector(labels)
        rows.append({"cve_id": f"CVE-2024-{1000 + index}", "description": f"Description number {index}",
                     "split": split, "dataset_version": VERSION, "in_scope": scoped,
                     "cvss_vector": vector, "cvss_base_score": calculate_base_score(vector),
                     "cvss_version": "3.1", **labels})
    return pd.DataFrame(rows)


def perfect_predictions(truth):
    rows = []
    for row in truth.to_dict(orient="records"):
        rows.append({"cve_id": row["cve_id"], "split": row["split"], "dataset_version": VERSION,
                     "model_version": MODEL, "prediction_usage": "evaluation",
                     **{f"pred_{metric}": row[metric] for metric in LABEL_ORDER},
                     "predicted_vector": row["cvss_vector"], "predicted_base_score": row["cvss_base_score"],
                     "vector_valid": True, "prediction_error": ""})
    return pd.DataFrame(rows, columns=PREDICTION_COLUMNS)


def artifact():
    return {"model_versions": {"tfidf": MODEL, "dummy": MODEL + "-dummy"},
            "dataset_version": VERSION, "label_order": copy.deepcopy(LABEL_ORDER)}


class EvaluationChecks(unittest.TestCase):
    def evaluate(self, truth, predictions):
        return evaluate_predictions(truth, predictions, model_version=MODEL, dataset_version=VERSION)

    def test_joins_shuffled_rows_by_id_and_keeps_support_zero(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth)
        original = predictions.copy(deep=True)
        expected = self.evaluate(truth, predictions)
        actual = self.evaluate(truth.iloc[[2, 0, 1]], predictions.iloc[[1, 2, 0]])
        self.assertEqual(expected, actual)
        assert_frame_equal(predictions, original)
        validation = actual["scopes"]["all_ml"]["validation"]
        self.assertEqual(validation["exact_vector_accuracy"], 1)
        self.assertEqual(validation["score_coverage"], {"numerator": 2, "denominator": 2, "fraction": 1})
        self.assertEqual(validation["base_score_mae"], 0)
        self.assertEqual(validation["per_metric"]["AV"]["macro_f1"], 0.5)
        self.assertEqual(validation["per_metric"]["AV"]["per_class"]["P"]["support"], 0)
        self.assertEqual(validation["per_metric"]["AV"]["confusion_matrix"],
                         [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]])
        self.assertEqual(actual["scopes"]["in_scope"]["validation"]["sample_count"], 1)
        json.dumps(actual, allow_nan=False)

    def test_invalid_predictions_count_once_and_remain_in_denominators(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth)
        predictions.loc[1, ["predicted_vector", "predicted_base_score", "pred_AV"]] = [None, None, "X"]
        predictions.loc[1, "vector_valid"] = False
        predictions.loc[1, "prediction_error"] = "inference failed"
        metrics = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertEqual(metrics["invalid_prediction_count"], 1)
        self.assertEqual(metrics["exact_vector_accuracy"], 0.5)
        self.assertEqual(metrics["exact_vector_denominator"], 2)
        self.assertEqual(metrics["score_coverage"], {"numerator": 1, "denominator": 2, "fraction": 0.5})
        component = metrics["per_metric"]["AV"]
        self.assertEqual(component["accuracy"], 0.5)
        self.assertEqual(component["macro_f1"], 0.25)
        self.assertEqual(component["coverage"]["numerator"], 1)
        self.assertEqual(component["status"], "incomplete")
        self.assertEqual(component["invalid_predictions_by_true_label"]["A"], 1)

    def test_score_corruption_and_false_success_are_invalid_predictions(self):
        truth = truth_frame()
        for column, value in [("predicted_base_score", 0.1), ("prediction_error", "scorer failed"),
                              ("vector_valid", False), ("pred_AV", "L")]:
            with self.subTest(column=column):
                predictions = perfect_predictions(truth)
                predictions.loc[0, column] = value
                report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
                self.assertEqual(report["invalid_prediction_count"], 1)
                self.assertEqual(report["exact_vector_accuracy"], 0.5)
                self.assertEqual(report["score_coverage"]["numerator"], 1)

    def test_null_predicted_labels_remain_errors_without_crashing(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth).astype({"pred_AV": "string"})
        predictions.loc[0, "pred_AV"] = pd.NA
        report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertEqual(report["invalid_prediction_count"], 1)
        self.assertEqual(report["per_metric"]["AV"]["coverage"]["numerator"], 1)

    def test_invalid_targets_reported_separately(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth)
        truth.loc[0, "cvss_vector"] = "CVSS:3.0/AV:N"
        report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertEqual(report["sample_count"], 2)
        self.assertEqual(report["invalid_target_count"], 1)
        self.assertEqual(report["invalid_prediction_count"], 0)
        self.assertEqual(report["exact_vector_denominator"], 1)
        self.assertEqual(report["score_coverage"]["denominator"], 1)
        # Zero impact is a legitimate score, including in coverage.
        self.assertEqual(report["base_score_mae"], 0)

    def test_no_valid_score_pairs_and_no_valid_targets_are_null(self):
        truth = truth_frame().iloc[:1].copy()
        predictions = perfect_predictions(truth)
        predictions.loc[0, "prediction_error"] = "unavailable"
        report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertIsNone(report["base_score_mae"])
        self.assertIsNone(report["base_score_rmse"])
        self.assertEqual(report["score_coverage"]["fraction"], 0)
        truth.loc[0, "AV"] = pd.NA
        report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertIsNone(report["exact_vector_accuracy"])
        self.assertIsNone(report["per_metric"]["AV"]["macro_f1"])
        self.assertEqual(report["invalid_target_count"], 1)

    def test_empty_split_scope_and_dataset_are_null(self):
        truth = truth_frame().iloc[:2].copy()
        truth["in_scope"] = False
        report = self.evaluate(truth, perfect_predictions(truth))
        self.assertIsNone(report["scopes"]["all_ml"]["test"])
        self.assertIsNone(report["scopes"]["in_scope"]["validation"])
        report = self.evaluate(truth.iloc[:0], perfect_predictions(truth).iloc[:0])
        self.assertTrue(all(value is None for scope in report["scopes"].values() for value in scope.values()))

    def test_empty_arrow_string_frames_preserve_schema_and_return_null_metrics(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth)
        truth = truth.astype({column: "string[pyarrow]" for column in truth.select_dtypes(include=["str", "object"]).columns}).iloc[:0]
        predictions = predictions.astype({column: "string[pyarrow]" for column in predictions.select_dtypes(include=["str", "object"]).columns}).iloc[:0]
        predicted = predict_frame(artifact(), truth)
        self.assertTrue(predicted.empty)
        self.assertEqual(list(predicted.columns), list(PREDICTION_COLUMNS))
        report = self.evaluate(truth, predictions)
        self.assertTrue(all(value is None for scope in report["scopes"].values() for value in scope.values()))

    def test_entirely_null_arrow_prediction_is_retained_as_one_error(self):
        truth = truth_frame().iloc[:1].copy()
        predictions = perfect_predictions(truth)
        for column in ("predicted_vector", "prediction_error", *(f"pred_{metric}" for metric in LABEL_ORDER)):
            predictions[column] = pd.Series([pd.NA], dtype="string[pyarrow]")
        predictions["vector_valid"] = pd.Series([pd.NA], dtype="boolean")
        predictions["predicted_base_score"] = pd.Series([pd.NA], dtype="Float64")
        report = self.evaluate(truth, predictions)["scopes"]["all_ml"]["validation"]
        self.assertEqual(report["invalid_prediction_count"], 1)
        self.assertEqual(report["exact_vector_accuracy"], 0)
        self.assertEqual(report["score_coverage"]["numerator"], 0)

    def test_missing_extra_duplicate_and_triple_ids_are_rejected(self):
        truth = truth_frame()
        predictions = perfect_predictions(truth)
        extra = predictions.iloc[[0]].copy()
        extra["cve_id"] = "CVE-2024-9999"
        for bad in [predictions.iloc[:2], pd.concat([predictions, extra]),
                    pd.concat([predictions, predictions.iloc[[0]]]),
                    pd.concat([predictions, predictions.iloc[[0]], predictions.iloc[[0]]])]:
            with self.subTest(rows=len(bad)):
                with self.assertRaisesRegex(ValueError, "ID mismatch|duplicate"):
                    self.evaluate(truth, bad)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.evaluate(pd.concat([truth, truth.iloc[[0]]]), predictions)

    def test_strict_provenance_schema_and_boolean_types(self):
        truth = truth_frame()
        for column, value in [("dataset_version", "wrong"), ("model_version", "wrong"),
                              ("split", "test"), ("prediction_usage", "demo")]:
            with self.subTest(column=column):
                predictions = perfect_predictions(truth)
                predictions.loc[0, column] = value
                with self.assertRaises(ValueError):
                    self.evaluate(truth, predictions)
        predictions = perfect_predictions(truth)
        with self.assertRaisesRegex(ValueError, "Missing predictions"):
            self.evaluate(truth, predictions.drop(columns="pred_A"))
        with self.assertRaisesRegex(ValueError, "unique columns"):
            self.evaluate(truth, pd.concat([predictions, predictions[["pred_A"]]], axis=1))
        predictions["vector_valid"] = "False"
        with self.assertRaisesRegex(ValueError, "booleans"):
            self.evaluate(truth, predictions)
        truth["in_scope"] = "False"
        with self.assertRaisesRegex(ValueError, "in_scope"):
            self.evaluate(truth, perfect_predictions(truth))

    def test_cli_csv_roundtrip_preserves_cvss_version(self):
        truth = truth_frame()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            truth.to_csv(folder / "truth.csv", index=False)
            perfect_predictions(truth).to_csv(folder / "predictions.csv", index=False)
            evaluate_main(["--truth", str(folder / "truth.csv"), "--predictions", str(folder / "predictions.csv"),
                           "--model-version", MODEL, "--dataset-version", VERSION, "--output", str(folder / "metrics.json")])
            result = json.loads((folder / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(result["scopes"]["all_ml"]["validation"]["invalid_target_count"], 0)


class PredictionChecks(unittest.TestCase):
    @staticmethod
    def labels(_artifact, descriptions, **_kwargs):
        return pd.DataFrame([{f"pred_{metric}": value for metric, value in BASE.items()} for _ in descriptions])

    @patch("src.model.predict.predict_labels", side_effect=labels)
    def test_schema_shared_scorer_and_failed_description_preserved(self, predict):
        frame = truth_frame().iloc[:2].copy()
        frame.loc[1, "description"] = "  "
        result = predict_frame(artifact(), frame)
        self.assertEqual(list(result.columns), list(PREDICTION_COLUMNS))
        self.assertEqual(result.cve_id.tolist(), frame.cve_id.tolist())
        self.assertEqual(result.loc[0, "predicted_base_score"], 9.8)
        self.assertTrue(result.loc[0, "vector_valid"])
        self.assertFalse(result.loc[1, "vector_valid"])
        self.assertTrue(result.loc[1, "prediction_error"])
        self.assertTrue(pd.isna(result.loc[1, "predicted_base_score"]))
        self.assertEqual(predict.call_args.args[1].tolist(), [frame.loc[0, "description"]])

    def test_inference_failure_isolated_per_row(self):
        def inference(_artifact, descriptions, **kwargs):
            if descriptions.str.contains("number 1").any():
                raise RuntimeError("bad example")
            return self.labels(_artifact, descriptions, **kwargs)
        with patch("src.model.predict.predict_labels", side_effect=inference):
            result = predict_frame(artifact(), truth_frame().iloc[:2])
        self.assertTrue(result.loc[0, "vector_valid"])
        self.assertFalse(result.loc[1, "vector_valid"])
        self.assertIn("inference_failed", result.loc[1, "prediction_error"])

    def test_demo_and_empty_frame(self):
        with patch("src.model.predict.predict_labels", side_effect=self.labels):
            result = predict_frame(artifact(), pd.DataFrame({"cve_id": ["demo"], "description": ["Remote issue"]}),
                                   prediction_usage="demo", model_kind="dummy")
            self.assertEqual(result.loc[0, "prediction_usage"], "demo")
            self.assertEqual(result.loc[0, "model_version"], MODEL + "-dummy")
            empty = predict_frame(artifact(), truth_frame().iloc[:0])
            self.assertTrue(empty.empty)
            self.assertEqual(list(empty.columns), list(PREDICTION_COLUMNS))

    def test_version_split_id_mapping_and_null_label_guards(self):
        for column, value in [("dataset_version", "wrong"), ("split", "train"), ("cve_id", "bad")]:
            frame = truth_frame().iloc[:1].copy()
            frame.loc[0, column] = value
            with self.assertRaises(ValueError):
                predict_frame(artifact(), frame)
        bad = artifact()
        bad["label_order"]["AV"] = ["N", "P"]
        with self.assertRaisesRegex(ValueError, "label_order"):
            predict_frame(bad, truth_frame())
        with self.assertRaisesRegex(ValueError, "invalid predicted"):
            labels_to_vector({**BASE, "AV": pd.NA})


if __name__ == "__main__":
    unittest.main()
