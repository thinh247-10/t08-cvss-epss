"""Offline ML data audit checks; no training or source-table mutation."""

import copy
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pandas as pd
import yaml
from pandas.testing import assert_frame_equal, assert_series_equal

from src.collect.prepare_handoff import SAMPLE_COLUMNS, SAMPLE_DTYPES
from src.model import audit_data
from src.model.audit_data import audit_frame
from src.model.baseline import prepare_baseline_inputs
from src.model.data_validation import LABEL_ORDER, ModelInputError, validate_model_input


VERSION = "test-full-ml-audit-v1"
LABELS = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("N", "L", "H"),
    "I": ("N", "L", "H"),
    "A": ("N", "L", "H"),
}
SPLIT_CONFIG = {
    "status": "provisional",
    "strategy": "published_time",
    "train": {"start": "2023-01-01", "end_exclusive": "2024-01-01"},
    "validation": {"start": "2024-01-01", "end_exclusive": "2024-07-01"},
    "test": {"start": "2024-07-01", "end_exclusive": "2025-01-01"},
}
BASE_LABELS = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def sample_frame(*overrides):
    """Small contract-shaped fixture with UTC dates and nullable scalars."""
    rows = []
    for index, changes in enumerate(overrides):
        row = {
            "cve_id": f"CVE-2023-{1000 + index}",
            "published": "2023-06-01T12:00:00Z",
            "last_modified": "2026-10-01T12:00:00Z",
            "vuln_status": "Analyzed",
            "description": f"Example vulnerability {index} with substantive details.",
            "cvss_version": "3.1",
            "cvss_vector": BASE_VECTOR,
            "cvss_base_score": 9.8,
            "cvss_source": "nvd@nist.gov",
            "cvss_type": "Primary",
            **BASE_LABELS,
            "has_cvss31_label": True,
            "epss": 0.2,
            "epss_percentile": 0.9,
            "epss_date": "2026-09-29",
            "is_kev": False,
            "kev_date_added": None,
            "kev_known_ransomware": None,
            "domain_tags": [],
            "in_scope": False,
            "scope_reason": "Web/mobile scope review is pending",
            "scope_evidence": [],
            "scope_status": "needs_review",
            "split": None,
            "dataset_version": VERSION,
            "retrieved_at": "2026-10-05T00:00:00Z",
        }
        row.update(changes)
        rows.append(row)
    frame = pd.DataFrame(rows, columns=SAMPLE_COLUMNS)
    for column, dtype in SAMPLE_DTYPES.items():
        if column not in {"published", "last_modified", "retrieved_at", "domain_tags", "scope_evidence"}:
            frame[column] = frame[column].astype(dtype)
    for column in ("published", "last_modified", "retrieved_at"):
        frame[column] = pd.to_datetime(frame[column], format="ISO8601", utc=True)
    return frame


class ModelDataAuditChecks(unittest.TestCase):
    def audit(self, frame, **kwargs):
        return audit_frame(frame, dataset_version=VERSION, split_config=copy.deepcopy(SPLIT_CONFIG), **kwargs)

    def assert_finding(self, result, cve_id, column, code):
        matches = [item for item in result["findings"]
                   if item["cve_id"] == cve_id and item["column"] == column and item["code"] == code]
        self.assertTrue(matches, f"Missing finding {cve_id}, {column}, {code}")
        self.assertTrue(all(isinstance(item["detail"], str) and item["detail"] for item in matches))

    def test_valid_rows_are_ml_candidates_and_result_is_json_serializable(self):
        result = self.audit(sample_frame({}, {"published": "2024-02-01T00:00:00Z"}))
        self.assertEqual(result["summary"]["total_records"], 2)
        self.assertEqual(result["summary"]["unique_cve_count"], 2)
        self.assertEqual(result["summary"]["ml_candidates"], 2)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 2)
        self.assertEqual(result["summary"]["assigned_source_split"], 0)
        self.assertEqual(result["split_counts"], {"train": 1, "validation": 1, "test": 0, "unassigned": 0})
        json.dumps(result, allow_nan=False)

    def test_vector_mismatch_reports_id_and_metric_without_rewriting_label(self):
        frame = sample_frame({"AV": "L"})
        result = self.audit(frame)
        self.assert_finding(result, "CVE-2023-1000", "AV", "label_vector_mismatch")
        self.assertEqual(result["summary"]["ml_candidates"], 1)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 0)
        self.assertEqual(result["exclusion_counts"]["vector_invalid_or_mismatch"], 1)
        self.assertEqual(frame.loc[0, "AV"], "L")
        self.assertEqual(frame.loc[0, "cvss_vector"], BASE_VECTOR)

    def test_missing_and_whitespace_descriptions_are_excluded(self):
        result = self.audit(sample_frame({"description": " \t\n "}, {"description": pd.NA}, {}))
        self.assertEqual(result["summary"]["missing_description"], 2)
        self.assertEqual(result["summary"]["ml_candidates"], 1)
        self.assertEqual(result["exclusion_counts"]["missing_description"], 2)
        for cve_id in ("CVE-2023-1000", "CVE-2023-1001"):
            self.assert_finding(result, cve_id, "description", "description_missing")

    def test_numeric_description_is_reported_and_never_becomes_ml_text(self):
        frame = sample_frame({})
        frame["description"] = pd.Series([42], dtype="object")
        original = frame.copy(deep=True)
        result = self.audit(frame)
        self.assertEqual(result["summary"]["ml_candidates"], 0)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 0)
        self.assert_finding(result, "CVE-2023-1000", "description", "description_type_invalid")
        assert_frame_equal(frame, original)

    def test_text_boolean_fields_are_reported_without_truthy_coercion_or_crash(self):
        frame = sample_frame({})
        for column in ("has_cvss31_label", "is_kev", "in_scope"):
            frame[column] = pd.Series(["False"], dtype="string")
        original = frame.copy(deep=True)
        result = self.audit(frame)
        for column in ("has_cvss31_label", "is_kev", "in_scope"):
            self.assert_finding(result, "CVE-2023-1000", column, "boolean_type_invalid")
        json.dumps(result, allow_nan=False)
        assert_frame_equal(frame, original)

    def test_rejected_record_is_excluded_even_with_valid_labels(self):
        result = self.audit(sample_frame({"vuln_status": "Rejected"}, {}))
        self.assertEqual(result["summary"]["rejected_records"], 1)
        self.assertEqual(result["summary"]["ml_candidates"], 1)
        self.assertEqual(result["exclusion_counts"]["rejected"], 1)
        self.assert_finding(result, "CVE-2023-1000", "vuln_status", "rejected")

    def test_invalid_and_missing_labels_are_excluded(self):
        result = self.audit(sample_frame({"AV": "X"}, {"PR": pd.NA}, {}))
        self.assertEqual(result["summary"]["ml_candidates"], 1)
        self.assertEqual(result["exclusion_counts"]["missing_or_invalid_labels"], 2)
        self.assert_finding(result, "CVE-2023-1000", "AV", "invalid_label")
        self.assertTrue(any(item["cve_id"] == "CVE-2023-1001" and item["column"] == "PR"
                            for item in result["findings"]))

    def test_unknown_status_is_reported_and_excluded(self):
        result = self.audit(sample_frame({"vuln_status": "Unknown status"}, {}))
        self.assertEqual(result["summary"]["ml_candidates"], 1)
        self.assertEqual(result["exclusion_counts"]["unknown_status"], 1)
        self.assertTrue(any(item["cve_id"] == "CVE-2023-1000" and item["column"] == "vuln_status"
                            for item in result["findings"]))

    def test_counts_include_every_class_and_empty_split(self):
        result = self.audit(sample_frame({}), rare_support=2)
        counts = {(item["cohort"], item["metric"], item["label"]): item["support"]
                  for item in result["label_counts"]}
        self.assertEqual(len(counts), 4 * sum(len(values) for values in LABELS.values()))
        for cohort in ("all", "train", "validation", "test"):
            for metric, values in LABELS.items():
                for label in values:
                    expected = int(cohort in {"all", "train"} and label == BASE_LABELS[metric])
                    self.assertEqual(counts[cohort, metric, label], expected)
        absent = {(item["cohort"], item["metric"], item["label"]): item["support"]
                  for item in result["absent_classes"]}
        rare = {(item["cohort"], item["metric"], item["label"]): item["support"]
                for item in result["rare_classes"]}
        self.assertEqual(absent, {key: support for key, support in counts.items() if support == 0})
        self.assertEqual(rare, {key: support for key, support in counts.items() if 0 < support < 2})

    def test_single_class_targets_are_marked_for_fallback(self):
        result = self.audit(sample_frame({}, {}))
        single = {(item["cohort"], item["metric"], item["label"])
                  for item in result["single_class_targets"]}
        self.assertEqual(single, {(cohort, metric, label) for cohort in ("all", "train")
                                  for metric, label in BASE_LABELS.items()})

    def test_duplicate_ids_across_proposed_splits_are_reported(self):
        cve_id = "CVE-2023-1000"
        result = self.audit(sample_frame({"cve_id": cve_id},
                                        {"cve_id": cve_id, "published": "2024-02-01T00:00:00Z"}))
        self.assertEqual(result["summary"]["unique_cve_count"], 1)
        group = next(item for item in result["duplicate_ids"] if item["cve_id"] == cve_id)
        self.assertEqual(group["rows"], 2)
        self.assertEqual(set(group["splits"]), {"train", "validation"})
        self.assert_finding(result, cve_id, "cve_id", "duplicate_id")

    def test_normalized_duplicate_descriptions_cross_split_are_reported(self):
        result = self.audit(sample_frame({"description": "  Same\n\tDESCRIPTION  "},
                                        {"description": "same description", "published": "2024-08-01T00:00:00Z"},
                                        {"description": "An unrelated description."}))
        duplicates = result["description_duplicates"]
        self.assertTrue(duplicates["normalization"])
        self.assertEqual(duplicates["groups"], 1)
        self.assertEqual(duplicates["cross_split_groups"], 1)
        self.assertEqual(duplicates["cross_split_rows"], 2)
        example = next(item for item in duplicates["examples"] if item["row_count"] == 2)
        self.assertEqual(set(example["cve_ids"]), {"CVE-2023-1000", "CVE-2023-1001"})
        self.assertEqual(set(example["splits"]), {"train", "test"})
        self.assertRegex(example["description_sha256"], r"^[0-9a-f]{64}$")

    def test_proposed_splits_use_published_with_exclusive_end_boundaries(self):
        dates = (
            "2022-12-31T23:59:59Z", "2023-01-01T00:00:00Z", "2023-12-31T23:59:59Z",
            "2024-01-01T00:00:00Z", "2024-06-30T23:59:59Z", "2024-07-01T00:00:00Z",
            "2024-12-31T23:59:59Z", "2025-01-01T00:00:00Z",
        )
        frame = sample_frame(*({"published": value} for value in dates))
        result = self.audit(frame)
        self.assertEqual(result["split_counts"], {"train": 2, "validation": 2, "test": 2, "unassigned": 2})
        self.assert_finding(result, "CVE-2023-1000", "published", "published_outside_split")
        self.assert_finding(result, "CVE-2023-1007", "published", "published_outside_split")
        self.assertTrue(frame["split"].isna().all())

    def test_missing_and_invalid_published_values_are_unassigned(self):
        frame = sample_frame({}, {})
        frame["published"] = pd.Series([pd.NA, "not a timestamp"], dtype="string")
        result = self.audit(frame)
        self.assertEqual(result["split_counts"]["unassigned"], 2)
        self.assert_finding(result, "CVE-2023-1000", "published", "published_missing")
        self.assert_finding(result, "CVE-2023-1001", "published", "published_invalid")

    def test_missing_epss_is_kept_in_ml_and_zero_is_present(self):
        frame = sample_frame({"epss": pd.NA, "epss_percentile": pd.NA}, {"epss": 0.0})
        frame["epss_status"] = pd.Series(["missing", "available"], dtype="string")
        result = self.audit(frame)
        self.assertEqual(result["summary"]["ml_candidates"], 2)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 2)
        self.assertEqual(result["summary"]["candidate_without_epss"], 1)

    def test_has_label_flag_disagreement_is_reported(self):
        result = self.audit(sample_frame({"has_cvss31_label": False}))
        self.assert_finding(result, "CVE-2023-1000", "has_cvss31_label", "has_label_mismatch")
        self.assertEqual(result["summary"]["ml_candidates"], 1)

    def test_invalid_vector_and_wrong_version_do_not_pass_strict_validation(self):
        result = self.audit(sample_frame({"cvss_vector": "CVSS:3.1/AV:N"},
                                        {"cvss_version": "3.0"}))
        self.assertEqual(result["summary"]["ml_candidates"], 2)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 0)
        self.assertTrue(any(item["cve_id"] == "CVE-2023-1000" and item["column"] == "cvss_vector"
                            for item in result["findings"]))
        self.assertTrue(any(item["cve_id"] == "CVE-2023-1001" and item["column"] == "cvss_version"
                            for item in result["findings"]))

    def test_source_split_assignment_is_reported_and_not_used_for_proposal(self):
        frame = sample_frame({"split": "test", "published": "2023-02-01T00:00:00Z"})
        result = self.audit(frame)
        self.assertEqual(result["summary"]["assigned_source_split"], 1)
        self.assertEqual(result["split_counts"], {"train": 1, "validation": 0, "test": 0, "unassigned": 0})
        self.assert_finding(result, "CVE-2023-1000", "split", "source_split_assigned")
        self.assertEqual(frame.loc[0, "split"], "test")

    def test_audit_leaves_input_and_configuration_unchanged(self):
        frame = sample_frame({"AV": "L"}, {"description": " \t "},
                             {"published": "2024-07-01T00:00:00Z"})
        frame.index = pd.Index([10, 20, 30], name="original_index")
        original = frame.copy(deep=True)
        original_lists = copy.deepcopy(frame[["domain_tags", "scope_evidence"]].to_dict("records"))
        config = copy.deepcopy(SPLIT_CONFIG)
        original_config = copy.deepcopy(config)
        audit_frame(frame, dataset_version=VERSION, split_config=config)
        assert_frame_equal(frame, original)
        self.assertEqual(frame[["domain_tags", "scope_evidence"]].to_dict("records"), original_lists)
        self.assertEqual(config, original_config)
        self.assertNotIn("proposed_split", frame.columns)

    def test_overlapping_split_configuration_is_rejected(self):
        config = copy.deepcopy(SPLIT_CONFIG)
        config["validation"]["start"] = "2023-12-31"
        with self.assertRaises(ValueError):
            audit_frame(sample_frame({}), dataset_version=VERSION, split_config=config)

    def test_relative_rarity_uses_candidate_denominator_and_strict_one_percent_boundary(self):
        for size in (100, 101):
            with self.subTest(size=size):
                rows = [{} for _ in range(size)]
                rows[-1] = {"AV": "P", "cvss_vector": BASE_VECTOR.replace("/AV:N/", "/AV:P/")}
                result = self.audit(sample_frame(*rows))
                relative = {(item["cohort"], item["metric"], item["label"])
                            for item in result["rare_relative_classes"]}
                expected = {("all", "AV", "P"), ("train", "AV", "P")} if size == 101 else set()
                self.assertEqual(relative, expected)

    def test_duplicate_description_conflicts_are_reported_without_relabelling(self):
        frame = sample_frame(
            {"description": "Generic issue"},
            {"description": " GENERIC\tissue ", "published": "2024-08-01T00:00:00Z", "AV": "P",
             "cvss_vector": BASE_VECTOR.replace("/AV:N/", "/AV:P/")},
            {"description": "Generic issue", "vuln_status": "Rejected"},
        )
        result = self.audit(frame)
        duplicates = result["description_duplicates"]
        self.assertEqual(duplicates["rows"], 2)
        self.assertEqual(duplicates["conflicting_vector_groups"], 1)
        self.assertEqual(duplicates["cross_split_conflicting_vector_groups"], 1)
        self.assertEqual(duplicates["examples"][0]["distinct_vectors"], 2)
        self.assertEqual(result["summary"]["strict_valid_candidates"], 2)
        self.assertEqual(result["summary"]["label_vector_mismatches"], 0)
        self.assertFalse(any(item["cve_id"] == "CVE-2023-1002" and item["code"] == "description_cross_split"
                             for item in result["findings"]))
        self.assertEqual(frame["AV"].tolist(), ["N", "P", "N"])


class ModelInputValidationChecks(unittest.TestCase):
    def assert_input_issue(self, frame, cve_id, column, **kwargs):
        with self.assertRaises(ModelInputError) as raised:
            validate_model_input(frame, **kwargs)
        issues = raised.exception.issues
        self.assertIsInstance(issues, list)
        self.assertTrue(issues)
        for issue in issues:
            self.assertTrue({"cve_id", "column", "code", "detail"}.issubset(issue))
            self.assertIsInstance(issue["code"], str)
            self.assertTrue(issue["code"])
            self.assertIsInstance(issue["detail"], str)
            self.assertTrue(issue["detail"])
        matches = [issue for issue in issues if issue["column"] == column
                   and (cve_id is None or issue["cve_id"] == cve_id)]
        self.assertTrue(matches, f"Missing input issue for {cve_id}, {column}: {issues}")
        return issues

    def test_baseline_whitelists_description_and_orders_eight_targets(self):
        frame = sample_frame({}, {})
        frame.index = pd.Index([50, 10], name="source_row")
        frame = frame.loc[:, list(reversed(frame.columns))]
        inputs = prepare_baseline_inputs(frame, dataset_version=VERSION)
        expected_order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
        self.assertEqual(tuple(LABEL_ORDER), expected_order)
        self.assertIsInstance(inputs.features, pd.Series)
        self.assertEqual(inputs.features.name, "description")
        self.assertEqual(list(inputs.targets.columns), list(expected_order))
        assert_series_equal(inputs.features, frame["description"])
        assert_series_equal(inputs.cve_ids, frame["cve_id"])
        assert_frame_equal(inputs.targets, frame.loc[:, list(expected_order)])

    def test_risk_and_cvss_metadata_cannot_leak_into_baseline_features(self):
        frame = sample_frame({})
        inputs = prepare_baseline_inputs(frame)
        changed = frame.copy(deep=True)
        for column in ("epss", "epss_percentile", "cvss_base_score", "cvss_source", "is_kev"):
            changed[column] = pd.Series(["sentinel excluded from text"], dtype="object")
        changed["cvss_vector"] = BASE_VECTOR.replace("/AV:N/", "/AV:P/")
        changed["AV"] = "P"
        original_changed = changed.copy(deep=True)
        after = prepare_baseline_inputs(changed)
        assert_series_equal(after.features, inputs.features)
        assert_series_equal(after.cve_ids, inputs.cve_ids)
        self.assertEqual(after.targets.loc[0, "AV"], "P")
        assert_frame_equal(changed, original_changed)

    def test_missing_epss_and_optional_metadata_preserve_valid_records(self):
        frame = sample_frame({"epss": pd.NA, "epss_percentile": pd.NA}, {})
        required = ["cve_id", "description", "vuln_status", "cvss_version", "cvss_vector", *LABEL_ORDER]
        for candidate in (frame, frame.loc[:, required]):
            with self.subTest(columns=list(candidate.columns)):
                inputs = prepare_baseline_inputs(candidate)
                self.assertEqual(len(inputs.features), 2)
                assert_series_equal(inputs.features, frame["description"])

    def test_returned_inputs_are_copies_and_source_is_unchanged(self):
        frame = sample_frame({}, {})
        frame.index = pd.Index([50, 10], name="source_row")
        original = frame.copy(deep=True)
        inputs = validate_model_input(frame)
        inputs.features.iloc[0] = "Changed extracted text"
        inputs.targets.iloc[0, 0] = "P"
        inputs.cve_ids.iloc[0] = "CVE-2023-9999"
        assert_frame_equal(frame, original)
        self.assertEqual(inputs.features.index.tolist(), [50, 10])
        self.assertEqual(inputs.targets.index.tolist(), [50, 10])
        self.assertEqual(inputs.cve_ids.index.tolist(), [50, 10])

    def test_missing_blank_and_numeric_descriptions_are_rejected_without_coercion(self):
        for description in (None, pd.NA, " \t\n ", 42):
            with self.subTest(description=description):
                frame = sample_frame({})
                frame["description"] = pd.Series([description], dtype="object")
                original = frame.copy(deep=True)
                self.assert_input_issue(frame, "CVE-2023-1000", "description")
                assert_frame_equal(frame, original)

    def test_invalid_rows_raise_structured_errors_instead_of_implicit_filtering(self):
        frame = sample_frame({}, {"vuln_status": "Rejected"}, {"AV": "X"},
                             {"PR": pd.NA}, {"cvss_version": "3.0"},
                             {"vuln_status": "Unknown status"})
        original = frame.copy(deep=True)
        expected = {("CVE-2023-1001", "vuln_status"), ("CVE-2023-1002", "AV"),
                    ("CVE-2023-1003", "PR"), ("CVE-2023-1004", "cvss_version"),
                    ("CVE-2023-1005", "vuln_status")}
        issues = self.assert_input_issue(frame, "CVE-2023-1001", "vuln_status")
        self.assertTrue(expected.issubset({(issue["cve_id"], issue["column"]) for issue in issues}))
        with self.assertRaises(ModelInputError):
            prepare_baseline_inputs(frame)
        assert_frame_equal(frame, original)

    def test_missing_malformed_and_mismatched_vectors_are_rejected(self):
        for changes, column in (({"cvss_vector": pd.NA}, "cvss_vector"),
                                ({"cvss_vector": "CVSS:3.1/AV:N"}, "cvss_vector"),
                                ({"AV": "L"}, "AV")):
            with self.subTest(changes=changes):
                self.assert_input_issue(sample_frame(changes), "CVE-2023-1000", column)

    def test_duplicate_and_invalid_ids_are_rejected_with_nondefault_index(self):
        duplicate_id = "CVE-2023-1000"
        frame = sample_frame({"cve_id": duplicate_id}, {"cve_id": duplicate_id})
        frame.index = pd.Index([50, 10], name="source_row")
        self.assert_input_issue(frame, duplicate_id, "cve_id")
        for cve_id in (pd.NA, "", "not-a-cve"):
            with self.subTest(cve_id=cve_id):
                self.assert_input_issue(sample_frame({"cve_id": cve_id}), None, "cve_id")

    def test_missing_required_columns_raise_column_specific_schema_errors(self):
        for column in ("cve_id", "description", "vuln_status", "cvss_version", "cvss_vector", "AV"):
            with self.subTest(column=column):
                self.assert_input_issue(sample_frame({}).drop(columns=column), None, column)

    def test_optional_label_flag_requires_boolean_true_without_string_coercion(self):
        for flag, dtype in (("True", "string"), ("False", "string"), (False, "boolean"),
                            (pd.NA, "boolean"), (1, "int64")):
            with self.subTest(flag=flag, dtype=dtype):
                frame = sample_frame({})
                frame["has_cvss31_label"] = pd.Series([flag], dtype=dtype)
                self.assert_input_issue(frame, "CVE-2023-1000", "has_cvss31_label")

    def test_expected_dataset_version_requires_present_matching_values(self):
        frame = sample_frame({})
        inputs = validate_model_input(frame, dataset_version=VERSION)
        self.assertEqual(len(inputs.features), 1)
        self.assert_input_issue(frame, "CVE-2023-1000", "dataset_version", dataset_version="another-version")
        self.assert_input_issue(frame.drop(columns="dataset_version"), None, "dataset_version",
                                dataset_version=VERSION)
        self.assert_input_issue(sample_frame({"dataset_version": pd.NA}), "CVE-2023-1000", "dataset_version",
                                dataset_version=VERSION)


class ModelDataAuditProvenanceChecks(unittest.TestCase):
    def setUp(self):
        # TemporaryDirectory confines automatic cleanup to this test-owned workspace path.
        self.temporary = tempfile.TemporaryDirectory(prefix=".ml-audit-", dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source-package"
        self.source.mkdir()
        self.table = self.source / "cves.parquet"
        sample_frame({}, {"published": "2024-07-01T00:00:00Z"}).to_parquet(self.table, index=False)
        self.config_path = self.root / "project.yaml"
        self.config = {"project": {"schema_version": "0.1"}, "split": copy.deepcopy(SPLIT_CONFIG)}
        self.config_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")
        self.metadata_path = self.source / "metadata.json"
        self.metadata = {
            "status": "complete",
            "schema_version": "0.1",
            "dataset_version": VERSION,
            "table_sha256": audit_data.digest(self.table),
            "config_sha256": audit_data.digest(self.config_path),
            "statistics": {"total_records": 2, "unique_cve_count": 2, "rejected_records": 0,
                           "description_and_label_candidates_before_scope": 2,
                           "available_epss": 2, "in_kev": 0, "assigned_split": 0},
            "scope_reviewed": False,
            "training_ready": False,
        }
        self.write_json(self.metadata_path, self.metadata)
        self.archive_path = self.root / "source-package.zip"
        with zipfile.ZipFile(self.archive_path, "w") as archive:
            for path in (self.table, self.metadata_path):
                archive.write(path, f"source-package/{path.name}")
        self.manifest_path = self.root / "handoff.json"
        self.manifest = {
            "dataset_version": VERSION,
            "archive_sha256": audit_data.digest(self.archive_path),
            "archive_bytes": self.archive_path.stat().st_size,
            "entries": [{"path": f"source-package/{path.name}", "sha256": audit_data.digest(path),
                         "bytes": path.stat().st_size} for path in (self.table, self.metadata_path)],
        }
        self.write_json(self.manifest_path, self.manifest)
        self.outputs = [self.root / "reports" / name for name in ("audit.md", "counts.csv", "findings.csv")]

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")

    def verify(self, *, with_manifest=True, with_archive=False):
        return audit_data.verify_inputs(self.table, self.metadata_path, self.config_path,
                                        self.manifest_path if with_manifest else None,
                                        self.archive_path if with_archive else None)

    def cli_args(self, outputs=None):
        report, counts, findings = self.outputs if outputs is None else outputs
        return ["--table", str(self.table), "--metadata", str(self.metadata_path),
                "--config", str(self.config_path), "--manifest", str(self.manifest_path),
                "--archive", str(self.archive_path), "--report", str(report),
                "--counts", str(counts), "--findings", str(findings)]

    def reseal_fixture(self):
        """Update trusted checksums so semantic guards are reached after fixture edits."""
        self.metadata["config_sha256"] = audit_data.digest(self.config_path)
        self.write_json(self.metadata_path, self.metadata)
        for entry in self.manifest["entries"]:
            path = self.source / Path(entry["path"]).name
            entry.update(sha256=audit_data.digest(path), bytes=path.stat().st_size)
        with zipfile.ZipFile(self.archive_path, "w") as archive:
            for path in (self.table, self.metadata_path):
                archive.write(path, f"source-package/{path.name}")
        self.manifest["archive_sha256"] = audit_data.digest(self.archive_path)
        self.manifest["archive_bytes"] = self.archive_path.stat().st_size
        self.write_json(self.manifest_path, self.manifest)

    def test_real_parquet_manifest_and_archive_hashes_verify_independently(self):
        meta, manifest, paths, provenance = self.verify(with_archive=True)
        self.assertEqual(meta["dataset_version"], VERSION)
        self.assertEqual(manifest["dataset_version"], VERSION)
        self.assertTrue(provenance["metadata_independently_verified"])
        self.assertEqual(len(provenance["checked_entries"]), 2)
        self.assertTrue({self.table, self.metadata_path, self.config_path, self.manifest_path,
                         self.archive_path}.issubset(set(paths)))
        self.assertEqual(provenance["hashes"][str(self.table)], audit_data.digest(self.table))

    def test_without_manifest_independent_verification_is_not_claimed(self):
        _, manifest, _, provenance = self.verify(with_manifest=False)
        self.assertIsNone(manifest)
        self.assertFalse(provenance["metadata_independently_verified"])

    def test_modified_table_is_rejected_by_metadata_checksum(self):
        sample_frame({"description": "Changed source description"}).to_parquet(self.table, index=False)
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_manifest_hash_and_byte_size_mismatches_are_rejected(self):
        for field, value in (("sha256", "0" * 64), ("bytes", self.table.stat().st_size + 1)):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["entries"][0][field] = value
                self.write_json(self.manifest_path, manifest)
                with self.assertRaisesRegex(ValueError, "checksum/size"):
                    self.verify()

    def test_modified_metadata_is_rejected_by_independent_manifest(self):
        self.metadata["statistics"]["total_records"] = 99
        self.write_json(self.metadata_path, self.metadata)
        with self.assertRaisesRegex(ValueError, "checksum/size"):
            self.verify()

    def test_manifest_dataset_version_mismatch_is_rejected(self):
        self.manifest["dataset_version"] = "another-dataset-version"
        self.write_json(self.manifest_path, self.manifest)
        with self.assertRaisesRegex(ValueError, "version"):
            self.verify()

    def test_manifest_must_cover_both_table_and_metadata(self):
        for omitted in ("cves.parquet", "metadata.json"):
            with self.subTest(omitted=omitted):
                manifest = copy.deepcopy(self.manifest)
                manifest["entries"] = [entry for entry in manifest["entries"]
                                       if Path(entry["path"]).name != omitted]
                self.write_json(self.manifest_path, manifest)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_changed_build_config_is_rejected(self):
        self.config["split"]["test"]["end_exclusive"] = "2026-01-01"
        self.config_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "config"):
            self.verify()

    def test_archive_without_manifest_or_with_changed_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires --manifest"):
            self.verify(with_manifest=False, with_archive=True)
        self.archive_path.write_bytes(b"changed archive")
        with self.assertRaisesRegex(ValueError, "Archive checksum/size"):
            self.verify(with_archive=True)

    def test_unsafe_manifest_entry_path_is_rejected(self):
        self.manifest["entries"][0]["path"] = "../cves.parquet"
        self.write_json(self.manifest_path, self.manifest)
        with self.assertRaisesRegex(ValueError, "Unsafe manifest"):
            self.verify()

    def test_cli_output_collisions_and_protected_source_paths_stop_before_write(self):
        protected_paths = (self.table, self.metadata_path, self.config_path, self.manifest_path, self.archive_path)
        original_hashes = {path: audit_data.digest(path) for path in protected_paths}
        forbidden_outputs = [
            [self.outputs[0], self.outputs[0], self.outputs[2]],
            [self.table, self.outputs[1], self.outputs[2]],
            [self.config_path, self.outputs[1], self.outputs[2]],
            [self.manifest_path, self.outputs[1], self.outputs[2]],
            [self.archive_path, self.outputs[1], self.outputs[2]],
            [self.source / "nested" / "audit.md", self.outputs[1], self.outputs[2]],
        ]
        for outputs in forbidden_outputs:
            with self.subTest(report=outputs[0]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    audit_data.main(self.cli_args(outputs))
                self.assertEqual(stopped.exception.code, 2)
            self.assertFalse(self.outputs[0].parent.exists())
            self.assertFalse((self.source / "nested").exists())
            self.assertEqual({path: audit_data.digest(path) for path in protected_paths}, original_hashes)

    def test_cli_success_writes_small_reports_without_changing_source_files(self):
        protected_paths = (self.table, self.metadata_path, self.config_path, self.manifest_path, self.archive_path)
        original_hashes = {path: audit_data.digest(path) for path in protected_paths}
        with redirect_stdout(io.StringIO()):
            exit_code = audit_data.main(self.cli_args())
        self.assertEqual(exit_code, 0)
        self.assertTrue(all(path.is_file() for path in self.outputs))
        self.assertIn(VERSION, self.outputs[0].read_text(encoding="utf-8"))
        counts = pd.read_csv(self.outputs[1])
        findings = pd.read_csv(self.outputs[2])
        self.assertEqual(len(counts), 4 * sum(len(values) for values in LABELS.values()))
        self.assertNotIn("description", counts.columns)
        self.assertNotIn("description", findings.columns)
        self.assertEqual({path: audit_data.digest(path) for path in protected_paths}, original_hashes)

    def test_cli_rejects_incomplete_metadata_status_before_writing_outputs(self):
        self.metadata["status"] = "building"
        self.reseal_fixture()
        with self.assertRaisesRegex(ValueError, "complete"), redirect_stdout(io.StringIO()):
            audit_data.main(self.cli_args())
        self.assertFalse(self.outputs[0].parent.exists())
        self.assertFalse(any(path.exists() for path in self.outputs))

    def test_cli_rejects_schema_version_mismatch_with_valid_hashes_before_write(self):
        self.config["project"]["schema_version"] = "9.9"
        self.config_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")
        self.reseal_fixture()
        with self.assertRaisesRegex(ValueError, "[Ss]chema"), redirect_stdout(io.StringIO()):
            audit_data.main(self.cli_args())
        self.assertFalse(self.outputs[0].parent.exists())
        self.assertFalse(any(path.exists() for path in self.outputs))


if __name__ == "__main__":
    unittest.main()
