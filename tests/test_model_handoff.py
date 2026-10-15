"""Offline integrity and reproduction checks using a tiny fitted artifact."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.model.baseline import save_artifact, train_baseline
from src.model.predict import predict_frame
from src.model.verify_handoff import EXPECTED_FIELDS, main, verify_handoff
from tests.test_baseline import sample_config, sample_frame


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = sample_frame()
        cls.artifact = train_baseline(cls.frame, sample_config(), model_version="handoff-unit-v1")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.model_path = self.root / "models/baseline.joblib"
        save_artifact(self.artifact, self.model_path)
        validation = self.frame.loc[self.frame.split.eq("validation")]
        cases = [{"cve_id": row.cve_id, "split": "validation", "description": row.description,
                  "expected": {}} for row in validation.itertuples()]
        for kind in ("dummy", "tfidf"):
            predictions = predict_frame(self.artifact, validation, model_kind=kind, prediction_usage="demo")
            for case, row in zip(cases, predictions.to_dict(orient="records")):
                case["expected"][kind] = {field: row[field] for field in EXPECTED_FIELDS}
        digest = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        self.manifest = {
            "dataset_version": self.artifact["dataset_version"],
            "model_versions": deepcopy(self.artifact["model_versions"]),
            "library_versions": deepcopy(self.artifact["library_versions"]),
            "files": {"models/baseline.joblib": {"bytes": self.model_path.stat().st_size, "sha256": digest}},
            "lock": {"artifact": "models/baseline.joblib", "artifact_sha256": digest,
                     "dataset_version": self.artifact["dataset_version"],
                     "model_versions": deepcopy(self.artifact["model_versions"])},
            "reproduction_smoke": {"usage": "demo_validation_reproduction", "cases": cases},
            "n1_second_machine_reproduction": "not_run",
        }
        self.manifest_path = self.root / "docs/handoffs/phase-2-model.json"
        self.manifest_path.parent.mkdir(parents=True)
        self.write_manifest()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest, allow_nan=False), encoding="utf-8")

    def verify(self, **kwargs):
        return verify_handoff(self.manifest_path, repo_root=self.root, **kwargs)

    def test_verifies_hash_metadata_predictions_without_changing_manifest(self):
        before = self.manifest_path.read_bytes()
        report = self.verify()
        self.assertEqual(report["result"], "PHASE2 HANDOFF VERIFIED")
        self.assertEqual(report["files_verified"], 1)
        self.assertTrue(report["runtime_versions_match"])
        self.assertEqual(report["reproduction_smoke"], {
            "cases_verified": 1, "model_predictions_verified": 2,
            "prediction_usage": "demo", "all_predictions_match": True,
        })
        self.assertEqual(before, self.manifest_path.read_bytes())
        self.assertEqual(json.loads(before)["n1_second_machine_reproduction"], "not_run")

    def test_corruption_is_rejected_before_joblib_load(self):
        data = self.model_path.read_bytes()
        self.model_path.write_bytes(bytes([data[0] ^ 0x01]) + data[1:])
        with patch("src.model.verify_handoff.load_artifact") as loader:
            with self.assertRaisesRegex(ValueError, "checksum/size"):
                self.verify()
            loader.assert_not_called()

    def test_truncated_file_is_rejected(self):
        self.model_path.write_bytes(self.model_path.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, "checksum/size"):
            self.verify()

    def test_rejects_traversal_absolute_drive_unc_and_stream_paths(self):
        entry = next(iter(self.manifest["files"].values()))
        malicious = ["../outside.joblib", "models/../../outside.joblib", "/tmp/escape.joblib",
                     "C:/escape.joblib", "C:escape.joblib", "\\\\server\\share\\escape.joblib",
                     "models\\..\\escape.joblib", "models/baseline.joblib:stream", "models/.. /escape"]
        for name in malicious:
            with self.subTest(name=name):
                self.manifest["files"] = {name: entry}
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, "Unsafe|escapes"):
                    self.verify()

    def test_accepts_windows_manifest_separators_and_explicit_artifact(self):
        self.manifest["files"] = {"models\\baseline.joblib": next(iter(self.manifest["files"].values()))}
        self.write_manifest()
        self.assertEqual(self.verify(artifact_path=self.model_path)["files_verified"], 1)

    def test_rejects_duplicate_normalized_filenames(self):
        self.manifest["files"]["models\\baseline.joblib"] = dict(self.manifest["files"]["models/baseline.joblib"])
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.verify()

    def test_requires_artifact_covered_by_manifest(self):
        extra = self.root / "models/extra.joblib"
        extra.write_bytes(self.model_path.read_bytes())
        with self.assertRaisesRegex(ValueError, "covered"):
            self.verify(artifact_path=extra)
        with self.assertRaisesRegex(ValueError, "inside"):
            self.verify(artifact_path=self.root.parent / "elsewhere.joblib")

    def test_wrong_versions_and_lock_are_rejected(self):
        for field, value in [("dataset_version", "other"), ("model_versions", {"tfidf": "other"}),
                             ("library_versions", {"scikit-learn": "other"})]:
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = value
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, field):
                    self.verify()
                self.manifest[field] = original
        self.manifest["lock"]["artifact_sha256"] = "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "lock.*SHA-256"):
            self.verify()

    def test_expected_prediction_difference_fails_strict_comparison(self):
        expected = self.manifest["reproduction_smoke"]["cases"][0]["expected"]["tfidf"]
        original = deepcopy(expected)
        for field, value in [("pred_AV", "P"), ("predicted_vector", "CVSS:3.1/invalid"),
                             ("predicted_base_score", 0.1)]:
            with self.subTest(field=field):
                expected.update(original)
                expected[field] = value
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, f"prediction mismatch.*{field}"):
                    self.verify()

    def test_reproduction_rejects_test_cases_and_missing_expected_model(self):
        case = self.manifest["reproduction_smoke"]["cases"][0]
        case["split"] = "test"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "validation"):
            self.verify()
        case["split"] = "validation"
        del case["expected"]["dummy"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "dummy and tfidf"):
            self.verify()

    def test_missing_smoke_and_malformed_checksum_fail(self):
        self.manifest["reproduction_smoke"]["cases"] = []
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "nonempty reproduction"):
            self.verify()
        self.manifest["files"]["models/baseline.joblib"]["sha256"] = "invalid"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.verify()

    def test_runtime_version_difference_is_reported(self):
        with patch("src.model.verify_handoff._runtime_versions", return_value={"python": "different"}):
            report = self.verify()
        self.assertFalse(report["runtime_versions_match"])
        self.assertEqual(report["library_versions"], self.artifact["library_versions"])

    def test_cli_optional_report_preserves_manifest_and_status(self):
        before = self.manifest_path.read_bytes()
        output = self.root / "reports/local_handoff_check.json"
        with redirect_stdout(io.StringIO()) as stdout:
            status = main(["--manifest", str(self.manifest_path), "--repo-root", str(self.root),
                           "--output", str(output)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue()), json.loads(output.read_text(encoding="utf-8")))
        self.assertEqual(before, self.manifest_path.read_bytes())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["--manifest", str(self.manifest_path), "--repo-root", str(self.root),
                  "--output", str(self.manifest_path)])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(before, self.manifest_path.read_bytes())
        before_model = self.model_path.read_bytes()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["--manifest", str(self.manifest_path), "--repo-root", str(self.root),
                  "--output", str(self.model_path)])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(before_model, self.model_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
