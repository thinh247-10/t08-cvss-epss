"""Protect model selection and the final-test audit boundary without full training."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.model.run_phase2 import _validate_lock, choose_candidate, load_release, sha256


class Phase2WorkflowTests(unittest.TestCase):
    def test_selection_uses_validation_f1_and_only_uses_cost_for_ties(self):
        first = {"validation_mean_macro_f1": .6, "training_seconds": 1}
        better = {"validation_mean_macro_f1": .7, "training_seconds": 100}
        self.assertIs(choose_candidate([first, better]), better)
        tie = {"validation_mean_macro_f1": .6000001, "training_seconds": .5}
        self.assertIs(choose_candidate([first, tie]), tie)
        with self.assertRaises(ValueError):
            choose_candidate([first, better, tie])

    def test_lock_refuses_changed_artifact_config_or_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("model", "config", "dataset")]
            for path in paths:
                path.write_bytes(b"frozen")
            keys = ("artifact_sha256", "config_sha256", "dataset_sha256")
            lock = {key: sha256(path) for key, path in zip(keys, paths)}
            lock["test_status"] = "not_run"
            kwargs = dict(artifact_path=paths[0], config_path=paths[1], dataset_path=paths[2])
            _validate_lock(lock, **kwargs)
            for path in paths:
                path.write_bytes(b"modified")
                with self.assertRaisesRegex(ValueError, "changed"):
                    _validate_lock(lock, **kwargs)
                path.write_bytes(b"frozen")
            lock["test_status"] = "running"
            with self.assertRaisesRegex(ValueError, "already started"):
                _validate_lock(lock, **kwargs)

    def test_missing_release_never_falls_back_to_pilot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "model.json"
            config.write_text(json.dumps({"data": {
                "dataset": str(root / "missing" / "ml_cohort.parquet"),
                "metadata": str(root / "missing" / "metadata.json"),
            }}), encoding="utf-8")
            with patch("src.model.run_phase2.verify") as verify:
                with self.assertRaisesRegex(FileNotFoundError, "do not substitute the pilot"):
                    load_release(config, root / "manifest.json")
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
