"""Contract edge cases plus real, socket-blocked release smoke tests."""
import contextlib
import builtins
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import pandas as pd

from src.demo import data_loader as d
from src.demo.cli import main
from scripts.receive_demo_inputs import receive


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)


class Fixture:
    """Three CVEs; zero score, missing score and client review are distinct."""
    def __init__(self, root):
        self.p1, self.p2, self.p3 = [root / name for name in ("p1", "p2", "p3")]
        self.m1 = root / "phase1.json"
        self.n2 = self.p3 / "data/processed/p3_n2"
        self.n3 = self.p3 / "data/processed/p3_n3"
        self.p1.mkdir()
        self.n2.mkdir(parents=True)
        self.n3.mkdir(parents=True)
        self.ids = ["CVE-2023-10001", "CVE-2023-10002", "CVE-2023-10003"]
        dates = {"epss_date": "2026-09-29", "kev_date_released": "2026-09-30T16:59:23.0688Z", "kev_retrieved_at": "2026-10-01T11:29:35.854976+00:00"}
        self.ranks = [dict(cve_id=cve, cvss_base_score=score, epss=0., is_kev=False,
                           cvss_rank=i+1, epss_rank=i+1, kev_first_rank=i+1,
                           dataset_version=d.DATASET, epss_date=dates["epss_date"],
                           cohort_id=d.DATASET+":ranking", policy_version=d.POLICY)
                      for i, (cve, score) in enumerate(zip(self.ids, [9.8, 7.3, 0.]))]
        observed = [{**r, "description": "A validation description", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "cvss_source": "nvd", "cvss_type": "Primary", "split": split}
                    for r, split in zip(self.ranks, ["train", "validation", "test"])]
        pd.DataFrame(observed).to_parquet(self.p1 / "ranking_cohort.parquet")
        pd.DataFrame(observed).to_parquet(self.p1 / "ml_cohort.parquet")
        write_json(self.p1 / "metadata.json", {"status": "complete", "dataset_version": d.DATASET, **dates})
        write_json(self.m1, {"dataset_version": d.DATASET, "files": {p.name: d.file_info(p) for p in self.p1.iterdir()}})
        meta = dict(schema_version="p3-ranking-metrics-v1", dataset_version=d.DATASET,
                    cohort_id=d.DATASET+":ranking", policy_version=d.POLICY, context_version=d.CONTEXT,
                    source_dates=dates, n=3, total_kev=0)
        write_json(self.n2 / "metadata.json", meta)
        write_json(self.n2 / "ranking_metrics.json", meta)
        write_json(self.n2 / "context_metadata.json", {**meta, "schema_version": "p3-context-artifacts-v1", "inventory_version": "phase1-v1"})
        write_csv(self.n2 / "rankings.csv", self.ranks)
        pairs = [dict(cve_id=cve, asset_id=asset, dataset_version=d.DATASET, context_version=d.CONTEXT,
                      applicability="needs_review" if asset == "API-02" else "affected", mapping_reason="source reason")
                 for cve, asset in zip(self.ids, ["MOB-02", "API-02", "WEB-01"])]
        write_csv(self.n2 / "cve_asset_mapping.csv", pairs)
        write_csv(self.n2 / "environmental_scores.csv", [{**p, "environmental_score": score} for p, score in zip([pairs[0], pairs[2]], [9.8, 0.])])
        write_csv(self.n2 / "priority_queue.csv", [{**p, "environmental_score": score, "is_kev": False,
                  "exposure": exposure, "queue_status": "patch" if i == 2 else "review_required",
                  "priority_rank": 1 if i == 2 else None, "priority_reason": "review source reason",
                  "recommended_action": "verify", "policy_version": "context-v1"}
                 for i, (p, score, exposure) in enumerate(zip(pairs, [9.8, None, 0.], ["client", "internal", "internet"]))])
        write_json(self.p3 / "config/assets.yaml", {"inventory_version": "phase1-v1", "assets": [
            {"asset_id": asset, "exposure": exp} for asset, exp in zip(["MOB-02", "API-02", "WEB-01"], ["client", "internal", "internet"])]})
        write_json(self.p3 / "reports/p3_figures.md", {})
        write_json(self.n3 / "figures_manifest.json", {**meta, "context": {"context_version": d.CONTEXT}, "outputs": []})
        preds = [{"cve_id": cve, "split": split, "dataset_version": d.DATASET, "model_version": version,
                  "prediction_usage": "evaluation", **{f"pred_{m}": "N" for m in d.METRICS},
                  "predicted_vector": "fixture-vector", "predicted_base_score": 7.3,
                  "vector_valid": True, "prediction_error": ""}
                 for cve, split in zip(self.ids[1:], ["validation", "test"]) for version in [d.TFIDF, d.DISTILBERT]]
        write_csv(self.n3 / "predicted_rank_comparison.csv", [{k: r[k] for k in ["cve_id", "split", "dataset_version", "model_version", "predicted_base_score"]} for r in preds])
        write_json(self.n3 / "prediction_rank_metrics.json", {"dataset_version": d.DATASET, "splits": [
            {"split": split, "common_ids": [cve]} for cve, split in zip(self.ids[1:], ["validation", "test"])]})
        write_csv(self.p2 / "baseline/data/processed/predictions.csv", [r for r in preds if r["model_version"] == d.TFIDF])
        write_csv(self.p2 / "distilbert/predictions.csv", [r for r in preds if r["model_version"] == d.DISTILBERT])
        model = self.p2 / "baseline/models/baseline.joblib"
        model.parent.mkdir(parents=True)
        model.write_bytes(b"not deserialized during loading")
        self.reseal2()
        self.reseal3()

    def reseal2(self):
        with zipfile.ZipFile(self.p2 / "baseline.zip", "w") as archive:
            for p in (self.p2 / "baseline").rglob("*"):
                if p.is_file():
                    archive.write(p, p.relative_to(self.p2 / "baseline").as_posix())
        write_json(self.p2 / "manifest.json", {"status": "complete", "dataset_version": d.DATASET,
                   "baseline_model_versions": {"tfidf": d.TFIDF}, "distilbert_model_version": d.DISTILBERT,
                   "files": {n: d.file_info(self.p2/n) for n in ["baseline.zip", "distilbert/predictions.csv"]}})

    def reseal3(self):
        write_json(self.p3 / "phase3_manifest.json", {"status": "complete", "dataset_version": d.DATASET,
                   "context_version": d.CONTEXT, "release_version": "phase3-n1-integrated-20261021",
                   "files": {p.relative_to(self.p3).as_posix(): d.file_info(p)
                             for p in self.p3.rglob("*") if p.is_file() and p.name != "phase3_manifest.json"}})

    def load(self, **kwargs):
        return d.load_release(self.p1, kwargs.get("phase2", self.p2), self.p3, phase1_manifest=self.m1)


class DemoContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def test_false_zero_null_and_left_join(self):
        r = self.f.load()
        self.assertFalse(r.lookup_cve(self.f.ids[0])["is_kev"])
        self.assertEqual(len(r.pairs), 3)
        client = r.pairs[r.pairs.asset_id.eq("MOB-02")].iloc[0]
        self.assertEqual(client.environmental_score, 9.8)
        self.assertTrue(pd.isna(client.priority_rank))
        missing = r.pairs[r.pairs.asset_id.eq("API-02")].iloc[0]
        self.assertTrue(pd.isna(missing.environmental_score))
        zero = r.pairs[r.pairs.asset_id.eq("WEB-01")].iloc[0]
        self.assertEqual(zero.environmental_score, 0)
        self.assertEqual(d.display_value(0), "0")
        self.assertIn("N/A", d.display_value(None, "source reason"))

    def test_bad_hash_blocks_release(self):
        (self.f.n2 / "rankings.csv").write_text("changed", encoding="utf-8")
        with self.assertRaises(d.DemoError): self.f.load()

    def test_bad_phase1_hash(self):
        (self.f.p1 / "metadata.json").write_text("{}")
        with self.assertRaisesRegex(d.DemoError, "hash"): self.f.load()

    def test_version_mismatch_even_with_valid_hash(self):
        rows = [{**r, "dataset_version": "wrong"} for r in self.f.ranks]
        write_csv(self.f.n2 / "rankings.csv", rows)
        self.f.reseal3()
        with self.assertRaisesRegex(d.DemoError, "dataset_version"): self.f.load()

    def test_context_v1_rejected(self):
        path = self.f.n2 / "context_metadata.json"
        write_json(path, {**d.read_json(path), "context_version": "phase3-context-v1"})
        self.f.reseal3()
        with self.assertRaisesRegex(d.DemoError, "context_version"): self.f.load()

    def test_duplicate_cve_rejected(self):
        write_csv(self.f.n2 / "rankings.csv", self.f.ranks + self.f.ranks[:1])
        self.f.reseal3()
        with self.assertRaisesRegex(d.DemoError, "trùng"): self.f.load()

    def test_duplicate_pair_rejected(self):
        path = self.f.n2 / "priority_queue.csv"
        df = pd.read_csv(path)
        pd.concat([df, df.iloc[:1]]).to_csv(path, index=False)
        self.f.reseal3()
        with self.assertRaisesRegex(d.DemoError, "trùng"): self.f.load()

    def test_overlapping_observed_fields_must_match(self):
        self.f.ranks[0]["is_kev"] = True
        write_csv(self.f.n2 / "rankings.csv", self.f.ranks)
        self.f.reseal3()
        with self.assertRaisesRegex(d.DemoError, "is_kev"): self.f.load()

    def test_missing_ai_does_not_break_summary(self):
        for p2 in [None, self.f.p2 / "absent"]:
            r = self.f.load(phase2=p2)
            self.assertEqual(r.summary()["n"], 3)
            self.assertEqual(r.lookup_prediction(self.f.ids[1])["mode"], "unavailable")

    def test_bad_ai_hash_stops_only_ai(self):
        (self.f.p2 / "distilbert/predictions.csv").write_text("changed")
        r = self.f.load()
        self.assertEqual(r.summary()["n"], 3)
        self.assertTrue(r.predictions.empty)
        self.assertIn("hash", r.ai_status)

    def test_model_missing_saved_predictions_still_work(self):
        (self.f.p2 / "baseline/models/baseline.joblib").unlink()
        r = self.f.load()
        self.assertEqual(r.lookup_prediction(self.f.ids[1])["mode"], "saved")
        self.assertEqual(r.live_prediction(self.f.ids[1])["mode"], "saved")

    def test_model_removed_after_load_falls_back(self):
        r = self.f.load()
        (self.f.p2 / "baseline/models/baseline.joblib").unlink()
        self.assertEqual(r.live_prediction(self.f.ids[1])["mode"], "saved")

    def test_cli_preserves_string_list_items(self):
        from src.demo.cli import render
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            render({"assumptions": ["iOS 1.11.1", "client path needs review"]})
        self.assertIn("iOS 1.11.1", output.getvalue())
        self.assertIn("client path needs review", output.getvalue())

    def test_unknown_prediction_id_does_not_break_notebook(self):
        from src.demo.presentation import show_prediction
        with contextlib.redirect_stdout(io.StringIO()):
            result = show_prediction(self.f.load(), "CVE-2099-99999")
        self.assertEqual(result["mode"], "unavailable")

    def test_split_and_model_selection(self):
        r = self.f.load()
        self.assertIn("reason", r.lookup_prediction(self.f.ids[0]))
        self.assertIn("reason", r.lookup_prediction(self.f.ids[1], split="test"))
        self.assertEqual(r.lookup_prediction(self.f.ids[1], d.DISTILBERT)["model_version"], d.DISTILBERT)
        with self.assertRaises(d.DemoError): r.lookup_prediction(self.f.ids[1], d.TFIDF + "-dummy")
        with self.assertRaises(d.DemoError): r.compare_predictions("train")

    def test_ai_split_mismatch_locks_ai(self):
        path = self.f.p2 / "baseline/data/processed/predictions.csv"
        df = pd.read_csv(path)
        df.loc[0, "split"] = "test"
        df.to_csv(path, index=False)
        self.f.reseal2()
        r = self.f.load()
        self.assertTrue(r.predictions.empty)
        self.assertIn("split", r.ai_status)

    def test_duplicate_prediction_locks_ai(self):
        path = self.f.p2 / "distilbert/predictions.csv"
        df = pd.read_csv(path)
        pd.concat([df, df.iloc[:1]]).to_csv(path, index=False)
        self.f.reseal2()
        self.assertTrue(self.f.load().predictions.empty)

    def test_blank_id_and_outside_cohort(self):
        r = self.f.load()
        for cve in ["", " ", "not-cve", "CVE-2099-99999"]:
            with self.assertRaises(d.DemoError): r.lookup_cve(cve)

    def test_blank_description_no_model_call(self):
        r = self.f.load()
        r.cves.loc[r.cves.cve_id.eq(self.f.ids[1]), "description"] = " "
        with patch("src.model.baseline.load_artifact", side_effect=AssertionError("no load")):
            self.assertIn("rỗng", r.live_prediction(self.f.ids[1])["reason"])

    def test_unknown_figure_rejected(self):
        with self.assertRaises(d.DemoError): self.f.load().figure_path("unverified")

    def test_path_traversal(self):
        for name in ["../outside", "C:/outside", "a/../../x", "//server/share", "a:stream"]:
            with self.assertRaises(d.DemoError): d.safe_path(self.f.p3, name)

    def test_bad_boolean_and_fractional_rank(self):
        for col, value in [("is_kev", "maybe"), ("cvss_rank", "1.5"), ("priority_rank", "0"), ("epss", "2")]:
            path = Path(self.temp.name) / "invalid.csv"
            write_csv(path, [{col: value}])
            with self.assertRaises((ValueError, TypeError)): d.read_csv(path)

    def test_load_readonly_no_network_train_or_inference(self):
        before = {p: d.file_info(p) for p in Path(self.temp.name).rglob("*") if p.is_file()}
        with contextlib.ExitStack() as stack:
            for target in ["socket.socket.connect", "socket.create_connection", "socket.getaddrinfo",
                           "src.model.baseline.train_baseline", "src.model.baseline.load_artifact", "src.model.predict.predict_frame"]:
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            self.f.load()
        self.assertEqual(before, {p: d.file_info(p) for p in Path(self.temp.name).rglob("*") if p.is_file()})

    def test_saved_views_without_ml_dependencies(self):
        original = builtins.__import__
        def without_ml(name, *args, **kwargs):
            if name.split(".")[0] in {"torch", "transformers", "sklearn", "joblib"}:
                raise ImportError("ML dependency intentionally absent")
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=without_ml):
            self.assertEqual(self.f.load().lookup_prediction(self.f.ids[1])["mode"], "saved")

    def test_receive_rejects_bad_hash_before_extract(self):
        archive = Path(self.temp.name) / "bad.zip"
        archive.write_bytes(b"bad")
        receipt = Path(self.temp.name) / "receipt.json"
        write_json(receipt, {"bytes": 3, "sha256": "0" * 64})
        dest = Path(self.temp.name) / "dest"
        with self.assertRaises(d.DemoError): receive(archive, dest, receipt)
        self.assertFalse(dest.exists())

    def test_receive_rejects_unsafe_zip(self):
        archive = Path(self.temp.name) / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as bundle: bundle.writestr("../outside", "bad")
        receipt = Path(self.temp.name) / "receipt.json"
        write_json(receipt, d.file_info(archive))
        with self.assertRaises(d.DemoError): receive(archive, Path(self.temp.name) / "dest", receipt)


@unittest.skipUnless(d.DEFAULT_P3.exists() and d.DEFAULT_P2.exists(), "Real received releases not installed")
class RealReleaseSmokeTests(unittest.TestCase):
    def test_real_offline_readonly_and_live_model_reload(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("src.model.baseline.train_baseline", side_effect=AssertionError("training forbidden")):
            r = d.load_release()
            self.assertEqual((len(r.cves), len(r.pairs), r.summary()["scored"]), (396, 15, 10))
            self.assertEqual(r.summary()["queue"], {"patch": 8, "review_required": 7})
            row = r.lookup_cve("CVE-2023-41387")
            self.assertEqual([row[k] for k in ["cvss_rank", "epss_rank", "kev_first_rank"]], [30, 128, 127])
            self.assertIn("reason", r.lookup_prediction(row["cve_id"]))
            self.assertEqual([r.compare_predictions(s)["common_n"] for s in ["validation", "test"]], [69, 108])
            saved = r.lookup_prediction("CVE-2023-38709")
            live = r.live_prediction("CVE-2023-38709")
            self.assertEqual(live["mode"], "live")
            for key in [*(f"pred_{m}" for m in d.METRICS), "predicted_vector", "predicted_base_score", "vector_valid"]:
                self.assertEqual(live[key], saved[key], key)
            self.assertNotEqual(r.lookup_cve("CVE-2023-38709")["cvss_base_score"], live["predicted_base_score"])
            for path, expected in r.verified_files.items():
                self.assertEqual(d.file_info(path), expected)

    def test_missing_dependency_falls_back_to_saved(self):
        r = d.load_release()
        with patch("src.model.baseline.load_artifact", side_effect=ImportError("missing sklearn")):
            result = r.live_prediction("CVE-2023-38709")
        self.assertEqual(result["mode"], "saved")
        self.assertIn("ImportError", result["fallback_reason"])

    def test_cli_json_and_error(self):
        # main reconfigures real terminals only; StringIO is also supported.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(main(["--no-ai", "--json", "summary"]), 0)
            self.assertEqual(main(["--no-ai", "cve", ""]), 2)
        self.assertEqual(json.loads(out.getvalue())["n"], 396)
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
