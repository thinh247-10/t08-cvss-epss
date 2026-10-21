"""Hand-checkable synthetic fixtures, never used in published research outputs."""
import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
import pandas as pd
from src.analysis.prediction_rank_impact import analyze, heldout_cohort, main, file_info, VERSIONS, DATASET

VHIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VMID = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def fixture():
    ids = [f"CVE-2099-{i}" for i in range(1000, 1006)]
    ml = pd.DataFrame({"cve_id": ids, "cvss_base_score": [9.8, 7.5, 7.5]*2,
                       "dataset_version": DATASET, "split": ["validation"]*3 + ["test"]*3,
                       "domain_tags": [["web"] for _ in ids]})
    ranking = ml[["cve_id", "cvss_base_score", "dataset_version"]].copy()
    pred = {}
    for model, version in VERSIONS.items():
        pred[model] = pd.DataFrame({"cve_id": ids, "model_version": version, "dataset_version": DATASET,
            "split": ml.split, "prediction_usage": "evaluation", "vector_valid": True,
            "prediction_error": None, "predicted_base_score": [7.5, 9.8, 7.5]*2,
            "predicted_vector": [VMID, VHIGH, VMID]*2})
    return ranking, ml, pred


class PredictionImpactTests(unittest.TestCase):
    def test_id_join_ties_known_jaccard_tau_and_no_mutation(self):
        r, ml, p = fixture()
        original = p["tfidf"].copy(deep=True)
        p["distilbert"] = p["distilbert"].iloc[::-1]
        out, metrics, excluded = analyze(r.iloc[::-1], ml, p, ks=(1, 2, 3))
        self.assertTrue(excluded.empty)
        row = out.loc[(out.model == "tfidf") & (out.cve_id == "CVE-2099-1000")].iloc[0]
        self.assertEqual((row.observed_rank, row.predicted_rank, row.rank_delta), (1, 2, -1))
        for split in metrics["splits"]:
            self.assertEqual(split["common_n"], 3)
            for model in split["models"]:
                self.assertAlmostEqual(model["kendall_tau_b"], -.5)
                self.assertEqual([j["value"] for j in model["jaccard"]], [0., 1., None])
        pd.testing.assert_frame_equal(p["tfidf"], original)

    def test_duplicates_fail(self):
        for kind in ("ranking", "ml", "prediction"):
            r, ml, p = fixture()
            if kind == "ranking": r = pd.concat([r, r.iloc[:1]])
            elif kind == "ml": ml = pd.concat([ml, ml.iloc[:1]])
            else: p["tfidf"] = pd.concat([p["tfidf"], p["tfidf"].iloc[:1]])
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "duplicate"):
                analyze(r, ml, p)

    def test_version_filter_ignores_dummy(self):
        r, ml, p = fixture()
        p["tfidf"] = pd.concat([p["tfidf"], p["tfidf"].assign(model_version="dummy")])
        out, _, _ = analyze(r, ml, p)
        self.assertEqual(len(out), 12)
        p["tfidf"] = p["tfidf"].assign(model_version="wrong")
        with self.assertRaises(ValueError): analyze(r, ml, p)

    def test_missing_and_invalid_reduce_both_models_to_common_ids(self):
        r, ml, p = fixture()
        p["tfidf"] = p["tfidf"].iloc[1:].copy()
        p["distilbert"].loc[1, "predicted_base_score"] = float("nan")
        out, metrics, excluded = analyze(r, ml, p)
        val = metrics["splits"][0]
        self.assertEqual(val["common_n"], 1)
        self.assertEqual(val["coverage"]["tfidf"]["missing"], 1)
        self.assertEqual(val["coverage"]["distilbert"]["invalid"], 1)
        self.assertEqual(len(excluded), 4)
        singleton = out.loc[out.split.eq("validation")]
        self.assertEqual(set(singleton.cve_id), {"CVE-2099-1002"})
        self.assertTrue(singleton[["observed_rank", "predicted_rank", "rank_delta"]].isna().all().all())
        self.assertIsNone(val["models"][0]["kendall_tau_b"])

    def test_wrong_split_usage_dataset_and_vector_score(self):
        for column, value in (("split", "train"), ("prediction_usage", "demo"), ("dataset_version", "wrong")):
            r, ml, p = fixture()
            p["tfidf"].loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError): analyze(r, ml, p)
        r, ml, p = fixture()
        p["tfidf"].loc[0, "predicted_base_score"] = 0.
        _, metrics, exclusions = analyze(r, ml, p)
        self.assertEqual(metrics["splits"][0]["common_n"], 2)
        self.assertIn("vector_score_mismatch", exclusions.reason.tolist())

    def test_train_not_used_and_constant_tau_undefined(self):
        r, ml, p = fixture()
        extra = ml.iloc[:1].assign(cve_id="CVE-2099-9999", split="train")
        ml = pd.concat([ml, extra], ignore_index=True)
        r = pd.concat([r, extra[r.columns]], ignore_index=True)
        self.assertEqual(len(heldout_cohort(r, ml)), 6)
        p["tfidf"] = p["tfidf"].assign(predicted_vector=VHIGH, predicted_base_score=9.8)
        _, metrics, _ = analyze(r, ml, p)
        self.assertEqual(metrics["splits"][0]["models"][0]["undefined_reason"], "constant raw score")

    def test_wrong_join_split_unknown_id_blank_key_and_source_version_fail(self):
        for case in ("wrong_split", "unknown_id", "blank_id", "ranking_version", "ml_version", "unknown_ml_split"):
            r, ml, p = fixture()
            if case == "wrong_split": p["tfidf"].loc[0, "split"] = "test"
            elif case == "unknown_id": p["tfidf"].loc[0, "cve_id"] = "CVE-2099-9999"
            elif case == "blank_id": p["tfidf"].loc[0, "cve_id"] = " "
            elif case == "ranking_version": r.loc[0, "dataset_version"] = "WRONG"
            elif case == "ml_version": ml.loc[0, "dataset_version"] = "WRONG"
            else: ml.loc[0, "split"] = "WRONG"
            with self.subTest(case=case), self.assertRaises(ValueError):
                analyze(r, ml, p)

    def test_observed_mismatch_and_missing_observation(self):
        r, ml, p = fixture()
        r.loc[0, "cvss_base_score"] = 9.7
        with self.assertRaisesRegex(ValueError, "Observed Base"):
            analyze(r, ml, p)
        r.loc[0, "cvss_base_score"] = float("nan")
        ml.loc[0, "cvss_base_score"] = float("nan")
        out, metrics, exclusions = analyze(r, ml, p)
        self.assertEqual(metrics["splits"][0]["invalid_observed"], 1)
        self.assertEqual(set(exclusions.reason), {"invalid_observed_score"})
        self.assertEqual(out.loc[out.split.eq("validation")].groupby("model").size().to_dict(), {"tfidf": 2, "distilbert": 2})

    def test_empty_split_and_join_audit(self):
        r, ml, p = fixture()
        r = r.iloc[3:].copy()
        r = pd.concat([r, r.iloc[:1].assign(cve_id="CVE-2099-9999")], ignore_index=True)
        out, metrics, _ = analyze(r, ml, p)
        self.assertEqual(metrics["join_audit"]["ranking_missing_from_ml_ids"], ["CVE-2099-9999"])
        val = metrics["splits"][0]
        self.assertEqual((val["eligible"], val["common_n"]), (0, 0))
        self.assertIsNone(val["coverage"]["tfidf"]["coverage"])
        self.assertEqual(len(out), 6)
        json.dumps(metrics, allow_nan=False)

    def test_zero_score_valid_and_invalid_vector_counted_without_zero_imputation(self):
        r, ml, p = fixture()
        p["tfidf"].loc[0, ["predicted_base_score", "predicted_vector"]] = [0.,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"]
        p["distilbert"].loc[1, "vector_valid"] = False
        out, metrics, excluded = analyze(r, ml, p)
        self.assertEqual(metrics["splits"][0]["common_n"], 2)
        self.assertIn("invalid_vector_flag", excluded.reason.tolist())
        self.assertEqual(out.loc[out.model.eq("tfidf") & out.cve_id.eq("CVE-2099-1000"), "predicted_base_score"].item(), 0.)

    def test_cli_reports_actual_paths_and_protects_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            r, ml, p = fixture()
            r.to_parquet(root / "ranking.parquet")
            ml.to_parquet(root / "ml.parquet")
            for model in p:
                p[model].to_csv(root / f"{model}.csv", index=False)
            args = ["--ranking-cohort", str(root / "ranking.parquet"), "--ml-cohort", str(root / "ml.parquet"),
                    "--tfidf", str(root / "tfidf.csv"), "--distilbert", str(root / "distilbert.csv"),
                    "--output-dir", str(root / "output"), "--report", str(root / "report.md")]
            with contextlib.redirect_stdout(io.StringIO()): main(args)
            metrics = json.loads((root / "output/prediction_rank_metrics.json").read_text())
            self.assertEqual(metrics["command"][-len(args):], args)
            self.assertEqual(len(metrics["count_warnings"]), 2)
            for record in metrics["inputs"] + metrics["outputs"]:
                self.assertEqual(file_info(record["path"]), record)
            self.assertIn(str(root / "ranking.parquet"), (root / "report.md").read_text(encoding="utf-8"))
            before = (root / "tfidf.csv").read_bytes()
            args[-1] = str(root / "tfidf.csv")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): main(args)
            self.assertEqual((root / "tfidf.csv").read_bytes(), before)

    @unittest.skipUnless(Path("data/processed/phase2_received/distilbert/predictions.csv").is_file(), "Frozen release not installed")
    def test_frozen_release_common_ids_and_split_separation(self):
        release = Path("data/processed/phase1_v1_20261010")
        received = Path("data/processed/phase2_received")
        ranking = pd.read_parquet(release / "ranking_cohort.parquet")
        ml = pd.read_parquet(release / "ml_cohort.parquet")
        out, metrics, exclusions = analyze(ranking, ml, {
            "tfidf": pd.read_csv(received / "baseline/data/processed/predictions.csv"),
            "distilbert": pd.read_csv(received / "distilbert/predictions.csv")})
        self.assertEqual(len(out), 354)
        self.assertTrue(exclusions.empty)
        self.assertEqual(metrics["join_audit"]["train_excluded"], 219)
        for split, n in (("validation", 69), ("test", 108)):
            part = out.loc[out.split.eq(split)]
            expected = set(ranking.cve_id) & set(ml.loc[ml.split.eq(split), "cve_id"])
            for model in VERSIONS:
                self.assertEqual(set(part.loc[part.model.eq(model), "cve_id"]), expected)
                self.assertEqual(len(expected), n)
            scores = part.pivot(index="cve_id", columns="model", values="observed_rank")
            self.assertTrue(scores.tfidf.eq(scores.distilbert).all())
        self.assertFalse(set(out.loc[out.split.eq("validation"), "cve_id"]) & set(out.loc[out.split.eq("test"), "cve_id"]))


if __name__ == "__main__":
    unittest.main()
