"""Hand-derived fixtures; never use the implementation as expected values."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml

import pandas as pd
from pandas.testing import assert_frame_equal

from src.analysis.compare_rankings import build_rankings, digest
from src.analysis.ranking_metrics import compute_metrics, main


def cohort():
    # CVSS order A,B,C; EPSS B,C,A; KEV-first C,B,A.
    return pd.DataFrame(dict(cve_id=["CVE-2024-1001", "CVE-2024-1002", "CVE-2024-1003"],
                             cvss_base_score=[9.0, 8.0, 7.0], epss=[0.1, 0.9, 0.8],
                             is_kev=[False, False, True], dataset_version=["test-v1"] * 3,
                             epss_date=["2026-09-29"] * 3))


def rank(source):
    return build_rankings(source, dataset_version="test-v1", cohort_id="test:ranking")


def metrics(frame, ks=(2,), **kwargs):
    return compute_metrics(frame, ks=ks, dataset_version="test-v1",
                           cohort_id="test:ranking", **kwargs)


class RankingMetricsChecks(unittest.TestCase):
    def test_hand_calculated_jaccard_recall_delta_and_tau(self):
        summary, top, overlap, delta = metrics(rank(cohort()))
        pair = overlap.query("policy_a == 'cvss' and policy_b == 'epss'").iloc[0]
        self.assertEqual((pair.intersection, pair.union), (1, 3))
        self.assertAlmostEqual(pair.jaccard, 1 / 3)
        # Three pairs: one concordant, two discordant -> -1/3.
        self.assertAlmostEqual(summary["kendall_tau_b"]["value"], -1 / 3)
        self.assertEqual(top.kev_hits.tolist(), [0, 1, 1])
        self.assertEqual(top.kev_recall.iloc[:2].tolist(), [0, 1])
        self.assertTrue(pd.isna(top.kev_recall.iloc[2]))
        self.assertEqual(top.kev_recall_reason.iloc[2], "policy_uses_kev_directly")
        self.assertEqual(delta.rank_delta_cvss_epss.tolist(), [-2, 1, 1])
        json.dumps(summary, allow_nan=False)

    def test_ties_use_raw_scores_not_id_order(self):
        source = cohort()
        source["cvss_base_score"] = [9.0, 9.0, 7.0]
        source["epss"] = [0.9, 0.8, 0.8]
        summary, top, _, _ = metrics(rank(source), ks=[1])
        # One concordant, zero discordant, one x-only tie, one y-only tie -> 1/2.
        self.assertAlmostEqual(summary["kendall_tau_b"]["value"], 0.5)
        self.assertEqual(top.iloc[0].cutoff_tie_count, 2)
        self.assertEqual(top.iloc[0].selected_from_cutoff_tie, 1)

    def test_kev_first_cutoff_tuple_excludes_id(self):
        source = cohort()
        source["cvss_base_score"] = [9.0] * 3
        source["epss"] = [0.5] * 3
        source["is_kev"] = [True] * 3
        _, top, _, _ = metrics(rank(source), ks=[2])
        self.assertEqual(top.cutoff_tie_count.tolist(), [3, 3, 3])
        self.assertEqual(top.selected_from_cutoff_tie.tolist(), [2, 2, 2])

    def test_shuffled_input_is_identical_and_unchanged(self):
        original = rank(cohort())
        before = original.copy(deep=True)
        left = metrics(original)
        right = metrics(original.iloc[::-1])
        self.assertEqual(left[0], right[0])
        for a, b in zip(left[1:], right[1:]):
            assert_frame_equal(a, b)
        assert_frame_equal(original, before)

    def test_zero_kev_is_null_not_zero(self):
        source = cohort()
        source["is_kev"] = False
        summary, top, _, _ = metrics(rank(source))
        self.assertTrue(top.kev_recall.isna().all())
        self.assertEqual(top.kev_hits.tolist(), [0, 0, 0])
        self.assertEqual(summary["topk"][0]["kev_recall_reason"], "no_kev_in_cohort")
        self.assertIsNone(summary["topk"][2]["kev_recall"])

    def test_single_row_and_k_at_least_n_are_explicit(self):
        summary, top, overlap, _ = metrics(rank(cohort().iloc[:1]), ks=[1, 10])
        self.assertIsNone(summary["kendall_tau_b"]["value"])
        self.assertEqual(summary["kendall_tau_b"]["reason"], "fewer_than_two_rows")
        self.assertFalse(top.selection_is_discriminating.any())
        self.assertEqual(top.effective_k.tolist(), [1] * 6)
        self.assertEqual(overlap.jaccard.tolist(), [1] * 6)

    def test_constant_column_tau_is_null(self):
        for column in ("cvss_base_score", "epss"):
            source = cohort()
            source[column] = source[column].iloc[0]
            summary, _, _, _ = metrics(rank(source))
            self.assertIsNone(summary["kendall_tau_b"]["value"])
            self.assertEqual(summary["kendall_tau_b"]["reason"], "constant_score_column")
            json.dumps(summary, allow_nan=False)

    def test_invalid_k(self):
        for ks in ([], [0], [-1], [1.5], [True], [1, 1], "10", None):
            with self.subTest(ks=ks), self.assertRaises(ValueError):
                metrics(rank(cohort()), ks=ks)

    def test_different_ids_or_scores_from_reference_rejected(self):
        for column, value in (("cve_id", "CVE-2024-9999"), ("epss", 0.11)):
            changed = cohort()
            changed.loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError):
                metrics(rank(changed), reference_cohort=cohort())

    def test_bad_rank_cohort_version_duplicate_missing_rejected(self):
        for column, value in (("cvss_rank", 2), ("cohort_id", "wrong"),
                              ("dataset_version", "wrong"), ("policy_version", "wrong"),
                              ("epss", None), ("cve_id", "CVE-2024-1002"),
                              ("is_kev", None)):
            bad = rank(cohort()).copy()
            if value is None:
                bad[column] = bad[column].astype(object)
            bad.loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError):
                metrics(bad)

    def test_empty_wrong_schema_and_float_rank_rejected(self):
        frame = rank(cohort())
        for bad in (frame.iloc[:0], frame.drop(columns="epss"),
                    frame.assign(cvss_rank=frame.cvss_rank.astype(float))):
            with self.assertRaises(ValueError):
                metrics(bad)

    def test_cli_bad_config_fails_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "bad.yaml"
            config.write_text("schema_version: unsupported\n", encoding="utf-8")
            output = Path(folder) / "output"
            with self.assertRaisesRegex(ValueError, "Unsupported config"):
                main(["--rankings", str(Path(folder) / "rankings.csv"),
                      "--config", str(config), "--output-dir", str(output)])
            self.assertFalse(output.exists())

    def test_cli_roundtrip_hashes_nulls_and_reference_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            release, output = base / "release", base / "out"
            release.mkdir()
            source = release / "ranking_cohort.parquet"
            cohort().to_parquet(source, index=False)
            dates = dict(epss_date="2026-09-29", kev_date_released="2026-09-30",
                         kev_retrieved_at="2026-10-01")
            meta = dict(status="complete", ranking_ready=True, dataset_version="test-v1",
                        statistics=dict(ranking=3, ranking_kev=1), **dates,
                        files={source.name: dict(bytes=source.stat().st_size, sha256=digest(source))})
            (release / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
            rankings = base / "rankings.csv"
            rank(cohort()).to_csv(rankings, index=False)
            config = base / "config.yaml"
            cfg = dict(schema_version="p3-ranking-metrics-v1", dataset_version="test-v1",
                       cohort_id="test:ranking", policy_version="cvss-epss-kev-first-v1",
                       context_version="test-context", release_folder=str(release),
                       rankings_path=str(rankings), output_dir=str(output), k=[2],
                       illustrative_thresholds=dict(cvss=7.0, epss=0.10), source_dates=dates,
                       missing_policy="reject_ranking_inputs_null_undefined_metrics_with_reason")
            config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
            args = ["--rankings", str(rankings), "--config", str(config), "--output-dir", str(output)]
            with patch("src.analysis.ranking_metrics.git_output", return_value="test-commit"):
                main(args)
            loaded = json.loads((output / "ranking_metrics.json").read_text())
            self.assertIsNone(loaded["topk"][2]["kev_recall"])
            self.assertNotIn("NaN", (output / "ranking_metrics.json").read_text())
            provenance = json.loads((output / "metadata.json").read_text())
            self.assertEqual(provenance["inputs"]["config.yaml"]["sha256"], digest(config))
            for name, record in provenance["outputs"].items():
                self.assertEqual(record["sha256"], digest(output / name))
            self.assertEqual(provenance["outputs"]["rank_deltas.csv"]["rows"], 3)
            changed = cohort()
            changed.loc[0, "cve_id"] = "CVE-2024-9999"
            rank(changed).to_csv(rankings, index=False)
            old_hash = digest(output / "ranking_metrics.json")
            with self.assertRaisesRegex(ValueError, "fixed cohort"):
                main(args)
            self.assertEqual(old_hash, digest(output / "ranking_metrics.json"))


if __name__ == "__main__":
    unittest.main()
