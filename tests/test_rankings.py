"""Synthetic fixtures with hand-ordered expected positions; no API calls."""

import unittest

import pandas as pd
from pandas.testing import assert_frame_equal

from src.analysis.compare_rankings import build_rankings, OUTPUT_COLUMNS


def fixture():
    # KEV first, then EPSS, then CVSS, then ID; each tie-break has a witness.
    frame = pd.DataFrame({
        "cve_id": [f"CVE-2024-{n}" for n in (1005, 1003, 1001, 1004, 1002)],
        "cvss_base_score": [9.8, 7.0, 7.0, 9.8, 7.0],
        "epss": [0.8, 0.2, 0.2, 0.2, 0.2],
        "is_kev": [False, True, True, True, False],
        "dataset_version": ["test-v1"] * 5,
        "epss_date": ["2026-09-29"] * 5,
    })
    return frame


def run(frame, **kwargs):
    return build_rankings(frame, dataset_version="test-v1", cohort_id="synthetic", **kwargs)


class RankingChecks(unittest.TestCase):
    def test_hand_ordered_ties_and_same_population(self):
        result = run(fixture())
        expected = {
            "cvss_rank": [1004, 1005, 1001, 1002, 1003],
            "epss_rank": [1005, 1001, 1002, 1003, 1004],
            "kev_first_rank": [1004, 1001, 1003, 1005, 1002],
        }
        for column, ids in expected.items():
            with self.subTest(column=column):
                self.assertEqual(result.sort_values(column).cve_id.tolist(),
                                 [f"CVE-2024-{n}" for n in ids])
                self.assertEqual(sorted(result[column]), list(range(1, 6)))
        self.assertEqual(tuple(result.columns), OUTPUT_COLUMNS)

    def test_reordered_input_and_nonunique_index_do_not_change_result(self):
        original = fixture()
        before = original.copy(deep=True)
        shuffled = original.iloc[::-1].copy()
        shuffled.index = [0] * len(shuffled)
        assert_frame_equal(run(original), run(shuffled))
        assert_frame_equal(original, before)

    def test_duplicate_and_invalid_ids_are_rejected(self):
        for bad_id in ("CVE-2024-1005", "", "cve-2024-1001"):
            frame = fixture()
            frame.loc[1, "cve_id"] = bad_id
            with self.subTest(bad_id=bad_id), self.assertRaises(ValueError):
                run(frame)

    def test_missing_values_and_columns_are_rejected(self):
        for column in fixture().columns:
            with self.subTest(column=column):
                frame = fixture().astype(object)
                frame.loc[0, column] = None
                with self.assertRaises(ValueError):
                    run(frame)
                with self.assertRaises(ValueError):
                    run(fixture().drop(columns=column))

    def test_mixed_wrong_version_and_policy_are_rejected(self):
        for value in ("old-version", None):
            frame = fixture()
            frame.loc[0, "dataset_version"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                run(frame)
        with self.assertRaises(ValueError):
            run(fixture(), policy_version="different-policy")

    def test_invalid_scores_and_string_booleans_are_rejected(self):
        for column, value in (("cvss_base_score", 10.1), ("epss", -0.1),
                              ("epss", float("inf")), ("is_kev", "False")):
            frame = fixture()
            if column == "is_kev":
                frame[column] = frame[column].astype(object)
            frame.loc[0, column] = value
            with self.subTest(column=column, value=value), self.assertRaises(ValueError):
                run(frame)

    def test_mixed_or_invalid_dates_are_rejected(self):
        for value in ("2026-09-30", "2026-02-30", "20260929"):
            frame = fixture()
            frame["epss_date"] = value
            if value == "2026-09-30":
                frame.loc[0, "epss_date"] = "2026-09-29"
            with self.subTest(value=value), self.assertRaises(ValueError):
                run(frame)

    def test_valid_zero_scores_and_nullable_booleans_are_preserved(self):
        frame = fixture()
        frame.loc[0, ["cvss_base_score", "epss"]] = 0.0
        frame["is_kev"] = pd.array(frame.is_kev, dtype="boolean")
        result = run(frame)
        self.assertEqual(result.loc[result.cve_id.eq("CVE-2024-1005"), "epss"].iloc[0], 0.0)
        self.assertEqual(result.is_kev.sum(), 3)


if __name__ == "__main__":
    unittest.main()
