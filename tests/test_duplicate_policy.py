"""Meaningful leakage-policy cases, using small offline CVE fixtures."""
import copy
import unittest

import pandas as pd
from pandas.testing import assert_frame_equal

from src.model.duplicate_policy import plan_duplicates
from tests.test_model_data_audit import sample_frame, SPLIT_CONFIG, VERSION


class DuplicatePolicyTests(unittest.TestCase):
    def plan(self, frame, split_config=None):
        return plan_duplicates(frame, dataset_version=VERSION,
                               split_config=split_config or copy.deepcopy(SPLIT_CONFIG))

    def test_normalization_later_periods_and_within_period_retention(self):
        frame = sample_frame(
            {"description": "ＡＢＣ  vulnerability"},
            {"description": "abc\nVULNERABILITY"},
            {"description": "abc vulnerability", "published": "2024-01-01T00:00:00Z"},
            {"description": "abc vulnerability", "published": "2024-07-01T00:00:00Z"},
            {"description": "unique test", "published": "2024-12-31T23:59:59Z"},
        )
        before = frame.copy(deep=True)
        decisions, counts, summary = self.plan(frame)
        self.assertEqual(decisions.keep_in_preview.tolist(), [True, True, False, False, True])
        self.assertEqual(summary["kept_candidates"], 3)
        self.assertEqual(summary["cross_split_groups_after"], 0)
        self.assertEqual(len(counts), 132)  # all 22 classes, 3 splits, before/after
        absent_val = counts.loc[(counts.stage == "after") & (counts.split == "validation")]
        self.assertTrue(absent_val.support.eq(0).all())
        assert_frame_equal(frame, before)

    def test_validation_only_group_excludes_test_not_moves_it(self):
        frame = sample_frame(
            {"description": "same", "published": "2024-02-01T00:00:00Z"},
            {"description": "same", "published": "2024-08-01T00:00:00Z"})
        decisions, _, _ = self.plan(frame)
        self.assertEqual(decisions.proposed_split.tolist(), ["validation", "test"])
        self.assertEqual(decisions.keep_in_preview.tolist(), [True, False])

    def test_labels_epss_and_kev_do_not_choose_kept_rows(self):
        frame = sample_frame({"description": "same"},
                             {"description": "same", "published": "2024-07-01T00:00:00Z"})
        expected, _, _ = self.plan(frame)
        frame.loc[1, "AV"] = "L"
        frame.loc[1, "cvss_vector"] = frame.loc[1, "cvss_vector"].replace("AV:N", "AV:L")
        frame.loc[0, "epss"] = pd.NA
        frame.loc[1, "is_kev"] = True
        actual, _, _ = self.plan(frame)
        assert_frame_equal(expected, actual)

    def test_stable_when_input_order_or_index_changes(self):
        frame = sample_frame({"description": "same"},
                             {"description": "same", "published": "2024-07-01T00:00:00Z"})
        expected, _, _ = self.plan(frame)
        frame = frame.iloc[::-1].copy()
        frame.index = [7, 7]
        actual, _, _ = self.plan(frame)
        assert_frame_equal(expected, actual)

    def test_invalid_or_outside_date_rejected(self):
        for date in (pd.NaT, "2025-01-01T00:00:00Z"):
            with self.subTest(date=date), self.assertRaisesRegex(ValueError, "date inside"):
                self.plan(sample_frame({"published": date}))

    def test_overlap_rejected(self):
        config = copy.deepcopy(SPLIT_CONFIG)
        config["train"]["end_exclusive"] = "2024-02-01"
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            self.plan(sample_frame({}), config)

    def test_rejected_or_duplicate_id_not_silently_filtered(self):
        for frame in (sample_frame({"vuln_status": "Rejected"}),
                      sample_frame({"cve_id": "CVE-2023-1000"}, {"cve_id": "CVE-2023-1000"})):
            with self.assertRaises(ValueError):
                self.plan(frame)


if __name__ == "__main__":
    unittest.main()
