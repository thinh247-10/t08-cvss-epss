"""Offline checks for pilot limits and rejected/missing-label reporting."""

import unittest

import pandas as pd

from src.collect.collect_pilot import build_params, candidate_mask, summarize_records


class PilotChecks(unittest.TestCase):
    def test_expanding_page_does_not_change_date_window_or_exclude_rejected(self):
        config = {"collection": {"start_date": "2023-01-01", "end_date": "2024-12-31"}}
        small = build_params(config)
        large = build_params(config, limit=1000)
        self.assertEqual(large, {**small, "resultsPerPage": 1000})
        self.assertNotIn("noRejected", large)
        for limit in (0, 1001):
            with self.assertRaises(ValueError):
                build_params(config, limit=limit)

    def test_all_rejected_page_explains_missing_labels(self):
        frame = pd.DataFrame({
            "vuln_status": ["Rejected"] * 50,
            "description": ["Rejected reason: this record has not been used."] * 50,
            "cvss_vector": [None] * 50,
        })
        summary = summarize_records(frame)
        self.assertEqual(summary["downloaded_records"], 50)
        self.assertEqual(summary["status_counts"], {"Rejected": 50})
        self.assertEqual(summary["missing_parseable_base_cvss31"], 50)
        self.assertEqual(summary["non_rejected_description_and_vector_candidates"], 0)

    def test_candidate_reporting_keeps_rows_and_excludes_rejected_even_with_labels(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        frame = pd.DataFrame({
            "vuln_status": ["Rejected", "Analyzed", "Analyzed", "Analyzed", None],
            "description": ["Rejected reason", "Real description", "No label", "  ", "Unknown status"],
            "cvss_vector": [vector, vector, None, vector, vector],
        })
        before = frame.copy(deep=True)
        self.assertEqual(candidate_mask(frame).tolist(), [False, True, False, False, False])
        summary = summarize_records(frame)
        self.assertEqual(summary["rejected_records"], 1)
        self.assertEqual(summary["unknown_status_records"], 1)
        self.assertEqual(summary["missing_description"], 1)
        self.assertEqual(summary["non_rejected_description_and_vector_candidates"], 1)
        pd.testing.assert_frame_equal(frame, before)


if __name__ == "__main__":
    unittest.main()
