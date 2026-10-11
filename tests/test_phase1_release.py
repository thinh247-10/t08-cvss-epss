"""Offline checks for scoring, evidence scope and leakage decisions."""
import unittest
import pandas as pd
from pandas.testing import assert_frame_equal

from src.environmental.cvss_base import calculate_base_score, roundup
from src.collect.filter_scope import classify_scope, cpe_product, vulnerable_cpes
from src.model.duplicate_policy import plan_duplicates
from src.model.near_duplicates import plan_near_duplicates
from tests.test_model_data_audit import sample_frame, SPLIT_CONFIG, VERSION


class BaseScorerTests(unittest.TestCase):
    def test_observed_and_published_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            # Discourse GHSA-5www-jxvf-vrc3 published 5.7.
            "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N": 5.7,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(calculate_base_score(vector), expected)

    def test_roundup_float_noise(self):
        self.assertEqual(roundup(.1 + .2), .3)
        self.assertEqual(roundup(4.02), 4.1)
        self.assertEqual(roundup(4.0), 4.0)

    def test_bad_version_missing_duplicate_and_extra_metrics(self):
        base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        for vector in (None, base.replace("3.1", "3.0"), base + "/E:X",
                       base.replace("AC:L", "AV:N"), base.replace("/A:H", ""), base.replace("AV:N", "AV:X")):
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                calculate_base_score(vector)


class ScopeTests(unittest.TestCase):
    policy = {"policy_version": "test", "products": [
        {"vendor": "joomla", "product": "joomla!", "domain": "web", "evidence": "https://www.joomla.org/", "role": "CMS"},
        {"vendor": "patreon", "product": "flutter_downloader", "domain": "mobile", "evidence": "https://pub.dev/packages/flutter_downloader", "role": "SDK"}]}

    def test_escaped_product_and_exact_application_match(self):
        value = r"cpe:2.3:a:joomla:joomla\!:*:*:*:*:*:*:*:*"
        self.assertEqual(cpe_product(value), ("a", "joomla", "joomla!"))
        row = classify_scope("CVE-2023-1000", [value], [], self.policy)
        self.assertTrue(row["in_scope"])
        self.assertEqual(row["domain_tags"], ["web"])
        self.assertEqual(len(row["scope_evidence"]), 2)

    def test_environment_and_negation_not_used(self):
        cpe = "cpe:2.3:a:patreon:flutter_downloader:*:*:*:*:*:*:*:*"
        data = [{"nodes": [{"cpeMatch": [{"vulnerable": False, "criteria": cpe}]}]},
                {"negate": True, "nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}]
        self.assertEqual(list(vulnerable_cpes(data)), [])

    def test_os_not_mobile_and_unknown_not_excluded(self):
        row = classify_scope("CVE-2023-1000", ["cpe:2.3:o:google:android:12:*:*:*:*:*:*:*"], [], self.policy)
        self.assertEqual(row["scope_status"], "needs_review")
        self.assertFalse(row["in_scope"])

    def test_mobile_plugin_and_repeated_cpes_not_duplicate_rows(self):
        cpe = "cpe:2.3:a:patreon:flutter_downloader:*:*:*:*:*:*:*:*"
        row = classify_scope("CVE-2023-1000", [cpe, cpe], [], self.policy)
        self.assertEqual(row["domain_tags"], ["mobile"])
        self.assertEqual(len(row["product_groups"]), 1)


class NearDuplicateTests(unittest.TestCase):
    def test_near_variant_removed_with_dates_and_labels_preserved(self):
        text = " ".join(f"word{i}" for i in range(160))
        frame = sample_frame({"description": text},
                             {"description": text + " suffix", "published": "2024-02-01T00:00:00Z"},
                             {"description": "completely unrelated short text", "published": "2024-08-01T00:00:00Z"})
        before = frame.copy(deep=True)
        exact, _, _ = plan_duplicates(frame, dataset_version=VERSION, split_config=SPLIT_CONFIG)
        result, edges, stats = plan_near_duplicates(frame, exact)
        self.assertEqual(result.keep_in_preview.tolist(), [True, False, True])
        self.assertEqual(len(edges), 1)
        self.assertEqual(stats["verified_edges"], 1)
        assert_frame_equal(frame, before)
        again, _, _ = plan_near_duplicates(frame.iloc[::-1], exact)
        assert_frame_equal(result, again)

    def test_exact_groups_stay_connected_without_lsh_edges(self):
        frame = sample_frame({"description": "identical"},
                             {"description": "identical", "published": "2024-08-01T00:00:00Z"})
        exact, _, _ = plan_duplicates(frame, dataset_version=VERSION, split_config=SPLIT_CONFIG)
        result, edges, _ = plan_near_duplicates(frame, exact)
        self.assertEqual(result.keep_in_preview.tolist(), [True, False])
        self.assertEqual(result.component_id.nunique(), 1)
        self.assertTrue(edges.empty)


if __name__ == "__main__":
    unittest.main()
