"""Check handoff missing values, source labels, and stable sample selection."""

from io import StringIO
import json
import unittest

import pandas as pd

from src.collect.nvd_collector import extract_cve
from src.collect.prepare_handoff import (
    SAMPLE_COLUMNS, SAMPLE_DTYPES, label_counts, make_annotations, make_sample, select_rows,
)


def fixture_frame():
    valid = {
        "id": "CVE-2023-10000", "vulnStatus": "Analyzed",
        "published": "2023-01-02T00:00:00.000", "lastModified": "2023-01-03T00:00:00.000",
        "descriptions": [{"lang": "en", "value": 'A description, with "quotes" and\na newline.'}],
        "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "baseScore": 7.5,
        }}]},
    }
    rejected = {"id": "CVE-2023-10001", "vulnStatus": "Rejected", "metrics": {}}
    frame = pd.DataFrame([extract_cve(valid), extract_cve(rejected)])
    for column in ("published", "last_modified"):
        frame[column] = pd.to_datetime(frame[column], utc=True)
    return frame


class HandoffChecks(unittest.TestCase):
    def test_csv_roundtrip_preserves_unknown_booleans_missing_labels_and_text(self):
        source = fixture_frame()
        sample = make_sample(source, "sample-v1", "2026-09-30T00:00:00+00:00")
        loaded = pd.read_csv(
            StringIO(sample.to_csv(index=False)), dtype=SAMPLE_DTYPES,
            keep_default_na=False, na_values=[""], true_values=["True"], false_values=["False"],
        )
        self.assertEqual(list(loaded.columns), SAMPLE_COLUMNS)
        self.assertTrue(loaded["is_kev"].isna().all())
        self.assertTrue(loaded["epss"].isna().all())
        self.assertTrue(loaded["split"].isna().all())
        self.assertFalse(loaded["in_scope"].any())
        self.assertTrue(loaded["scope_status"].eq("needs_review").all())
        self.assertEqual(loaded["has_cvss31_label"].tolist(), [True, False])
        self.assertTrue(pd.isna(loaded.loc[1, "AV"]))
        self.assertEqual(loaded.loc[0, "description"], source.loc[0, "description"])
        self.assertEqual(json.loads(loaded.loc[0, "domain_tags"]), [])
        self.assertEqual(loaded.loc[0, "cvss_version"], "3.1")

    def test_sampling_does_not_depend_on_row_order(self):
        frame = pd.DataFrame({"cve_id": [f"CVE-2023-{n}" for n in range(10000, 10020)]})
        first = select_rows(frame, 5, 42)
        second = select_rows(frame.iloc[::-1], 5, 42)
        self.assertEqual(first["cve_id"].tolist(), second["cve_id"].tolist())
        self.assertEqual(len(first), 5)
        with self.assertRaises(ValueError):
            select_rows(frame, 21, 42)

    def test_conflicting_extracted_label_cannot_be_handed_off(self):
        frame = fixture_frame()
        frame.loc[0, "AV"] = "P"
        with self.assertRaisesRegex(ValueError, "Nhan khong khop vector"):
            make_sample(frame, "v1", "2026-09-30T00:00:00+00:00")

    def test_reference_links_are_not_automatically_marked_as_scope_evidence(self):
        chosen = fixture_frame().iloc[:1]
        raw = {"CVE-2023-10000": {"references": [{"url": "https://example.org/advisory"}]}}
        annotations = make_annotations(chosen, raw, "v1", "draft-v0.1")
        self.assertEqual(annotations.loc[0, "scope_status"], "needs_review")
        self.assertEqual(annotations.loc[0, "evidence_url"], "")
        self.assertEqual(annotations.loc[0, "reviewer"], "")
        self.assertEqual(json.loads(annotations.loc[0, "reference_urls"]), ["https://example.org/advisory"])

    def test_label_report_includes_classes_with_zero_examples(self):
        counts = label_counts(fixture_frame().iloc[:1])
        self.assertEqual(counts["AV"], {"A": 0, "L": 0, "N": 1, "P": 0})
        self.assertTrue(all(sum(values.values()) == 1 for values in counts.values()))


if __name__ == "__main__":
    unittest.main()
