"""Verify the current N2 narrative against generated CSV, not hand-copied constants."""
import re
from pathlib import Path
import unittest

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed/p3_n2"


class Phase3ReportChecks(unittest.TestCase):
    def test_five_case_table_matches_observed_ranking_environmental_queue(self):
        report = (ROOT / "docs/analysis-results.md").read_text(encoding="utf-8")
        rank = pd.read_csv(DATA / "rankings.csv").set_index("cve_id")
        env = pd.read_csv(DATA / "environmental_scores.csv").set_index(["cve_id", "asset_id"])
        queue = pd.read_csv(DATA / "priority_queue.csv").set_index(["cve_id", "asset_id"])
        count = 0
        for line in report.splitlines():
            if not re.match(r"^\| \d{4}-\d+ / ", line):
                continue
            parts = [p.strip() for p in line.strip("|").split("|")]
            cve, asset = parts[0].split(" / ")
            cve = "CVE-" + cve
            observed, scored, queued = rank.loc[cve], env.loc[(cve, asset)], queue.loc[(cve, asset)]
            self.assertEqual(float(parts[1]), observed.cvss_base_score)
            self.assertEqual(float(parts[2]), observed.epss)
            self.assertEqual([int(v) for v in parts[3:6]],
                             [observed.cvss_rank, observed.epss_rank, observed.kev_first_rank])
            self.assertEqual(float(parts[6]), scored.environmental_score)
            expected_rank = "null" if pd.isna(queued.priority_rank) else str(int(queued.priority_rank))
            self.assertEqual(parts[7], f"{queued.queue_status} / {expected_rank}")
            count += 1
        self.assertEqual(count, 5)

    def test_playbook_has_operational_controls_not_empty_threshold_template(self):
        report = (ROOT / "docs/04-patch-playbook.md").read_text(encoding="utf-8")
        self.assertNotIn("_?_", report)
        for term in ("Trigger", "backup", "restore", "rollback", "compatibility",
                     "sau vá", "giả định", "review_required", "deadline", "mobile"):
            self.assertIn(term, report)

    def test_context_summary_count_and_pair_population(self):
        mapping = pd.read_csv(DATA / "cve_asset_mapping.csv")
        env = pd.read_csv(DATA / "environmental_scores.csv")
        queue = pd.read_csv(DATA / "priority_queue.csv")
        comparison = pd.read_csv(DATA / "context_comparison.csv")
        self.assertEqual((len(mapping), len(env), len(queue), len(comparison)), (15, 10, 15, 8))
        self.assertTrue(mapping.context_version.eq("phase3-context-v2").all())
        self.assertEqual(queue.queue_status.value_counts().to_dict(), {"patch": 8, "review_required": 7})
        patch = queue.loc[queue.queue_status.eq("patch")]
        self.assertEqual(set(zip(comparison.cve_id, comparison.asset_id)), set(zip(patch.cve_id, patch.asset_id)))


if __name__ == "__main__":
    unittest.main()
