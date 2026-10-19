"""Synthetic context scenarios; hand-derived status/order and pair membership."""
from dataclasses import asdict
from pathlib import Path
import contextlib
import io
import json
import tempfile
import unittest

import pandas as pd
from pandas.testing import assert_frame_equal

from src.environmental.asset_inventory import load_inventory
from src.analysis.context_priority import (build_environmental, build_queue, compare_context,
                                           validate_mapping, MAP_COLUMNS, main)
from src.analysis.compare_rankings import digest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION, CONTEXT = "t08-v1.0-20261010", "phase3-context-v1"


def fixture():
    assets = pd.DataFrame([asdict(a) for a in load_inventory(ROOT / "config/assets.yaml").assets])
    mapping = pd.DataFrame(yaml.safe_load((ROOT / "config/phase3_mapping.yaml").read_text(encoding="utf-8"))["mappings"])
    ids = sorted(mapping.cve_id.unique())
    master = pd.DataFrame(dict(cve_id=ids, cvss_vector=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]*len(ids),
                               cvss_base_score=[9.8]*len(ids), epss=[0.1]*len(ids),
                               is_kev=[False]*len(ids), dataset_version=[VERSION]*len(ids)))
    return master, mapping, assets


def env(master, mapping, assets):
    return build_environmental(master, mapping, assets, dataset_version=VERSION, context_version=CONTEXT)[0]


def queue(master, mapping, assets, scores=None, policy="context-v1"):
    return build_queue(master, mapping, assets, env(master, mapping, assets) if scores is None else scores,
                       dataset_version=VERSION, context_version=CONTEXT, policy_version=policy)


class ContextChecks(unittest.TestCase):
    def test_all_pairs_preserved_and_clients_review(self):
        master, mapping, assets = fixture()
        output = queue(master, mapping, assets)
        self.assertEqual(len(output), 6)
        self.assertEqual(output.queue_status.value_counts().to_dict(), {"patch": 3, "review_required": 3})
        self.assertEqual(sorted(output.priority_rank.dropna().tolist()), [1, 2, 3])
        self.assertTrue(output.loc[output.exposure.eq("client"), "priority_rank"].isna().all())
        self.assertTrue(output.loc[output.asset_id.eq("API-02"), "environmental_score"].isna().all())

    def test_unaffected_precedes_kev_and_client(self):
        master, mapping, assets = fixture()
        mapping.loc[mapping.asset_id.eq("MOB-01"), "applicability"] = "unaffected"
        mapping.loc[mapping.asset_id.eq("MOB-01"), "mapping_reason"] = "Synthetic: component removed, verified absence."
        master["is_kev"] = True
        output = queue(master, mapping, assets)
        row = output.loc[output.asset_id.eq("MOB-01")].iloc[0]
        self.assertEqual(row.queue_status, "not_applicable")
        self.assertTrue(pd.isna(row.priority_rank))

    def test_kev_unknown_mapping_stays_visible_with_verify_promptly(self):
        master, mapping, assets = fixture()
        master["is_kev"] = True
        row = queue(master, mapping, assets).query("asset_id == 'API-02'").iloc[0]
        self.assertEqual(row.queue_status, "review_required")
        self.assertIn("Verify promptly", row.recommended_action)

    def test_missing_signals_scores_cve_and_exposure_review(self):
        for change in ("epss", "is_kev", "environmental", "cve", "exposure"):
            master, mapping, assets = fixture()
            scores = env(master, mapping, assets)
            if change in ("epss", "is_kev"):
                master[change] = master[change].astype(object)
                master.loc[master.cve_id.eq("CVE-2018-25067"), change] = None
            elif change == "environmental":
                scores = scores.loc[scores.asset_id.ne("WEB-01")]
            elif change == "cve":
                master = master.loc[master.cve_id.ne("CVE-2018-25067")]
                scores = scores.loc[scores.asset_id.ne("WEB-01")]
            else:
                assets.loc[assets.asset_id.eq("WEB-01"), "exposure"] = None
            with self.subTest(change=change):
                row = queue(master, mapping, assets, scores).query("asset_id == 'WEB-01'").iloc[0]
                self.assertEqual(row.queue_status, "review_required")
                self.assertTrue(pd.isna(row.priority_rank))

    def test_duplicate_joins_rejected(self):
        for which in ("master", "mapping", "assets", "environmental"):
            master, mapping, assets = fixture()
            scores = env(master, mapping, assets)
            tables = dict(master=master, mapping=mapping, assets=assets, environmental=scores)
            tables[which] = pd.concat([tables[which], tables[which].iloc[:1]])
            with self.subTest(which=which), self.assertRaises(ValueError):
                queue(tables["master"], tables["mapping"], tables["assets"], tables["environmental"])

    def test_unknown_asset_version_and_bad_evidence_rejected(self):
        for column, value in (("asset_id", "nonexistent"), ("dataset_version", "old"),
                              ("assumed_version", "wrong"), ("evidence_url", "http://unsafe"),
                              ("reviewer", ""), ("applicability", "maybe")):
            master, mapping, assets = fixture()
            mapping.loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError):
                queue(master, mapping, assets)

    def test_shuffled_input_and_ties_deterministic(self):
        master, mapping, assets = fixture()
        scores = env(master, mapping, assets)
        output = queue(master, mapping, assets, scores)
        reordered = queue(master.iloc[::-1], mapping.iloc[::-1], assets.iloc[::-1], scores.iloc[::-1])
        assert_frame_equal(output, reordered)
        patch_ids = output.loc[output.queue_status.eq("patch")].sort_values("priority_rank").asset_id.tolist()
        self.assertEqual(patch_ids, ["WEB-01", "API-01", "ADMIN-01"])

    def test_forged_or_orphan_environmental_rejected(self):
        master, mapping, assets = fixture()
        for column, value in (("score_source", "predicted"), ("environmental_score", 1.0),
                              ("context_version", "old"), ("asset_id", "API-02")):
            scores = env(master, mapping, assets)
            scores.loc[0, column] = value
            with self.subTest(column=column), self.assertRaises(ValueError):
                queue(master, mapping, assets, scores)

    def test_sensitivity_and_base_env_compare_same_pairs(self):
        master, mapping, assets = fixture()
        scores = env(master, mapping, assets)
        a = queue(master, mapping, assets, scores)
        b = queue(master, mapping, assets, scores, "context-v1-env-first")
        comparison, summary = compare_context(a, b, scores)
        self.assertEqual(len(comparison), 3)
        self.assertTrue(summary["identical_pair_set"])
        # Synthetic identical score fixture: policies both use ID after ties.
        self.assertFalse(summary["context_order_changed"])
        self.assertFalse(summary["base_environmental_order_changed"])
        altered = b.copy()
        altered.loc[altered.asset_id.eq("WEB-01"), "queue_status"] = "review_required"
        with self.assertRaises(ValueError):
            compare_context(a, altered, scores)

    def test_small_patch_population_null_topk(self):
        master, mapping, assets = fixture()
        mapping = mapping.loc[mapping.asset_id.eq("WEB-01")]
        scores = env(master, mapping, assets)
        a = queue(master, mapping, assets, scores)
        b = queue(master, mapping, assets, scores, "context-v1-env-first")
        _, summary = compare_context(a, b, scores)
        self.assertTrue(all(row["jaccard"] is None for row in summary["topk"]))

    def test_env_first_changes_order_but_not_membership_and_kev_dominates(self):
        master, mapping, assets = fixture()
        for cve in ("CVE-2018-25067", "CVE-2023-22626"):
            mask = master.cve_id.eq(cve)
            master.loc[mask, "cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            master.loc[mask, "cvss_base_score"] = 7.5
        scores = env(master, mapping, assets)
        a = queue(master, mapping, assets, scores)
        b = queue(master, mapping, assets, scores, "context-v1-env-first")
        a_ids = a.query("queue_status=='patch'").sort_values("priority_rank").asset_id.tolist()
        b_ids = b.query("queue_status=='patch'").sort_values("priority_rank").asset_id.tolist()
        self.assertEqual(a_ids, ["API-01", "WEB-01", "ADMIN-01"])
        self.assertEqual(b_ids, ["API-01", "ADMIN-01", "WEB-01"])
        comparison, summary = compare_context(a, b, scores)
        self.assertTrue(summary["context_order_changed"])
        self.assertEqual(comparison.query("asset_id=='ADMIN-01'").iloc[0].rank_delta_context_sensitivity, 1)
        master.loc[master.cve_id.eq("CVE-2018-25067"), "is_kev"] = True
        for policy in ("context-v1", "context-v1-env-first"):
            ordered = queue(master, mapping, assets, scores, policy).sort_values("priority_rank")
            self.assertEqual(ordered.iloc[0].asset_id, "WEB-01")

    def test_no_patch_pairs_outputs_empty_comparison_without_nan(self):
        master, mapping, assets = fixture()
        mapping["applicability"] = "needs_review"
        scores = env(master, mapping, assets)
        a = queue(master, mapping, assets, scores)
        b = queue(master, mapping, assets, scores, "context-v1-env-first")
        comparison, summary = compare_context(a, b, scores)
        self.assertTrue(comparison.empty)
        self.assertEqual(summary["patch_pairs"], 0)
        self.assertTrue(all(row["jaccard"] is None for row in summary["topk"]))

    def test_invalid_vector_is_excluded_not_zero(self):
        master, mapping, assets = fixture()
        master.loc[master.cve_id.eq("CVE-2018-25067"), "cvss_vector"] = "invalid"
        scores, excluded = build_environmental(master, mapping, assets, dataset_version=VERSION, context_version=CONTEXT)
        self.assertFalse(scores.asset_id.eq("WEB-01").any())
        self.assertTrue(any(row["asset_id"] == "WEB-01" for row in excluded))
        self.assertEqual(queue(master, mapping, assets, scores).query("asset_id=='WEB-01'").iloc[0].queue_status,
                         "review_required")

    def test_cli_real_release_roundtrip_and_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            inputs = [ROOT / "data/processed/phase1_v1_20261010/cves.parquet",
                      ROOT / "config/phase3_mapping.yaml", ROOT / "config/assets.yaml",
                      ROOT / "config/phase3.yaml"]
            before = [digest(p) for p in inputs]
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--master", str(inputs[0]), "--mapping", str(inputs[1]),
                      "--inventory", str(inputs[2]), "--config", str(inputs[3]),
                      "--output-dir", str(output)])
            meta = json.loads((output / "context_metadata.json").read_text())
            for name, info in meta["outputs"].items():
                self.assertEqual(digest(output / name), info["sha256"])
            queue_csv = pd.read_csv(output / "priority_queue.csv")
            self.assertEqual(len(queue_csv), 6)
            self.assertTrue(queue_csv.loc[queue_csv.exposure.eq("client"), "priority_rank"].isna().all())
            self.assertEqual(before, [digest(p) for p in inputs])

    def test_comparison_missing_scores_and_bad_policy_rejected(self):
        master, mapping, assets = fixture()
        scores = env(master, mapping, assets)
        a = queue(master, mapping, assets, scores)
        b = queue(master, mapping, assets, scores, "context-v1-env-first")
        with self.assertRaises(ValueError):
            compare_context(a, b, scores.loc[scores.asset_id.ne("WEB-01")])
        with self.assertRaises(ValueError):
            queue(master, mapping, assets, scores, "unknown-policy")


if __name__ == "__main__":
    unittest.main()
