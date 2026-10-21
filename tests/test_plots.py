"""Synthetic fixtures only; temporary smoke files never enter research outputs."""
from pathlib import Path
import tempfile
import unittest
import contextlib
import io
import json
import copy
import numpy as np
import pandas as pd
import yaml
from src.analysis.plots import (validate_rankings, topk_table, scatter_figure,
    top50_figure, save_figure, recall_table, context_table, context_figure,
    queue_tables, read_context, metric_figures, read_n2, main, file_info)


def synthetic_rankings(n=60):
    return pd.DataFrame({"cve_id": [f"CVE-2099-{i:04}" for i in range(1000, 1000+n)],
        "cvss_base_score": [9.8] * n, "epss": [0.] * n, "is_kev": [True] + [False] * (n-1),
        "cvss_rank": range(1, n+1), "epss_rank": range(n, 0, -1), "kev_first_rank": range(1, n+1),
        "dataset_version": "SYNTHETIC-ONLY", "cohort_id": "SYNTHETIC-ONLY:ranking",
        "policy_version": "synthetic", "epss_date": "2099-01-01"})


def synthetic_context():
    """Four synthetic pairs: patch, client review, unknown review, unaffected."""
    scores = pd.DataFrame({
        "cve_id": [f"CVE-2099-{i}" for i in range(1000, 1004)],
        "asset_id": ["SYNTHETIC-API", "SYNTHETIC-CLIENT", "SYNTHETIC-UNKNOWN", "SYNTHETIC-UNAFFECTED"],
        "base_score": [7., 7., np.nan, np.nan],
        "environmental_score": [6., 8., np.nan, np.nan],
        "base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "environmental_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L",
        "CR": "H", "IR": "M", "AR": "L", "modification_reason": "SYNTHETIC assumptions only",
        "score_source": "observed", "dataset_version": "SYNTHETIC-ONLY",
        "context_version": "synthetic-context",
    })
    comparison = scores.iloc[:2][["cve_id", "asset_id", "base_score", "environmental_score",
                                  "dataset_version", "context_version"]].copy()
    comparison["base_rank"] = [1, 2]
    comparison["environmental_rank"] = [2, 1]
    comparison = comparison.iloc[::-1].reset_index(drop=True)
    queue = scores[["cve_id", "asset_id", "environmental_score", "dataset_version", "context_version"]].copy()
    queue["applicability"] = ["affected", "affected", "unknown", "unaffected"]
    queue["is_kev"] = pd.Series([True, False, pd.NA, False], dtype="boolean")
    queue["epss"] = [.3, .2, np.nan, .0]
    queue["exposure"] = ["internet", "client", "unknown", "client"]
    queue["queue_status"] = ["patch", "review_required", "review_required", "not_applicable"]
    queue["priority_rank"] = pd.Series([1, pd.NA, pd.NA, pd.NA], dtype="Int64")
    queue["priority_reason"] = ["SYNTHETIC patch", "SYNTHETIC client review",
                                "SYNTHETIC unknown applicability", "SYNTHETIC unaffected"]
    queue["recommended_action"] = "SYNTHETIC verify only"
    queue["policy_version"] = "synthetic-queue"
    cfg = yaml.safe_load(Path("config/phase3_plots.yaml").read_text(encoding="utf-8"))
    cfg["expected"]["dataset_version"] = "SYNTHETIC-ONLY"
    cfg["context"] = {"version": "synthetic-context", "queue_policy_version": "synthetic-queue"}
    return scores, comparison, queue, cfg


def write_synthetic_context(root):
    scores, comparison, queue, cfg = synthetic_context()
    folder = Path(root) / "SYNTHETIC-context"
    folder.mkdir()
    comparison = comparison.loc[comparison.asset_id.eq("SYNTHETIC-API")].copy()
    comparison["base_rank"] = 1
    comparison["environmental_rank"] = 1
    outputs = {}
    for name, frame in zip(("environmental_scores.csv", "context_comparison.csv", "priority_queue.csv"),
                           (scores, comparison, queue)):
        frame.to_csv(folder / name, index=False)
        outputs[name] = file_info(folder / name)
    mapping = queue[["cve_id", "asset_id", "applicability", "dataset_version", "context_version"]]
    mapping.to_csv(folder / "cve_asset_mapping.csv", index=False)
    outputs["cve_asset_mapping.csv"] = file_info(folder / "cve_asset_mapping.csv")
    schema = "synthetic-context-artifacts-v1"
    metadata = {"schema_version": schema, "dataset_version": "SYNTHETIC-ONLY",
                "context_version": "synthetic-context", "outputs": outputs}
    (folder / "context_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    contract = Path(root) / "SYNTHETIC-context-contract.md"
    contract.write_text(f"# SYNTHETIC test fixture only\nSchema: {schema}\n", encoding="utf-8")
    return folder, contract, schema, cfg


class PlotTests(unittest.TestCase):
    def test_full_ids_top50_and_immutable(self):
        frame = synthetic_rankings().sample(frac=1, random_state=3)
        original = frame.copy(deep=True)
        validated = validate_rankings(frame)
        self.assertEqual(set(frame.cve_id), set(validated.cve_id))
        top = topk_table(frame)
        self.assertEqual(len(top), 150)
        for p in ("cvss", "epss", "kev_first"):
            part = top.loc[top.policy.eq(p)]
            self.assertEqual(part["rank"].tolist(), list(range(1, 51)))
            self.assertEqual(set(part.cve_id), set(frame.loc[frame[p+'_rank'].le(50), 'cve_id']))
        pd.testing.assert_frame_equal(frame, original)

    def test_duplicates_missing_and_rank_gaps_fail(self):
        frame = synthetic_rankings()
        for bad in [pd.concat([frame, frame.iloc[:1]]), frame.drop(columns="epss"),
                    frame.assign(epss=float("nan")), frame.assign(is_kev="False"),
                    frame.assign(cvss_rank=1)]:
            with self.subTest(), self.assertRaises(ValueError):
                validate_rankings(bad)

    def test_nonselective_k_rejected(self):
        with self.assertRaisesRegex(ValueError, "K < N"):
            topk_table(synthetic_rankings(50))

    def test_zero_points_preserved_and_png_svg_smoke(self):
        cfg = yaml.safe_load(Path("config/phase3_plots.yaml").read_text())
        frame = synthetic_rankings()
        fig = scatter_figure(frame, cfg)
        self.assertEqual(sum(len(c.get_offsets()) for c in fig.axes[0].collections), 60)
        with tempfile.TemporaryDirectory() as folder:
            paths = save_figure(fig, folder, "synthetic_scatter", dpi=35)
            self.assertTrue(all(p.stat().st_size > 100 for p in paths))
            for page in (1, 2):
                fig = top50_figure(topk_table(frame), page, cfg)
                labels = [t.get_text() for ax in fig.axes for t in ax.texts]
                self.assertEqual(sum(t.startswith("CVE-") for t in labels), 75)
                save_figure(fig, folder, f"synthetic_page{page}", dpi=35)

    def test_na_preserved_and_kev_policy_excluded(self):
        frame = pd.DataFrame({"policy": ["cvss", "epss", "kev_first"], "k": 10,
                              "n": 60, "kev_total": 0, "kev_hits": 0, "kev_recall": None,
                              "kev_recall_reason": "no_kev_in_cohort"})
        original = frame.copy(deep=True)
        out = recall_table(frame)
        self.assertEqual(len(out), 2)
        self.assertTrue(out.kev_recall.isna().all())
        self.assertTrue(out.display.str.startswith("N/A").all())
        pd.testing.assert_frame_equal(frame, original)
        with self.assertRaisesRegex(ValueError, "requires"):
            recall_table(frame.assign(kev_total=3, kev_recall_reason=""))

    def test_context_join_by_pair_not_position(self):
        scores = pd.DataFrame({"cve_id": ["CVE-2099-1000"]*2, "asset_id": ["A", "B"],
                               "base_score": [7., 7.], "environmental_score": [8., 6.]})
        comp = scores.assign(base_rank=[1, 2], environmental_rank=[1, 2]).iloc[::-1]
        columns = {k:k for k in ("base_score", "environmental_score", "base_rank", "environmental_rank")}
        result = context_table(comp, scores, columns)
        self.assertEqual(result.asset_id.tolist(), ["B", "A"])
        with self.assertRaisesRegex(ValueError, "same complete"):
            context_table(comp.iloc[:1], scores, columns)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            context_table(pd.concat([comp, comp.iloc[:1]]), scores, columns)

    def test_context_samepair_scores_immutable_and_n_lt_two_has_no_line(self):
        scores, comp, _, cfg = synthetic_context()
        original_scores, original_comp = scores.copy(deep=True), comp.copy(deep=True)
        result = context_table(comp, scores.sample(frac=1, random_state=2), cfg["context_columns"])
        self.assertEqual(result.asset_id.tolist(), comp.asset_id.tolist())
        self.assertEqual(set(zip(result.cve_id, result.asset_id)),
                         set(zip(scores.iloc[:2].cve_id, scores.iloc[:2].asset_id)))
        pd.testing.assert_frame_equal(scores, original_scores)
        pd.testing.assert_frame_equal(comp, original_comp)
        with self.assertRaisesRegex(ValueError, "same complete"):
            context_table(comp.iloc[:1], scores, cfg["context_columns"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            context_table(comp, pd.concat([scores, scores.iloc[:1]]), cfg["context_columns"])
        singleton = context_table(comp.iloc[:1], scores.loc[scores.asset_id.eq(comp.asset_id.iloc[0])],
                                  cfg["context_columns"])
        self.assertIsNone(context_figure(singleton, cfg))
        empty = context_table(comp.iloc[:0], scores.iloc[:0], cfg["context_columns"])
        self.assertIsNone(context_figure(empty, cfg))

    def test_context_missing_duplicate_and_blank_pair_keys_fail(self):
        scores, comp, _, cfg = synthetic_context()
        for bad in (comp.assign(cve_id=""), comp.assign(asset_id="  "), comp.assign(asset_id=pd.NA)):
            with self.subTest(), self.assertRaises(ValueError):
                context_table(bad, scores, cfg["context_columns"])

    def test_queue_counts_preserve_client_unknown_and_nullable_boolean(self):
        _, _, queue, _ = synthetic_context()
        before = queue.copy(deep=True)
        tables = queue_tables(queue, policy_version="synthetic-queue")
        self.assertEqual(tables["queue_status_counts.csv"].set_index("queue_status").pairs.to_dict(),
                         {"patch": 1, "review_required": 2, "not_applicable": 1})
        review = tables["queue_review.csv"]
        self.assertEqual(set(review.exposure), {"client", "unknown"})
        self.assertTrue(review.priority_rank.isna().all())
        self.assertEqual(str(tables["queue_source.csv"].is_kev.dtype), "boolean")
        self.assertTrue(pd.isna(review.loc[review.exposure.eq("unknown"), "is_kev"]).all())
        pd.testing.assert_frame_equal(queue, before)

    def test_queue_rejects_client_patch_or_review_priority(self):
        _, _, queue, _ = synthetic_context()
        client_patch = queue.copy(deep=True)
        client_patch.loc[1, ["queue_status", "priority_rank"]] = ["patch", 2]
        with self.assertRaisesRegex(ValueError, "Client|client|exposure"):
            queue_tables(client_patch, policy_version="synthetic-queue")
        review_priority = queue.copy(deep=True)
        review_priority.loc[1, "priority_rank"] = 2
        with self.assertRaisesRegex(ValueError, "null|Review"):
            queue_tables(review_priority, policy_version="synthetic-queue")

    def test_read_context_synthetic_three_checksums_and_same_pairs(self):
        import matplotlib.pyplot as plt
        with tempfile.TemporaryDirectory() as root:
            folder, contract, schema, cfg = write_synthetic_context(root)
            before = {p.name: p.read_bytes() for p in folder.iterdir()}
            cfg_before = copy.deepcopy(cfg)
            fig, tables, summary, inputs = read_context(folder, contract, schema, cfg)
            self.assertEqual(summary["figure_status"], "insufficient_data")
            self.assertEqual((summary["score_rows"], summary["complete_pairs"], summary["excluded_score_rows"]),
                             (4, 1, 3))
            self.assertEqual(summary["client_review_pairs"], 1)
            self.assertEqual(len(tables["queue_review.csv"]), 2)
            self.assertEqual(len(tables["context_excluded.csv"]), 3)
            self.assertEqual(len(inputs), 6)
            self.assertTrue(all(file_info(record["path"]) == record for record in inputs))
            for name, payload in before.items():
                self.assertEqual((folder / name).read_bytes(), payload)
            self.assertEqual(cfg, cfg_before)
            self.assertIsNone(fig)
            plt.close("all")

    def test_read_context_checksum_version_and_missing_contract_fail(self):
        with tempfile.TemporaryDirectory() as root:
            folder, contract, schema, cfg = write_synthetic_context(root)
            metadata_path = folder / "context_metadata.json"
            original = json.loads(metadata_path.read_text(encoding="utf-8"))
            for name in ("environmental_scores.csv", "context_comparison.csv", "priority_queue.csv"):
                with self.subTest(name=name):
                    bad = copy.deepcopy(original)
                    bad["outputs"][name]["sha256"] = "0" * 64
                    metadata_path.write_text(json.dumps(bad), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "checksum|bytes"):
                        read_context(folder, contract, schema, cfg)
            for field in ("dataset_version", "context_version", "schema_version"):
                with self.subTest(field=field):
                    bad = copy.deepcopy(original)
                    bad[field] = "WRONG-SYNTHETIC-VERSION"
                    metadata_path.write_text(json.dumps(bad), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, field):
                        read_context(folder, contract, schema, cfg)
            metadata_path.write_text(json.dumps(original), encoding="utf-8")
            contract.unlink()
            with self.assertRaisesRegex(FileNotFoundError, "context input"):
                read_context(folder, contract, schema, cfg)

    def test_read_context_requires_every_consumed_file_manifest_entry(self):
        with tempfile.TemporaryDirectory() as root:
            folder, contract, schema, cfg = write_synthetic_context(root)
            path = folder / "context_metadata.json"
            metadata = json.loads(path.read_text(encoding="utf-8"))
            del metadata["outputs"]["context_comparison.csv"]
            path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum|manifest|Missing"):
                read_context(folder, contract, schema, cfg)

    def test_read_context_refuses_noncontext_schema_and_predicted_scores(self):
        with tempfile.TemporaryDirectory() as root:
            folder, contract, schema, cfg = write_synthetic_context(root)
            with self.assertRaisesRegex(ValueError, "supplemental|schema"):
                read_context(folder, contract, "p3-ranking-metrics-v1", cfg)
            score_path = folder / "environmental_scores.csv"
            scores = pd.read_csv(score_path).assign(score_source="predicted")
            scores.to_csv(score_path, index=False)
            metadata_path = folder / "context_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["outputs"][score_path.name] = file_info(score_path)
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "observed|predictions"):
                read_context(folder, contract, schema, cfg)

    def test_context_rejects_lost_review_pair_and_expanded_population(self):
        for changed_file in ("priority_queue.csv", "context_comparison.csv"):
            with self.subTest(changed_file=changed_file), tempfile.TemporaryDirectory() as root:
                folder, contract, schema, cfg = write_synthetic_context(root)
                path = folder / changed_file
                frame = pd.read_csv(path)
                if changed_file == "priority_queue.csv":
                    frame = frame.loc[frame.asset_id.ne("SYNTHETIC-CLIENT")]
                else:
                    # Scored client stays outside both comparison populations.
                    frame = synthetic_context()[1]
                frame.to_csv(path, index=False)
                metadata_path = folder / "context_metadata.json"
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata["outputs"][changed_file] = file_info(path)
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_context(folder, contract, schema, cfg)

    @unittest.skipUnless(Path("data/processed/p3_n2_context_20261019_r1_received/handoff_manifest.json").is_file(),
                         "Pinned r1 package not installed")
    def test_real_context_patch_population_retains_clients_and_readable_legend(self):
        import matplotlib.pyplot as plt
        root = Path("data/processed/p3_n2_context_20261019_r1_received")
        before = {p: file_info(p) for p in root.rglob("*") if p.is_file()}
        cfg = yaml.safe_load(Path("config/phase3_plots.yaml").read_text(encoding="utf-8"))
        fig, tables, summary, _ = read_context(root / "p3_n2",
            root / "docs/phase-3-artifact-contract.md", "p3-context-artifacts-v1", cfg)
        self.addCleanup(plt.close, fig)
        self.assertEqual((summary["score_rows"], summary["complete_pairs"], summary["queue_rows"]), (5, 3, 6))
        self.assertEqual(summary["client_review_pairs"], 2)
        paired = tables["context_plot.csv"].set_index("asset_id")
        self.assertEqual(paired[["base_rank", "environmental_rank"]].to_dict("index"), {
            "WEB-01": {"base_rank": 3, "environmental_rank": 3},
            "API-01": {"base_rank": 1, "environmental_rank": 2},
            "ADMIN-01": {"base_rank": 2, "environmental_rank": 1}})
        review = tables["queue_review.csv"]
        self.assertEqual(set(review.asset_id), {"API-02", "MOB-01", "MOB-02"})
        self.assertTrue(review.priority_rank.isna().all())
        self.assertEqual(set(tables["context_excluded.csv"].asset_id), set(review.asset_id))
        fig.canvas.draw()
        renderer = fig.canvas.get_renderer()
        self.assertFalse(fig.legends[0].get_window_extent(renderer).overlaps(
            fig.axes[0].xaxis.label.get_window_extent(renderer)))
        self.assertEqual(before, {p: file_info(p) for p in before})

    def test_metric_figures_undefined_jaccard_and_recall_remain_nan(self):
        import matplotlib.pyplot as plt
        cfg = yaml.safe_load(Path("config/phase3_plots.yaml").read_text(encoding="utf-8"))
        overlap = pd.DataFrame({"policy_a": ["cvss", "cvss", "epss"],
            "policy_b": ["epss", "kev_first", "kev_first"], "k": 10,
            "jaccard": [np.nan, .4, .6], "undefined_reason": ["SYNTHETIC no valid pairs", "", ""]})
        metrics = pd.DataFrame({"policy": ["cvss", "epss", "kev_first"], "k": 10,
            "n": 60, "kev_total": 0, "kev_hits": 0, "kev_recall": np.nan,
            "kev_recall_reason": ["no_kev_in_cohort", "no_kev_in_cohort", "policy_uses_kev_directly"]})
        original_overlap, original_metrics = overlap.copy(deep=True), metrics.copy(deep=True)
        figures, recall = metric_figures(overlap, metrics, cfg)
        axes = {name: fig.axes[0] for name, fig in figures}
        self.assertTrue(any(np.isnan(np.asarray(line.get_ydata(), dtype=float)).any()
                            for line in axes["topk_overlap"].lines))
        self.assertTrue(any("N/A" in text.get_text() for text in axes["topk_overlap"].texts))
        self.assertEqual(set(recall.policy), {"cvss", "epss"})
        self.assertTrue(all(np.isnan(np.asarray(line.get_ydata(), dtype=float)).all()
                            for line in axes["kev_recall_at_k"].lines))
        self.assertNotIn("KEV-first", axes["kev_recall_at_k"].get_legend_handles_labels()[1])
        pd.testing.assert_frame_equal(overlap, original_overlap)
        pd.testing.assert_frame_equal(metrics, original_metrics)
        plt.close("all")
        with self.assertRaisesRegex(ValueError, "reason|Jaccard|jaccard"):
            metric_figures(overlap.drop(columns="undefined_reason"), metrics, cfg)
        plt.close("all")

    def test_recall_rejects_rate_count_mismatch_and_blank_undefined_reason(self):
        rows = pd.DataFrame({"policy": ["cvss", "epss"], "k": 10, "n": 60,
                             "kev_total": 3, "kev_hits": 1, "kev_recall": .9})
        with self.assertRaisesRegex(ValueError, "recall|Recall|count|ratio"):
            recall_table(rows)
        with self.assertRaisesRegex(ValueError, "reason"):
            recall_table(rows.assign(kev_recall=np.nan, kev_recall_reason=" "))

    def test_cli_cannot_write_inside_n2_read_directory(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            n2 = root / "SYNTHETIC-n2-input"
            n2.mkdir()
            sentinel = n2 / "metadata.json"
            sentinel.write_text('{"SYNTHETIC":"producer-owned"}', encoding="utf-8")
            original = sentinel.read_bytes()
            ranking_path = root / "SYNTHETIC-rankings.csv"
            synthetic_rankings().to_csv(ranking_path, index=False)
            base = ["--rankings", str(ranking_path), "--tables-dir", str(root / "tables"),
                    "--output-dir", str(root / "figures"), "--report", str(root / "captions.md"),
                    "--n2-dir", str(n2)]
            for flag, destination in (("--report", sentinel), ("--tables-dir", n2), ("--output-dir", n2)):
                args = list(base)
                args[args.index(flag) + 1] = str(destination)
                with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()) as errors:
                    with self.assertRaises(SystemExit):
                        main(args)
                    self.assertRegex(errors.getvalue().lower(), "overwrite|protected|input|read.only")
                self.assertEqual(sentinel.read_bytes(), original)
            self.assertEqual({path.name for path in n2.iterdir()}, {"metadata.json"})

    def test_n2_missing_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(FileNotFoundError, "Required N2"):
            read_n2(Path(folder), synthetic_rankings(), {})

    def test_high_epss_labels_below_points_and_markers_not_clipped(self):
        cfg = yaml.safe_load(Path("config/phase3_plots.yaml").read_text())
        fig = scatter_figure(synthetic_rankings().assign(epss=.99), cfg)
        ax = fig.axes[0]
        labels = [t for t in ax.texts if t.get_text().startswith("CVE-")]
        self.assertEqual(len(labels), 1)
        self.assertLess(labels[0].get_position()[1], 0)
        self.assertTrue(all(not c.get_clip_on() for c in ax.collections))
        import matplotlib.pyplot as plt
        plt.close(fig)

    def test_missing_cli_input_and_input_overwrite_error(self):
        with tempfile.TemporaryDirectory() as folder:
            args = ["--rankings", str(Path(folder)/"missing.csv"), "--tables-dir", folder, "--output-dir", folder]
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit):
                main(args)
            self.assertIn("Required input missing", errors.getvalue())
            path = Path(folder) / "top50_long.csv"
            synthetic_rankings().to_csv(path, index=False)
            before = path.read_bytes()
            args[1] = str(path)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)
            self.assertEqual(path.read_bytes(), before)

    @unittest.skipUnless(Path("data/processed/p3_n3_input/rankings.csv").is_file(), "Real release not installed")
    def test_real_release_cli_manifest_and_full_top50(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--rankings", "data/processed/p3_n3_input/rankings.csv",
                      "--tables-dir", folder, "--output-dir", str(root/"figures"),
                      "--report", str(root/"captions.md")])
            manifest = json.loads((root/"figures_manifest.json").read_text())
            self.assertEqual((manifest["n"], manifest["kev"]), (396, 3))
            self.assertEqual(manifest["source_dates"], {"epss_date":"2026-09-29",
                "kev_date_released":"2026-09-30", "kev_retrieved_date_utc":"2026-10-01"})
            for record in manifest["outputs"]:
                self.assertEqual(file_info(record["path"]), record)
            top = pd.read_csv(root/"top50_long.csv")
            self.assertEqual(top.groupby("policy").size().to_dict(), {p:50 for p in ("cvss","epss","kev_first")})
            self.assertEqual(len(pd.read_csv(root/"scatter_source.csv")), 396)


if __name__ == "__main__":
    unittest.main()
