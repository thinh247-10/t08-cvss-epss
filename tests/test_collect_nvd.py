"""Offline pagination/resume tests with saved raw pages and simulated failures."""

import io
import json
import shutil
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import pandas as pd
import requests

from src.collect import collect_nvd as nvd


CONFIG = {
    "project": {"dataset_version": "test", "schema_version": "0.1", "seed": 42},
    "collection": {"start_date": "2023-01-01", "end_date": "2024-12-31", "description_language": "en"},
    "cvss": {"version": "3.1", "preferred_source": "nvd@nist.gov"},
}


def page(ids, offset=0, total=3, published="2023-01-01T12:00:00.000"):
    return {"totalResults": total, "startIndex": offset, "resultsPerPage": len(ids),
            "timestamp": "2026-01-01T00:00:00.000", "vulnerabilities": [
                {"cve": {"id": f"CVE-2023-{i}", "published": published, "lastModified": published,
                         "vulnStatus": "Rejected" if i == 1000 else "Analyzed",
                         "descriptions": [{"lang": "en", "value": "Example description"}],
                         "metrics": {}, "references": [{"url": "https://example.org/advisory"}]}} for i in ids]}


class PlanningChecks(unittest.TestCase):
    def test_leap_day_and_window_boundaries_have_no_gap_or_overlap(self):
        plan = nvd.make_plan(CONFIG, "2024-02-28", "2024-03-02", page_size=2, window_days=2)
        self.assertEqual(plan["windows"], [
            {"pubStartDate": "2024-02-28T00:00:00.000", "pubEndDate": "2024-02-29T23:59:59.999"},
            {"pubStartDate": "2024-03-01T00:00:00.000", "pubEndDate": "2024-03-02T23:59:59.999"},
        ])

    def test_invalid_range_and_limits_rejected(self):
        for start, end, size, days in [("2022-01-01", "2023-01-01", 2, 2), ("2023-01-03", "2023-01-01", 2, 2),
                                       ("2023-01-01", "2023-01-03", 0, 2), ("2023-01-01", "2023-01-03", 2, 91)]:
            with self.subTest(start=start, size=size, days=days), self.assertRaises(ValueError):
                nvd.make_plan(CONFIG, start, end, size, days)

    def test_wrong_offset_changing_total_empty_page_and_outside_date_rejected(self):
        params = {**nvd.make_plan(CONFIG, "2023-01-01", "2023-01-02", 2)["windows"][0], "startIndex": 0, "resultsPerPage": 2}
        cases = [page([1000], offset=1), page([1000], total=4), page([], total=3), page([1000], published="2023-01-03T00:00:00")]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                nvd.validate_page(payload, params, expected_total=3)

    @patch.object(nvd.time, "sleep")
    @patch.object(nvd.requests, "get")
    def test_timeout_retries_without_converting_to_empty_results(self, get, sleep):
        get.side_effect = [requests.Timeout(), Mock(status_code=200, content=b"ok")]
        self.assertEqual(nvd.request_page({"startIndex": 0}), b"ok")
        self.assertEqual(get.call_count, 2)
        get.reset_mock()
        get.side_effect = requests.Timeout()
        with self.assertRaises(requests.Timeout):
            nvd.request_page({"startIndex": 0})
        self.assertEqual(get.call_count, 3)


class ResumeChecks(unittest.TestCase):
    def setUp(self):
        self.workspace = nvd.ROOT.resolve()
        self.root = self.workspace / "tests" / f".nvd-test-{uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(self.cleanup)
        self.plan = nvd.make_plan(CONFIG, "2023-01-01", "2023-01-03", 2, 2)

    def cleanup(self):
        target = self.root.resolve()
        if target.parent != self.workspace / "tests" or not target.name.startswith(".nvd-test-"):
            raise RuntimeError("Refuse cleanup outside test directory")
        shutil.rmtree(target)

    def run_collect(self, responses, resume=None):
        values = [json.dumps(value).encode() if isinstance(value, dict) else value for value in responses]
        with patch.object(nvd, "ROOT", self.root), patch.object(nvd, "request_page", side_effect=values) as request, redirect_stdout(io.StringIO()):
            result = nvd.collect(CONFIG, None if resume else self.plan, resume=resume)
        return result, request

    def checkpoint(self):
        path = next(self.root.glob("data/raw/nvd/collection_*/checkpoint.json"))
        return path, json.loads(path.read_text(encoding="utf-8"))

    def test_failure_resume_only_fetches_remaining_pages_and_completed_run_is_offline(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([page([1000, 1001]), requests.Timeout()])
        checkpoint, state = self.checkpoint()
        self.assertEqual(state["status"], "failed")
        self.assertEqual(len(state["raw_pages"]), 1)
        self.assertFalse(list(self.root.rglob("nvd_cves.parquet")))
        first_raw = self.root / state["raw_pages"][0]["file"]
        first_bytes = first_raw.read_bytes()
        resume = checkpoint.relative_to(self.root).as_posix()
        meta, request = self.run_collect([page([1002], offset=2, published="2023-01-02T00:00:00"), page([], total=0)], resume)
        self.assertEqual(request.call_args_list[0].args[0]["startIndex"], 2)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(first_raw.read_bytes(), first_bytes)
        self.assertEqual(meta["downloaded_records"], 3)
        self.assertEqual(meta["rejected_records"], 1)
        self.assertEqual(meta["missing_parseable_base_cvss31"], 3)
        self.assertTrue(meta["complete_for_requested_window"])
        frame = pd.read_parquet(self.root / meta["table_file"])
        self.assertEqual(frame.cve_id.nunique(), 3)
        self.assertEqual(nvd.digest(self.root / meta["table_file"]), meta["table_sha256"])
        again, request = self.run_collect([], resume)
        request.assert_not_called()
        self.assertEqual(again["table_sha256"], meta["table_sha256"])

    def test_duplicate_cve_page_is_saved_but_not_committed_to_checkpoint(self):
        with self.assertRaises(ValueError):
            self.run_collect([page([1000, 1001]), page([1001], offset=2)])
        checkpoint, state = self.checkpoint()
        self.assertEqual(len(state["raw_pages"]), 1)
        self.assertEqual(len(list(checkpoint.parent.glob("window_*.json"))), 2)
        self.assertFalse(list(self.root.rglob("nvd_cves.parquet")))

    def test_modified_cache_stops_before_network(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([page([1000, 1001]), requests.Timeout()])
        checkpoint, state = self.checkpoint()
        (self.root / state["raw_pages"][0]["file"]).write_bytes(b"modified")
        with patch.object(nvd, "ROOT", self.root), patch.object(nvd, "request_page") as request, redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                nvd.collect(CONFIG, resume=checkpoint.relative_to(self.root).as_posix())
            request.assert_not_called()

    def test_same_checkpoint_cannot_run_concurrently(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([requests.Timeout()])
        checkpoint, _ = self.checkpoint()
        lock = checkpoint.parent / "run.lock"
        lock.write_text("other-process", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_collect([], checkpoint.relative_to(self.root).as_posix())
        self.assertTrue(lock.exists())

    def test_keyboard_interrupt_preserves_valid_checkpoint_and_releases_lock(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_collect([page([1000, 1001]), KeyboardInterrupt()])
        checkpoint, state = self.checkpoint()
        self.assertEqual(state["status"], "interrupted")
        self.assertEqual(len(state["raw_pages"]), 1)
        self.assertFalse((checkpoint.parent / "run.lock").exists())


if __name__ == "__main__":
    unittest.main()
