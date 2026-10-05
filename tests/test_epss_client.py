"""Offline tests: fixed dates, missingness, response integrity and saved artifacts."""

import io
import json
import shutil
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import pandas as pd
import requests

from src.collect import epss_client as epss


DAY = "2024-01-15"
CVE = "CVE-2023-1000"


def payload(ids, day=DAY):
    return {
        "status": "OK", "status-code": 200, "offset": 0, "total": len(ids),
        "data": [{"cve": value, "epss": "0.0", "percentile": "0.12", "date": day} for value in ids],
    }


class ResponseChecks(unittest.TestCase):
    def test_batches_respect_character_and_record_limits_without_losing_ids(self):
        ids = [f"CVE-2023-{10**25 + i}" for i in range(543)]
        batches = epss.make_batches(ids)
        self.assertEqual([value for batch in batches for value in batch], sorted(ids))
        self.assertTrue(all(len(batch) <= 100 and len(",".join(batch)) <= 2000 for batch in batches))
        with self.assertRaises(ValueError):
            epss.make_batches([CVE, CVE])

    def test_missing_score_differs_from_valid_zero_and_survives_parquet(self):
        found = epss.validate_response(payload([CVE]), [CVE, "CVE-2023-1001"], DAY)
        frame = epss.make_table([CVE, "CVE-2023-1001"], found, "test", "2024-01-16T00:00:00Z")
        self.assertEqual(frame.loc[0, "epss"], 0.0)
        self.assertTrue(pd.isna(frame.loc[1, "epss"]))
        self.assertTrue(pd.isna(frame.loc[1, "epss_date"]))
        self.assertEqual(frame.loc[1, "epss_status"], "not_returned")
        buffer = io.BytesIO()
        frame.to_parquet(buffer, index=False)
        buffer.seek(0)
        pd.testing.assert_frame_equal(frame, pd.read_parquet(buffer))

    def test_rejects_partial_wrong_date_duplicate_foreign_and_invalid_scores(self):
        bad_total = payload([CVE])
        bad_total["total"] = 2
        cases = [bad_total, payload([CVE], "2024-01-14"), payload([CVE, CVE]), payload(["CVE-2023-9999"])]
        for value in ("NaN", "inf", "-0.01", "1.01", None, True):
            invalid = payload([CVE])
            invalid["data"][0]["epss"] = value
            cases.append(invalid)
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                epss.validate_response(invalid, [CVE], DAY)

    def test_explicit_date_required(self):
        for value in (None, "", "20240115", "2024-02-30", "2020-01-01", "2999-01-01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                epss.iso_date(value)

    @patch.object(epss.time, "sleep")
    @patch.object(epss.requests, "get")
    def test_transient_retry_and_persistent_error_never_become_empty_data(self, get, sleep):
        success = Mock(status_code=200, content=b"{}")
        get.side_effect = [requests.Timeout(), success]
        self.assertEqual(epss.request_bytes({"cve": CVE}), b"{}")
        self.assertEqual(get.call_count, 2)
        get.reset_mock()
        get.side_effect = requests.Timeout()
        with self.assertRaises(requests.Timeout):
            epss.request_bytes({"cve": CVE})
        self.assertEqual(get.call_count, 3)


class CollectionChecks(unittest.TestCase):
    def setUp(self):
        # Ordinary workspace directory avoids platform-specific temp permissions.
        self.workspace = epss.ROOT.resolve()
        self.root = self.workspace / "tests" / f".epss-test-{uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(self.remove_test_directory)
        (self.root / "config").mkdir()
        (self.root / "config/project.yaml").write_text(f'epss:\n  snapshot_date: "{DAY}"\n', encoding="utf-8")
        table = self.root / "nvd.parquet"
        pd.DataFrame({"cve_id": [CVE, "CVE-2023-1001"]}).to_parquet(table, index=False)
        self.source = {"table_file": "nvd.parquet", "table_sha256": epss.digest(table),
                       "downloaded_records": 2, "dataset_version": "test-nvd", "complete_for_requested_window": True}
        (self.root / "metadata.json").write_text(json.dumps(self.source), encoding="utf-8")

    def remove_test_directory(self):
        target = self.root.resolve()
        if target.parent != self.workspace / "tests" or not target.name.startswith(".epss-test-"):
            raise RuntimeError("Refuse cleanup outside isolated test directory")
        shutil.rmtree(target)

    def run_collect(self, responses):
        with patch.object(epss, "ROOT", self.root), patch.object(epss, "request_bytes", side_effect=responses), \
                patch.object(epss.time, "sleep"), redirect_stdout(io.StringIO()):
            return epss.collect("metadata.json")

    def test_success_records_provenance_and_keeps_missing_without_adding_probe(self):
        manifest = self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(), json.dumps(payload([CVE])).encode()])
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["available_records"], 1)
        self.assertEqual(manifest["missing_records"], 1)
        table = self.root / manifest["table_file"]
        self.assertEqual(epss.digest(table), manifest["table_sha256"])
        frame = pd.read_parquet(table)
        self.assertEqual(set(frame.cve_id), {CVE, "CVE-2023-1001"})
        for raw in manifest["raw_responses"]:
            self.assertEqual(raw["params"]["date"], DAY)
            self.assertEqual(epss.digest(self.root / raw["file"]), raw["sha256"])

    def test_failed_batch_writes_failed_manifest_and_no_final_table(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(), requests.Timeout("test timeout")])
        manifests = list((self.root / "data/raw/epss").glob("*/metadata.json"))
        saved = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "failed")
        self.assertNotIn("missing_records", saved)
        self.assertFalse(list(self.root.rglob("epss.parquet")))

    def test_empty_probe_cannot_mark_entire_dataset_missing(self):
        with self.assertRaises(ValueError):
            self.run_collect([json.dumps(payload([])).encode()])
        self.assertFalse(list(self.root.rglob("epss.parquet")))

    def test_bad_input_checksum_stops_before_request(self):
        (self.root / "nvd.parquet").write_bytes(b"changed")
        with patch.object(epss, "ROOT", self.root), patch.object(epss, "request_bytes") as request:
            with self.assertRaises(ValueError):
                epss.collect("metadata.json")
            request.assert_not_called()

    def test_resume_skips_successful_batches_and_complete_run_uses_no_network(self):
        ids = [f"CVE-2023-{i}" for i in range(1000, 1101)]
        table = self.root / "nvd.parquet"
        pd.DataFrame({"cve_id": ids}).to_parquet(table, index=False)
        self.source.update(table_sha256=epss.digest(table), downloaded_records=len(ids))
        (self.root / "metadata.json").write_text(json.dumps(self.source), encoding="utf-8")
        with self.assertRaises(requests.Timeout):
            self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(),
                              json.dumps(payload(ids[:100])).encode(), requests.Timeout()])
        path = next((self.root / "data/raw/epss").glob("*/metadata.json"))
        before = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(before["raw_responses"]), 2)
        raw_files_before = {entry["file"]: (self.root / entry["file"]).read_bytes() for entry in before["raw_responses"]}
        with patch.object(epss, "ROOT", self.root), patch.object(epss.time, "sleep"), redirect_stdout(io.StringIO()):
            with patch.object(epss, "request_bytes", return_value=json.dumps(payload(ids[100:])).encode()) as request:
                result = epss.collect(resume=path.relative_to(self.root).as_posix())
                request.assert_called_once()
                self.assertEqual(request.call_args.args[0]["cve"], ids[-1])
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["available_records"], 101)
            self.assertEqual(len(result["raw_responses"]), 3)
            for name, raw in raw_files_before.items():
                self.assertEqual((self.root / name).read_bytes(), raw)
            with patch.object(epss, "request_bytes") as request:
                again = epss.collect(resume=path.relative_to(self.root).as_posix())
                request.assert_not_called()
                self.assertEqual(again["table_sha256"], result["table_sha256"])

    def test_modified_cache_stops_resume_before_network(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(), requests.Timeout()])
        path = next((self.root / "data/raw/epss").glob("*/metadata.json"))
        before = json.loads(path.read_text(encoding="utf-8"))
        (self.root / before["raw_responses"][0]["file"]).write_bytes(b"modified")
        with patch.object(epss, "ROOT", self.root), patch.object(epss, "request_bytes") as request, redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                epss.collect(resume=path.relative_to(self.root).as_posix())
            request.assert_not_called()

    def test_changed_snapshot_date_rejects_resume(self):
        with self.assertRaises(requests.Timeout):
            self.run_collect([requests.Timeout()])
        path = next((self.root / "data/raw/epss").glob("*/metadata.json"))
        (self.root / "config/project.yaml").write_text('epss:\n  snapshot_date: "2024-01-16"\n', encoding="utf-8")
        with patch.object(epss, "ROOT", self.root), patch.object(epss, "request_bytes") as request:
            with self.assertRaises(ValueError):
                epss.collect(resume=path.relative_to(self.root).as_posix())
            request.assert_not_called()

    def test_invalid_response_is_retained_but_not_checkpointed_and_can_retry(self):
        with self.assertRaises(ValueError):
            self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(), b"not JSON"])
        path = next((self.root / "data/raw/epss").glob("*/metadata.json"))
        before = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(before["raw_responses"]), 1)
        invalid = next(path.parent.glob("batch_*.json"))
        self.assertEqual(invalid.read_bytes(), b"not JSON")
        with patch.object(epss, "ROOT", self.root), patch.object(epss.time, "sleep"), redirect_stdout(io.StringIO()), \
                patch.object(epss, "request_bytes", return_value=json.dumps(payload([CVE])).encode()):
            result = epss.collect(resume=path.relative_to(self.root).as_posix())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(invalid.read_bytes(), b"not JSON")

    def test_interrupt_preserves_cache_and_releases_lock(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_collect([json.dumps(payload([epss.PROBE_CVE])).encode(), KeyboardInterrupt()])
        path = next((self.root / "data/raw/epss").glob("*/metadata.json"))
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(len(saved["raw_responses"]), 1)
        self.assertFalse((path.parent / "run.lock").exists())

    def test_incomplete_nvd_source_cannot_start_collection(self):
        self.source["complete_for_requested_window"] = False
        (self.root / "metadata.json").write_text(json.dumps(self.source), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_collect([])
        self.assertFalse((self.root / "data").exists())


if __name__ == "__main__":
    unittest.main()
