"""Offline KEV tests: integrity gates, provenance and failure behavior."""

import io
import json
import shutil
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import pandas as pd
import requests

from src.collect import kev_client as kev


def catalog():
    return {
        "catalogVersion": "2024.01.16", "dateReleased": "2024-01-16T12:00:00.000Z", "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2023-1000", "vendorProject": "Example", "product": "Example app",
            "vulnerabilityName": "Example vulnerability", "dateAdded": "2024-01-15",
            "shortDescription": "Example description", "requiredAction": "Apply vendor updates.",
            "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown",
            "notes": "Preserved in raw JSON", "futureField": {"keep": True},
        }],
    }


class ValidationChecks(unittest.TestCase):
    def test_preserves_ransomware_unknown_and_optional_missing(self):
        payload = catalog()
        rows, _ = kev.validate_catalog(payload)
        self.assertEqual(rows[0]["kev_known_ransomware"], "Unknown")
        self.assertTrue(rows[0]["is_kev"])
        del payload["vulnerabilities"][0]["knownRansomwareCampaignUse"]
        rows, _ = kev.validate_catalog(payload)
        self.assertIsNone(rows[0]["kev_known_ransomware"])

    def test_rejects_empty_truncated_and_duplicate_catalogs(self):
        cases = [catalog() for _ in range(3)]
        cases[0].update(count=0, vulnerabilities=[])
        cases[1]["count"] = 2
        cases[2]["vulnerabilities"] *= 2
        cases[2]["count"] = 2
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                kev.validate_catalog(payload)

    def test_rejects_invalid_dates_ids_and_missing_required_fields(self):
        for field, value in (("cveID", "CVE-2023-1"), ("dateAdded", "2024-01-17"),
                             ("dateAdded", "2024-02-30"), ("dueDate", "not-a-date"),
                             ("product", None), ("knownRansomwareCampaignUse", False)):
            payload = catalog()
            payload["vulnerabilities"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                kev.validate_catalog(payload)
        payload = catalog()
        payload["dateReleased"] = "2024-01-16T12:00:00"
        with self.assertRaises(ValueError):
            kev.validate_catalog(payload)

    @patch.object(kev.time, "sleep")
    @patch.object(kev.requests, "get")
    def test_retry_and_failure_do_not_create_fake_empty_catalog(self, get, sleep):
        success = Mock(status_code=200, content=b"catalog")
        get.side_effect = [requests.Timeout(), success]
        self.assertEqual(kev.download(), b"catalog")
        get.reset_mock()
        get.side_effect = requests.Timeout()
        with self.assertRaises(requests.Timeout):
            kev.download()
        self.assertEqual(get.call_count, 3)


class SavedCatalogChecks(unittest.TestCase):
    def setUp(self):
        self.workspace = kev.ROOT.resolve()
        self.root = self.workspace / "tests" / f".kev-test-{uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(self.remove_test_directory)
        (self.root / "config").mkdir()
        (self.root / "config/project.yaml").write_text(
            'project:\n  dataset_version: "test"\nepss:\n  snapshot_date: "2024-01-15"\n', encoding="utf-8")

    def remove_test_directory(self):
        target = self.root.resolve()
        if target.parent != self.workspace / "tests" or not target.name.startswith(".kev-test-"):
            raise RuntimeError("Refuse cleanup outside isolated test directory")
        shutil.rmtree(target)

    def run_collect(self, raw):
        with patch.object(kev, "ROOT", self.root), patch.object(kev, "download", return_value=raw), \
                redirect_stdout(io.StringIO()):
            return kev.collect()

    def test_success_preserves_raw_and_records_dates_and_checksums(self):
        raw = json.dumps(catalog()).encode()
        manifest = self.run_collect(raw)
        self.assertEqual(manifest["status"], "complete")
        self.assertTrue(manifest["complete_for_declared_catalog"])
        self.assertFalse(manifest["historical_catalog_for_epss_date"])
        self.assertEqual(manifest["catalog_release_date_minus_epss_days"], 1)
        self.assertEqual((self.root / manifest["raw_file"]).read_bytes(), raw)
        self.assertEqual(kev.digest(self.root / manifest["raw_file"]), manifest["raw_sha256"])
        self.assertEqual(kev.digest(self.root / manifest["table_file"]), manifest["table_sha256"])
        frame = pd.read_parquet(self.root / manifest["table_file"])
        self.assertEqual(len(frame), 1)
        self.assertEqual(str(frame.is_kev.dtype), "boolean")
        self.assertEqual(frame.kev_known_ransomware.tolist(), ["Unknown"])
        again = self.run_collect(raw)
        self.assertNotEqual(manifest["raw_file"], again["raw_file"])
        self.assertTrue((self.root / manifest["table_file"]).is_file())

    def test_bad_payload_keeps_raw_and_failed_manifest_without_table(self):
        for raw in (b"<html>blocked</html>", json.dumps({**catalog(), "count": 3}).encode()):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.run_collect(raw)
        manifests = list((self.root / "data/raw/kev").glob("*/metadata.json"))
        self.assertEqual(len(manifests), 2)
        for path in manifests:
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "failed")
            self.assertTrue((self.root / saved["raw_file"]).is_file())
            self.assertNotIn("complete_for_declared_catalog", saved)
        self.assertFalse(list(self.root.rglob("kev.parquet")))

    def test_network_failure_never_claims_complete(self):
        with patch.object(kev, "ROOT", self.root), patch.object(kev, "download", side_effect=requests.Timeout()):
            with self.assertRaises(requests.Timeout):
                kev.collect()
        path = next((self.root / "data/raw/kev").glob("*/metadata.json"))
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "failed")
        self.assertFalse(list(self.root.rglob("kev.parquet")))


if __name__ == "__main__":
    unittest.main()
