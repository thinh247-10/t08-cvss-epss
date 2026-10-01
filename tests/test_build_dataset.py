"""Offline join checks: no dropped/duplicated CVEs, provenance and nullable data."""

import io
import json
import shutil
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import patch

import pandas as pd

from src.collect import build_dataset as builder
from src.collect.epss_client import make_table
from src.collect.nvd_collector import ALLOWED_LABELS

DAY = "2024-01-15"
BUILT = "2024-01-17T00:00:00+00:00"


def tables():
    rows = []
    for i in range(3):
        row = {"cve_id": f"CVE-2023-{1000+i}", "published": ["2023-01-01T00:00:00.123Z", "2023-01-02T00:00:00Z", "2023-01-03T00:00:00Z"][i],
               "last_modified": "2024-01-01T00:00:00Z", "description": "Example description",
               "vuln_status": "Rejected" if i == 2 else "Analyzed", "cvss_version": None,
               "cvss_source": None, "cvss_type": None, "cvss_vector": None, "cvss_base_score": None,
               **{key: None for key in ALLOWED_LABELS}, "dataset_version": "test-nvd"}
        if i == 0:
            row.update(cvss_version="3.1", cvss_source="nvd@nist.gov", cvss_type="Primary", cvss_base_score=9.8,
                       cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        rows.append(row)
    nvd = pd.DataFrame(rows)
    for name in ("published", "last_modified"):
        nvd[name] = pd.to_datetime(nvd[name], format="ISO8601", utc=True)
    epss = make_table(nvd.cve_id, {"CVE-2023-1000": {"epss": 0.0, "epss_percentile": 0.1, "epss_date": DAY}}, "test-epss", BUILT)
    kev = pd.DataFrame({"cve_id": ["CVE-2023-1001", "CVE-2023-9999"], "is_kev": pd.array([True, True], dtype="boolean"),
                        "kev_date_added": [DAY, DAY], "kev_known_ransomware": ["Unknown", None],
                        "dataset_version": "test-kev"})
    return nvd, epss, kev


class JoinChecks(unittest.TestCase):
    def test_preserves_missing_zero_rejected_and_pending_scope_with_mixed_dates(self):
        nvd, epss, kev = tables()
        joined = builder.join_pilot(nvd, epss, kev, "joined", BUILT, kev_complete=True)
        self.assertEqual(len(joined), 3)
        self.assertEqual(joined.is_kev.tolist(), [False, True, False])
        self.assertEqual(joined.loc[0, "epss"], 0.0)
        self.assertTrue(pd.isna(joined.loc[1, "epss"]))
        self.assertTrue(pd.isna(joined.loc[1, "cvss_vector"]))
        self.assertEqual(joined.loc[2, "vuln_status"], "Rejected")
        self.assertTrue(joined.split.isna().all())
        self.assertTrue(joined.scope_status.eq("needs_review").all())
        self.assertFalse(joined.in_scope.any())
        self.assertEqual(joined.domain_tags.tolist(), [[], [], []])
        self.assertEqual(str(joined.published.dt.tz), "UTC")

    def test_duplicate_ids_in_any_source_stop_join(self):
        for index in range(3):
            inputs = list(tables())
            inputs[index] = pd.concat([inputs[index], inputs[index].iloc[:1]], ignore_index=True)
            with self.subTest(source=index), self.assertRaises(ValueError):
                builder.join_pilot(*inputs, "joined", BUILT, kev_complete=True)

    def test_incomplete_catalog_or_wrong_epss_population_stops_join(self):
        nvd, epss, kev = tables()
        with self.assertRaises(ValueError):
            builder.join_pilot(nvd, epss, kev, "joined", BUILT, kev_complete=False)
        with self.assertRaises(ValueError):
            builder.join_pilot(nvd, epss.iloc[:1], kev, "joined", BUILT, kev_complete=True)


class BuildChecks(unittest.TestCase):
    def setUp(self):
        self.workspace = builder.ROOT.resolve()
        self.root = self.workspace / "tests" / f".join-test-{uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(self.cleanup)
        (self.root / "config").mkdir()
        (self.root / "config/project.yaml").write_text('project:\n  schema_version: "0.1"\nepss:\n  snapshot_date: "2024-01-15"\n', encoding="utf-8")
        nvd, epss, kev = tables()
        for name, frame in (("nvd", nvd), ("epss", epss), ("kev", kev)):
            frame.to_parquet(self.root / f"{name}.parquet", index=False)
        self.write_json("nvd.json", {"totalResults": 3, "startIndex": 0, "vulnerabilities": [{"cve": {"id": x}} for x in nvd.cve_id]})
        self.nm = {"dataset_version": "test-nvd", "downloaded_records": 3, "complete_for_requested_window": True,
                   "table_file": "nvd.parquet", "table_sha256": builder.digest(self.root / "nvd.parquet"),
                   "raw_file": "nvd.json", "raw_sha256": builder.digest(self.root / "nvd.json"), "params": {}}
        self.write_json("nvd-meta.json", self.nm)
        self.write_json("batch_001.json", {"status": "OK", "status-code": 200, "total": 1, "offset": 0,
                                         "data": [{"cve": "CVE-2023-1000", "epss": "0.0", "percentile": "0.1", "date": DAY}]})
        self.em = {"status": "complete", "dataset_version": "test-epss", "requested_records": 3,
                   "table_file": "epss.parquet", "table_sha256": builder.digest(self.root / "epss.parquet"),
                   "requested_date": DAY, "returned_dates": [DAY], "available_records": 1, "missing_records": 2,
                   "input_metadata_sha256": builder.digest(self.root / "nvd-meta.json"),
                   "input_table_sha256": self.nm["table_sha256"], "input_dataset_version": "test-nvd",
                   "raw_responses": [{"file": "batch_001.json", "sha256": builder.digest(self.root / "batch_001.json"),
                                      "params": {"date": DAY, "cve": ",".join(nvd.cve_id)}}]}
        self.write_json("epss-meta.json", self.em)
        entries = [{"cveID": row.cve_id, "vendorProject": "Example", "product": "Example app", "vulnerabilityName": "Example issue",
                    "shortDescription": "Example", "requiredAction": "Update", "dateAdded": DAY, "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": None if pd.isna(row.kev_known_ransomware) else row.kev_known_ransomware} for row in kev.itertuples()]
        self.write_json("kev.json", {"catalogVersion": "test", "dateReleased": "2024-01-16T00:00:00Z", "count": 2, "vulnerabilities": entries})
        self.km = {"status": "complete", "dataset_version": "test-kev", "downloaded_records": 2,
                   "complete_for_declared_catalog": True, "declared_count": 2, "unique_cve_count": 2,
                   "table_file": "kev.parquet", "table_sha256": builder.digest(self.root / "kev.parquet"),
                   "raw_file": "kev.json", "raw_sha256": builder.digest(self.root / "kev.json"),
                   "catalog_version": "test", "catalog_date_released": "2024-01-16T00:00:00Z",
                   "epss_reference_date": DAY, "retrieved_at": BUILT}
        self.write_json("kev-meta.json", self.km)

    def cleanup(self):
        target = self.root.resolve()
        if target.parent != self.workspace / "tests" or not target.name.startswith(".join-test-"):
            raise RuntimeError("Refuse cleanup outside test directory")
        shutil.rmtree(target)

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def run_build(self, check_only=False):
        with patch.object(builder, "ROOT", self.root), redirect_stdout(io.StringIO()):
            return builder.build("nvd-meta.json", "epss-meta.json", "kev-meta.json", check_only)

    def test_complete_build_roundtrip_does_not_modify_handoff(self):
        sample = self.root / "data/sample/cves_sample.csv"
        sample.parent.mkdir(parents=True)
        sample.write_text("teammate work", encoding="utf-8")
        meta = self.run_build()
        self.assertEqual(meta["status"], "complete")
        self.assertFalse(meta["training_ready"])
        self.assertFalse(meta["ranking_ready"])
        self.assertEqual(meta["statistics"]["total_records"], 3)
        self.assertEqual(meta["kev_release_date_minus_epss_days"], 1)
        frame = pd.read_parquet(self.root / meta["table_file"])
        self.assertEqual(frame.is_kev.tolist(), [False, True, False])
        self.assertTrue(pd.isna(frame.loc[1, "epss"]))
        csv = pd.read_csv(self.root / meta["csv_file"], dtype={"is_kev": "boolean", "in_scope": "boolean", "epss": "Float64"})
        self.assertEqual(csv.is_kev.tolist(), [False, True, False])
        self.assertEqual(json.loads(csv.loc[0, "domain_tags"]), [])
        self.assertTrue(pd.isna(csv.loc[1, "epss"]))
        self.assertEqual(builder.digest(self.root / meta["table_file"]), meta["table_sha256"])
        self.assertEqual(sample.read_text(encoding="utf-8"), "teammate work")
        second = self.run_build()
        self.assertNotEqual(meta["table_file"], second["table_file"])

    def test_check_only_writes_nothing(self):
        stats = self.run_build(check_only=True)
        self.assertEqual(stats["in_kev"], 1)
        self.assertFalse((self.root / "data").exists())

    def test_wrong_snapshot_provenance_stops_before_output(self):
        self.em["input_metadata_sha256"] = "wrong"
        self.write_json("epss-meta.json", self.em)
        with self.assertRaises(ValueError):
            self.run_build()
        self.assertFalse((self.root / "data").exists())

    def test_failed_or_incomplete_kev_stops_before_output(self):
        for field, value in (("status", "failed"), ("complete_for_declared_catalog", False)):
            saved = {**self.km, field: value}
            self.write_json("kev-meta.json", saved)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_build()
        self.assertFalse((self.root / "data").exists())

    def test_modified_table_checksum_stops_build(self):
        (self.root / "epss.parquet").write_bytes(b"modified")
        with self.assertRaises(ValueError):
            self.run_build()


if __name__ == "__main__":
    unittest.main()
