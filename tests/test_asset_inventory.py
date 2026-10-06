"""Tests for the hypothetical asset inventory loader and validator."""

import copy
import tempfile
import unittest
from pathlib import Path

import yaml

from src.environmental.asset_inventory import load_assets, load_inventory


def valid_document():
    return {
        "inventory_version": "test-v1",
        "scenario_type": "hypothetical",
        "organization": "Test shop",
        "assets": [
            {
                "asset_id": "WEB-01",
                "name": "Storefront",
                "function": "Accept orders",
                "domain": "web",
                "product": None,
                "version": None,
                "exposure": "internet",
                "data_type": ["orders"],
                "CR": "M",
                "IR": "H",
                "AR": "H",
                "rationale": "Order integrity and availability are important.",
                "assumptions": ["Hypothetical deployment."],
            }
        ],
    }


class AssetInventoryChecks(unittest.TestCase):
    def write_inventory(self, document):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "assets.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    def test_repository_inventory_loads(self):
        inventory = load_inventory(Path("config/assets.yaml"))
        self.assertEqual(inventory.inventory_version, "draft-v0.3")
        self.assertEqual(len(inventory.assets), 6)
        self.assertEqual(len({asset.asset_id for asset in inventory.assets}), 6)

    def test_duplicate_asset_id_is_rejected(self):
        document = valid_document()
        document["assets"].append(copy.deepcopy(document["assets"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate asset_id.*WEB-01"):
            load_inventory(self.write_inventory(document))

    def test_missing_required_asset_field_is_rejected(self):
        document = valid_document()
        del document["assets"][0]["rationale"]
        with self.assertRaisesRegex(ValueError, "missing required fields: rationale"):
            load_inventory(self.write_inventory(document))

    def test_invalid_security_requirement_is_rejected(self):
        for metric in ("CR", "IR", "AR"):
            with self.subTest(metric=metric):
                document = valid_document()
                document["assets"][0][metric] = "X"
                with self.assertRaisesRegex(ValueError, metric):
                    load_inventory(self.write_inventory(document))

    def test_invalid_domain_and_exposure_are_rejected(self):
        for field, value in (("domain", "desktop"), ("exposure", "public")):
            with self.subTest(field=field):
                document = valid_document()
                document["assets"][0][field] = value
                with self.assertRaisesRegex(ValueError, field):
                    load_inventory(self.write_inventory(document))

    def test_null_product_and_version_are_valid(self):
        asset = load_assets(self.write_inventory(valid_document()))[0]
        self.assertIsNone(asset.product)
        self.assertIsNone(asset.version)

    def test_client_exposure_is_valid_inventory_data(self):
        document = valid_document()
        document["assets"][0].update(
            asset_id="MOB-01", domain="mobile", exposure="client"
        )
        asset = load_assets(self.write_inventory(document))[0]
        self.assertEqual(asset.exposure, "client")
        self.assertFalse(hasattr(asset, "exposure_priority"))


if __name__ == "__main__":
    unittest.main()
