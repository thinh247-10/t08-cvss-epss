"""Load and validate the hypothetical asset inventory.

This module validates inventory facts only. It deliberately does not infer CVE
applicability, change CVSS Modified Metrics, or assign a priority to client
assets.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


ALLOWED_DOMAINS = frozenset({"web", "mobile"})
ALLOWED_EXPOSURES = frozenset({"internet", "internal", "isolated", "client"})
ALLOWED_REQUIREMENTS = frozenset({"L", "M", "H"})

REQUIRED_ASSET_FIELDS = (
    "asset_id",
    "name",
    "function",
    "domain",
    "product",
    "version",
    "exposure",
    "data_type",
    "CR",
    "IR",
    "AR",
    "rationale",
    "assumptions",
)


@dataclass(frozen=True)
class Asset:
    """One validated hypothetical asset."""

    asset_id: str
    name: str
    function: str
    domain: str
    product: str | None
    version: str | None
    exposure: str
    data_type: tuple[str, ...]
    CR: str
    IR: str
    AR: str
    rationale: str
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class AssetInventory:
    """Validated inventory metadata and assets."""

    inventory_version: str
    scenario_type: str
    organization: str
    assets: tuple[Asset, ...]


def _non_empty_string(value: Any, field: str, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{location}.{field} must be a non-empty string")
    return value.strip()


def _nullable_string(value: Any, field: str, location: str) -> str | None:
    if value is None:
        return None
    return _non_empty_string(value, field, location)


def _string_list(value: Any, field: str, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{location}.{field} must be a non-empty list of strings")
    return tuple(_non_empty_string(item, field, location) for item in value)


def _validate_asset(raw: Any, index: int) -> Asset:
    location = f"assets[{index}]"
    if not isinstance(raw, Mapping):
        raise ValueError(f"{location} must be a mapping")

    missing = [field for field in REQUIRED_ASSET_FIELDS if field not in raw]
    if missing:
        raise ValueError(f"{location} is missing required fields: {', '.join(missing)}")

    asset_id = _non_empty_string(raw["asset_id"], "asset_id", location)
    domain = _non_empty_string(raw["domain"], "domain", location)
    if domain not in ALLOWED_DOMAINS:
        raise ValueError(
            f"{location}.domain must be one of {sorted(ALLOWED_DOMAINS)}, got {domain!r}"
        )

    exposure = _non_empty_string(raw["exposure"], "exposure", location)
    if exposure not in ALLOWED_EXPOSURES:
        raise ValueError(
            f"{location}.exposure must be one of {sorted(ALLOWED_EXPOSURES)}, "
            f"got {exposure!r}"
        )

    requirements: dict[str, str] = {}
    for metric in ("CR", "IR", "AR"):
        value = _non_empty_string(raw[metric], metric, location)
        if value not in ALLOWED_REQUIREMENTS:
            raise ValueError(
                f"{location}.{metric} must be one of {sorted(ALLOWED_REQUIREMENTS)}, "
                f"got {value!r}"
            )
        requirements[metric] = value

    return Asset(
        asset_id=asset_id,
        name=_non_empty_string(raw["name"], "name", location),
        function=_non_empty_string(raw["function"], "function", location),
        domain=domain,
        product=_nullable_string(raw["product"], "product", location),
        version=_nullable_string(raw["version"], "version", location),
        exposure=exposure,
        data_type=_string_list(raw["data_type"], "data_type", location),
        CR=requirements["CR"],
        IR=requirements["IR"],
        AR=requirements["AR"],
        rationale=_non_empty_string(raw["rationale"], "rationale", location),
        assumptions=_string_list(raw["assumptions"], "assumptions", location),
    )


def validate_inventory(raw: Any) -> AssetInventory:
    """Validate parsed YAML and return a typed inventory.

    ``product`` and ``version`` may be null during design. ``client`` is a valid
    exposure value, but this function does not convert it to an exposure score.
    """

    if not isinstance(raw, Mapping):
        raise ValueError("inventory document must be a mapping")

    required_top_level = ("inventory_version", "scenario_type", "organization", "assets")
    missing = [field for field in required_top_level if field not in raw]
    if missing:
        raise ValueError(f"inventory is missing required fields: {', '.join(missing)}")

    raw_assets = raw["assets"]
    if not isinstance(raw_assets, list) or not raw_assets:
        raise ValueError("inventory.assets must be a non-empty list")

    assets = tuple(_validate_asset(item, index) for index, item in enumerate(raw_assets))
    seen: set[str] = set()
    duplicate_ids: set[str] = set()
    for asset in assets:
        if asset.asset_id in seen:
            duplicate_ids.add(asset.asset_id)
        seen.add(asset.asset_id)
    if duplicate_ids:
        raise ValueError(f"duplicate asset_id values: {', '.join(sorted(duplicate_ids))}")

    return AssetInventory(
        inventory_version=_non_empty_string(
            raw["inventory_version"], "inventory_version", "inventory"
        ),
        scenario_type=_non_empty_string(raw["scenario_type"], "scenario_type", "inventory"),
        organization=_non_empty_string(raw["organization"], "organization", "inventory"),
        assets=assets,
    )


def load_inventory(path: str | Path) -> AssetInventory:
    """Read a UTF-8 YAML inventory from *path* and validate it."""

    inventory_path = Path(path)
    try:
        raw = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot read inventory {inventory_path}: {exc}") from exc
    return validate_inventory(raw)


def load_assets(path: str | Path) -> tuple[Asset, ...]:
    """Load an inventory and return its validated assets."""

    return load_inventory(path).assets
