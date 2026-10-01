"""Save and validate the current CISA KEV catalog, without assigning pilot labels.

Run: python -m src.collect.kev_client
The official GitHub mirror avoids the cisa.gov 403 seen during this project.
This downloads a current catalog, NOT a historical catalog for the EPSS date.
"""

import argparse
import hashlib
import json
import re
import time
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import yaml

ROOT = Path(__file__).resolve().parents[2]
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CANONICAL_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUIRED_TEXT = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                 "shortDescription", "requiredAction", "dueDate")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Ngay phai co dang YYYY-MM-DD")
    return date.fromisoformat(value)


def download():
    for attempt in range(3):
        delay = 2 ** (attempt + 1)
        try:
            response = requests.get(KEV_URL, timeout=(10, 45))
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise
        else:
            retryable = response.status_code == 429 or 500 <= response.status_code < 600
            if not retryable or attempt == 2:
                response.raise_for_status()
                return response.content
            retry_after = response.headers.get("Retry-After", "")
            if retry_after and (not retry_after.isdigit() or int(retry_after) > 60):
                response.raise_for_status()
            if retry_after:
                delay = max(delay, int(retry_after))
        time.sleep(delay)


def validate_catalog(payload):
    """Validate fields used by the pipeline; retain all other fields in raw JSON."""
    if not isinstance(payload, dict):
        raise ValueError("Catalog KEV phai la JSON object")
    if not isinstance(payload.get("catalogVersion"), str) or not payload["catalogVersion"].strip():
        raise ValueError("Thieu catalogVersion")
    released = payload.get("dateReleased")
    if not isinstance(released, str) or "T" not in released:
        raise ValueError("Thieu/sai dateReleased")
    released_at = datetime.fromisoformat(released.replace("Z", "+00:00"))
    if released_at.tzinfo is None:
        raise ValueError("dateReleased phai co timezone")
    released_at = released_at.astimezone(timezone.utc)
    if released_at > datetime.now(timezone.utc):
        raise ValueError("dateReleased o tuong lai; kiem tra catalog/dong ho")
    entries = payload.get("vulnerabilities")
    if (not isinstance(entries, list) or type(payload.get("count")) is not int
            or payload["count"] != len(entries) or not entries):
        raise ValueError("Catalog rong hoac count khong khop; khong duoc suy ra CVE vang mat")
    seen, rows = set(), []
    for entry in entries:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) or not entry[k].strip() for k in REQUIRED_TEXT):
            raise ValueError("KEV entry thieu/sai truong bat buoc")
        cve_id = entry["cveID"]
        if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve_id) or cve_id in seen:
            raise ValueError("CVE ID sai hoac trung trong catalog")
        seen.add(cve_id)
        if parse_date(entry["dateAdded"]) > released_at.date():
            raise ValueError("dateAdded sau ngay phat hanh catalog")
        parse_date(entry["dueDate"])
        ransomware = entry.get("knownRansomwareCampaignUse")
        if ransomware is not None and not isinstance(ransomware, str):
            raise ValueError("knownRansomwareCampaignUse phai la string neu co")
        rows.append({
            "cve_id": cve_id, "is_kev": True,
            "kev_date_added": entry["dateAdded"], "kev_known_ransomware": ransomware,
            "kev_vendor_project": entry["vendorProject"], "kev_product": entry["product"],
            "kev_vulnerability_name": entry["vulnerabilityName"],
            "kev_short_description": entry["shortDescription"],
            "kev_required_action": entry["requiredAction"], "kev_due_date": entry["dueDate"],
        })
    return rows, released_at


def collect():
    config_path = ROOT / "config/project.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    snapshot = config.get("epss", {}).get("snapshot_date")
    if snapshot is None:
        raise ValueError("Hay dien epss.snapshot_date truoc de ghi nhan do lech thoi gian")
    epss_day = parse_date(str(snapshot))
    started = datetime.now(timezone.utc)
    if epss_day > started.date():
        raise ValueError("Ngay EPSS trong config o tuong lai")
    run_id = started.strftime("%Y%m%dT%H%M%S_%fZ")
    version = f"{config['project']['dataset_version']}-kev-{run_id}"
    folder = ROOT / "data/raw/kev" / f"catalog_{run_id}"
    folder.mkdir(parents=True, exist_ok=False)
    manifest = {
        "status": "in_progress", "dataset_version": version,
        "schema_stage": "Full KEV catalog; pilot membership not assigned yet",
        "endpoint": KEV_URL, "canonical_endpoint": CANONICAL_URL,
        "started_at": started.isoformat(), "config_sha256": digest(config_path),
        "epss_reference_date": epss_day.isoformat(),
        "historical_catalog_for_epss_date": False,
        "validation_scope": "Required fields, declared count, unique IDs and dates; not a full JSON Schema validator",
        "limitations": [
            "Current catalog, not a historical reconstruction for the EPSS date.",
            "Absence from KEV does not prove absence of exploitation.",
            "dateAdded is catalog inclusion date, not first exploitation date.",
            "Unknown ransomware use does not mean no ransomware use.",
            "No Web/mobile filtering or pilot join has been performed.",
        ],
    }

    def write_manifest():
        (folder / "metadata.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    write_manifest()
    try:
        raw = download()
        retrieved = datetime.now(timezone.utc)
        raw_path = folder / "catalog.json"
        raw_path.write_bytes(raw)
        manifest.update({"retrieved_at": retrieved.isoformat(), "raw_file": raw_path.relative_to(ROOT).as_posix(),
                         "raw_sha256": digest(raw_path)})
        write_manifest()
        payload = json.loads(raw)
        rows, released_at = validate_catalog(payload)
        frame = pd.DataFrame(rows).sort_values("cve_id").reset_index(drop=True)
        frame["dataset_version"] = version
        frame["retrieved_at"] = retrieved.isoformat()
        for column in frame.columns:
            frame[column] = frame[column].astype("boolean" if column == "is_kev" else "string")
        output = folder / "kev.parquet"
        frame.to_parquet(output, index=False)
        manifest.update({
            "status": "complete", "completed_at": datetime.now(timezone.utc).isoformat(),
            "catalog_version": payload["catalogVersion"], "catalog_date_released": payload["dateReleased"],
            "declared_count": payload["count"], "downloaded_records": len(frame),
            "unique_cve_count": frame.cve_id.nunique(), "complete_for_declared_catalog": True,
            "catalog_release_date_minus_epss_days": (released_at.date() - epss_day).days,
            "retrieval_date_minus_epss_days": (retrieved.date() - epss_day).days,
            "table_file": output.relative_to(ROOT).as_posix(), "table_sha256": digest(output),
        })
        write_manifest()
    except Exception as exc:
        manifest.update({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)})
        write_manifest()
        raise
    print(f"Catalog version: {manifest['catalog_version']}\nNgay phat hanh: {manifest['catalog_date_released']}")
    print(f"Tong CVE trong KEV: {len(frame)}\nKiem tra count va ID: OK")
    print(f"Ngay EPSS tham chieu: {epss_day}\nLech ngay phat hanh KEV - EPSS: {manifest['catalog_release_date_minus_epss_days']} ngay")
    print(f"Lech ngay tai KEV - EPSS: {manifest['retrieval_date_minus_epss_days']} ngay (UTC)")
    print(f"Bang: {manifest['table_file']}\nMetadata: {(folder / 'metadata.json').relative_to(ROOT).as_posix()}")
    print("Day la catalog hien tai. Chua ghep vao 543 CVE; chua gan is_kev=False cho CVE nao.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        collect()
    except (ValueError, KeyError, TypeError, OSError, requests.RequestException) as exc:
        parser.exit(1, f"Dung thu thap KEV: {exc}\n")


if __name__ == "__main__":
    main()
