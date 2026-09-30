"""Download one small NVD page to check collection and extraction.

Run from the repository root:
    python -m src.collect.collect_pilot
    python -m src.collect.collect_pilot --limit 1000

This is a first-page sample, not a representative Web/mobile dataset.
No EPSS/KEV enrichment, scope filtering, or model training happens here.
"""

import argparse
import hashlib
import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests
import yaml
from dotenv import load_dotenv

from src.collect.nvd_collector import extract_cve


ROOT = Path(__file__).resolve().parents[2]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PILOT_LIMIT = 50


def build_params(config, limit=PILOT_LIMIT):
    """Use at most the first seven days of the configured collection range."""
    if not 1 <= limit <= 1000:
        raise ValueError("Pilot chi cho phep limit tu 1 den 1000")
    start = date.fromisoformat(str(config["collection"]["start_date"]))
    configured_end = date.fromisoformat(str(config["collection"]["end_date"]))
    if configured_end < start:
        raise ValueError("collection.end_date phai >= start_date")
    end = min(start + timedelta(days=6), configured_end)
    return {
        "pubStartDate": f"{start.isoformat()}T00:00:00.000",
        "pubEndDate": f"{end.isoformat()}T23:59:59.999",
        "startIndex": 0,
        "resultsPerPage": limit,
    }


def fetch_page(params):
    """Retry transient failures up to three attempts; never print headers."""
    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}

    for attempt in range(3):
        try:
            response = requests.get(
                NVD_URL, params=params, headers=headers, timeout=(10, 60)
            )
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise
        else:
            retryable = response.status_code == 429 or 500 <= response.status_code < 600
            if not retryable or attempt == 2:
                response.raise_for_status()
                return response.content

        delay = 30 * (attempt + 1)
        print(f"Loi tam thoi; doi {delay} giay truoc khi thu lai...")
        time.sleep(delay)

    raise RuntimeError("Khong tai duoc NVD")


def candidate_mask(frame):
    """Initial label candidates only; score/scope/split checks are still needed."""
    status = frame["vuln_status"].astype("string")
    return (
        status.notna()
        & status.ne("Rejected").fillna(False)
        & frame["description"].astype("string").str.strip().fillna("").ne("")
        & frame["cvss_vector"].notna()
    )


def summarize_records(frame):
    """Separate rejected records from missing labels without dropping rows."""
    status = frame["vuln_status"].astype("string")
    return {
        "downloaded_records": len(frame),
        "status_counts": {
            str(name): int(count)
            for name, count in status.fillna("UNKNOWN").value_counts().items()
        },
        "rejected_records": int(status.eq("Rejected").fillna(False).sum()),
        "unknown_status_records": int(status.isna().sum()),
        "missing_description": int(
            frame["description"].astype("string").str.strip().fillna("").eq("").sum()
        ),
        "missing_parseable_base_cvss31": int(frame["cvss_vector"].isna().sum()),
        "non_rejected_description_and_vector_candidates": int(candidate_mask(frame).sum()),
    }


def save_pilot(raw_bytes, params, config, root=ROOT):
    """Keep raw bytes first, then save extracted records and provenance."""
    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%S_%fZ")
    retrieved_at = now.isoformat()
    dataset_version = f"{config['project']['dataset_version']}-{run_id}"

    raw_dir = root / config["paths"]["raw_dir"] / "nvd" / f"pilot_{run_id}"
    output_dir = root / Path(config["paths"]["dataset"]).parent / f"pilot_{run_id}"
    raw_dir.mkdir(parents=True, exist_ok=False)
    raw_path = raw_dir / "response.json"
    raw_path.write_bytes(raw_bytes)

    payload = json.loads(raw_bytes)
    items = payload["vulnerabilities"]
    total = payload["totalResults"]
    if not isinstance(items, list) or not isinstance(total, int) or total < 0:
        raise ValueError("NVD tra schema khong hop le; da giu raw de kiem tra")
    if payload.get("startIndex") != params["startIndex"]:
        raise ValueError("NVD tra startIndex khac yeu cau")
    if not items:
        raise ValueError("NVD tra 0 CVE; kiem tra response.json va khoang ngay")
    if len(items) > params["resultsPerPage"] or len(items) > total:
        raise ValueError("So CVE tra ve khong khop thong tin phan trang")

    rows = [extract_cve(item["cve"]) for item in items]
    frame = pd.DataFrame(rows)
    if frame["cve_id"].duplicated().any():
        raise ValueError("Phat hien CVE ID trung; chua xuat bang du lieu")

    for column in ("published", "last_modified"):
        frame[column] = pd.to_datetime(frame[column], format="ISO8601", utc=True)
    frame["cvss_base_score"] = pd.to_numeric(frame["cvss_base_score"])
    for column in frame.columns.difference(["published", "last_modified", "cvss_base_score"]):
        frame[column] = frame[column].astype("string")
    frame["dataset_version"] = dataset_version

    output_dir.mkdir(parents=True, exist_ok=False)
    table_path = output_dir / "nvd_pilot.parquet"
    frame.to_parquet(table_path, index=False)

    metadata = {
        "purpose": "first_page_pipeline_smoke_test",
        "schema_stage": "NVD-only pilot; not the full master schema",
        "dataset_version": dataset_version,
        "retrieved_at": retrieved_at,
        "endpoint": NVD_URL,
        "params": params,
        "nvd_response_timestamp": payload.get("timestamp"),
        "api_total_results": total,
        "complete_for_requested_window": params["startIndex"] == 0 and len(frame) == total,
        **summarize_records(frame),
        "scope_reviewed": False,
        "raw_file": raw_path.relative_to(root).as_posix(),
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "table_file": table_path.relative_to(root).as_posix(),
        "table_sha256": hashlib.sha256(table_path.read_bytes()).hexdigest(),
        "limitations": [
            "First API page only; not a random or representative sample.",
            "Web/mobile scope has not been checked.",
            "EPSS and KEV have not been joined; no training split is assigned.",
            "CVSS base scores are copied from source, not recalculated yet.",
            "Rejected records are retained, but excluded from label candidate counts.",
        ],
    }
    metadata_path = output_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return frame, metadata, metadata_path


def main():
    parser = argparse.ArgumentParser(description="Tai mot trang NVD de kiem tra pipeline")
    parser.add_argument(
        "--limit", type=int, default=PILOT_LIMIT,
        help="So CVE toi da trong mot trang (1-1000; mac dinh 50)",
    )
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error("--limit phai nam trong khoang 1-1000")

    load_dotenv(ROOT / ".env")
    config = yaml.safe_load((ROOT / "config/project.yaml").read_text(encoding="utf-8"))
    params = build_params(config, limit=args.limit)
    print(f"Khoang ngay: {params['pubStartDate']} -> {params['pubEndDate']}")
    print(f"Dang tai trang dau, toi da {args.limit} CVE...")

    raw_bytes = fetch_page(params)
    frame, metadata, metadata_path = save_pilot(raw_bytes, params, config)

    print(f"\nDa luu: {len(frame)} / {metadata['api_total_results']} CVE trong khoang ngay")
    print(f"Trang thai: {metadata['status_counts']}")
    print(f"CVE Rejected (van giu trong bang): {metadata['rejected_records']}")
    print(f"Thieu mo ta: {metadata['missing_description']}")
    print(f"Thieu vector Base 3.1 tach duoc: {metadata['missing_parseable_base_cvss31']}")
    print(
        "Ung vien co mo ta + vector 3.1, khong Rejected: "
        f"{metadata['non_rejected_description_and_vector_candidates']}"
    )
    print(f"Da lay du khoang ngay: {metadata['complete_for_requested_window']}")
    print(f"Raw: {metadata['raw_file']}")
    print(f"Bang: {metadata['table_file']}")
    print(f"Metadata: {metadata_path.relative_to(ROOT).as_posix()}")
    candidates = frame.loc[candidate_mask(frame)]
    print("\nXem toi da 5 ung vien co mo ta + vector, khong Rejected:")
    if candidates.empty:
        print("Chua co ung vien trong trang nay; xem metadata va raw de kiem tra.")
    else:
        print(candidates[["cve_id", "cvss_base_score", "cvss_source", "AV", "AC"]].head().to_string(index=False))


if __name__ == "__main__":
    main()
