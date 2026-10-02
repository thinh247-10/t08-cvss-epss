"""Paged NVD collection with immutable raw pages and a resumable checkpoint.

Uses the existing nvd_collector parser. Explicit dates are required for a new
run. --plan is offline; --resume reuses verified cached pages. No scope/split.
"""

import argparse
import hashlib
import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests
import yaml
from dotenv import load_dotenv

from src.collect.collect_pilot import summarize_records
from src.collect.nvd_collector import ALLOWED_LABELS, extract_cve

ROOT = Path(__file__).resolve().parents[2]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_GAP = 6.5  # Conservative project policy, including runs without a key.


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("Duong dan phai nam trong repo")
    return path


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def date_value(value):
    text = str(value)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise ValueError("Ngay phai co dang YYYY-MM-DD")
    return date.fromisoformat(text)


def nvd_settings(config):
    if (config["collection"]["description_language"] != "en" or config["cvss"]["version"] != "3.1"
            or config["cvss"]["preferred_source"] != "nvd@nist.gov"):
        raise ValueError("Parser hien ho tro en, CVSS 3.1, uu tien nvd@nist.gov")
    return {"project": config["project"], "collection": config["collection"], "cvss": config["cvss"]}


def make_plan(config, start, end, page_size=500, window_days=31):
    start, end = date_value(start), date_value(end)
    if not date_value(config["collection"]["start_date"]) <= start <= end <= date_value(config["collection"]["end_date"]):
        raise ValueError("Khoang yeu cau phai nam trong collection.start_date/end_date")
    if end > datetime.now(timezone.utc).date():
        raise ValueError("Khong thu thap khoang ngay tuong lai")
    # These conservative caps are project limits, not claims about API maxima.
    if not 1 <= page_size <= 1000 or not 1 <= window_days <= 90:
        raise ValueError("Gioi han cua script: page-size 1..1000, window-days 1..90")
    windows, cursor = [], start
    while cursor <= end:
        last = min(cursor + timedelta(days=window_days - 1), end)
        windows.append({"pubStartDate": f"{cursor}T00:00:00.000", "pubEndDate": f"{last}T23:59:59.999"})
        cursor = last + timedelta(days=1)
    return {"start_date": str(start), "end_date": str(end), "page_size": page_size,
            "window_days": window_days, "windows": windows}


def request_page(params):
    key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"apiKey": key} if key else {}
    for attempt in range(3):
        time.sleep(REQUEST_GAP)
        try:
            response = requests.get(NVD_URL, params=params, headers=headers, timeout=(10, 60))
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
                time.sleep(int(retry_after))
        delay = 15 * (attempt + 1)
        print(f"Loi mang/HTTP tam thoi; doi {delay}s roi thu lai...", flush=True)
        time.sleep(delay)


def validate_page(payload, params, expected_total=None):
    if not isinstance(payload, dict):
        raise ValueError("NVD response phai la object")
    for field in ("totalResults", "startIndex", "resultsPerPage"):
        if type(payload.get(field)) is not int or payload[field] < 0:
            raise ValueError(f"NVD sai {field}")
    total, offset = payload["totalResults"], payload["startIndex"]
    items = payload.get("vulnerabilities")
    if not isinstance(items, list) or offset != params["startIndex"]:
        raise ValueError("NVD sai vulnerabilities/startIndex")
    if expected_total is not None and total != expected_total:
        raise ValueError("totalResults thay doi giua cac trang; can bat dau run moi de kiem tra")
    if (not len(items) <= payload["resultsPerPage"] <= params["resultsPerPage"]
            or offset + len(items) > total or (not items and not (offset == total == 0))):
        raise ValueError("NVD trang rong bat thuong hoac so dong sai")
    low, high = (pd.Timestamp(params[k], tz="UTC") for k in ("pubStartDate", "pubEndDate"))
    records = []
    for item in items:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve.get("id", ""))):
            raise ValueError("NVD CVE ID sai")
        published = pd.to_datetime(cve.get("published"), format="ISO8601", utc=True, errors="raise")
        if pd.isna(published) or not low <= published <= high:
            raise ValueError("NVD tra CVE ngoai khoang published yeu cau")
        records.append(cve)
    return records, total


def replay_pages(state, root=None):
    """Derive cursor from cached bytes, never trust an unchecked next-page index."""
    root = (root or ROOT).resolve()
    windows = state["plan"]["windows"]
    progress = [{"next": 0, "total": None, "complete": False} for _ in windows]
    records, seen = [], set()
    for entry in state["raw_pages"]:
        index = entry["window_index"]
        if type(index) is not int or not 0 <= index < len(windows):
            raise ValueError("Checkpoint window index sai")
        cursor = progress[index]
        if cursor["complete"] or any(not p["complete"] for p in progress[:index]):
            raise ValueError("Checkpoint bi nhay/nhan trang")
        params = {**windows[index], "startIndex": cursor["next"], "resultsPerPage": state["plan"]["page_size"]}
        if entry["params"] != params:
            raise ValueError("Checkpoint params khong khop trang ke tiep")
        raw_path = (root / entry["file"]).resolve()
        if not raw_path.is_relative_to(root):
            raise ValueError("Raw path nam ngoai repo")
        if digest(raw_path) != entry["sha256"]:
            raise ValueError("Raw cache bi thay doi; dung resume")
        page, total = validate_page(json.loads(raw_path.read_bytes()), params, cursor["total"])
        ids = [cve["id"] for cve in page]
        if len(set(ids)) != len(ids) or seen.intersection(ids):
            raise ValueError("CVE ID trung giua cac trang/cua so; khong tu bo trung")
        if entry["records"] != len(page) or entry["total_results"] != total:
            raise ValueError("Checkpoint so dong khong khop raw")
        records.extend(page)
        seen.update(ids)
        cursor.update(next=cursor["next"] + len(page), total=total)
        cursor["complete"] = cursor["next"] == total
    return records, progress


def finalize(state, checkpoint, records, progress):
    rows = [extract_cve(cve) for cve in records]
    columns = ["cve_id", "published", "last_modified", "vuln_status", "description", "cvss_version",
               "cvss_source", "cvss_type", "cvss_vector", "cvss_base_score", *ALLOWED_LABELS]
    frame = pd.DataFrame(rows, columns=columns)
    for column in frame:
        if column in ("published", "last_modified"):
            frame[column] = pd.to_datetime(frame[column], format="ISO8601", utc=True, errors="raise")
        elif column == "cvss_base_score":
            frame[column] = pd.to_numeric(frame[column], errors="raise").astype("Float64")
        else:
            frame[column] = frame[column].astype("string")
    frame["dataset_version"] = state["dataset_version"]
    frame = frame.sort_values("cve_id").reset_index(drop=True)
    if frame.cve_id.duplicated().any() or not all(p["complete"] for p in progress):
        raise ValueError("Khong du dieu kien xuat NVD")
    now = datetime.now(timezone.utc)
    folder = ROOT / "data/processed" / f"nvd_{now.strftime('%Y%m%dT%H%M%S_%fZ')}"
    folder.mkdir(parents=True, exist_ok=False)
    table = folder / "nvd_cves.parquet"
    meta = {"status": "in_progress", "dataset_version": state["dataset_version"],
            "schema_stage": "Paged NVD-only collection; scope, EPSS/KEV and split pending",
            "raw_layout": "paged-v1", "endpoint": NVD_URL, "plan": state["plan"],
            "nvd_settings": state["nvd_settings"], "started_at": state["started_at"],
            "retrieved_at": now.isoformat(), "raw_pages": state["raw_pages"],
            "checkpoint_file": checkpoint.relative_to(ROOT).as_posix(),
            "scope_reviewed": False, "limitations": [
                "A sequence of current API responses, not an atomic or historical NVD snapshot.",
                "Stable total counts and unique IDs are checked; upstream edits with unchanged counts may still occur.",
                "Rejected and missing labels retained; scope, split and CVSS score recomputation pending.",
                "No EPSS/KEV enrichment; do not reuse the old pilot EPSS table for this larger population.",
            ]}
    meta_path = folder / "metadata.json"
    write_json(meta_path, meta)
    try:
        frame.to_parquet(table, index=False)
        meta.update({"status": "complete", "complete_for_requested_window": True,
                     "api_total_results": sum(p["total"] for p in progress),
                     "table_file": table.relative_to(ROOT).as_posix(), "table_sha256": digest(table),
                     **summarize_records(frame)})
        write_json(meta_path, meta)
    except Exception:
        meta["status"] = "failed"
        write_json(meta_path, meta)
        raise
    state.update(status="complete", output_metadata=meta_path.relative_to(ROOT).as_posix(), output_metadata_sha256=digest(meta_path))
    state.pop("last_error_type", None)
    write_json(checkpoint, state)
    print(f"Da luu: {len(frame)} / {meta['api_total_results']} CVE", flush=True)
    print(f"So trang: {len(state['raw_pages'])}; so cua so: {len(progress)}\nDa lay du khoang yeu cau: True")
    print(f"Rejected: {meta['rejected_records']}; thieu vector: {meta['missing_parseable_base_cvss31']}")
    print(f"Ung vien mo ta + vector, khong Rejected: {meta['non_rejected_description_and_vector_candidates']}")
    print(f"Bang: {meta['table_file']}\nMetadata: {meta_path.relative_to(ROOT).as_posix()}")
    print("NVD ONLY: chua ghep EPSS/KEV, chua scope/split/train.")
    return meta


def collect(config, plan=None, resume=None):
    settings = nvd_settings(config)
    if resume:
        checkpoint = local_path(resume)
        state = json.loads(checkpoint.read_text(encoding="utf-8"))
        if state.get("checkpoint_version") != 1 or state["nvd_settings"] != settings:
            raise ValueError("Checkpoint/config NVD khong khop; khong resume voi cau hinh khac")
        expected = make_plan(config, state["plan"]["start_date"], state["plan"]["end_date"], state["plan"]["page_size"], state["plan"]["window_days"])
        if state["plan"] != expected:
            raise ValueError("Checkpoint plan da bi thay doi")
        folder = checkpoint.parent
    else:
        if plan is None:
            raise ValueError("Can plan cho run moi")
        now = datetime.now(timezone.utc)
        run_id = now.strftime("%Y%m%dT%H%M%S_%fZ")
        folder = ROOT / "data/raw/nvd" / f"collection_{run_id}"
        folder.mkdir(parents=True, exist_ok=False)
        checkpoint = folder / "checkpoint.json"
        state = {"checkpoint_version": 1, "status": "in_progress", "plan": plan, "nvd_settings": settings,
                 "dataset_version": f"{config['project']['dataset_version']}-nvd-{run_id}",
                 "started_at": now.isoformat(), "raw_pages": []}
        write_json(checkpoint, state)
    print(f"Checkpoint: {checkpoint.relative_to(ROOT).as_posix()}", flush=True)
    lock = folder / "run.lock"
    try:
        lock_handle = lock.open("x", encoding="utf-8")
    except FileExistsError:
        raise ValueError("Run dang bi khoa; khong chay cung checkpoint o hai terminal. Neu lan truoc bi tat dot ngot, can kiem tra tien trinh truoc khi go khoa.") from None
    try:
        lock_handle.write(str(os.getpid()))
        lock_handle.close()
        records, progress = replay_pages(state)
        if state["status"] == "complete":
            meta_path = local_path(state["output_metadata"])
            if digest(meta_path) != state["output_metadata_sha256"]:
                raise ValueError("Output metadata da thay doi")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if digest(local_path(meta["table_file"])) != meta["table_sha256"]:
                raise ValueError("Output table da thay doi")
            print(f"Run da complete; dung cache, khong tai lai. Metadata: {state['output_metadata']}")
            return meta
        state["status"] = "in_progress"
        write_json(checkpoint, state)
        seen = {cve["id"] for cve in records}
        print(f"Cache hop le: {len(state['raw_pages'])} trang, {len(records)} CVE", flush=True)
        for index, cursor in enumerate(progress):
            while not cursor["complete"]:
                params = {**state["plan"]["windows"][index], "startIndex": cursor["next"], "resultsPerPage": state["plan"]["page_size"]}
                print(f"Cua so {index+1}/{len(progress)}, startIndex={cursor['next']}...", flush=True)
                raw = request_page(params)
                retrieved = datetime.now(timezone.utc)
                raw_path = folder / f"window_{index:03d}_offset_{cursor['next']:08d}_{retrieved.strftime('%Y%m%dT%H%M%S_%fZ')}.json"
                with raw_path.open("xb") as raw_file:
                    raw_file.write(raw)
                payload = json.loads(raw)
                page, total = validate_page(payload, params, cursor["total"])
                ids = [cve["id"] for cve in page]
                if len(set(ids)) != len(ids) or seen.intersection(ids):
                    raise ValueError("CVE trung giua cac trang; dung de kiem tra thay vi tu xoa")
                # Checkpoint advances only after the saved page has passed checks.
                state["raw_pages"].append({"file": raw_path.relative_to(ROOT).as_posix(), "sha256": digest(raw_path),
                                          "window_index": index, "params": params, "records": len(page), "total_results": total,
                                          "retrieved_at": retrieved.isoformat(), "api_timestamp": payload.get("timestamp")})
                write_json(checkpoint, state)
                records.extend(page)
                seen.update(ids)
                cursor.update(next=cursor["next"] + len(page), total=total)
                cursor["complete"] = cursor["next"] == total
                print(f"  Da luu {cursor['next']}/{total} CVE cua cua so nay", flush=True)
        return finalize(state, checkpoint, records, progress)
    except (Exception, KeyboardInterrupt) as exc:
        state["status"] = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        state["last_error_type"] = type(exc).__name__  # Do not persist HTTP headers or secrets.
        write_json(checkpoint, state)
        print(f"Da giu cache. Resume bang --resume {checkpoint.relative_to(ROOT).as_posix()}", flush=True)
        raise
    finally:
        lock_handle.close()
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-date")
    parser.add_argument("--end-date")
    parser.add_argument("--page-size", type=int)
    parser.add_argument("--window-days", type=int)
    parser.add_argument("--plan", action="store_true", help="Chi in ke hoach, khong goi API")
    parser.add_argument("--resume", help="Duong dan checkpoint.json cua run can tiep tuc")
    args = parser.parse_args()
    try:
        config = yaml.safe_load((ROOT / "config/project.yaml").read_text(encoding="utf-8"))
        nvd_settings(config)
        if args.resume:
            if any(value is not None for value in (args.start_date, args.end_date, args.page_size, args.window_days)) or args.plan:
                parser.error("--resume dung rieng, khong kem ngay/page-size/window-days/plan")
            plan = None
        else:
            if not args.start_date or not args.end_date:
                parser.error("Run moi can --start-date va --end-date")
            plan = make_plan(config, args.start_date, args.end_date,
                             args.page_size if args.page_size is not None else 500,
                             args.window_days if args.window_days is not None else 31)
            if args.plan:
                print(json.dumps(plan, indent=2))
                print("PLAN ONLY: chua goi API, chua tao output.")
                return
        load_dotenv(ROOT / ".env")
        collect(config, plan, args.resume)
    except KeyboardInterrupt:
        parser.exit(130, "Da dung theo yeu cau; cac trang da checkpoint van con.\n")
    except (ValueError, KeyError, TypeError, OSError, requests.RequestException) as exc:
        parser.exit(1, f"Dung NVD: {exc}\n")


if __name__ == "__main__":
    main()
