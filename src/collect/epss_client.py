"""Collect a fixed-date EPSS snapshot for an existing NVD dataset.

Run --probe to inspect an available date, then set epss.snapshot_date in
config/project.yaml before running --nvd-metadata PATH. No API key is needed.
New runs support --resume PATH_TO_EPSS_METADATA after interruption.
Docs: https://api.first.org/epss/ and https://api.first.org/
"""

import argparse
import hashlib
import json
import math
import os
import re
import time
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import yaml

ROOT = Path(__file__).resolve().parents[2]
EPSS_URL = "https://api.first.org/data/v1/epss"
PROBE_CVE = "CVE-2021-44228"


def local_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("Duong dan phai nam trong repo")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def iso_date(value):
    text = str(value)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise ValueError("Can ngay YYYY-MM-DD; hay dien epss.snapshot_date trong config/project.yaml")
    parsed = date.fromisoformat(text)
    if not date(2021, 4, 14) <= parsed <= datetime.now(timezone.utc).date():
        raise ValueError("Ngay EPSS ngoai khoang ho tro hoac o tuong lai")
    return text


def make_batches(cve_ids):
    ids = list(cve_ids)
    if not ids or any(not isinstance(x, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", x) for x in ids):
        raise ValueError("Danh sach CVE rong hoac ID khong hop le")
    if len(set(ids)) != len(ids):
        raise ValueError("Trung CVE ID trong dau vao")
    batches, batch = [], []
    for cve_id in sorted(ids):
        if len(cve_id) > 2000:
            raise ValueError("CVE ID vuot gioi han API")
        if batch and (len(batch) == 100 or len(",".join([*batch, cve_id])) > 2000):
            batches.append(batch)
            batch = []
        batch.append(cve_id)
    if batch:
        batches.append(batch)
    return batches


def request_bytes(params):
    """Retry transient failures, never turn failed requests into missing scores."""
    for attempt in range(3):
        delay = 2 ** (attempt + 1)
        try:
            response = requests.get(EPSS_URL, params=params, timeout=(10, 45))
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 2:
                raise
        else:
            retryable = response.status_code == 429 or 500 <= response.status_code < 600
            if not retryable or attempt == 2:
                response.raise_for_status()
                return response.content
            retry_after = response.headers.get("Retry-After", "")
            # Stop on long or date-based Retry-After instead of retrying too early.
            if retry_after and (not retry_after.isdigit() or int(retry_after) > 60):
                response.raise_for_status()
            if retry_after:
                delay = max(delay, int(retry_after))
        time.sleep(delay)


def validate_response(payload, requested_ids, expected_date=None):
    if not isinstance(payload, dict) or payload.get("status") != "OK" or payload.get("status-code") != 200:
        raise ValueError("EPSS response khong bao thanh cong")
    rows = payload.get("data")
    if (not isinstance(rows, list) or type(payload.get("total")) is not int
            or payload["total"] != len(rows) or payload.get("offset") != 0):
        raise ValueError("EPSS response thieu trang hoac sai schema; khong the ket luan missing")
    requested, found = set(requested_ids), {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Dong EPSS khong phai object")
        cve_id = row.get("cve")
        if not isinstance(cve_id, str) or cve_id not in requested or cve_id in found:
            raise ValueError("EPSS tra ve CVE ngoai yeu cau hoac bi trung")
        returned_date = iso_date(row.get("date"))
        if expected_date is not None and returned_date != expected_date:
            raise ValueError("Ngay EPSS tra ve khac ngay yeu cau")
        values = {}
        for source, target in (("epss", "epss"), ("percentile", "epss_percentile")):
            if isinstance(row.get(source), bool) or row.get(source) is None:
                raise ValueError("Diem EPSS/percentile khong hop le")
            value = float(row[source])
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("Diem EPSS/percentile phai nam trong [0,1]")
            values[target] = value
        found[cve_id] = {"cve_id": cve_id, **values, "epss_date": returned_date}
    return found


def make_table(cve_ids, found, version, retrieved_at):
    rows = []
    for cve_id in sorted(cve_ids):
        match = found.get(cve_id)
        rows.append({
            "cve_id": cve_id,
            "epss": match["epss"] if match else None,
            "epss_percentile": match["epss_percentile"] if match else None,
            "epss_date": match["epss_date"] if match else None,
            "epss_status": "available" if match else "not_returned",
            "dataset_version": version, "retrieved_at": retrieved_at,
        })
    frame = pd.DataFrame(rows)
    for column in frame.columns:
        frame[column] = frame[column].astype("Float64" if column in ("epss", "epss_percentile") else "string")
    return frame


def collect(metadata_path=None, resume=None):
    config = yaml.safe_load((ROOT / "config/project.yaml").read_text(encoding="utf-8"))
    snapshot = iso_date(config["epss"]["snapshot_date"])
    saved = None
    if resume:
        manifest_path = local_path(resume)
        saved = json.loads(manifest_path.read_text(encoding="utf-8"))
        if saved.get("collector_version") != 2:
            raise ValueError("Resume chi ho tro cac run moi cua collector version 2")
        if metadata_path is not None:
            raise ValueError("Dung --resume rieng, khong kem NVD metadata")
        metadata_path = saved["input_metadata"]
    source_path = local_path(metadata_path)
    source = json.loads(source_path.read_text(encoding="utf-8"))
    if source.get("complete_for_requested_window") is not True or source.get("status", "complete") != "complete":
        raise ValueError("NVD source chua hoan tat")
    table_path = local_path(source["table_file"])
    if digest(table_path) != source["table_sha256"]:
        raise ValueError("Checksum NVD khong khop; dung de kiem tra dau vao")
    nvd = pd.read_parquet(table_path, columns=["cve_id"])
    if len(nvd) != source["downloaded_records"]:
        raise ValueError("So dong NVD khong khop metadata")
    cve_ids = nvd["cve_id"].tolist()
    batches = make_batches(cve_ids)
    input_info = {"input_metadata_sha256": digest(source_path), "input_table_sha256": source["table_sha256"],
                  "input_dataset_version": source["dataset_version"], "requested_records": len(cve_ids),
                  "requested_date": snapshot}
    if saved is not None:
        if any(saved.get(key) != value for key, value in input_info.items()) or saved.get("endpoint") != EPSS_URL:
            raise ValueError("Config ngay EPSS hoac NVD input da thay doi; khong resume run nay")
        folder, manifest = manifest_path.parent, saved
        version = manifest["dataset_version"]
    else:
        now = datetime.now(timezone.utc)
        run_id = now.strftime("%Y%m%dT%H%M%S_%fZ")
        version = f"{source['dataset_version']}-epss-{snapshot}-{run_id}"
        folder = ROOT / "data/raw/epss" / f"{snapshot}_{run_id}"
        folder.mkdir(parents=True, exist_ok=False)
        manifest_path = folder / "metadata.json"
        manifest = {
            "collector_version": 2,
            "status": "in_progress", "dataset_version": version,
            "schema_stage": "EPSS-only enrichment; not joined master",
            "endpoint": EPSS_URL, "requested_date": snapshot, "started_at": now.isoformat(),
            "input_metadata": source_path.relative_to(ROOT).as_posix(),
            "input_metadata_sha256": digest(source_path), "input_table_sha256": source["table_sha256"],
            "input_dataset_version": source["dataset_version"], "requested_records": len(cve_ids),
            "raw_responses": [], "epss_model_version": None,
            "limitations": [
                "Current snapshot comparison, not retrospective exploit prediction.",
                "Missing score is null, not zero; not_returned does not explain the absence.",
                "All input CVEs retained, including Rejected; Web/mobile scope is pending.",
                "REST API version is not the EPSS model version.",
            ],
        }

    def write_manifest():
        temporary = manifest_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        temporary.replace(manifest_path)

    probe_params = {"cve": PROBE_CVE, "date": snapshot, "limit": 100, "offset": 0}
    planned = {"probe.json": (probe_params, [PROBE_CVE])}
    for index, batch in enumerate(batches, 1):
        planned[f"batch_{index:03d}.json"] = ({"cve": ",".join(batch), "date": snapshot, "limit": 100, "offset": 0}, batch)
    cached = {}

    def fetch_saved(name, params, ids):
        if name in cached:
            return cached[name]
        time.sleep(1)
        raw = request_bytes(params)
        retrieved = datetime.now(timezone.utc)
        path = folder / f"{Path(name).stem}_{retrieved.strftime('%Y%m%dT%H%M%S_%fZ')}.json"
        with path.open("xb") as handle:
            handle.write(raw)
        result = validate_response(json.loads(raw), ids, snapshot)
        if name == "probe.json" and PROBE_CVE not in result:
            raise ValueError("Chua xac nhan duoc ngay snapshot bang CVE tham chieu")
        # Invalid raw is retained but never checkpointed as a successful batch.
        manifest["raw_responses"].append({
            "file": path.relative_to(ROOT).as_posix(), "sha256": digest(path),
            "params": params, "retrieved_at": retrieved.isoformat(), "cache_key": name,
        })
        write_manifest()
        return result

    print(f"Metadata/checkpoint EPSS: {manifest_path.relative_to(ROOT).as_posix()}", flush=True)
    print(f"Ngay EPSS: {snapshot}; tong CVE: {len(cve_ids)}; so lo: {len(batches)}", flush=True)
    lock = folder / "run.lock"
    try:
        lock_handle = lock.open("x", encoding="utf-8")
    except FileExistsError:
        raise ValueError("Run EPSS dang bi khoa; khong chay cung metadata o hai terminal") from None
    try:
        lock_handle.write(str(os.getpid()))
        lock_handle.close()
        for entry in manifest["raw_responses"]:
            name = entry["cache_key"]
            if name not in planned or name in cached or entry["params"] != planned[name][0]:
                raise ValueError("Cache EPSS co lo trung/sai tham so")
            raw_path = local_path(entry["file"])
            if raw_path.parent != folder or digest(raw_path) != entry["sha256"]:
                raise ValueError("Checksum/duong dan raw EPSS khong khop; dung resume")
            cached[name] = validate_response(json.loads(raw_path.read_bytes()), planned[name][1], snapshot)
            if name == "probe.json" and PROBE_CVE not in cached[name]:
                raise ValueError("Cache probe khong xac nhan duoc snapshot")
        if manifest["status"] == "complete":
            if set(cached) != set(planned) or digest(local_path(manifest["table_file"])) != manifest["table_sha256"]:
                raise ValueError("Run complete nhung cache/table khong khop")
            print(f"Run da complete; khong tai lai. Bang: {manifest['table_file']}")
            return manifest
        manifest["status"] = "in_progress"
        manifest.pop("error", None)
        manifest.pop("error_type", None)
        write_manifest()
        print(f"Cache hop le: {sum(name.startswith('batch_') for name in cached)}/{len(batches)} lo", flush=True)
        # An unavailable date must not turn every target into a missing score.
        probe = fetch_saved("probe.json", probe_params, [PROBE_CVE])
        if PROBE_CVE not in probe:
            raise ValueError("Chua xac nhan duoc ngay snapshot bang CVE tham chieu")
        found = {}
        for index, batch in enumerate(batches, 1):
            params = {"cve": ",".join(batch), "date": snapshot, "limit": 100, "offset": 0}
            name = f"batch_{index:03d}.json"
            from_cache = name in cached
            found.update(fetch_saved(name, params, batch))
            print(f"Lo {index}/{len(batches)}: da kiem tra {len(batch)} CVE ({'cache' if from_cache else 'API'})", flush=True)
        if PROBE_CVE in cve_ids and PROBE_CVE not in found:
            raise ValueError("CVE tham chieu co diem o probe nhung mat trong batch")
        completed = datetime.now(timezone.utc).isoformat()
        frame = make_table(cve_ids, found, version, completed)
        output = folder / "epss.parquet"
        temporary_table = folder / "epss.parquet.tmp"
        frame.to_parquet(temporary_table, index=False)
        temporary_table.replace(output)
        manifest.update({
            "status": "complete", "completed_at": completed,
            "returned_dates": sorted({row["epss_date"] for row in found.values()}),
            "available_records": len(found), "missing_records": len(cve_ids) - len(found),
            "table_file": output.relative_to(ROOT).as_posix(), "table_sha256": digest(output),
        })
        write_manifest()
    except (Exception, KeyboardInterrupt) as exc:
        manifest.update({"status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", "error_type": type(exc).__name__, "error": str(exc)})
        write_manifest()
        print(f"Da giu cache; tiep tuc bang --resume {manifest_path.relative_to(ROOT).as_posix()}", flush=True)
        raise
    finally:
        lock_handle.close()
        lock.unlink()
    print(f"Ngay EPSS: {snapshot}\nTong CVE: {len(frame)}\nCo EPSS: {len(found)}\nThieu EPSS: {len(frame) - len(found)}")
    print(f"Bang: {manifest['table_file']}\nMetadata: {(folder / 'metadata.json').relative_to(ROOT).as_posix()}")
    print("Chua ghep KEV, chua loc Web/mobile, chua train model.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true", help="Xem ngay API tra ve; khong sua config")
    mode.add_argument("--nvd-metadata", help="Metadata cua NVD dataset da luu")
    mode.add_argument("--resume", help="Metadata cua run EPSS version 2 can tiep tuc")
    args = parser.parse_args()
    try:
        if args.probe:
            params = {"cve": PROBE_CVE, "limit": 100, "offset": 0}
            found = validate_response(json.loads(request_bytes(params)), [PROBE_CVE])
            if PROBE_CVE not in found:
                raise ValueError("CVE tham chieu khong co EPSS")
            row = found[PROBE_CVE]
            print(f"CVE tham chieu: {PROBE_CVE}\nNgay EPSS API tra ve: {row['epss_date']}")
            print("Neu dung ngay nay, dien config/project.yaml:")
            print(f"epss:\n  snapshot_date: \"{row['epss_date']}\"")
            print("Probe khong sua config va khong them CVE tham chieu vao pilot.")
        elif args.resume:
            collect(resume=args.resume)
        else:
            collect(args.nvd_metadata)
    except KeyboardInterrupt:
        parser.exit(130, "Da dung; cac lo EPSS da checkpoint van con.\n")
    except (ValueError, KeyError, TypeError, OSError, requests.RequestException) as exc:
        parser.exit(1, f"Dung thu thap: {exc}\n")


if __name__ == "__main__":
    main()
