"""Offline NVD + EPSS + KEV pilot join; scope and training split stay pending.

Only --pilot is currently supported. Explicit source manifests are required;
the builder never guesses the latest directory or overwrites team handoffs.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

from src.collect.epss_client import validate_response
from src.collect.kev_client import validate_catalog
from src.collect.prepare_handoff import SAMPLE_COLUMNS, make_sample

ROOT = Path(__file__).resolve().parents[2]
EPSS_COLUMNS = ["epss", "epss_percentile", "epss_date"]
KEV_COLUMNS = ["is_kev", "kev_date_added", "kev_known_ransomware"]


def local_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("Duong dan phai nam trong repo")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_file(value, checksum):
    path = local_path(value)
    if digest(path) != checksum:
        raise ValueError(f"Checksum khong khop: {value}")
    return path


def check_ids(frame, name):
    if ("cve_id" not in frame or frame.empty or frame.cve_id.isna().any()
            or frame.cve_id.duplicated().any()
            or not frame.cve_id.astype("string").str.fullmatch(r"CVE-\d{4}-\d{4,}").all()):
        raise ValueError(f"{name}: ID rong, sai hoac trung")


def read_source(value, kind):
    path = local_path(value)
    meta = json.loads(path.read_text(encoding="utf-8"))
    if kind == "nvd":
        if meta.get("complete_for_requested_window") is not True:
            raise ValueError("NVD pilot chua lay du khoang ngay da yeu cau")
    elif meta.get("status") != "complete":
        raise ValueError(f"{kind}: lan tai chua complete")
    table = pd.read_parquet(checked_file(meta["table_file"], meta["table_sha256"]))
    check_ids(table, kind)
    expected_count = meta["requested_records"] if kind == "epss" else meta["downloaded_records"]
    if len(table) != expected_count:
        raise ValueError(f"{kind}: so dong khong khop metadata")
    if "dataset_version" not in table or table.dataset_version.isna().any() or not table.dataset_version.eq(meta["dataset_version"]).all():
        raise ValueError(f"{kind}: dataset_version khong khop")
    source = {"metadata_file": path.relative_to(ROOT).as_posix(), "metadata_sha256": digest(path),
              "dataset_version": meta["dataset_version"], "table_sha256": meta["table_sha256"],
              "retrieved_at": meta.get("retrieved_at", meta.get("completed_at"))}
    return meta, table, source


def check_epss_raw(meta, table, nvd_ids):
    if set(table.cve_id) != nvd_ids:
        raise ValueError("EPSS khong co dung tap ID cua NVD pilot")
    requested, found = set(), {}
    for item in meta["raw_responses"]:
        raw_path = checked_file(item["file"], item["sha256"])
        params = item["params"]
        if params.get("date") != meta["requested_date"]:
            raise ValueError("EPSS raw co ngay yeu cau khong dong nhat")
        ids = params["cve"].split(",")
        rows = validate_response(json.loads(raw_path.read_bytes()), ids, meta["requested_date"])
        if raw_path.name.startswith("batch_"):
            if len(set(ids)) != len(ids) or requested.intersection(ids):
                raise ValueError("Trung ID giua cac lo EPSS")
            requested.update(ids)
            found.update(rows)
    if requested != nvd_ids:
        raise ValueError("Cac lo EPSS chua truy van du dung tap NVD")
    if (len(found) != meta["available_records"] or len(table) - len(found) != meta["missing_records"]
            or sorted({row["epss_date"] for row in found.values()}) != meta["returned_dates"]):
        raise ValueError("Thong ke EPSS khong khop raw")
    for row in table.to_dict("records"):
        match = found.get(row["cve_id"])
        if match:
            if row["epss_status"] != "available" or any(pd.isna(row[c]) or row[c] != match[c] for c in EPSS_COLUMNS):
                raise ValueError("Diem EPSS trong bang khong khop raw")
        elif row["epss_status"] != "not_returned" or any(pd.notna(row[c]) for c in EPSS_COLUMNS):
            raise ValueError("EPSS thieu phai giu null, khong thay bang 0")


def check_kev_raw(meta, table):
    if meta.get("complete_for_declared_catalog") is not True:
        raise ValueError("KEV chua duoc xac nhan du catalog")
    raw_path = checked_file(meta["raw_file"], meta["raw_sha256"])
    payload = json.loads(raw_path.read_bytes())
    rows, released = validate_catalog(payload)
    if (len(table) != payload["count"] or len(table) != meta["declared_count"]
            or len(table) != meta["unique_cve_count"]
            or payload["catalogVersion"] != meta["catalog_version"]
            or payload["dateReleased"] != meta["catalog_date_released"]):
        raise ValueError("KEV metadata/bang khong khop catalog goc")
    actual = table[["cve_id", *KEV_COLUMNS]].sort_values("cve_id").reset_index(drop=True)
    expected = pd.DataFrame(rows)[["cve_id", *KEV_COLUMNS]].sort_values("cve_id").reset_index(drop=True)
    for column in actual:
        dtype = "boolean" if column == "is_kev" else "string"
        if not actual[column].astype(dtype).equals(expected[column].astype(dtype)):
            raise ValueError(f"KEV: cot {column} khong khop raw")
    return released


def join_pilot(nvd, epss, kev, version, built_at, *, kev_complete):
    if kev_complete is not True:
        raise ValueError("Khong duoc gan is_kev=False khi catalog chua hoan chinh")
    for name, frame in (("nvd", nvd), ("epss", epss), ("kev", kev)):
        check_ids(frame, name)
    if set(nvd.cve_id) != set(epss.cve_id):
        raise ValueError("EPSS va NVD khac tap ID")
    if str(kev.is_kev.dtype) not in ("boolean", "bool") or not kev.is_kev.fillna(False).all():
        raise ValueError("Bang catalog KEV chi duoc chua membership true")
    # The handoff template checks labels against the vector, keeps missing CVSS,
    # and deliberately leaves scope/split unresolved. No annotations are edited.
    master = make_sample(nvd, version, built_at).drop(columns=[*EPSS_COLUMNS, *KEV_COLUMNS])
    master = master.merge(epss[["cve_id", *EPSS_COLUMNS, "epss_status"]], how="left", on="cve_id", validate="one_to_one")
    master = master.merge(kev[["cve_id", *KEV_COLUMNS]], how="left", on="cve_id", validate="one_to_one")
    master["is_kev"] = master.is_kev.astype("boolean").fillna(False)
    master["has_cvss31_label"] = master.has_cvss31_label.astype("boolean")
    master["in_scope"] = master.in_scope.astype("boolean")
    for column in ("cvss_base_score", "epss", "epss_percentile"):
        master[column] = master[column].astype("Float64")
    for column in ("published", "last_modified", "retrieved_at"):
        master[column] = pd.to_datetime(master[column], format="ISO8601", utc=True, errors="raise")
    for column in ("domain_tags", "scope_evidence"):
        master[column] = master[column].map(json.loads)
    master = master[[*SAMPLE_COLUMNS, "epss_status"]].sort_values("cve_id").reset_index(drop=True)
    if len(master) != len(nvd):
        raise ValueError("Join lam thay doi so dong NVD")
    return master


def summarize(master):
    non_rejected = master.vuln_status.notna() & master.vuln_status.ne("Rejected")
    description_ok = master.description.fillna("").str.strip().ne("")
    candidates = non_rejected & description_ok & master.has_cvss31_label
    return {
        "total_records": len(master), "unique_cve_count": master.cve_id.nunique(),
        "rejected_records": int(master.vuln_status.eq("Rejected").sum()),
        "available_epss": int(master.epss.notna().sum()), "missing_epss": int(master.epss.isna().sum()),
        "in_kev": int(master.is_kev.sum()), "not_in_kev": int((~master.is_kev).sum()),
        "unknown_kev": int(master.is_kev.isna().sum()),
        "description_and_label_candidates_before_scope": int(candidates.sum()),
        "candidates_with_epss_before_scope": int((candidates & master.epss.notna()).sum()),
        "scope_needs_review": int(master.scope_status.eq("needs_review").sum()),
        "confirmed_in_scope": int(master.in_scope.sum()), "assigned_split": int(master.split.notna().sum()),
    }


def build(nvd_path, epss_path, kev_path, check_only=False):
    config_path = ROOT / "config/project.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    nm, nvd, ns = read_source(nvd_path, "nvd")
    em, epss, es = read_source(epss_path, "epss")
    km, kev, ks = read_source(kev_path, "kev")
    if (em["input_metadata_sha256"] != ns["metadata_sha256"]
            or em["input_table_sha256"] != nm["table_sha256"]
            or em["input_dataset_version"] != nm["dataset_version"]):
        raise ValueError("EPSS duoc thu thap tu mot NVD snapshot khac")
    if str(config["epss"]["snapshot_date"]) != em["requested_date"] or km["epss_reference_date"] != em["requested_date"]:
        raise ValueError("Ngay EPSS trong config/metadata cac nguon khong khop")
    nvd_raw = json.loads(checked_file(nm["raw_file"], nm["raw_sha256"]).read_bytes())
    raw_ids = [item["cve"]["id"] for item in nvd_raw["vulnerabilities"]]
    if (set(raw_ids) != set(nvd.cve_id) or len(raw_ids) != len(nvd)
            or nvd_raw["totalResults"] != len(nvd) or nvd_raw["startIndex"] != 0):
        raise ValueError("Pilot NVD raw khong day du/khong khop bang")
    check_epss_raw(em, epss, set(nvd.cve_id))
    released = check_kev_raw(km, kev)
    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%S_%fZ")
    version = f"{nm['dataset_version']}-joined-{run_id}"
    master = join_pilot(nvd, epss, kev, version, now.isoformat(), kev_complete=True)
    stats = summarize(master)
    print(json.dumps(stats, indent=2))
    if check_only:
        print("CHECK OK: doc va ghep offline thanh cong; chua ghi dataset moi.")
        return stats
    folder = ROOT / "data/processed" / f"joined_pilot_{run_id}"
    folder.mkdir(parents=True, exist_ok=False)
    epss_day = datetime.fromisoformat(em["requested_date"]).date()
    manifest = {
        "status": "in_progress", "dataset_version": version, "schema_version": config["project"]["schema_version"],
        "schema_stage": "Joined pilot; scope and split pending; not dataset v1",
        "built_at": now.isoformat(), "config_sha256": digest(config_path),
        "sources": {"nvd": ns, "epss": es, "kev": ks},
        "nvd_published_params": nm["params"], "epss_date": em["requested_date"],
        "kev_catalog_version": km["catalog_version"], "kev_date_released": km["catalog_date_released"],
        "kev_retrieved_at": km["retrieved_at"],
        "kev_release_date_minus_epss_days": (released.date() - epss_day).days,
        "kev_retrieval_date_minus_epss_days": (datetime.fromisoformat(km["retrieved_at"]).astimezone(timezone.utc).date() - epss_day).days,
        "scope_reviewed": False, "training_ready": False, "ranking_ready": False,
        "cvss_scores_recalculated": False, "statistics": stats,
        "limitations": [
            "Only the first NVD pilot window, not the full configured collection interval.",
            "All CVEs retained, including Rejected; research cohorts must exclude Rejected.",
            "All scope decisions are pending; in_scope=false means not admitted yet, not reviewed out of scope.",
            "No train/validation/test split has been assigned; class audit is pending.",
            "CVSS vectors and labels checked; base scores copied from NVD, not recalculated.",
            "EPSS and current KEV catalog differ in time; this is not a historical forecast evaluation.",
            "KEV absence is not evidence that exploitation never happened.",
        ],
    }
    def write_manifest():
        (folder / "metadata.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    write_manifest()
    try:
        table_path = folder / "cves.parquet"
        master.to_parquet(table_path, index=False)
        csv = master.copy()
        for column in ("domain_tags", "scope_evidence"):
            csv[column] = csv[column].map(lambda values: json.dumps(values, ensure_ascii=False))
        csv_path = folder / "cves.csv"
        csv.to_csv(csv_path, index=False, encoding="utf-8")
        report_path = folder / "data_quality.md"
        report = ["# Joined pilot — data quality", "", "Status: scope and split pending; not dataset v1.", "",
                  "| Check | Result |", "|---|---:|"]
        report += [f"| {key} | {value} |" for key, value in stats.items()]
        report += ["", f"EPSS date: {em['requested_date']}; KEV released: {km['catalog_date_released']}.", "",
                   "## Limitations", "", *[f"- {item}" for item in manifest["limitations"]]]
        report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
        manifest.update({"status": "complete", "table_file": table_path.relative_to(ROOT).as_posix(),
                         "table_sha256": digest(table_path), "csv_file": csv_path.relative_to(ROOT).as_posix(),
                         "csv_sha256": digest(csv_path), "quality_report": report_path.relative_to(ROOT).as_posix(),
                         "quality_report_sha256": digest(report_path)})
        write_manifest()
    except Exception as exc:
        manifest.update({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)})
        write_manifest()
        raise
    print(f"Dataset: {manifest['table_file']}\nCSV: {manifest['csv_file']}")
    print(f"Metadata: {(folder / 'metadata.json').relative_to(ROOT).as_posix()}\nReport: {manifest['quality_report']}")
    print("PILOT ONLY: chua scope, chua split, chua train hay xep hang chinh thuc.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot", action="store_true", required=True, help="Xac nhan day chi la pilot")
    for name in ("nvd", "epss", "kev"):
        parser.add_argument(f"--{name}-metadata", required=True)
    parser.add_argument("--check-only", action="store_true", help="Kiem tra offline, khong ghi output")
    args = parser.parse_args()
    try:
        build(args.nvd_metadata, args.epss_metadata, args.kev_metadata, args.check_only)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(1, f"Dung build: {exc}\n")


if __name__ == "__main__":
    main()
