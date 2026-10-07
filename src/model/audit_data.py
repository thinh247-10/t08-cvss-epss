"""Offline NLP data audit. No training, source edits, or official split assignment."""
import argparse
import hashlib
import itertools
import json
import platform
import sys
from pathlib import Path

import pandas as pd
import pyarrow
import pyarrow.parquet as pq
import yaml

from src.collect.nvd_collector import parse_base_vector
from src.collect.prepare_handoff import SAMPLE_COLUMNS, SAMPLE_DTYPES
from src.model.data_validation import KNOWN_STATUSES, LABEL_ORDER, checked_boolean

SPLITS = ("train", "validation", "test")
NORMALIZATION = "Unicode NFKC -> collapse whitespace -> strip -> casefold"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def proposed_splits(published, split_config):
    """Assign UTC [start, end_exclusive) intervals only in a new Series."""
    dates = pd.to_datetime(published, format="ISO8601", utc=True, errors="coerce")
    intervals = []
    for name in SPLITS:
        bounds = split_config[name]
        start = pd.Timestamp(bounds["start"])
        end = pd.Timestamp(bounds["end_exclusive"])
        start = start.tz_localize("UTC") if start.tz is None else start.tz_convert("UTC")
        end = end.tz_localize("UTC") if end.tz is None else end.tz_convert("UTC")
        if start >= end:
            raise ValueError(f"Invalid split interval: {name}")
        intervals.append((name, start, end))
    for a, b in itertools.combinations(intervals, 2):
        if max(a[1], b[1]) < min(a[2], b[2]):
            raise ValueError(f"Overlapping split intervals: {a[0]}, {b[0]}")
    result = pd.Series(pd.NA, index=published.index, dtype="string")
    for name, start, end in intervals:
        result.loc[dates.ge(start) & dates.lt(end)] = name
    return dates, result


def _schema(frame):
    rows = []
    numbers = {"cvss_base_score", "epss", "epss_percentile"}
    booleans = {"has_cvss31_label", "in_scope", "is_kev"}
    timestamps = {"published", "last_modified", "retrieved_at"}
    dates = {"epss_date", "kev_date_added"}
    for column in frame:
        series = frame[column]
        actual = str(series.dtype)
        note = ""
        if column in numbers:
            expected = "nullable float"
            ok = pd.api.types.is_float_dtype(series)
        elif column in booleans:
            expected = "boolean (nullable is_kev)"
            ok = pd.api.types.is_bool_dtype(series)
        elif column in timestamps:
            expected = "UTC timestamp"
            ok = isinstance(series.dtype, pd.DatetimeTZDtype) and str(series.dt.tz) == "UTC"
        elif column in ("domain_tags", "scope_evidence"):
            expected, ok = "list[string]", False
            note = "Pandas object values checked separately; typed string elements require Arrow schema verification."
        elif column in LABEL_ORDER:
            expected = "categorical nullable"
            ok = isinstance(series.dtype, pd.CategoricalDtype)
            if not ok:
                note = "Stored as text; class membership is checked separately. No source cast."
        elif column in dates:
            expected = "date nullable"
            ok = isinstance(series.dtype, pd.ArrowDtype) and pyarrow.types.is_date(series.dtype.pyarrow_dtype)
            note = "Calendar values checked separately; ISO text serialization is recorded without a source cast."
        else:
            expected = "string / enum"
            ok = pd.api.types.is_string_dtype(series)
        rows.append({"column": column, "actual_dtype": actual,
                     "contract_type": expected, "physical_match": bool(ok), "note": note})
    return rows


def audit_frame(frame, *, dataset_version, split_config, rare_support=20):
    """Read a frame without mutating it; separate semantic from strict candidates."""
    missing = set(SAMPLE_COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    if not frame.columns.is_unique:
        raise ValueError("Duplicate column names")
    if rare_support < 1:
        raise ValueError("rare_support must be positive")
    data = frame.copy(deep=True).reset_index(drop=True)
    findings = []

    def add(mask, column, code, detail, severity="error"):
        mask = pd.Series(mask, index=data.index, dtype="boolean").fillna(False)
        for idx in data.index[mask]:
            value = data.at[idx, "cve_id"]
            findings.append({"cve_id": "<missing>" if pd.isna(value) else str(value),
                             "row": int(idx), "column": column, "code": code,
                             "severity": severity, "detail": detail})

    published, proposed = proposed_splits(data.published, split_config)
    id_text = data.cve_id.astype("string")
    id_ok = id_text.str.fullmatch(r"CVE-\d{4}-\d{4,}").fillna(False)
    add(~id_ok, "cve_id", "invalid_id", "ID missing or not a CVE identifier")
    version_ok = data.dataset_version.astype("string").eq(dataset_version).fillna(False)
    add(~version_ok, "dataset_version", "dataset_version_mismatch", "Does not match metadata")
    status = data.vuln_status.astype("string")
    rejected = status.eq("Rejected").fillna(False)
    unknown_status = ~status.isin(KNOWN_STATUSES)
    description_text = data.description.map(lambda value: isinstance(value, str))
    description_missing = data.description.where(description_text).astype("string").str.strip().fillna("").eq("")
    add(data.description.notna() & ~description_text, "description",
        "description_type_invalid", "Expected text; numeric descriptions are not NLP input")
    add(rejected, "vuln_status", "rejected", "Retained in master; excluded from ML", "expected_exclusion")
    add(unknown_status, "vuln_status", "unknown_status", "Missing or unsupported status")
    add(description_missing, "description", "description_missing", "Missing or whitespace-only", "expected_exclusion")
    label_ok = pd.Series(True, index=data.index)
    missing_labels = data[list(LABEL_ORDER)].isna().any(axis=1)
    for metric, values in LABEL_ORDER.items():
        present = data[metric].notna()
        allowed = data[metric].isin(values)
        label_ok &= allowed
        add(present & ~allowed, metric, "invalid_label", "Not an allowed Base metric label")
    add(~rejected & missing_labels, "|".join(LABEL_ORDER),
        "missing_labels", "At least one Base label absent; no relabelling", "expected_exclusion")

    parsed = data.cvss_vector.map(parse_base_vector)
    vector_ok = parsed.map(lambda value: value is not None)
    add(data.cvss_vector.notna() & ~vector_ok, "cvss_vector",
        "invalid_vector", "Not a complete Base CVSS 3.1 vector")
    matching = pd.Series(True, index=data.index)
    for metric in LABEL_ORDER:
        expected = parsed.map(lambda values: None if values is None else values[metric])
        mismatch = vector_ok & ~data[metric].eq(expected).fillna(False)
        matching &= ~mismatch
        add(mismatch, metric, "label_vector_mismatch", "Stored label differs from vector")
    cvss_version_ok = data.cvss_version.astype("string").eq("3.1").fillna(False)
    add(vector_ok & ~cvss_version_ok, "cvss_version", "cvss_version_mismatch", "Vector is 3.1 but version column is not")
    verified = vector_ok & matching & cvss_version_ok & label_ok
    booleans = {}
    for column in ("has_cvss31_label", "in_scope", "is_kev"):
        booleans[column], invalid = checked_boolean(data[column])
        add(invalid, column, "boolean_type_invalid", "Expected boolean/null; string or numeric values are invalid")
        if column != "is_kev":
            add(data[column].isna(), column, "boolean_missing", "Non-null boolean required by contract")
    flag = booleans["has_cvss31_label"]
    add(flag.isna() | flag.ne(verified).fillna(True), "has_cvss31_label",
        "has_label_mismatch", "Flag differs from verified vector/labels")

    candidate = ~rejected & ~unknown_status & ~description_missing & label_ok
    strict = candidate & verified
    numeric = pd.to_numeric(data.cvss_base_score, errors="coerce")
    add(vector_ok & (numeric.isna() | ~numeric.between(0, 10)),
        "cvss_base_score", "base_score_invalid", "Missing/non-numeric/outside [0,10]; score not recalculated")
    add(vector_ok & data.cvss_source.isna(), "cvss_source", "label_source_missing", "Vector has no recorded source")
    add(vector_ok & data.cvss_type.isna(), "cvss_type", "label_type_missing", "Vector has no recorded type")
    for column in ("epss", "epss_percentile"):
        value = pd.to_numeric(data[column], errors="coerce")
        add(data[column].notna() & (value.isna() | ~value.between(0, 1)),
            column, "probability_invalid", "Non-numeric/outside [0,1]")
    for column in ("epss_date", "kev_date_added"):
        value = data[column].astype("string")
        valid = value.str.fullmatch(r"\d{4}-\d{2}-\d{2}").fillna(False)
        parsed_date = pd.to_datetime(value, format="%Y-%m-%d", utc=True, errors="coerce")
        add(value.notna() & (~valid | parsed_date.isna()), column,
            "date_invalid", "Not a valid ISO calendar date")
    for column in ("domain_tags", "scope_evidence"):
        def list_ok(value):
            if hasattr(value, "tolist"):
                value = value.tolist()
            return isinstance(value, list) and all(isinstance(item, str) for item in value)
        ok = data[column].map(list_ok)
        add(~ok, column, "list_invalid", "Expected a list of strings")
    scope_status = data.scope_status.astype("string")
    add(~scope_status.isin(("included", "excluded", "needs_review")),
        "scope_status", "scope_status_invalid", "Unknown scope enum")
    assigned = data.split.notna()
    add(assigned, "split", "source_split_assigned", "Source split is assigned; audit never changes it")
    add(data.published.isna(), "published", "published_missing", "No date for temporal split")
    add(data.published.notna() & published.isna(), "published", "published_invalid", "Cannot parse timestamp")
    add(published.notna() & proposed.isna(), "published", "published_outside_split", "Outside configured intervals", "warning")

    modified = pd.to_datetime(data.last_modified, format="ISO8601", utc=True, errors="coerce")
    retrieved = pd.to_datetime(data.retrieved_at, format="ISO8601", utc=True, errors="coerce")
    for column, dates in (("last_modified", modified), ("retrieved_at", retrieved)):
        add(dates.isna(), column, "timestamp_invalid", "Missing/unparseable UTC timestamp")
    add(modified.lt(published), "last_modified", "modified_before_published", "Earlier than published")
    duplicate_ids = []
    for cve_id, group in data.loc[id_text.duplicated(keep=False) & id_text.notna()].groupby("cve_id", sort=True):
        indices = group.index
        duplicate_ids.append({"cve_id": str(cve_id), "rows": len(group),
                              "splits": sorted(proposed.loc[indices].dropna().unique().tolist())})
    add(id_text.duplicated(keep=False) & id_text.notna(), "cve_id", "duplicate_id", "ID appears more than once")

    cohorts = {"all": candidate, **{name: candidate & proposed.eq(name).fillna(False) for name in SPLITS}}
    label_counts = []
    single_class_targets = []
    for cohort, mask in cohorts.items():
        for metric, values in LABEL_ORDER.items():
            supports = []
            for label in values:
                support = int((mask & data[metric].eq(label).fillna(False)).sum())
                size = int(mask.sum())
                row = {"cohort": cohort, "metric": metric, "label": label, "support": support,
                       "cohort_size": size, "share": support / size if size else 0.0}
                label_counts.append(row)
                if support:
                    supports.append(label)
            if len(supports) == 1:
                single_class_targets.append({"cohort": cohort, "metric": metric, "label": supports[0]})

    normalized = data.description.astype("string").str.normalize("NFKC").str.replace(
        r"\s+", " ", regex=True).str.strip().str.casefold()
    descriptions = pd.DataFrame({"normalized": normalized[candidate], "cve_id": id_text[candidate],
                                 "proposed_split": proposed[candidate], "vector": data.cvss_vector[candidate]})
    descriptions = descriptions.loc[descriptions.normalized.duplicated(keep=False)]
    groups = cross_groups = cross_rows = conflict_groups = cross_conflict_groups = 0
    duplicates_rows = 0
    cross_by_split = {name: 0 for name in SPLITS}
    pair_counts = {"|".join(pair): 0 for pair in itertools.combinations(SPLITS, 2)}
    examples = []
    for text, group in descriptions.groupby("normalized", sort=True):
        groups += 1
        duplicates_rows += len(group)
        splits = sorted(group.proposed_split.dropna().unique().tolist())
        label_variants = len(data.loc[group.index, list(LABEL_ORDER)].drop_duplicates())
        conflicting = label_variants > 1
        conflict_groups += int(conflicting)
        if len(splits) > 1:
            cross_groups += 1
            cross_rows += len(group)
            cross_conflict_groups += int(conflicting)
            signature = hashlib.sha256(text.encode("utf-8")).hexdigest()
            for name in SPLITS:
                cross_by_split[name] += int(group.proposed_split.eq(name).sum())
            for pair in itertools.combinations(SPLITS, 2):
                if all(name in splits for name in pair):
                    pair_counts["|".join(pair)] += 1
            representatives = []
            for name in SPLITS:
                for idx, row in group.loc[group.proposed_split.eq(name)].sort_values("cve_id").head(1).iterrows():
                    representatives.append({"cve_id": str(row.cve_id), "split": name,
                                            "vector": str(row.vector)})
            examples.append({"description_sha256": signature, "cve_ids": sorted(group.cve_id.tolist()),
                             "splits": splits, "row_count": len(group),
                             "distinct_vectors": label_variants, "representatives": representatives})
            add(data.index.isin(group.index), "description", "description_cross_split",
                f"Normalized exact match; sha256={signature}; splits={','.join(splits)}; target_variants={label_variants}", "risk")

    def counts(series):
        return {str(key): int(value) for key, value in series.astype("string").fillna("<missing>").value_counts().items()}

    def span(dates):
        return [None if pd.isna(value) else value.isoformat() for value in (dates.min(), dates.max())]

    source_counts = data.loc[candidate, ["cvss_source", "cvss_type"]].fillna("<missing>").value_counts()
    source_rows = [{"source": str(a), "type": str(b), "support": int(count)}
                   for (a, b), count in source_counts.items()]
    split_sources = []
    for name in SPLITS:
        for (source, kind), count in data.loc[cohorts[name], ["cvss_source", "cvss_type"]].fillna("<missing>").value_counts().items():
            split_sources.append({"split": name, "source": str(source), "type": str(kind), "support": int(count)})
    primary_reason = pd.Series("eligible", index=data.index)
    primary_reason.loc[~label_ok] = "missing_or_invalid_labels"
    primary_reason.loc[description_missing] = "missing_description"
    primary_reason.loc[unknown_status] = "unknown_status"
    primary_reason.loc[rejected] = "rejected"
    after_split_end = {}
    for name in SPLITS:
        end = pd.Timestamp(split_config[name]["end_exclusive"], tz="UTC")
        after_split_end[name] = int((cohorts[name] & modified.ge(end)).sum())
    examples.sort(key=lambda group: (-group["row_count"], group["description_sha256"]))
    return {
        "summary": {"total_records": len(data), "unique_cve_count": int(data.cve_id.nunique()),
                    "ml_candidates": int(candidate.sum()), "strict_valid_candidates": int(strict.sum()),
                    "missing_description": int(description_missing.sum()), "rejected_records": int(rejected.sum()),
                    "assigned_source_split": int(assigned.sum()),
                    "candidate_without_epss": int((candidate & data.epss.isna()).sum()),
                    "non_rejected_missing_labels": int((~rejected & missing_labels).sum()),
                    "valid_vectors": int(vector_ok.sum()), "label_vector_mismatches": int((vector_ok & ~matching).sum()),
                    "in_kev": int(booleans["is_kev"].fillna(False).sum()),
                    "epss_present": int(data.epss.notna().sum())},
        "missing_counts": {name: int(data[name].isna().sum()) for name in data},
        "status_counts": counts(status),
        "exclusion_counts": {"rejected": int(rejected.sum()), "missing_description": int(description_missing.sum()),
                             "missing_or_invalid_labels": int((~label_ok).sum()),
                             "vector_invalid_or_mismatch": int((candidate & ~verified).sum()),
                             "unknown_status": int(unknown_status.sum())},
        "exclusive_exclusion_counts": counts(primary_reason),
        "split_counts": {**{name: int(cohorts[name].sum()) for name in SPLITS},
                         "unassigned": int((candidate & proposed.isna()).sum())},
        "master_split_counts": {**{name: int(proposed.eq(name).sum()) for name in SPLITS},
                                "unassigned": int(proposed.isna().sum())},
        "source_split_counts": counts(data.split),
        "label_counts": label_counts,
        "absent_classes": [row for row in label_counts if row["support"] == 0],
        "rare_classes": [row for row in label_counts if 0 < row["support"] < rare_support],
        "rare_relative_classes": [row for row in label_counts if 0 < row["share"] < 0.01],
        "rare_support_threshold": rare_support,
        "single_class_targets": single_class_targets,
        "duplicate_ids": duplicate_ids,
        "description_duplicates": {"normalization": NORMALIZATION, "groups": groups,
            "rows": duplicates_rows, "excess_rows": duplicates_rows - groups,
            "cross_split_groups": cross_groups, "cross_split_rows": cross_rows,
            "cross_split_by_split": cross_by_split, "pair_group_counts": pair_counts,
            "conflicting_vector_groups": conflict_groups,
            "cross_split_conflicting_vector_groups": cross_conflict_groups, "examples": examples},
        "source_counts": source_rows, "split_source_counts": split_sources,
        "timestamps": {"published_range": span(published), "last_modified_range": span(modified),
                       "modified_after_published": int(modified.gt(published).sum()),
                       "candidate_modified_after_published": int((candidate & modified.gt(published)).sum()),
                       "candidate_modified_after_split_end": after_split_end,
                       "candidate_modified_year_counts": counts(modified[candidate].dt.year),
                       "id_year_differs_published": int((id_ok & published.notna() & id_text.str.slice(4, 8).ne(published.dt.year.astype("Int64").astype("string")).fillna(False)).sum())},
        "scope": {"status_counts": counts(scope_status), "in_scope_true": int(booleans["in_scope"].fillna(False).sum()),
                  "web_mobile_by_split": {name: "pending/N/A" for name in SPLITS}},
        "schema": {"columns": _schema(data), "extra_columns": sorted(set(data.columns) - set(SAMPLE_COLUMNS))},
        "findings": findings,
    }


def verify_inputs(table, metadata_path, config_path, manifest_path=None, archive=None):
    paths = [table, metadata_path, config_path]
    hashes = {str(p): digest(p) for p in paths}
    meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = meta["table_sha256"] if table.suffix.lower() == ".parquet" else meta["csv_sha256"]
    if hashes[str(table)] != expected:
        raise ValueError("Table checksum differs from metadata")
    if hashes[str(config_path)] != meta["config_sha256"]:
        raise ValueError("Project config differs from dataset build config")
    checked_entries = []
    manifest = None
    if manifest_path:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        paths.append(manifest_path)
        hashes[str(manifest_path)] = digest(manifest_path)
        if manifest["dataset_version"] != meta["dataset_version"]:
            raise ValueError("Manifest version differs from metadata")
        for entry in manifest["entries"]:
            relative = Path(entry["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Unsafe manifest entry path")
            target = table.parent / relative.name
            actual = digest(target)
            if actual != entry["sha256"] or target.stat().st_size != entry["bytes"]:
                raise ValueError(f"Handoff entry checksum/size differs: {entry['path']}")
            paths.append(target)
            hashes[str(target)] = actual
            checked_entries.append({"file": str(target), "sha256": actual, "bytes": target.stat().st_size})
        verified_files = {Path(entry["file"]).resolve() for entry in checked_entries}
        if not {table.resolve(), metadata_path.resolve()}.issubset(verified_files):
            raise ValueError("Manifest must independently cover the supplied table and metadata")
    if archive:
        if not manifest:
            raise ValueError("--archive requires --manifest")
        actual = digest(archive)
        if actual != manifest["archive_sha256"] or archive.stat().st_size != manifest["archive_bytes"]:
            raise ValueError("Archive checksum/size differs from manifest")
        paths.append(archive)
        hashes[str(archive)] = actual
    return meta, manifest, paths, {"hashes": hashes, "checked_entries": checked_entries,
                                 "metadata_independently_verified": bool(manifest)}


def _table(headers, rows):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")
    return "\n".join(["| " + " | ".join(headers) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"] +
                     ["| " + " | ".join(cell(value) for value in row) + " |" for row in rows])


def render_report(result, meta, config, provenance, *, command, counts_path, findings_path, schema):
    s, duplicate = result["summary"], result["description_duplicates"]
    headers = ["Metric", "Lớp", "Toàn bộ ML", "train", "validation", "test"]
    supports = {(row["cohort"], row["metric"], row["label"]): row["support"] for row in result["label_counts"]}
    rows = [[metric, label, *[supports[c, metric, label] for c in ("all", *SPLITS)]]
            for metric, labels in LABEL_ORDER.items() for label in labels]
    error_rows = [f for f in result["findings"] if f["severity"] == "error"]
    missing_examples = [f for f in result["findings"] if f["code"] == "missing_labels"][:12]
    sections = [
        "# N3 — Audit ML toàn khoảng (Phase 1, bước 3)",
        f"Ngày chạy thực tế (Asia/Saigon): {pd.Timestamp.now(tz='Asia/Saigon').isoformat()}.",
        f"Dataset version: `{meta['dataset_version']}`; schema version: `{meta['schema_version']}`.",
        f"Đọc {s['total_records']:,} dòng; {s['unique_cve_count']:,} ID duy nhất. "
        f"Ứng viên ML theo điều kiện nhãn: **{s['ml_candidates']:,}**; "
        f"đã đối chiếu vector/version: **{s['strict_valid_candidates']:,}**.",
        "Báo cáo này dùng bảng ghép toàn khoảng 2023–2024; mẫu cũ 35 dòng và "
        "451 ứng viên pilot được báo cáo riêng trong pilot_ml_audit.md.",
        "## 1. Provenance, checksum và môi trường",
        _table(["File thực sự đọc/kiểm", "SHA-256"], provenance["hashes"].items()),
        f"Metadata được xác minh qua manifest độc lập: {provenance['metadata_independently_verified']}. "
        f"Đã đối chiếu cả {len(provenance['checked_entries'])} entry của gói về hash và dung lượng. "
        "Hash nguồn raw trong metadata chưa kiểm lại vì raw không có trong gói.",
        _table(["Thành phần", "Phiên bản"], [
            ["Python", sys.version.split()[0]], ["pandas", pd.__version__],
            ["pyarrow", pyarrow.__version__], ["PyYAML", yaml.__version__],
            ["Platform", platform.platform()]]),
        f"Config SHA-256 khớp bản build. Scope_reviewed={meta.get('scope_reviewed')}; "
        f"training_ready={meta.get('training_ready')}; split chưa khóa. "
        "Input NLP chỉ description; tám metric là target. EPSS/KEV không làm feature.",
        "## 2. Schema và dtype",
        _table(["Cột", "Kiểu thực tế (pandas)", "Contract", "Khớp vật lý", "Ghi chú"],
               [[row[k] for k in ("column", "actual_dtype", "contract_type", "physical_match", "note")]
                for row in result["schema"]["columns"]]),
        f"Cột bổ sung ngoài contract mẫu: {', '.join(result['schema']['extra_columns']) or 'không có'}. "
        "epss_status là trường provenance của builder.",
        "Parquet lưu tám metric dưới dạng string thay cho categorical; epss_date/kev_date_added "
        "là ISO date string thay cho date vật lý. Timestamps UTC và nullable float/boolean đọc đúng. "
        "Các khác biệt dtype được giữ nguyên và báo cho N1; giá trị được kiểm trong bộ nhớ.",
        "Schema Arrow thực tế (list rỗng có thể là list<null>, chưa chứng minh list<string> cho file này):",
        "```text\n" + schema + "\n```",
        "## 3. Missing, nhãn, loại mẫu và đối chiếu metadata",
        _table(["Chỉ số", "Thực tế"], s.items()),
        _table(["Trạng thái NVD", "Số dòng"], result["status_counts"].items()),
        _table(["Cột", "Số missing"], result["missing_counts"].items()),
        "Điều kiện ML: status có giá trị được hỗ trợ, không Rejected; description có nội dung; đủ tám nhãn hợp lệ. "
        "Đếm thêm strict_valid_candidates sau kiểm vector Base 3.1/version/nhãn khớp. "
        "Missing EPSS không được dùng làm điều kiện loại.",
        _table(["Lý do loại chính (không đếm trùng)", "Số dòng"], result["exclusive_exclusion_counts"].items()),
        _table(["Lý do kiểm (có thể giao nhau)", "Số dòng"], result["exclusion_counts"].items()),
        _table(["Chỉ số đối chiếu", "Metadata", "Audit", "Khớp"],
               [[key, expected, actual, expected == actual] for key, expected, actual in result["metadata_comparison"]]),
        f"Phát hiện lỗi ngoài các missing/Rejected đã giữ: **{len(error_rows)}**. "
        "Mỗi phát hiện có CVE ID, cột, mã và mức độ trong file findings. "
        "Không sửa nhãn để khớp vector.",
        _table(["CVE ID ví dụ", "Cột", "Phát hiện"],
               [[f["cve_id"], f["column"], f["detail"]] for f in (error_rows[:12] or missing_examples)]),
        "Nếu bảng nhãn/version/hash không khớp, cần N1 sửa/build lại và N3 kiểm lại version mới; "
        "không dùng lỗi audit để âm thầm loại mẫu test.",
        "## 4. Split dự kiến và hỗ trợ lớp",
        _table(["Split", "Khoảng [start,end_exclusive) UTC", "Master", "ML", "Web/mobile"],
               [[name, f"[{config['split'][name]['start']}, {config['split'][name]['end_exclusive']})",
                 result["master_split_counts"][name], result["split_counts"][name], "pending/N/A"] for name in SPLITS]),
        f"Ứng viên không có proposed_split: {result['split_counts']['unassigned']}; "
        f"split nguồn đã gán: {s['assigned_source_split']}. proposed_split chỉ trong bộ nhớ.",
        _table(headers, rows),
        f"Ngưỡng cảnh báo hiếm dùng cho audit: 0 < support < {result['rare_support_threshold']} "
        "ở từng cohort; đây là quy ước thống kê, chưa là quyết định train.",
        _table(["Cohort", "Metric", "Lớp", "Support"],
               [[row[k] for k in ("cohort", "metric", "label", "support")]
                for row in result["absent_classes"] + result["rare_classes"]]),
        "Cảnh báo mất cân bằng bổ sung: lớp có tỷ lệ dưới 1% trong cohort; "
        "không đổi nhãn hay ranh giới split vì cảnh báo này.",
        _table(["Cohort", "Metric", "Lớp", "Support", "Tỷ lệ"],
               [[row["cohort"], row["metric"], row["label"], row["support"], f"{row['share']:.3%}"]
                for row in result["rare_relative_classes"]]),
        f"Target chỉ một lớp: {json.dumps(result['single_class_targets'], ensure_ascii=False)}.",
        "Giữ toàn bộ mapping lớp, cả support 0. Lớp vắng ở train phải ghi không có dữ liệu học; "
        "target train chỉ một lớp cần constant/Dummy fallback. Không gộp/xóa lớp khó. "
        "Nếu cần mở rộng năm, N1 ghi version/quyết định trước khi đánh giá test. "
        "Không đổi ranh giới hoặc chọn tham số bằng kết quả mô hình trên test.",
        "## 5. Nguồn nhãn và last_modified",
        _table(["Nguồn", "Type", "Support ML"],
               [[row["source"], row["type"], row["support"]] for row in result["source_counts"]]),
        _table(["Split", "Nguồn", "Type", "Support ML"],
               [[row[k] for k in ("split", "source", "type", "support")] for row in result["split_source_counts"]]),
        "Nguồn ngoài NVD không tự gọi là CNA; bảng chỉ thống kê địa chỉ nguồn đã chọn. "
        "Các metric nguồn thay thế và xung đột ưu tiên cần raw NVD để kiểm lại.",
        _table(["Chỉ số thời gian", "Thực tế"], [
            ["published min/max", result["timestamps"]["published_range"]],
            ["last_modified min/max", result["timestamps"]["last_modified_range"]],
            ["last_modified > published (master)", result["timestamps"]["modified_after_published"]],
            ["last_modified > published (ML)", result["timestamps"]["candidate_modified_after_published"]],
            ["ID mang năm khác published", result["timestamps"]["id_year_differs_published"]]]),
        _table(["Split", "ML có last_modified >= end_exclusive"],
               result["timestamps"]["candidate_modified_after_split_end"].items()),
        _table(["Năm last_modified của ứng viên ML", "Số dòng"],
               result["timestamps"]["candidate_modified_year_counts"].items()),
        "Chia theo published, không dùng năm CVE ID. Snapshot hiện tại đã chỉnh sửa sau công bố, "
        "nên chia thời gian không phục hồi dữ liệu lịch sử as-known-then. "
        "last_modified cho thấy thời điểm sửa record, chưa chứng minh trường description/metric cụ thể đã đổi.",
        "## 6. ID và mô tả trùng xuyên split",
        f"ID trùng: {len(result['duplicate_ids'])} nhóm; chi tiết: {json.dumps(result['duplicate_ids'][:10])}.",
        f"Quy tắc mô tả: **{duplicate['normalization']}**. Chỉ kiểm ứng viên ML; "
        "giữ nguyên punctuation, không bỏ phiên bản/số hoặc gộp sản phẩm.",
        _table(["Chỉ số duplicate ML", "Thực tế"], [
            ["Nhóm mô tả trùng", duplicate["groups"]], ["Dòng thuộc nhóm trùng", duplicate["rows"]],
            ["Dòng dư so với một dòng/nhóm", duplicate["excess_rows"]],
            ["Nhóm có mô tả trùng xuyên split", duplicate["cross_split_groups"]],
            ["Dòng thuộc nhóm xuyên split", duplicate["cross_split_rows"]],
            ["Nhóm trùng có nhiều vector nguồn", duplicate["conflicting_vector_groups"]],
            ["Nhóm xuyên split có nhiều vector nguồn", duplicate["cross_split_conflicting_vector_groups"]]]),
        _table(["Split", "Dòng thuộc nhóm trùng xuyên split"], duplicate["cross_split_by_split"].items()),
        _table(["Cặp split", "Số nhóm giao nhau (không cộng để ra tổng nhóm)"], duplicate["pair_group_counts"].items()),
        _table(["SHA-256 mô tả chuẩn hóa", "Số dòng", "Split", "CVE ID ví dụ", "Số vector khác nhau"],
               [[g["description_sha256"], g["row_count"], ",".join(g["splits"]),
                 "; ".join(f"{r['cve_id']} ({r['split']}): {r['vector']}" for r in g["representatives"]),
                 g["distinct_vectors"]] for g in duplicate["examples"][:12]]),
        "Các nhóm trên tạo nguy cơ leakage nội dung giữa split thời gian. Findings CSV liệt kê "
        "từng CVE trong tất cả nhóm xuyên split bằng hash mô tả, không chép mô tả vào reports. "
        "Đề nghị N1/N3 rà nhóm và chốt chính sách có version cho duplicate trước train; "
        "nếu tạo cohort đánh giá không trùng, công bố riêng số loại theo split và support lớp. "
        "Bản audit không xóa/dời dòng hoặc gán split chính thức.",
        "Mô tả trùng có vector khác nhau không đồng nghĩa nhãn lệch vector: "
        "có thể thiếu thông tin trong mô tả hoặc nguồn chấm khác nhau. "
        "Không thể tự sửa nhãn dựa trên một chuỗi mô tả chung; cần review source/raw.",
        "Gần trùng/nhóm sản phẩm: **chưa kiểm đầy đủ**. Phương pháp đề xuất: dùng token/shingle "
        "và MinHash để sàng lọc, rồi review các cặp cùng sản phẩm/phiên bản; "
        "chuẩn hóa CPE vendor/product để đối chiếu nhóm. Không fit TF-IDF trong audit này. "
        "Cần N1 cung cấp raw NVD/CPE/references đúng snapshot/checksum; generic template, "
        "tên sản phẩm thay đổi và các mô tả khác chữ là giới hạn của exact match.",
        "## 7. Scope, điểm Base và việc cần phối hợp",
        f"Scope thực tế: {json.dumps(result['scope'], ensure_ascii=False)}. "
        "in_scope=false cùng needs_review là chưa xác nhận, không phải tất cả ngoài phạm vi. "
        "Cập nhật Web/mobile theo split sau kết quả N2/N1.",
        "Base Score chỉ kiểm có mặt/range [0,10]; **chưa đối chiếu lại bằng scorer**. "
        "Không tự viết công thức điểm khác. Cần scorer dùng chung từ N2 trước khi khóa dataset.",
        f"EPSS ngày {meta.get('epss_date')}; KEV phát hành {meta.get('kev_date_released')}, "
        f"tải {meta.get('kev_retrieved_at')}. Không diễn giải là dự báo khai thác lịch sử tại published.",
        f"File thiết kế Phase 0 hiện có: {json.dumps(result['phase0_files_present'], ensure_ascii=False)}. "
        "Nếu thiếu, đề nghị N1 tích hợp PR Phase 0. "
        "Các kiến nghị mới ghi ở báo cáo này; chưa có xác nhận N1/N2 đã xử lý.",
        "## 8. Lệnh chạy và artifact",
        "```powershell\n" + command + "\n```",
        f"Bảng support nhỏ: `{counts_path}`. Toàn bộ phát hiện theo CVE/cột: `{findings_path}`. "
        "Hai CSV không chứa description. Không commit ZIP, Parquet, CSV nguồn hoặc model weights.",
        "Script chỉ đọc bảng/metadata/config/manifest và kiểm hash trước/sau. "
        "Không train, fit TF-IDF, gọi API, sửa bảng nguồn hay khóa split.",
    ]
    return "\n\n".join(sections) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=Path("config/project.yaml"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--report", type=Path, default=Path("reports/full_ml_audit.md"))
    parser.add_argument("--counts", type=Path, default=Path("reports/full_ml_label_counts.csv"))
    parser.add_argument("--findings", type=Path, default=Path("reports/full_ml_findings.csv"))
    parser.add_argument("--rare-support", type=int, default=20)
    args = parser.parse_args(argv)
    if args.table.suffix.lower() not in (".parquet", ".csv"):
        parser.error("--table must be Parquet or CSV")
    outputs = [args.report, args.counts, args.findings]
    inputs = [args.table, args.metadata, args.config, args.manifest, args.archive]
    protected = {p.resolve() for p in inputs if p is not None}
    if len({p.resolve() for p in outputs}) != len(outputs):
        parser.error("Output paths must be distinct")
    if any(p.resolve() in protected or p.resolve().is_relative_to(args.table.parent.resolve()) for p in outputs):
        parser.error("Output must not overwrite inputs or write inside the source package")
    meta, manifest, paths, provenance = verify_inputs(
        args.table, args.metadata, args.config, args.manifest, args.archive)
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    if meta.get("status") != "complete":
        raise ValueError("Dataset metadata status is not complete")
    if meta.get("schema_version") != config.get("project", {}).get("schema_version"):
        raise ValueError("Dataset schema version differs from project config")
    if args.table.suffix.lower() == ".parquet":
        schema = str(pq.read_schema(args.table))
        frame = pd.read_parquet(args.table)
    else:
        schema = "CSV serialized values; no Arrow physical schema"
        frame = pd.read_csv(args.table, dtype={**SAMPLE_DTYPES, "epss_status": "string"},
                            keep_default_na=False, na_values=[""],
                            true_values=["True"], false_values=["False"])
        for column in ("domain_tags", "scope_evidence"):
            frame[column] = frame[column].map(json.loads)
        for column in ("published", "last_modified", "retrieved_at"):
            frame[column] = pd.to_datetime(frame[column], format="ISO8601", utc=True, errors="raise")
    result = audit_frame(frame, dataset_version=meta["dataset_version"],
                         split_config=config["split"], rare_support=args.rare_support)
    result["phase0_files_present"] = {
        "config/model.yaml": (args.config.parent / "model.yaml").is_file(),
        "docs/model-plan.md": (args.config.parent.parent / "docs/model-plan.md").is_file()}
    mapping = {"total_records": "total_records", "unique_cve_count": "unique_cve_count",
               "rejected_records": "rejected_records",
               "description_and_label_candidates_before_scope": "ml_candidates",
               "available_epss": "epss_present", "in_kev": "in_kev", "assigned_split": "assigned_source_split"}
    result["metadata_comparison"] = []
    for key, value in mapping.items():
        expected = meta.get("statistics", {}).get(key)
        result["metadata_comparison"].append([key, expected, result["summary"][value]])
        if expected is not None and expected != result["summary"][value]:
            result["findings"].append({"cve_id": "<dataset>", "row": "", "column": key,
                "code": "metadata_count_mismatch", "severity": "error",
                "detail": f"metadata={expected}; audit={result['summary'][value]}"})
    for path in paths:
        if digest(path) != provenance["hashes"][str(path)]:
            raise ValueError(f"Input changed during audit: {path}")
    actual_argv = sys.argv[1:] if argv is None else argv
    command = ".\\.venv\\Scripts\\python.exe -m src.model.audit_data " + " ".join(
        "'" + str(value).replace("'", "''") + "'" if any(c.isspace() for c in str(value)) else str(value)
        for value in actual_argv)
    report = render_report(result, meta, config, provenance, command=command,
                           counts_path=args.counts, findings_path=args.findings, schema=schema)
    for path in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    pd.DataFrame(result["label_counts"]).to_csv(args.counts, index=False, lineterminator="\n")
    pd.DataFrame(result["findings"], columns=["cve_id", "row", "column", "code", "severity", "detail"]).to_csv(
        args.findings, index=False, lineterminator="\n")
    errors = sum(f["severity"] == "error" for f in result["findings"])
    print(json.dumps({"summary": result["summary"], "split_counts": result["split_counts"],
                      "cross_split_duplicate_groups": result["description_duplicates"]["cross_split_groups"],
                      "cross_split_duplicate_rows": result["description_duplicates"]["cross_split_rows"],
                      "absent_classes": result["absent_classes"], "rare_classes": result["rare_classes"],
                      "rare_relative_classes": result["rare_relative_classes"],
                      "errors": errors, "input_hashes_unchanged": True,
                      "outputs": [str(p) for p in outputs]}, ensure_ascii=True, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

