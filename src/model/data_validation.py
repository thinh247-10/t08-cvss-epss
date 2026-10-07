"""Validate submitted NLP rows and expose description-only baseline inputs.

This module does not filter the master table, assign split, fit a model or infer
training readiness. Callers must explicitly choose rows after the data audit.
"""
from dataclasses import dataclass

import pandas as pd

from src.collect.nvd_collector import parse_base_vector


LABEL_ORDER = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "PR": ("N", "L", "H"),
    "UI": ("N", "R"), "S": ("U", "C"), "C": ("N", "L", "H"),
    "I": ("N", "L", "H"), "A": ("N", "L", "H"),
}
KNOWN_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis", "Analyzed",
                  "Modified", "Deferred", "Rejected", "Not Scheduled"}
INPUT_COLUMN = "description"
TARGET_METRICS = tuple(LABEL_ORDER)
REQUIRED_COLUMNS = ("cve_id", INPUT_COLUMN, "vuln_status", "cvss_version",
                    "cvss_vector", *TARGET_METRICS)


@dataclass(frozen=True)
class ModelInputs:
    """Copies of features, targets and IDs, kept separate and index-aligned."""

    features: pd.Series
    targets: pd.DataFrame
    cve_ids: pd.Series


class ModelInputError(ValueError):
    """Invalid submitted rows, with complete CVE/column issues for the caller."""

    def __init__(self, issues):
        self.issues = issues
        preview = "; ".join(f"{item['cve_id']} [{item['column']}]: {item['detail']}"
                            for item in issues[:8])
        if len(issues) > 8:
            preview += f"; ... ({len(issues)} issues total; see .issues)"
        super().__init__(preview)


def checked_boolean(series):
    """Return nullable booleans and invalid-value mask without truthiness casts.

    Integer 0/1 and the strings True/False are invalid; an empty scalar stays NA.
    The returned Series is a copy, so source CSV mistakes are never fixed in place.
    """
    native = series.map(pd.api.types.is_bool)
    invalid = series.notna() & ~native
    return series.where(native, pd.NA).astype("boolean"), invalid


def validate_model_input(frame, *, dataset_version=None):
    """Reject invalid submitted rows and return only description + eight targets.

    Missing EPSS/KEV, pending scope and null split do not remove rows here.
    Eligibility is separate from training readiness, which must be confirmed
    through the full audit and the team-approved dataset/split.
    """
    if not isinstance(frame, pd.DataFrame):
        raise TypeError("Model input must be a pandas DataFrame")
    if not frame.columns.is_unique:
        raise ModelInputError([{"cve_id": "<dataset>", "column": "<schema>",
                                "code": "duplicate_columns", "detail": "Duplicate column names"}])
    required = (*REQUIRED_COLUMNS, "dataset_version") if dataset_version is not None else REQUIRED_COLUMNS
    missing = [column for column in required if column not in frame]
    if missing:
        raise ModelInputError([{"cve_id": "<dataset>", "column": column,
                                "code": "missing_column", "detail": "Required input column absent"}
                               for column in missing])
    if frame.empty:
        raise ModelInputError([{"cve_id": "<dataset>", "column": INPUT_COLUMN,
                                "code": "empty_input", "detail": "No submitted rows"}])

    # Positional indices make diagnostics safe even if the caller's index repeats.
    data = frame.reset_index(drop=True)
    issues = []

    def add(mask, column, code, detail):
        mask = pd.Series(mask, index=data.index, dtype="boolean").fillna(False)
        for row in data.index[mask]:
            cve_id = data.at[row, "cve_id"]
            issues.append({"cve_id": str(cve_id) if isinstance(cve_id, str) else "<missing/invalid>",
                           "column": column, "code": code, "detail": detail})

    id_strings = data.cve_id.map(lambda value: isinstance(value, str))
    valid_ids = id_strings & data.cve_id.astype("string").str.fullmatch(r"CVE-\d{4}-\d{4,}").fillna(False)
    add(~valid_ids, "cve_id", "invalid_id", "Missing or invalid CVE identifier")
    add(data.cve_id.duplicated(keep=False) & data.cve_id.notna(),
        "cve_id", "duplicate_id", "CVE ID appears more than once")
    description_text = data.description.map(lambda value: isinstance(value, str))
    add(data.description.notna() & ~description_text, INPUT_COLUMN,
        "description_type_invalid", "Description must be text")
    nonblank = data.description.where(description_text).astype("string").str.strip().fillna("").ne("")
    add(~nonblank, INPUT_COLUMN, "description_missing", "Description missing or whitespace-only")
    add(data.vuln_status.eq("Rejected").fillna(False), "vuln_status",
        "rejected", "Rejected rows cannot be submitted to the NLP model")
    add(~data.vuln_status.isin(KNOWN_STATUSES), "vuln_status",
        "unknown_status", "Missing or unsupported vulnerability status")

    for metric, values in LABEL_ORDER.items():
        add(~data[metric].isin(values), metric, "invalid_label",
            "Missing or invalid Base metric label")
    add(~data.cvss_version.eq("3.1").fillna(False), "cvss_version",
        "cvss_version_invalid", "Only CVSS 3.1 Base labels are supported")
    parsed = data.cvss_vector.map(parse_base_vector)
    vector_ok = parsed.map(lambda value: value is not None)
    add(~vector_ok, "cvss_vector", "invalid_vector", "Missing or invalid Base CVSS 3.1 vector")
    for metric in TARGET_METRICS:
        expected = parsed.map(lambda value: None if value is None else value[metric])
        mismatch = vector_ok & ~data[metric].eq(expected).fillna(False)
        add(mismatch, metric, "label_vector_mismatch", "Label differs from source vector")

    if "has_cvss31_label" in data:
        flag, invalid = checked_boolean(data.has_cvss31_label)
        add(invalid, "has_cvss31_label", "boolean_type_invalid", "Expected boolean; do not cast a string by truthiness")
        add(~invalid & (flag.isna() | ~flag.fillna(False)), "has_cvss31_label",
            "has_label_mismatch", "Submitted rows require a verified CVSS 3.1 label flag")
    if dataset_version is not None:
        if not isinstance(dataset_version, str) or not dataset_version.strip():
            raise ValueError("Expected dataset_version must be nonblank text")
        add(~data.dataset_version.eq(dataset_version).fillna(False),
            "dataset_version", "dataset_version_mismatch", "Does not match expected dataset version")
    if issues:
        raise ModelInputError(issues)

    return ModelInputs(
        features=frame.loc[:, INPUT_COLUMN].copy(deep=True),
        targets=frame.loc[:, list(TARGET_METRICS)].copy(deep=True),
        cve_ids=frame.loc[:, "cve_id"].copy(deep=True),
    )

