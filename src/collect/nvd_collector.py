"""Trich du lieu NVD tu file JSON da tai.

Buoc hien tai: doc offline, chua thu thap hang loat.
"""

import json
import sys
from pathlib import Path


# Cac gia tri nhan Base CVSS 3.1 theo data contract.
ALLOWED_LABELS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


def parse_base_vector(vector):
    """Tach vector chi gom 8 Base metrics; tra None neu khong hop le."""
    if not isinstance(vector, str):
        return None

    parts = vector.split("/")

    if parts[0] != "CVSS:3.1" or len(parts) != 9:
        return None

    labels = {}

    for part in parts[1:]:
        name, separator, value = part.partition(":")

        if separator != ":":
            return None

        if name not in ALLOWED_LABELS or name in labels:
            return None

        if value not in ALLOWED_LABELS[name]:
            return None

        labels[name] = value

    if set(labels) != set(ALLOWED_LABELS):
        return None

    return labels


def extract_cve(cve):
    """Chuyen mot doi tuong CVE thanh cac truong can dung."""
    description = next(
        (
            item["value"]
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en" and item.get("value")
        ),
        None,
    )

    # Tao dong truoc: thieu CVSS van giu thong tin CVE.
    row = {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": description,
        "cvss_version": None,
        "cvss_source": None,
        "cvss_type": None,
        "cvss_vector": None,
        "cvss_base_score": None,
        **{name: None for name in ALLOWED_LABELS},
    }

    candidates = []

    for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
        data = metric.get("cvssData", {})
        labels = parse_base_vector(data.get("vectorString"))

        if data.get("version") == "3.1" and labels is not None:
            candidates.append((metric, labels))

    if not candidates:
        return row

    # NVD truoc, tiep theo Primary, roi source/vector de pha hoa.
    candidates.sort(
        key=lambda candidate: (
            candidate[0].get("source") != "nvd@nist.gov",
            candidate[0].get("type") != "Primary",
            candidate[0].get("source") or "",
            candidate[0]["cvssData"]["vectorString"],
        )
    )

    selected, labels = candidates[0]
    data = selected["cvssData"]

    row.update({
        "cvss_version": data["version"],
        "cvss_source": selected.get("source"),
        "cvss_type": selected.get("type"),
        "cvss_vector": data["vectorString"],
        "cvss_base_score": data.get("baseScore"),
    })
    row.update(labels)

    return row


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Cach dung: python src/collect/nvd_collector.py <file_json>"
        )

    input_path = Path(sys.argv[1])

    with input_path.open(encoding="utf-8") as file:
        payload = json.load(file)

    records = [
        extract_cve(item["cve"])
        for item in payload.get("vulnerabilities", [])
    ]

    print(json.dumps(records, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()