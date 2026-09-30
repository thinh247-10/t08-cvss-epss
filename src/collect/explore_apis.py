#!/usr/bin/env python3
"""
T08 — Buoc 1: Kham pha schema cua 3 nguon du lieu (NVD / EPSS / CISA KEV).

Muc dich: CHUA thu thap hang loat. Chi goi 1 CVE de hieu ro cau truc JSON
truoc khi viet pipeline lon — dac biet la truong `source` cua tung metric CVSS,
vi tu 2026 phan lon diem CVSS den tu CNA chu khong phai NVD.

Cach dung:
    pip install requests python-dotenv
    echo "NVD_API_KEY=xxx" > .env
    python explore_apis.py CVE-2021-44228
"""

import json
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)


def fetch_nvd(cve_id: str) -> dict:
    """Lay 1 CVE tu NVD API 2.0."""
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    else:
        print("[!] Chua co NVD_API_KEY — rate limit se rat thap (5 req / 30s)\n")

    r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


def inspect_nvd(payload: dict) -> None:
    """In ra cac truong quan trong cho do an."""
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        print("[!] Khong tim thay CVE nay")
        return

    cve = vulns[0]["cve"]

    print("=" * 70)
    print("NVD")
    print("=" * 70)
    print(f"CVE ID     : {cve['id']}")
    print(f"Published  : {cve.get('published')}")
    print(f"Modified   : {cve.get('lastModified')}")
    print(f"Status     : {cve.get('vulnStatus')}")   # <- 'Not Scheduled' = khong co ke hoach cham diem

    # Mo ta tieng Anh — day chinh la INPUT cho mo hinh NLP
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        None,
    )
    print(f"\nDescription (input cua model):\n  {desc}\n")

    # CVSS metrics — LABEL cua mo hinh. Chu y: co the co NHIEU nguon khac nhau.
    metrics = cve.get("metrics", {})
    print(f"Cac phien ban CVSS co san: {list(metrics.keys())}")

    for version_key, entries in metrics.items():
        if not version_key.startswith("cvssMetric"):   # bo qua ssvcV203, v.v.
            print(f"\n--- {version_key} (bo qua, khong phai CVSS) ---")
            continue
        print(f"\n--- {version_key} ---")
        for m in entries:
            data = m["cvssData"]
            source = m.get("source")
            is_nvd = source == "nvd@nist.gov"
            print(f"  source     : {source}  {'(NVD)' if is_nvd else '(CNA)'}")
            print(f"  type       : {m.get('type')}")   # Primary / Secondary
            print(f"  vector     : {data.get('vectorString')}")
            print(f"  baseScore  : {data.get('baseScore')}")
            # 8 thanh phan = 8 head cua model
            for field in ("attackVector", "attackComplexity", "privilegesRequired",
                          "userInteraction", "scope", "confidentialityImpact",
                          "integrityImpact", "availabilityImpact"):
                print(f"    {field:24s}: {data.get(field)}")
            print()


def fetch_epss(cve_id: str) -> None:
    """EPSS: xac suat bi khai thac trong 30 ngay toi (0-1), cap nhat hang ngay."""
    r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=30)
    r.raise_for_status()
    payload = r.json()

    print("=" * 70)
    print("EPSS (FIRST.org)")
    print("=" * 70)
    for item in payload.get("data", []):
        print(f"  cve        : {item.get('cve')}")
        print(f"  epss       : {item.get('epss')}        # xac suat 0-1")
        print(f"  percentile : {item.get('percentile')}  # xep hang tuong doi")
        print(f"  date       : {item.get('date')}        # <- LUU LAI, EPSS doi moi ngay")
    print()
    # Ghi chu: API ho tro nhieu CVE cung luc (?cve=A,B,C) va tham so &date=YYYY-MM-DD
    # de lay snapshot lich su — se can khi so sanh ranking o Pha 3.


def check_kev(cve_id: str) -> None:
    """KEV: danh sach CVE da duoc XAC NHAN bi khai thac thuc te."""
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    catalog = r.json()

    entries = {v["cveID"]: v for v in catalog.get("vulnerabilities", [])}

    print("=" * 70)
    print("CISA KEV")
    print("=" * 70)
    print(f"Tong so CVE trong catalog : {len(entries)}")
    print(f"Ngay phat hanh catalog    : {catalog.get('dateReleased')}")

    hit = entries.get(cve_id)
    if hit:
        print(f"\n  [YES] {cve_id} NAM TRONG KEV")
        print(f"  dateAdded        : {hit.get('dateAdded')}")
        print(f"  knownRansomware  : {hit.get('knownRansomwareCampaignUse')}")
    else:
        print(f"\n  [NO] {cve_id} khong nam trong KEV")
    print()


def main() -> None:
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"\n>>> Dang kham pha: {cve_id}\n")

    payload = fetch_nvd(cve_id)

    # Luu ngay khi NVD tra du lieu thanh cong.
    out = f"sample_{cve_id}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"Da luu raw NVD JSON vao: {out}")

    inspect_nvd(payload)
    fetch_epss(cve_id)

    print(f"Nguon tai KEV: {KEV_URL}")
    check_kev(cve_id)
if __name__ == "__main__":
    main()
