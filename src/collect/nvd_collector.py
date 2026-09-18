#!/usr/bin/env python3
"""
Thu thap CVE hang loat tu NVD API 2.0.

TODO (nguoi phu trach Data/Infra):
  - Chia khoang ngay theo thang de tranh timeout (NVD gioi han 120 ngay/request)
  - Ton trong rate limit: 50 req/30s khi co API key, 5 req/30s khi khong
  - Retry voi exponential backoff khi gap 503
  - LUU TRUONG `source` cua tung metric CVSS (nvd@nist.gov vs CNA) — bat buoc
  - Bo qua CVE khong co CVSS vector nao (trang thai Not Scheduled)
  - Ghi ra data/raw/nvd_cves.parquet

Cach dung:
    python src/collect/nvd_collector.py --start 2020-01-01 --end 2025-12-31
"""
