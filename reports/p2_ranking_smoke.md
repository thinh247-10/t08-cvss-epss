# Phase 2 N2 — Ranking sơ bộ

- Ngày chạy: 2026-10-12, Asia/Saigon; người thực hiện: CanhLai.
- Branch: `feat/p2-cvss-scorer`; Python 3.13.12, pandas 3.0.6.
- Dataset version: `t08-v1.0-20261010`.
- Cohort ID: `t08-v1.0-20261010:ranking`.
- Policy version: `cvss-epss-kev-first-v1`.
- EPSS date: `2026-09-29`.

## Đầu vào và đầu ra

Input: `data/processed/phase1_v1_20261010/ranking_cohort.parquet`.
SHA-256: `07bdaba5b21e2f21161b1339704e68924d8f4bfa34118b8eb02ec8b51affdfff`.
Gói đã vượt `src.collect.verify_phase1` ở Bước A. CLI tiếp tục kiểm hash/size,
dataset version, ngày EPSS và counts với metadata trước khi ghi output.

Output: `data/processed/rankings.csv`, đủ **396 dòng/CVE duy nhất, 3 KEV**.
SHA-256: `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.

Schema đúng mục 7 data contract:

```text
cve_id,cvss_base_score,epss,is_kev,cvss_rank,epss_rank,kev_first_rank,dataset_version,epss_date,cohort_id,policy_version
```

## Chính sách sort

| Rank | Sort theo thứ tự |
|---|---|
| `cvss_rank` | CVSS Base quan sát giảm; CVE ID tăng |
| `epss_rank` | EPSS giảm; CVE ID tăng |
| `kev_first_rank` | KEV trước; EPSS giảm; CVSS Base giảm; CVE ID tăng |

Rank là vị trí nguyên 1–396, không dùng dense rank. Ba chính sách giữ đúng cùng
396 ID; output sắp theo CVE ID để tái tạo độc lập với thứ tự input.
Module từ chối missing/duplicate/invalid ID, điểm ngoài khoảng, KEV không phải
boolean, ngày EPSS hỗn hợp/sai định dạng và version không khớp. Không tự loại dòng.

## Lệnh đã chạy và kiểm tra

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_rankings -v
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings
```

- 8/8 test đạt: thứ tự expected tính tay, tie-break, input đảo/thay index,
  duplicate/invalid/missing ID và trường, version/policy sai, score invalid,
  KEV dạng chuỗi, ngày sai/hỗn hợp, số 0 hợp lệ và nullable boolean.
- Đọc lại CSV: schema đạt; IDs và các giá trị nguồn được giữ nguyên.
- Sort độc lập bằng Python kiểm đúng cả ba thứ tự, mỗi cột rank có đủ 1–396.
- `git diff --check` đạt cho thay đổi tracked.

Ba CVE KEV có vị trí sau (chỉ mô tả artifact, chưa đánh giá chất lượng policy):

| CVE | CVSS rank | EPSS rank | KEV-first rank |
|---|---:|---:|---:|
| CVE-2023-23752 | 296 | 3 | 3 |
| CVE-2023-44487 | 106 | 1 | 1 |
| CVE-2024-38475 | 32 | 2 | 2 |

## Bàn giao và giới hạn

`rankings.csv` bị Git ignore; gửi riêng cùng checksum/version cho N1 khi bàn giao.
N2 triển khai module sơ bộ ở Phase 2; chuyển quyền bảo trì ranking cho N1 ở Phase 3
theo kế hoạch, việc tiếp nhận thực tế còn chờ trao đổi nhóm.

Đây là thứ tự sơ bộ trên cohort v1 có phạm vi giới hạn (388 Web + 8 mobile).
Chưa tính metric tương quan/top-K hoặc plot; chưa kết luận chính sách nào tốt hơn.
KEV-first dùng KEV trực tiếp nên vị trí KEV không phải bằng chứng dự báo độc lập.
EPSS và catalog KEV khác ngày như đã khai báo trong metadata. Dùng CVSS quan sát;
Environmental và CVSS dự đoán không tham gia bảng này.
