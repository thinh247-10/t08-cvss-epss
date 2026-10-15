# Phase 2 N2 — Nhận v1 và kiểm chứng Base scorer

- Người thực hiện: CanhLai.
- Ngày: 2026-10-12 (Asia/Saigon).
- Branch: `feat/p2-cvss-scorer`, bắt đầu từ develop `fb4794b`.
- Dataset: `t08-v1.0-20261010`; schema `0.2`.
- Python 3.13.12; pandas 3.0.6; pyarrow 25.0.1; PyYAML 6.0.3.

## Tiếp nhận dữ liệu

ZIP nhận tại `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/2/phase1_v1_20261010.zip`.
Dung lượng 38.599.819 byte; SHA-256
`215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
13 file payload khớp checksum/dung lượng trong metadata. Verifier dùng manifest
độc lập trong repo kiểm 14 file, bao gồm metadata, và trả `PHASE1 RELEASE OK`.

| Kiểm tra verifier | Kết quả |
|---|---:|
| Master / CVE ID duy nhất | 71.653 / 71.653 |
| ML cohort | 67.242 |
| Train / validation / test | 28.815 / 19.606 / 18.821 |
| Ranking cohort | 396 |
| Web / mobile trong ranking | 388 / 8 |
| KEV trong ranking | 3 |
| Base score kiểm tra / không khớp | 67.912 / 0 |

Verifier đã kiểm checksum, version, tập ID/cohort, split, duplicate xuyên split,
nhãn, Base score và ngày EPSS. Gói làm việc nằm trong
`data/processed/phase1_v1_20261010`. Mapping hiệu chỉnh v1 có PgHero 3.0.1.

## Đối chiếu độc lập

Nguồn: [FIRST CVSS v3.1 specification, mục 7.1, 7.4 và Appendix A](https://www.first.org/cvss/v3.1/specification-document),
truy cập 2026-10-12. Kiểm code scorer và parser với công thức, hệ số và quy tắc
Roundup trong nguồn này. Expected bên dưới được cố định từ phép tính Decimal
độc lập theo FIRST; không lấy output của scorer làm expected.

Với ba impact H: ISS = 0.914816; Impact U = 5.87311872;
Impact C = 6.047730491544518703365256223.
Các vector dưới cùng dùng AV:N, AC:L, UI:N, C:H, I:H, A:H, trừ hai vector zero.

| Scope | PR | Tổng trước Roundup, sau giới hạn 10 | Expected | Actual |
|---|---|---:|---:|---:|
| U | N | 9.7601614950 | 9.8 | 9.8 |
| U | L | 8.7083734500 | 8.8 | 8.8 |
| U | H | 7.1078264250 | 7.2 | 7.2 |
| C | N | 10 | 10.0 | 10.0 |
| C | L | 9.889953888468080199634476721 | 9.9 | 9.9 |
| C | H | 9.000964340868080199634476721 | 9.1 | 9.1 |

### Vector đầy đủ

| Vector | Expected | Actual |
|---|---:|---:|
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | 9.8 |
| `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | 8.8 |
| `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 | 7.2 |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | 10.0 |
| `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 | 9.9 |
| `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 | 9.1 |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0.0 | 0.0 |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N` | 0.0 | 0.0 |

Zero-impact dùng quy tắc Impact <= 0. Fixture Roundup gồm 0.1+0.2 -> 0.3,
4.00 -> 4.0, 4.02 -> 4.1 và 9.00096434086808 -> 9.1.

## Test thực sự đã chạy

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
.\.venv\Scripts\python.exe -m unittest tests.test_phase1_release -v
.\.venv\Scripts\python.exe -m unittest tests.test_phase1_release tests.test_cvss -v
```

- Verifier: `PHASE1 RELEASE OK`.
- Test hiện có: 9/9 đạt.
- Lượt kết hợp: 15/15 đạt, gồm 6 test mới trong `tests/test_cvss.py`.
- Phủ PR N/L/H cho cả Scope U/C, impact zero, thứ tự metric, Roundup và vector
  thiếu/trùng/unknown/sai giá trị/sai phiên bản/không phải Base.
- Không phát hiện lỗi scorer trong các kiểm tra này; giữ nguyên module dùng chung.

## Giao diện cho N3 và tiến độ

```python
from src.environmental.cvss_base import calculate_base_score
```

Hàm trả Base Score với vector Base 3.1 hợp lệ và báo `ValueError` khi invalid.
Scorer không suy ra khả năng khai thác hoặc ưu tiên vá.

- [x] Nhận gói, kiểm checksum và chạy verifier.
- [x] Bước A: kiểm chứng scorer, bổ sung test và báo cáo.
- [x] Bước B: ranking sơ bộ và test; xem `reports/p2_ranking_smoke.md`.
- [x] Bước C: khung năm case từ mapping v1 trong `docs/analysis-results.md`.
- [x] Đọc 13 lỗi validation từ commit N3 `a5c0c16` ngày 2026-10-15; xem `reports/p2_validation_security_review.md`.
- [x] Commit/push phần kỹ thuật Phase 2: `8c07f6a` trên `feat/p2-cvss-scorer`.
- [ ] Tạo PR base `develop`, compare `feat/p2-cvss-scorer` (chưa tạo; integration trả 403).
- [ ] Gửi riêng `data/processed/rankings.csv` cùng checksum/version cho N1.
- [ ] N1/N3 tiếp nhận báo cáo review để tích hợp; chưa có xác nhận tiếp nhận.

Environmental và policy ưu tiên thuộc Phase 3. Kết quả kiểm chứng này không thay
thế việc xác minh nhãn nguồn hay chứng minh hiệu quả mô hình NLP.
