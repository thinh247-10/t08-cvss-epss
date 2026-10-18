# Phase 3 N2 — Bước A: tái tạo ranking

Ngày chạy: 2026-10-18. Người thực hiện: CanhLai (N2).
Branch: `feat/p3-ranking-context`; code đầu vào `2ce52fd`, chứa mốc `fb54a11`.

## Đầu vào và kiểm tra

- Dataset: `t08-v1.0-20261010`; cohort `t08-v1.0-20261010:ranking`.
- ZIP nhận tại `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/3/phase1_v1_20261010.zip`.
  SHA-256 `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe` khớp.
- Bản giải nén nằm trong `T08/3/phase1_v1_20261010/phase1_v1_20261010/`.
  Verifier trên cả bản nhận mới và bản `data/processed/phase1_v1_20261010/`
  trong repo đều trả `PHASE1 RELEASE OK`, 14 file; không ghi đè release.
- Gói `phase2_handoff_20261017` đã có nhưng không cần đọc model/prediction để chạy A.
- Python 3.13.12; pandas 3.0.6; pyarrow 25.0.1; PyYAML 6.0.3.
  `pip check`: `No broken requirements found.` Không cài thêm dependency.

## Lệnh thực chạy tại repo root

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1 --folder 'D:\UIT\Tài Liệu\NT\NT213 - Bao Mat Web\T08\3\phase1_v1_20261010\phase1_v1_20261010'
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings --input data/processed/phase1_v1_20261010/ranking_cohort.parquet --metadata data/processed/phase1_v1_20261010/metadata.json --output data/processed/p3_n2/rankings.csv
.\.venv\Scripts\python.exe -m unittest tests.test_rankings tests.test_cvss -v
Get-FileHash -LiteralPath data/processed/p3_n2/rankings.csv -Algorithm SHA256
```

## Kết quả thật

- 396 dòng dữ liệu, 396 ID duy nhất; cohort gồm 388 Web và 8 mobile, 3 KEV.
- 14/14 test đạt: 8 ranking và 6 CVSS.
- CSV đọc lại bằng `csv.DictReader`: ba cột rank đều đúng 1–396, kiểm thứ tự
  độc lập bằng Python `sorted`, không gọi lại `build_rankings` làm expected.
- CVSS: Base giảm, ID tăng. EPSS: EPSS giảm, ID tăng.
  KEV-first: KEV/EPSS/Base giảm, ID tăng. Không đổi cohort giữa ba policy.
- Output `data/processed/p3_n2/rankings.csv`, 48.438 byte, UTF-8, newline LF.
- SHA-256: `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.
- Policy: `cvss-epss-kev-first-v1`.
- 11 cột giữ nguyên: `cve_id,cvss_base_score,epss,is_kev,cvss_rank,epss_rank,kev_first_rank,dataset_version,epss_date,cohort_id,policy_version`.

## Đợt bàn giao A cho N3

Bản tiện gửi: `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/3/n2_p3_step_a_20261018/`.
Gửi `rankings.csv` và `p3_ranking_step_a.md` này cho N3 qua kênh nhóm.
N3 có thể đọc ranking để bắt đầu scatter/top-rank; metric tổng hợp sẽ giao ở B.
Đây là bản chuẩn bị bàn giao, chưa có xác nhận đã gửi hoặc N3 đã nhận.

EPSS snapshot 2026-09-29; KEV phát hành 2026-09-30, tải 2026-10-01 UTC.
Không dùng prediction AI, không tải lại tín hiệu, không diễn giải KEV-first như
kiểm định hiệu quả độc lập. Mẫu số KEV chỉ có 3; chưa có thống kê B hay kết quả context.

- [x] Bước A: verify, tái tạo CSV, test, checksum và chuẩn bị bàn giao.
- [ ] Người dùng gửi hai file cho N3 và xác nhận tiếp nhận.
- [ ] Bước B: metric/contract/metadata — chưa thực hiện trong bước A.
- [ ] Bước C–E: Environmental, queue, case/playbook — chưa thực hiện.
