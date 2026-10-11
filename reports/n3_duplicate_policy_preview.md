# N3 — Kết quả sửa và preview duplicate

Ngày kiểm: 2026-10-08. Chưa train, chưa khóa split/dataset cuối.

## Nguồn và kiểm chứng

- Dataset: `pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z`.
- Policy: `exact-earliest-period-v1`.
- Đã chạy 47 test audit gốc và 7 test duplicate mới: **54/54 đạt**.
- Kiểm checksum đầu vào trước/sau: giữ nguyên. Kiểm độc lập giao các tập mô tả
  chuẩn hóa sau loại: rỗng giữa mọi cặp train/validation/test.
- Mỗi ID có đúng một quyết định; không sửa bảng nguồn hoặc đổi nhãn CVSS.

## Kết quả chạy thật

| Split dự kiến | Trước | Giữ | Loại vì trùng ở giai đoạn trước |
|---|---:|---:|---:|
| train | 28.815 | 28.815 | 0 |
| validation | 19.921 | 19.617 | 304 |
| test | 19.176 | 18.848 | 328 |
| Tổng | 67.912 | 67.280 | 632 |

- Nhóm mô tả trùng xuyên split: **199 -> 0** trong preview này.
- Không nhầm 1.548 dòng thuộc các nhóm trùng với số phải loại: vẫn giữ các dòng
  trong giai đoạn đầu tiên, chỉ loại 632 dòng ở giai đoạn sau.
- Tất cả 22 lớp của 8 metric được đếm trước/sau trên mỗi split, kể cả support 0.
- Sau loại: không có ô lớp/split nào support bằng 0 hoặc nhỏ hơn 20.
  Điều này không có nghĩa dữ liệu cân bằng hoặc mô hình sẽ học tốt.

## Lệnh đã chạy

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_model_data_audit tests.test_duplicate_policy -q
.\.venv\Scripts\python.exe -m src.model.duplicate_policy --table data/processed/joined_pilot_20261005T164912_356960Z/cves.parquet --metadata data/processed/joined_pilot_20261005T164912_356960Z/metadata.json --manifest docs/handoffs/phase-1-joined-20261005.json --out-dir data/processed/ml_duplicate_preview_20261008_v1
```

## Artifact và truy nguyên

Output: `data/processed/ml_duplicate_preview_20261008_v1/` (ngoài Git).

- `decisions.csv`: quyết định từng CVE, không chứa description.
- `label_counts.csv`: support trước/sau theo split và lớp.
- `metadata.json`: source version, checksum đầu vào/đầu ra, split config, version
  policy, checksum module và giới hạn.
- SHA-256 decisions.csv: `622210812a6fb51297d95e3fed7a5b5abefabf8ec46f2a5f9d79b6991855d115`.
- SHA-256 label_counts.csv: `64b3b77b1c833f9307f387cedc1b76f5bd375471062ccb3da2e1224c345a8b26`.

## Giới hạn và việc chưa hoàn thành

- Đây là cohort trước scope, không phải 67.280 CVE đã được xác nhận Web/mobile.
- N3 cần chạy lại trên cohort sau scope; kiểm scorer chung và support sau lọc trước
  khi khóa dataset. Chưa đủ điều kiện train chính thức.
- Chưa kiểm đầy đủ gần trùng/nhóm sản phẩm. Trùng trong cùng split và khác nhãn
  nguồn được giữ, chưa giải quyết mơ hồ của mô tả.
- Snapshot NVD hiện tại không đại diện chính xác nội dung tại ngày published;
  không tuyên bố backtest lịch sử.
- Hai file thiết kế Phase 0 đã được tích hợp. Báo cáo audit gốc giữ nội dung lịch sử,
  kể cả ghi thiếu file ở thời điểm đó.
- Xem [hướng dẫn sau audit](../docs/phase-1-nguoi-3-sau-audit.md).
