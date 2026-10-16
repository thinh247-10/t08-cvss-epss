> Cập nhật 17/10/2026: N1 đã chạy lại cấu hình baseline N3 cố định C=1.0.
> Metric Dummy/TF-IDF khớp báo cáo N3; gói ZIP mới đã qua kiểm hash và inference
> sau giải nén. Đây là retraining riêng, chưa xác minh artifact gốc N3.
> Xem [kết quả chạy thật](p2_reproduction_n1.md). Code N2/N3 đã merge vào develop
> trong bước tiếp theo cùng ngày; DistilBERT chưa chạy. Các mục bên dưới là nhật ký
> theo thời điểm, không thay cho cập nhật mới nhất này.

Merge N3: `94782a0`; merge N2: `df49544`. Kiểm sau merge bằng
`python -m unittest discover -s tests -q`: **175/175 đạt trong 39,482 giây**.

# Phase 2 — Theo dõi tích hợp của Người 1

Khởi tạo: 2026-10-11. Dataset: `t08-v1.0-20261010`.
Chỉ cập nhật trạng thái khi có bằng chứng thực; chưa có báo cáo mới không đồng nghĩa
thành viên chưa bắt đầu. Bảng này không phải kết quả thí nghiệm.

| Hạng mục | Trạng thái đã biết | Bằng chứng cần ghi tiếp |
|---|---|---|
| Dataset/split/cohort v1 | Hoàn thành kỹ thuật | `docs/handoffs/phase-1-v1.json`, `reports/data_quality.md` |
| Scorer Base và inventory dùng chung | Đã triển khai Phase 1 | `src/environmental/cvss_base.py`, `src/environmental/asset_inventory.py` |
| N2 nhận và verify gói v1 | Đã nhận báo cáo verifier N2, Python 3.13.12; N1 kiểm ranking từ v1 ngày 17/10 | `reports/p2_scorer_check.md` trên branch N2; [biên nhận](../docs/handoffs/n2-phase2-receipt-20261017.json) |
| N3 nhận và verify gói v1 | Chưa ghi nhận xác nhận máy N3 | Ngày, version, log verifier, Python version |
| N2 kiểm scorer và ranking sơ bộ | 17/10: tiếp nhận `add095a`; ranking tái tạo giống byte/hash | [Review 17/10](p2_handoff_review_20261017.md), 396 ID / 3 KEV |
| N3 Dummy/TF-IDF và save/load | Commit `a5c0c16`; N1 chạy 161/161 test đạt; chưa merge | [Review 15/10](p2_commit_review_20261015.md); chờ artifact và sửa checksum text |
| N2 phân tích lỗi validation | Đã kiểm 13 CVE validation, 2 scoped Web, phủ 8 metric | Báo cáo trên branch N2; chờ N3 tổng hợp model card |
| N1 tái chạy inference | Đã cài dependencies N3; còn chờ model/prediction và xử lý checksum LF/CRLF | `reports/p2_reproduction_n1.md` chỉ tạo khi đã chạy model thật |
| Quyết định DistilBERT | Máy N1 có RTX 3050 6GB; Torch chưa cài, chưa kiểm backend/train | Xem kiểm tài nguyên bên dưới; vẫn cần chốt D05 |
| Đánh giá test cuối | N3 báo đã chạy, có metrics trong commit; N1 chưa tái xác minh từ artifact | Model card và `model_metrics.json` trên branch N3 |

## Nhật ký bổ sung

### Nhận N2 và kiểm kết hợp — 2026-10-17

N2 `add095a`, N3 vẫn `a5c0c16`. Bản kết hợp trong thư mục riêng chạy **175/175 test
đạt**; chưa merge develop. Ranking N2 đã được kiểm với dataset v1 và tái tạo đúng
SHA-256. Model/prediction N3 và lỗi checksum LF/CRLF vẫn còn là mục bàn giao chưa
hoàn tất. Xem [báo cáo đầy đủ](p2_handoff_review_20261017.md).

### Kiểm tài nguyên máy N1 — 2026-10-11

| Hạng mục | Kết quả / nguồn |
|---|---|
| Python `.venv` | 3.14.3, từ terminal N1 cung cấp |
| CPU | Intel Core i5-12450HX, 8 nhân, từ terminal N1 cung cấp |
| RAM vật lý | 12.578.578.432 byte, khoảng 11,71 GiB; không phải RAM trống |
| GPU | NVIDIA GeForce RTX 3050 6GB Laptop GPU; máy cũng liệt kê Intel UHD Graphics |
| VRAM tổng | 6.144 MiB, đọc trực tiếp bằng `nvidia-smi` |
| VRAM trống lúc kiểm | 6.002 MiB; có thể thay đổi theo ứng dụng đang chạy |
| Driver NVIDIA | 581.86, đọc trực tiếp bằng `nvidia-smi` |
| Torch trong `.venv` N1 | Chưa cài (`find_spec('torch')` trả None) |
| scikit-learn trong `.venv` N1 | Chưa cài (`find_spec('sklearn')` trả None) |

NVIDIA driver nhận GPU thành công. Chưa kiểm Torch CUDA hoặc đo một bước train
DistilBERT, nên chưa kết luận batch size/thời gian train/khả năng chứa mô hình.
Máy N1 là ứng viên chạy nhánh GPU của nhóm; N3 vẫn sở hữu code model. Khi baseline
đã có, cài đúng dependency N3 bàn giao để tái chạy. Trước nhánh DistilBERT cần kiểm
tương thích Python/Torch, backend, smoke test và thời gian máy khả dụng rồi chốt D05.
Chưa cài thêm thư viện hoặc khởi chạy train trong lần kiểm này.

Ghi theo mẫu: ngày — người — việc — commit/version — đường dẫn bằng chứng — kết quả.
Không tự điền lời xác nhận của N2/N3 hoặc số đo model.
