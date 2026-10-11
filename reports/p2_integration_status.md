# Phase 2 — Theo dõi tích hợp của Người 1

Khởi tạo: 2026-10-11. Dataset: `t08-v1.0-20261010`.
Chỉ cập nhật trạng thái khi có bằng chứng thực; chưa có báo cáo mới không đồng nghĩa
thành viên chưa bắt đầu. Bảng này không phải kết quả thí nghiệm.

| Hạng mục | Trạng thái đã biết | Bằng chứng cần ghi tiếp |
|---|---|---|
| Dataset/split/cohort v1 | Hoàn thành kỹ thuật | `docs/handoffs/phase-1-v1.json`, `reports/data_quality.md` |
| Scorer Base và inventory dùng chung | Đã triển khai Phase 1 | `src/environmental/cvss_base.py`, `src/environmental/asset_inventory.py` |
| N2 nhận và verify gói v1 | Chưa ghi nhận xác nhận máy N2 | Ngày, version, log verifier, Python version |
| N3 nhận và verify gói v1 | Chưa ghi nhận xác nhận máy N3 | Ngày, version, log verifier, Python version |
| N2 kiểm scorer và ranking sơ bộ | Chưa ghi nhận bàn giao Phase 2 | Commit/PR, test, artifact hash |
| N3 Dummy/TF-IDF và save/load | Chưa ghi nhận bàn giao Phase 2 | Commit/PR, validation run, model manifest |
| N2 phân tích lỗi validation | Chờ prediction validation | Báo cáo lỗi và số mẫu thực |
| N1 tái chạy inference | Chờ artifact/CLI/dependencies N3 | `reports/p2_reproduction_n1.md` khi đã chạy |
| Quyết định DistilBERT | Máy N1 có RTX 3050 6GB; Torch chưa cài, chưa kiểm backend/train | Xem kiểm tài nguyên bên dưới; vẫn cần chốt D05 |
| Đánh giá test cuối | Chưa ghi nhận | Config đã khóa, test metrics/version |

## Nhật ký bổ sung

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
