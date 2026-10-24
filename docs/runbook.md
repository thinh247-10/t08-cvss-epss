# Runbook demo Phase 4

Ngày 24/10/2026. Demo đọc release đã khóa, không gọi API hoặc train.
N2 `55fa749`, N3 `4c15746` được tích hợp vào develop tại `872f79b`.

## 1. Chuẩn bị máy nhận

Trong repo, lưu công việc riêng trước khi pull:

```powershell
git switch develop
git pull --ff-only origin develop
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m pip install -r requirements-model.txt
.\.venv\Scripts\python.exe -m pip check
```

Nếu đã có venv dùng được thì giữ lại. Model requirements phục vụ TF-IDF live;
Torch không bắt buộc. Không nhận `.venv`, `.env` hoặc API key từ đồng đội.
Máy N1 dùng Python 3.14.3; log N2 dùng 3.13.12. Không tuyên bố mọi phiên bản đều tương thích.

## 2. Nhận dữ liệu

Nhận ZIP Phase1/2/3 và đối chiếu SHA256/bytes với các receipt trong
`docs/handoffs/phase-1-v1.json`, `phase-2-complete-20261017.json`,
`phase-3-complete-20261021.json`. Dùng `Get-FileHash -Algorithm SHA256 <zip>`
và `(Get-Item <zip>).Length`; không giải nén gói không khớp.
Code Git không chứa các file dữ liệu lớn.

- Phase1: thư mục chứa `ranking_cohort.parquet`, `ml_cohort.parquet`, `metadata.json`.
- Phase2: thư mục chứa `manifest.json`, `baseline.zip`, `distilbert/`.
  Giải nén thêm `baseline.zip` vào `baseline/` ngay dưới thư mục Phase2.
- Phase3: thư mục chứa `phase3_manifest.json`, `data/processed/p3_n2/`, `reports/`.

Giải vào thư mục mới, không ghi đè release. Điền ba đường dẫn tương đối trong
`config/demo.yaml`; giá trị hiện tại là đường dẫn thật đã dùng trên máy N1.
Máy nhận có thể đổi sang `data/processed/phase2_received` và
`data/processed/p3_received_20261021`. Không đổi dataset/context version.

Kiểm Phase1 tại đường dẫn chuẩn:

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
.\.venv\Scripts\python.exe scripts/package_phase3_release.py --verify data/processed/reviews/phase3_handoff_verified_20261021
```

Lệnh Phase3 cần dùng đường dẫn bạn vừa cấu hình. Loader kiểm manifest Phase1/3,
Phase2 outer manifest, baseline ZIP và model trước inference. Xem trạng thái AI:
summary chạy được không có nghĩa AI đã sẵn sàng.

## 3. Chạy demo

```powershell
.\.venv\Scripts\python.exe scripts/run_demo.py --cli --json summary
.\.venv\Scripts\python.exe scripts/run_demo.py --cli cve CVE-2023-22626
.\.venv\Scripts\python.exe scripts/run_demo.py --cli cve CVE-2023-41387
.\.venv\Scripts\python.exe scripts/run_demo.py --cli predict CVE-2023-38709 --live
.\.venv\Scripts\python.exe scripts/run_demo.py --mode live
.\.venv\Scripts\python.exe scripts/run_demo.py --mode saved
.\.venv\Scripts\python.exe scripts/run_demo.py --mode no-ai
```

Notebook sinh trong `data/processed/p4_demo_n1/`, JSON bằng chứng trong
`reports/p4_n1_<mode>.json`. Chạy lại sẽ cập nhật các output này, không sửa release.
Mở notebook output bằng VS Code/Jupyter; đọc [script chung](../reports/demo-script.md).
Nếu chỉ mở output cũ phải gọi là kết quả đã lưu. `--mode` áp dụng cho notebook;
ở CLI, chỉ `predict ... --live` yêu cầu inference, `--mode no-ai` tắt AI.

Kỳ vọng: 396 CVE/3 KEV, 15 mapping/10 Environmental, 8 patch/7 review;
live ví dụ validation dự đoán 9.1, observed 7.3; no-AI vẫn có 7 cell/7 hình.

## 4. Lỗi và dự phòng

- Không tìm thấy python: kiểm thư mục repo và `.venv/Scripts/python.exe`.
- Thiếu release: sửa path YAML; không tải snapshot mới để thay thế.
- Sai hash/version: dừng view liên quan, nhận lại đúng ZIP; không sửa manifest.
- AI unavailable: kiểm Phase2/baseline extraction/dependencies, đọc fallback_reason.
- Live lỗi: dùng notebook saved, ghi rõ mode; không train để chữa lỗi demo.
- Lỗi in tiếng Việt: dùng `-X utf8` hoặc `$env:PYTHONUTF8='1'`.
- Mở bản notebook đã chạy hoặc 7 PNG Phase3 khi môi trường notebook không sẵn sàng.

## 5. Nghiệm thu người thật còn chờ

N2 đã chạy ba mode trên máy nhận trước runbook này, có log được tổng hợp trong
[reproduction](../reports/p4_reproduction.md). Cần người nhận thử đúng các bước mới
và báo lỗi nếu có; không ghi là đã chạy runbook mới chỉ dựa vào log cũ.
Cả nhóm trình bày thật, đo thời lượng, ghi thao tác lỗi và phương án dự phòng
vào [checklist](../reports/release-checklist.md). Thời gian code không phải thời gian nói.
