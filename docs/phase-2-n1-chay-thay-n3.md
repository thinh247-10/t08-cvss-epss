# N1 chạy lại baseline thay N3 — 17/10/2026

Theo yêu cầu của N1, chạy lại cấu hình baseline N3 đã chọn vì chưa nhận được
`baseline.joblib` và `predictions.csv` gốc. Đây là lần huấn luyện mới có tên
`tfidf-v1-n1-reproduction-20261017`, không phải xác minh model gốc của N3.

## Cách chạy

Script `scripts/reproduce_n3_baseline.py` nhận thư mục mã nguồn đã review và
một thư mục đầu ra mới. Script từ chối ghi đè một lần chạy có sẵn.

```powershell
.\.venv\Scripts\python.exe -X utf8 scripts/reproduce_n3_baseline.py --source data/processed/reviews/p2_combined_20261017 --output data/processed/p2_n1_reproduction_20261017
```

Lệnh này đã dùng để chạy thật; không cần chạy lại khi đã có kết quả. Thư mục
nguồn kết hợp N3 `a5c0c16` và N2 `add095a`, đã qua 175 test trong lần review.
Đường dẫn `data/processed/reviews/` là bản cục bộ, không được Git gửi sang máy khác.

Sau khi tích hợp hai nhánh vào develop, có thể dùng `--source .` thay cho thư
mục review nếu cần một lần tái lập mới. Luôn chọn đường dẫn `--output` mới;
không chạy lại chỉ để tìm kết quả test tốt hơn. Bộ dữ liệu v1 phải có sẵn.

Script thực hiện:

1. Xác minh 14 file của release Phase 1 bằng manifest gốc.
2. Fit TF-IDF và 8 Logistic Regression trên tập train; cố định `C=1.0`,
   seed 42 và preprocessing N3 đã dùng. Không thử lại C khác.
3. Lưu model và kiểm tra save/load trên 5 mẫu validation.
4. Khóa hash model/config/dataset trước khi đánh giá test.
5. Xuất prediction của Dummy và TF-IDF cho validation và test; tính metric
   riêng cho toàn bộ tập ML và tập đã xác nhận phạm vi Web/mobile.
6. So sánh metric với báo cáo gốc N3, không sửa cấu hình theo kết quả test.
7. Đóng gói nguyên byte model, prediction, config, mã nguồn và checksum vào ZIP.

## Sử dụng gói kết quả

Trong thư mục kết quả, chạy bằng Python của môi trường đã cài
`requirements-model.txt`:

```powershell
# Chạy tại thư mục dự án trước khi đổi thư mục:
$modelPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
Set-Location data/processed/p2_n1_reproduction_20261017
& $modelPython -m src.model.verify_handoff --repo-root .
& $modelPython -m src.model.predict --model models/baseline.joblib --description "A remote unauthenticated attacker can execute arbitrary code."
```

Ví dụ mô tả ở trên chỉ để kiểm tra CLI, không phải một kết luận về CVE thực tế.
Inference và verifier không cần API key hay dataset Phase 1. Muốn huấn luyện
lại cần release Phase 1 đúng checksum và điều chỉnh đường dẫn dữ liệu của máy nhận.

Đưa ZIP qua kênh chia sẻ file cùng SHA-256 trong `archive_receipt.json`.
Không dùng `git add -f` cho model/dataset. Giữ nguyên file trong ZIP để tránh
Git thay đổi LF/CRLF làm sai checksum.

## Giới hạn

- Không chứng minh model gốc N3 có hash chính xác vì chưa có file gốc.
- Chưa chạy DistilBERT; chưa thay đổi quyết định D05.
- Code N2/N3 đã được tích hợp vào develop trong bước tiếp theo cùng ngày;
  riêng model và prediction được chuyển bằng ZIP, không nằm trong Git.
- Chi tiết kết quả thực tế được ghi trong `reports/p2_reproduction_n1.md`.
