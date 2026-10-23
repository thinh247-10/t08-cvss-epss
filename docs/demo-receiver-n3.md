# Chạy demo trên máy nhận — hướng dẫn bàn giao N3

Bản N3 ngày 23/10/2026 để N1 tiếp nhận vào runbook chung. Không gắn nhãn
“runbook N1 đã duyệt”. Chỉ dùng các bản phát hành đã khóa, không train/tải API.

## 1. Code và dependency

Lấy branch `feat/p4-demo` bằng Git theo URL repo của nhóm; dùng working tree sạch.
Nếu có việc cũ, lưu riêng trước khi chuyển branch. Từ root repo:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -X utf8 -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -X utf8 -m pip check
```

Cài dependency trước khi ngắt mạng. Torch/Transformers không bắt buộc.
Máy kiểm của N3: Windows 11, Python 3.13.16. Bản model N1 có metadata Python 3.14.3;
khả năng load tại máy nhận phải được kiểm bằng bước live/saved dưới đây.

## 2. Đặt gói đúng vị trí

- Phase 1: `data/processed/phase1_v1_20261010`.
- Phase 2: `data/processed/phase2_received`, gồm manifest, `baseline.zip`,
  thư mục `baseline/` đã giải nén và `distilbert/`. Không dùng `models/baseline.joblib`
  cũ ở root để thay model khóa của N1.
- Phase 3: nhận ZIP theo receipt, giải nén vào thư mục mới:

```powershell
$p3Archive = 'C:\duong-dan-goi-da-nhan\phase3_handoff_20261021.zip'
.\.venv\Scripts\python.exe -X utf8 scripts/receive_demo_inputs.py --archive $p3Archive --destination data/processed/p3_received_20261021
```

Nếu thư mục đã có bản đúng thì bỏ bước nhận; receiver không ghi đè dữ liệu cũ.
Không có Phase 2 vẫn xem được tổng quan, Web/mobile, queue và hình; AI báo unavailable.
Gói fallback HTML hoạt động khi chỉ cần xem kết quả, không cần cả ba gói/model.

## 3. Xác minh và chạy

```powershell
.\.venv\Scripts\python.exe -X utf8 -m src.collect.verify_phase1
.\.venv\Scripts\python.exe -X utf8 scripts/package_phase3_release.py --verify data/processed/p3_received_20261021
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli --json summary
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli cve CVE-2023-41387
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli predict CVE-2023-38709 --split validation
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli predict CVE-2023-38709 --live
.\.venv\Scripts\python.exe -X utf8 scripts/execute_demo_notebook.py
.\.venv\Scripts\python.exe -X utf8 -m unittest tests.test_demo_data -v
```

Expected: 396 CVE/3 KEV; 15 mapping/10 Env/8 patch/7 review. Hai client giữ review,
priority rank N/A. Validation 69 và test 108 riêng. AI ví dụ quan sát Base 7.3,
predicted 9.1; live khớp tám metric/vector/score đã lưu. Notebook 7 cell/7 PNG.

Runner chặn socket của tiến trình Python và kiểm lại hash input; không cần tắt
card mạng cả máy để làm bài kiểm này. Không gắn nhãn đã ngắt card mạng Windows.
Muốn thử không mạng ở mức máy, lưu công việc, tự tắt Wi-Fi/Ethernet và chạy lại
lệnh runner; ghi kết quả thực tế rồi bật mạng lại. Không được chỉ dựa vào giả định.

Với thư mục input khác, truyền `--phase1`, `--phase2`, `--phase3` trước subcommand
CLI, hoặc trực tiếp cho runner. Xem [các lệnh chi tiết](demo-commands.md).

## 4. Dự phòng và diễn tập

Mở notebook đã chạy hoặc giải nén gói `p4_demo_fallback_20261023.zip`, mở
`offline-demo.html` bằng trình duyệt: ảnh đã nhúng, không CDN hoặc script/network.
Trang ghi rõ **kết quả đã lưu**; xem HTML không thực hiện inference.
Trong ZIP có CSV, PNG, lời thoại N2, Q&A và thao tác N3. Đối chiếu SHA/bytes
với [receipt fallback](../reports/p4_demo_fallback_receipt.json) trước khi dùng.

Theo [lời dẫn N3](../reports/demo-script-n3.md), đo sáu đoạn thực tế. Gửi log
runner/commit/máy/receipt/mode và feedback tới nhóm theo quy trình bàn giao.
Thời gian chạy code vài giây không thay thời gian người trình bày sáu phút.

## 5. Nếu lỗi

| Lỗi | Xử lý |
|---|---|
| Sai hash/bytes/context | Nhận lại đúng gói; không sửa manifest/CSV để bỏ qua |
| Thiếu Phase 2/dependency/model | Dùng `--no-ai` hoặc `--saved-only`; công bố mode |
| ID không có hoặc mô tả rỗng | Đọc thông báo; dùng ví dụ validation đã khóa |
| Lỗi Unicode trong terminal | Dùng `-X utf8` như các lệnh trên |
| Máy không có Python | Mở fallback HTML hoặc PNG/CSV đã xác minh |
| Code clean checkout chạy khác | Giữ log và input hashes; không đổi scorer/snapshot |

Kết quả tái chạy checkout sạch cùng máy N3 ở
[báo cáo bàn giao](../reports/p4_n3_delivery.md). Việc N1/N2 chạy trên máy riêng
và xác nhận nội dung vẫn cần bằng chứng từ chính thành viên đó.
