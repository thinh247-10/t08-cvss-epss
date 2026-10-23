# Demo Phase 4 — lệnh chạy Người 3

Thực hiện từ root repo, trên Windows PowerShell. CLI + notebook dùng cùng adapter
`src/demo/data_loader.py`; đọc điểm/rank/hình đã đóng băng. Không gọi API, fit model,
tính lại ranking hoặc sửa input. Xem [bàn giao hiện hành](../reports/p4_n3_delivery.md)
và [kiểm local ban đầu](../reports/p4_demo_check.md).

## 1. Input và môi trường

Mặc định tương đối root repo, không phụ thuộc ổ đĩa của người gửi:

| Input | Thư mục mặc định |
|---|---|
| Phase 1 | `data/processed/phase1_v1_20261010` |
| Phase 2 | `data/processed/phase2_received` (có `baseline/` đã giải nén và `baseline.zip`) |
| Phase 3 | `data/processed/p3_received_20261021` (gói tích hợp mới, context-v2) |

Chuẩn bị dependency trước buổi demo; lệnh cài có thể cần mạng. Máy hiện tại đã có
dependency và `pip check` đạt; không cài lại Torch hay tải model để làm demo.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m pip check
```

Luồng đọc artifact cần pandas/pyarrow/PyYAML; inference TF-IDF dùng
`requirements-model.txt`. `requirements-analysis.txt` đã bao gồm bộ này.
Runner dùng stdlib, không cần Jupyter/Torch/Transformers. Jupyter chỉ là tùy chọn
nếu muốn chạy tương tác bằng kernel của `.venv`.

Nhận **gói Phase 3 mới** theo receipt
`docs/handoffs/phase-3-complete-20261021.json`. Đặt đường dẫn ZIP thực tế vào biến:

```powershell
$p3Archive = 'C:\duong-dan-goi-da-nhan\phase3_handoff_20261021.zip'
.\.venv\Scripts\python.exe -X utf8 scripts/receive_demo_inputs.py --archive $p3Archive --destination data/processed/p3_received_20261021
.\.venv\Scripts\python.exe -X utf8 scripts/package_phase3_release.py --verify data/processed/p3_received_20261021
```

Receiver kiểm SHA-256/bytes **trước** giải nén, từ chối đường dẫn thoát thư mục,
đích đã tồn tại, sai CRC hoặc trùng member. Chỉ giải nén vào thư mục mới.
Nếu đã nhận đúng gói thì bỏ qua bước nhận; không xóa bản cũ để chạy lại.
Gói Phase 1/2 đã đúng có thể dùng lại. Receipt là nguồn tin cậy của nhóm;
không thay manifest để bỏ qua sai hash, không nạp joblib từ nguồn khác.

## 2. CLI

Các option đường dẫn/`--json`/`--no-ai` đặt **trước** subcommand:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli --help
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli summary
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli cve CVE-2023-22626
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli cve CVE-2023-41387
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli predict CVE-2023-38709 --split validation
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli predict CVE-2023-38709 --live
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli predict CVE-2023-38709 --model-version distilbert-v1-n1-20261017 --split validation
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli --no-ai --json summary
```

Đổi thư mục staging bằng `--phase1`, `--phase2`, `--phase3`, ví dụ:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m src.demo.cli --phase3 data/processed/p3_received_20261021 --json cve CVE-2023-41387
```

`summary`/`cve` không nạp joblib. `predict` mặc định ghi **kết quả đã lưu**.
Chỉ `--live` chạy TF-IDF CPU trên mô tả validation thuộc cohort, thông qua
`src.model.predict.predict_frame`. Model là `tfidf-v1-n1-reproduction-20261017`.
Hash model được kiểm lại ngay trước deserialize; không fit, không download.
Thiếu model/dependency: dùng prediction đã xác minh và ghi rõ fallback/mode.
Sai hash/version Phase 2: khóa AI; dữ liệu quan sát/bối cảnh vẫn mở nếu hợp lệ.
Thiếu Phase 1/3 hoặc sai integrity của chúng: CLI trả exit 2 với lỗi ngắn.

CLI text hiện `N/A — lý do`; JSON giữ `null`, boolean và số đúng kiểu, các cặp có
`environmental_missing_reason`/`priority_rank_missing_reason`. Không biến null thành 0.
ID rỗng/sai định dạng/ngoài cohort báo rõ, không có traceback. CVE mobile trên train
không có prediction held-out; không ghép train vào validation/test.

## 3. Notebook khoảng 6 phút

```powershell
.\.venv\Scripts\python.exe -X utf8 scripts/execute_demo_notebook.py
```

Mở [notebooks/03_demo.ipynb](../notebooks/03_demo.ipynb) bằng VS Code/Jupyter:
phạm vi/ngày → top-50 hai trang → Web/API-02 → Mobile → AI → quyết định/giới hạn.
7 code cells, 7 PNG thật có manifest; bảng HTML giữ đầy đủ reason/action.
Các mốc thời gian là dự kiến; chưa đo lời nói 6 phút và chưa có N2 duyệt nội dung.

Runner thực thi từ namespace mới, chặn socket bằng audit hook, thử guard bằng DNS
bị từ chối, kiểm hash input sau chạy rồi mới lưu notebook. Mặc định runner thực
hiện ví dụ live; notebook Jupyter mặc định `RUN_LIVE=False`. Trong Jupyter, sửa
`RUN_LIVE` ở cell đầu để chọn mode rồi Restart Kernel/Run All.

```powershell
# Chạy chỉ prediction đã lưu, lưu vào file riêng để giữ bản demo live:
.\.venv\Scripts\python.exe -X utf8 scripts/execute_demo_notebook.py --saved-only --output reports/p4_demo_saved.ipynb --report reports/p4_demo_saved_execution.json
# Thử khi không có AI; tổng quan/bối cảnh/hình vẫn mở:
.\.venv\Scripts\python.exe -X utf8 scripts/execute_demo_notebook.py --no-ai --output reports/p4_demo_no_ai.ipynb --report reports/p4_demo_no_ai_execution.json
```

Runner cũng nhận `--phase1`, `--phase2`, `--phase3`. Input sai làm dừng mà giữ
notebook đã chạy trước. Socket bị chặn ở tiến trình Python; không tuyên bố card mạng
Windows đã tắt. Timing log là thời gian tính toán, không là thời gian diễn tập.

## 4. Dự phòng không chạy code

- Mở output đã lưu trong `notebooks/03_demo.ipynb`; 7 hình đã nhúng, không cần kernel.
- Mở 7 PNG gốc tại `data/processed/p3_received_20261021/reports/figures/phase3/`.
  Top-50 phải dùng cả `top50_three_policies_p1.png` và `top50_three_policies_p2.png`.
- CSV: `data/processed/p3_received_20261021/data/processed/p3_n2/` gồm ranking,
  mapping, Environmental và queue; `p3_n3/` có `top50_long.csv`, các bảng hình,
  `predicted_rank_comparison.csv`. Caption ở `reports/p3_figures.md` trong staging.
- Prediction đã lưu: `phase2_received/baseline/data/processed/predictions.csv`
  và `phase2_received/distilbert/predictions.csv`. CLI lọc đúng model/split;
  không xem bản dummy như TF-IDF chính.
- Đã nhận `reports/demo-script-security.md`, `docs/demo-qa.md` từ branch N2 tại
  commit `43ce980`; [script N3](../reports/demo-script-n3.md) đã ghép cell/lời dẫn.
  Runbook/script cuối N1 và xác nhận N2 đã xem demo vẫn pending.
- Gói `data/processed/p4_demo_fallback_20261023.zip` có `offline-demo.html`,
  notebook output, 7 PNG, CSV, script và Q&A. Giải nén rồi mở HTML bằng trình duyệt,
  không cần Python/kernel/mạng. Đối chiếu [receipt](../reports/p4_demo_fallback_receipt.json).
  HTML luôn ghi kết quả đã lưu, không giả inference mới.

Tạo revision fallback khác sau khi chạy notebook mới (không ghi đè gói đã giao):

```powershell
.\.venv\Scripts\python.exe -X utf8 scripts/package_demo_fallback.py --output data/processed/p4_demo_fallback_revision2.zip --receipt reports/p4_demo_fallback_revision2.json
.\.venv\Scripts\python.exe -X utf8 scripts/check_demo_handoff.py
```

## 5. Kiểm thử và bàn giao

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest tests.test_demo_data -v
.\.venv\Scripts\python.exe -X utf8 -m src.collect.verify_phase1
```

Test fixture nhỏ và smoke trên release thật nằm trong cùng module. Smoke sẽ
skip nếu máy chưa có gói thật; không gọi kết quả fixture là đã tái lập release.
Máy hiện tại đã chạy smoke thật, đối chiếu live/saved và bảo toàn hash input.
Các test nghiệp vụ cũ được chạy riêng trong log tổng, không sửa scorer/policy.

Gửi N1 source mới, notebook, `reports/p4_demo_check.md`, log/JSON và receipt đầu vào.
Không cần đóng gói lại Phase 1/2/3. Đã tách branch `feat/p4-demo`; chỉ stage phần demo,
giữ các thay đổi có sẵn khác ngoài commit. Commit/push/PR và kết quả checkout sạch
ghi trong [bàn giao](../reports/p4_n3_delivery.md). Dùng
[hướng dẫn máy nhận N3](demo-receiver-n3.md) trong lúc chờ runbook N1 chính thức.
N2 review nội dung và rehearsal chung vẫn cần người trong nhóm xác nhận.
