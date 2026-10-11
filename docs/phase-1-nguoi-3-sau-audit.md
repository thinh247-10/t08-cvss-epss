# Người 3 — Bản sửa và việc tiếp theo sau audit

> **Cập nhật 2026-10-10:** bản preview này đã được thay bởi dataset v1 hoàn chỉnh về
> kỹ thuật. Dùng [hướng dẫn bàn giao mới](phase-1-completion.md), không tiếp tục train
> từ bảng preview 67.280 mẫu. Tập ML cuối có 67.242 mẫu và danh sách split đã khóa.

Ngày: 2026-10-08. N1 yêu cầu sửa/tích hợp phần N3 ngay trên bản làm việc `develop`.
Nguồn: audit `origin/test/p1-data-audit` tại `8b4b282`; thiết kế Phase 0
`origin/chore/p0-model-config` tại `1182468`. Đây là tích hợp nội dung file;
không phải đã merge hai branch trên GitHub. Chưa train model.

## 1. File đã có và chức năng

| File | Chức năng |
|---|---|
| `src/model/audit_data.py` | Kiểm provenance, schema, nhãn, phân bố lớp và split thời gian dự kiến |
| `src/model/data_validation.py` | Chặn đầu vào sai; trả description riêng và tám target riêng |
| `src/model/baseline.py` | Gọi validator; trainer vẫn là việc Phase 2 |
| `config/model.yaml` | Thiết kế model, mapping nhãn và tham chiếu chính sách duplicate |
| `docs/model-plan.md` | Thiết kế Phase 0 được tích hợp, bổ sung quyết định sau audit |
| `src/model/duplicate_policy.py` | Preview các ID giữ/loại vì mô tả trùng xuyên split; không sửa dataset |
| `tests/test_model_data_audit.py` | 47 test gốc N3 |
| `tests/test_duplicate_policy.py` | 7 test về leakage, bất biến đầu vào, mốc ngày và quyết định không dựa trên target |
| `reports/n3_duplicate_policy_preview.md` | Kết quả preview chạy thật và giới hạn |

Giữ báo cáo `full_ml_audit.md` gốc làm bằng chứng lần chạy của N3. Phần báo thiếu
hai file Phase 0 trong báo cáo đó phản ánh thời điểm cũ; hiện đã tích hợp hai file.
Các file dữ liệu gốc và `config/project.yaml` giữ nguyên để checksum snapshot còn đúng.

## 2. Quy tắc xử lý mô tả trùng

Version: `exact-earliest-period-v1`.

1. Chỉ xét các ứng viên có mô tả và nhãn CVSS 3.1 hợp lệ, không Rejected.
2. Chuẩn hóa mô tả: Unicode NFKC -> gộp whitespace -> strip -> casefold.
   Giữ nguyên tên sản phẩm, phiên bản và dấu câu; không fit tokenizer/vectorizer.
3. Xác định split dự kiến bằng `published`, theo các khoảng UTC trong project config.
4. Mỗi nhóm mô tả giống nhau giữ mọi CVE thuộc giai đoạn xuất hiện sớm nhất.
   Ví dụ cùng mô tả xuất hiện ở train/validation/test: giữ các dòng train,
   loại các dòng validation/test khỏi cohort preview. Chỉ xuất hiện validation/test:
   giữ validation, loại test. Không chuyển CVE từ test về train.
5. Không dùng nhãn để chọn mẫu; mô tả giống nhưng vector khác không tự sửa/xóa nhãn.
   Trùng trong cùng split vẫn giữ, cần trình bày ảnh hưởng tới trọng số mẫu.
6. Master/ranking không bị loại dòng. Preview chỉ xuất quyết định theo ID.

Quy tắc này làm giảm việc đánh giá trên mô tả đã xuất hiện ở giai đoạn trước.
Nó cũng thay đổi thành phần tập đánh giá; phải công bố số loại và support sau loại,
không dùng kết quả model để đổi quy tắc. Không giải quyết hết gần trùng hay nhóm sản phẩm.

## 3. Chạy lại từng bước

Chạy từ thư mục repo có `.venv`, `src` và `config`. Mỗi người tự tạo môi trường
theo hướng dẫn nhận gói. Không cần API key, mạng hay GPU cho các lệnh này.

**Bước 1 — Test:**

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_model_data_audit tests.test_duplicate_policy -q
```

**Bước 2 — Preview trên gói đã nhận:**

```powershell
.\.venv\Scripts\python.exe -m src.model.duplicate_policy --table data/processed/joined_pilot_20261005T164912_356960Z/cves.parquet --metadata data/processed/joined_pilot_20261005T164912_356960Z/metadata.json --manifest docs/handoffs/phase-1-joined-20261005.json --out-dir data/processed/ml_duplicate_preview_n3_v1
```

Output phải là thư mục mới; nếu đã tồn tại, dùng tên mới, không ghi đè snapshot cũ.
Lệnh kiểm checksum manifest/table/config, audit và kiểm lại input, rồi tạo:

- `decisions.csv`: CVE ID, source version, policy version, hash mô tả, split dự kiến,
  split xuất hiện đầu tiên, giữ/loại và lý do; không chứa mô tả.
- `label_counts.csv`: support tất cả 22 lớp của 8 metric trước/sau, theo từng split.
- `metadata.json`: nguồn/checksum, cấu hình split, số liệu và giới hạn; trạng thái luôn
  `preview_before_scope_not_training_ready`.

Không coi cột `keep_in_preview` là điều kiện train hoàn chỉnh. Module này kiểm tra
gói joined hiện tại còn chưa gán split; không dùng để ghi đè bảng cuối đã khóa.

## 4. Phần còn lại để kết thúc Phase 1

1. N1 tích hợp kết quả scope có bằng chứng của N2 vào một dataset version mới.
2. N2 cung cấp scorer chung; N1/N3 đối chiếu Base Score từ vector nguồn, báo sai lệch.
3. N3/N1 chạy lại thống kê và chính sách duplicate trên cohort ML đã chọn sau scope.
   Nếu mở rộng miền train, phải ghi quyết định rõ và báo riêng kết quả Web/mobile.
4. N1 cung cấp raw/CPE/references đúng snapshot; N3 rà gần trùng/nhóm sản phẩm,
   ghi phương pháp, kết quả và giới hạn còn lại. Không khẳng định đã xử lý mục này.
5. N3 kiểm support, lớp vắng/hiếm và số mẫu sau loại; N1 lưu danh sách ID, các lý do
   loại, dataset/split/policy version và checksum vào gói cuối.
6. Chỉ sau đó xác nhận split cuối và bắt đầu baseline Phase 2. Chốt ngân sách/máy
   DistilBERT theo D05; cấu hình Phase 0 hiện vẫn là đề xuất, không phải số đo.

## 5. Git và bàn giao

Bản sửa đang nằm trong working tree của N1 trên `develop`; chưa commit/push tự động.
Khi N1 đã push, N3 lưu/commit thay đổi riêng trước khi chuyển branch, rồi chạy:

```powershell
git switch develop
git pull --ff-only origin develop
```

Nếu Git báo phân kỳ hoặc có thay đổi cục bộ, dừng và xem `git status`; không force/reset.
Không cần merge lại nội dung cũ từ hai branch Phase 0/Phase 1 sau khi N1 đã tích hợp.
File ZIP/Parquet/preview lớn giữ ngoài Git; chuyển gói theo hướng dẫn bàn giao/checksum.
