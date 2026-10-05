# Phase 1 — Người 3: audit dữ liệu NLP và đề xuất split

Đọc [hướng dẫn nhận gói](phase-1-ban-giao.md), làm bước 2–4 trước.
Kế hoạch gốc: [Phase 1, mục 5](phases/phase-1-du-lieu-web-mobile.md).
Mục tiêu là tìm vấn đề dữ liệu trước train, chưa công bố chất lượng mô hình.

## 1. Branch

Sau khi cập nhật `develop`, tạo một lần:

```powershell
git switch -c test/p1-data-audit
git branch --show-current
```

Nếu branch đã tồn tại, dùng `git switch test/p1-data-audit`.
Giữ `config/model.yaml` và `docs/model-plan.md` từ Phase 0; nếu chưa có trên develop,
báo N1 tích hợp PR thiết kế. Không phải chờ việc đó để đọc/audit bảng bằng pandas.
Môi trường dữ liệu và API key theo hướng dẫn chung; audit không cần GPU hoặc key.

## 2. Hoàn tất kiểm mẫu cũ

**File tạo/cập nhật:** `reports/pilot_ml_audit.md`.
Làm theo [pilot-handoff, mục 4](pilot-handoff.md): mẫu 35 dòng, 30 có nhãn/5 không có nhãn,
so hỗ trợ lớp với thống kê 451 ứng viên pilot. Ghi version mẫu, Python/library versions,
kết quả đọc thật và các lỗi cụ thể. Không trộn các số này với bảng mới 71.653 dòng.

## 3. Audit toàn khoảng

**File code đề xuất:** `src/model/audit_data.py`, CLI offline nhận đường dẫn bảng và metadata.
**File báo cáo:** `reports/full_ml_audit.md`; bảng thống kê nhỏ có thể lưu
`reports/full_ml_label_counts.csv`. Không commit bản sao 71.653 mô tả vào reports.

Các file trên là phần N3 cần triển khai, chưa có sẵn vì hướng dẫn liệt kê.
Script chỉ đọc dữ liệu, không sửa Parquet, config/project.yaml hoặc gán split chính thức.

Các kiểm tra bắt buộc:

1. Hash/version đúng gói, 71.653 ID duy nhất, cột và dtype đúng contract.
2. Description rỗng/missing; Rejected; tám metric hợp lệ và khớp vector CVSS 3.1.
   Lỗi phải nêu CVE ID và cột, không tự sửa nhãn để khớp.
3. Ứng viên ML = không Rejected, mô tả có nội dung và đủ tám nhãn. Đối chiếu số 67.912,
   giải thích nếu bộ kiểm tra của mình tìm ra khác biệt. Thiếu EPSS không tự loại khỏi ML.
4. Đếm từng lớp AV/AC/PR/UI/S/C/I/A, kể cả số 0; phân loại lý do bị loại, nguồn nhãn và last_modified.
5. Audit split dự kiến theo `published` và ranh giới `config/project.yaml`:
   train năm 2023; validation nửa đầu 2024; test nửa cuối 2024, end_exclusive.
   Tạo `proposed_split` trong bộ nhớ/bảng audit riêng; `split` của dữ liệu nguồn vẫn null.
6. Đếm hỗ trợ lớp theo proposed_split, báo lớp vắng/hiếm, target chỉ một lớp.
   Không gộp/xóa lớp khó để làm đẹp dữ liệu; đề xuất fallback và điều chỉnh cho N1.
7. Kiểm ID và mô tả trùng xuyên split; ghi quy tắc chuẩn hóa khi kiểm trùng.
   Với gần trùng/nhóm sản phẩm, mô tả phương pháp và giới hạn, không khẳng định đã kiểm
   đầy đủ chỉ bằng exact-string match. Nếu cần CPE/raw, yêu cầu N1 cung cấp nguồn tương ứng.
8. Scope hiện chưa được xác nhận: Web/mobile theo split phải ghi pending/N/A,
   không diễn giải `in_scope=false` thành tất cả ngoài phạm vi. Cập nhật sau kết quả N2/N1.

Không fit TF-IDF/model trong bước thống kê. Không chọn tham số bằng test hoặc dùng năm
trong CVE ID thay published. NVD snapshot hiện tại có chỉnh sửa sau công bố;
chia thời gian không biến nó thành dữ liệu lịch sử đúng thời điểm công bố.

Báo cáo ghi dataset_version, SHA-256, lệnh thực sự chạy, phiên bản thư viện, số mẫu mỗi bước,
các phát hiện theo CVE ID, đề xuất xử lý và phần chưa xác minh. Chưa có scorer thì ghi
chưa đối chiếu lại Base Score, không tự viết công thức khác trong notebook.

## 4. Code kiểm đầu vào và test

Theo kế hoạch, có thể bổ sung kiểm đầu vào tối thiểu trong `src/model/baseline.py`
hoặc helper dùng chung mà file này gọi; chưa triển khai toàn bộ train Phase 2.
Feature vẫn chỉ description; target là tám nhãn, không lấy EPSS/KEV làm feature.

Test ở `tests/test_model_data_audit.py` với fixture nhỏ: nhãn không khớp vector,
description trắng, Rejected, lớp vắng, CVE trùng và các mốc ngày 01/01, 01/07/2024.
Kiểm audit không thay đổi dữ liệu nguồn. Chạy sau khi đã tạo:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_model_data_audit -v
```

Prompt có thể dùng:

```text
Tôi là N3 Phase 1, đọc docs/data_contract.md, config/project.yaml và hướng dẫn Phase 1 N3.
Viết src/model/audit_data.py để audit offline Parquet/metadata, nhãn/missing/Rejected,
hỗ trợ lớp theo split dự kiến và exact-duplicate description xuyên split.
Ghi rõ gần trùng/product group còn hạn chế nếu chưa có phương pháp/nguồn.
Chỉ description là input NLP. Không train, không sửa bảng nguồn hoặc khóa split.
Thêm fixture kiểm mốc ngày, lớp vắng, sai vector, ID trùng và giữ nguyên input.
Tạo báo cáo từ lần chạy thật, không điền kết quả dự đoán sẵn.
```

## 5. Commit, PR và bàn giao

Khi đã tạo/chạy các file tương ứng, stage đúng phần của mình:

```powershell
git diff --check
git add src/model/audit_data.py tests/test_model_data_audit.py reports/pilot_ml_audit.md reports/full_ml_audit.md
git diff --cached --stat
git commit -m "test(data): audit NLP labels and proposed temporal split"
git push -u origin test/p1-data-audit
```

Nếu đã tạo bảng thống kê nhỏ hoặc sửa helper/baseline thì add rõ từng đường dẫn sau khi xem diff.
Không add ZIP, bảng lớn, `.env`, `.venv` hoặc model weights.
Tạo PR base `develop`, compare `test/p1-data-audit`; ghi test/lệnh đã chạy, version,
số mẫu và đề xuất split. Không sửa file chung `reports/data_quality.md` đồng thời với N1;
N1 tổng hợp phát hiện từ báo cáo riêng này vào báo cáo chung.

Checklist trước nghiệm thu Phase 1 của N3:

- [ ] Đọc được mẫu cũ và gói lớn, phân biệt hai dataset_version.
- [ ] Báo cáo có thống kê thực và test cho bộ kiểm đầu vào.
- [ ] Lớp hiếm, missing, nhãn không khớp và duplicate được báo/giải thích.
- [ ] Đề xuất split rõ, những phần scope/gần trùng/nhóm sản phẩm chưa đủ bằng chứng được ghi lại.
- [ ] N1 nhận góp ý để sửa/build lại; N3 kiểm lại bản đó trước khi xác nhận split cuối cùng.
- [ ] Chưa coi audit dữ liệu là kết quả train hoặc bằng chứng DistilBERT tốt hơn baseline.
