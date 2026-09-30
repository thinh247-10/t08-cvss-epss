# Bàn giao mẫu NVD pilot — Người 1 → Người 2, Người 3

Gói này giúp ba người bắt đầu làm song song. Mẫu được tạo từ lần tải NVD cho
01–07/01/2023: 543 CVE, gồm 451 ứng viên có mô tả/vector Base CVSS 3.1 và 92 Rejected.
Đây là dữ liệu NVD-only để kiểm tra giao tiếp; chưa phải dataset v1 hay kết quả mô hình.

## 1. Các file và người phụ trách

| File | Chức năng | Người phụ trách |
|---|---|---|
| `src/collect/prepare_handoff.py` | Đọc pilot đã lưu, kiểm checksum, chọn mẫu, xuất CSV/metadata/thống kê; không gọi API | N1 |
| `data/sample/cves_sample.csv` | 30 ứng viên có nhãn + 5 Rejected để kiểm loader và missing; dùng tên cột trong data contract | N1 tạo, N2/N3 đọc |
| `data/sample/metadata.json` | Nguồn, version, cách chọn mẫu, seed, danh sách ID, checksum và giới hạn | N1 |
| `data/annotations/scope_review.csv` | 30 dòng chờ N2 xác minh Web/mobile, kèm mô tả và link tham khảo từ raw | N2 điền kết quả |
| `reports/pilot_label_distribution.json` | Số mẫu mỗi lớp trong tám metric, trên 451 ứng viên và riêng 30 dòng mẫu | N3 phân tích |
| `tests/test_prepare_handoff.py` | Kiểm CSV giữ đúng null/boolean/text, mẫu ổn định và scope chưa được tự xác nhận | N1 duy trì |
| `requirements-data.txt` | Thư viện tải/đọc dữ liệu, gồm PyYAML; môi trường này chưa cài bộ model | Cả nhóm |

Mẫu chọn theo thứ tự SHA-256 của `seed:CVE ID`, seed từ cấu hình (hiện là 42), riêng
hai nhóm ứng viên và Rejected. Không dùng tỷ lệ 30/5 để suy ra tỷ lệ của quần thể.
Mẫu nhỏ cũng không bảo đảm có mọi lớp CVSS hoặc có CVE mobile.

## 2. Các trường chưa hoàn thiện

- `epss`, `epss_percentile`, `epss_date`, `is_kev`, các trường KEV: để trống vì chưa ghép nguồn.
  `is_kev` trống là chưa biết; không chuyển thành false.
- `scope_status=needs_review`; `domain_tags=[]`, `scope_evidence=[]`; `in_scope=false` nghĩa là
  chưa được nhận vào cohort, không phải đã xác minh ngoài phạm vi.
- `split` để trống. Pilot chỉ nằm trong một tuần của năm 2023; không có bộ validation/test theo
  thiết kế 2024, nên chưa dùng để công bố F1, accuracy hoặc so sánh mô hình.
- `has_cvss31_label` xác nhận parse vector và nhãn khớp nhau; điểm nguồn đã được kiểm khoảng
  nhưng chưa tính lại bằng scorer CVSS. Cần hoàn tất bước đó trước khi khóa dataset.
- Năm trong CVE ID có thể khác năm của `published`; dùng `published` để lọc khoảng thời gian.

Các list được lưu dưới dạng JSON trong ô CSV. Không dùng `bool("False")` khi đọc CSV.

## 3. Người 2 làm ngay

Branch gợi ý: `feat/p1-scope-assets`, tạo từ `develop` đã cập nhật.
Quy trình lệnh Git: [hướng dẫn chung](06-git-workflow.md).

1. Viết `docs/scope.md` theo [Phase 0](phases/phase-0-pham-vi-va-thiet-ke.md): điều kiện nhận,
   loại, chưa rõ cho Web và mobile; cần bằng chứng sản phẩm/vai trò triển khai.
2. Mở `data/annotations/scope_review.csv`. Làm trước 10 dòng để kiểm quy tắc với nhóm,
   sau đó hoàn tất phần còn lại. Không bắt buộc mọi dòng được nhận vào phạm vi.
3. Với từng CVE, đọc `description`, mở các URL trong `reference_urls`, xác minh advisory/sản phẩm.
   Link được cung cấp để tra cứu, chưa được xem là bằng chứng scope đã kiểm chứng.
4. Điền các cột sau:

| Cột | Cách điền |
|---|---|
| `final_domain_tags` | JSON như `["web"]`, `["mobile"]`, `["web", "mobile"]`; chưa rõ hoặc ngoài phạm vi thì `[]` |
| `scope_status` | `included`, `excluded` hoặc `needs_review` |
| `reason` | Lý do cụ thể theo sản phẩm và quy tắc scope; không chỉ ghi một từ khóa |
| `evidence_url` | URL nguồn đã đọc và thực sự hỗ trợ quyết định; để trống nếu chưa có |
| `reviewer` | Tên người thực hiện phân loại |
| `reviewed_at` | Thời gian UTC ISO 8601 khi thực sự làm, ví dụ định dạng `YYYY-MM-DDTHH:MM:SSZ` |
| `scope_policy_version` | Phiên bản quy tắc đã dùng; cập nhật khi chốt hoặc đổi quy tắc |

`reviewer` ở đây là người ghi nhận quyết định scope, không phải yêu cầu review độc lập trước merge.
Giữ nguyên `cve_id`, mô tả, nhãn CVSS và `dataset_version` của mẫu. Dùng Git lưu các lần sửa annotation.
Không sửa Parquet hoặc CSV mẫu để tự đưa kết luận vào dataset; N1 sẽ xây bước áp dụng annotation.

`AV:N` không tự chứng minh Web. Nếu 30 dòng không có ca mobile phù hợp, ghi nhận thiếu coverage
và đề xuất sản phẩm/CVE bổ sung có advisory; không ép nhãn mobile cho đủ số lượng.
Ngoài CSV, tiếp tục thiết kế `config/assets.yaml` theo phân công Phase 0/1.

## 4. Người 3 làm ngay

Branch gợi ý: `test/p1-data-audit`, tạo từ `develop` đã cập nhật.
Trước tiên đọc [data contract](data_contract.md), cấu hình môi trường Python trên máy mình.
Với môi trường `.venv` đã tạo, cài phần dữ liệu:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
```

Đọc mẫu với dtype rõ ràng; có thể đặt đoạn sau vào script/notebook kiểm tra của N3:

```python
import json
import pandas as pd
from src.collect.prepare_handoff import SAMPLE_DTYPES

df = pd.read_csv(
    "data/sample/cves_sample.csv",
    dtype=SAMPLE_DTYPES,
    keep_default_na=False,
    na_values=[""],
    true_values=["True"],
    false_values=["False"],
)
for column in ("domain_tags", "scope_evidence"):
    df[column] = df[column].map(json.loads)
for column in ("published", "last_modified", "retrieved_at"):
    df[column] = pd.to_datetime(df[column], utc=True)

print(df.shape)
print(df["has_cvss31_label"].value_counts(dropna=False))
print(df["is_kev"].value_counts(dropna=False))
```

Kỳ vọng: 35 dòng, 30 dòng `has_cvss31_label=True`, 5 dòng False; 35 giá trị KEV chưa biết.
Tiếp theo tạo `reports/pilot_ml_audit.md`, ghi:

1. Máy N3 đọc đúng mẫu và metadata; có/không lỗi dtype, missing, ID trùng.
2. Tám metric có bao nhiêu mẫu mỗi lớp trên **451 ứng viên**, lấy từ
   `reports/pilot_label_distribution.json`; chỉ rõ lớp ít hoặc không có mẫu.
3. Mẫu 30 ứng viên có thiếu lớp nào so với 451; không suy diễn coverage toàn bộ Web/mobile.
4. Vì sao chưa chia train/validation/test từ tuần này; đề xuất kiểm tiếp khi có dữ liệu 2024.
5. Góp ý cho N1 về schema/nhãn, chuẩn bị `config/model.yaml` nếu phần Phase 0 này chưa có.

## 5. Người 1 tạo lại và bàn giao như thế nào?

Lệnh tạo gói từ snapshot hiện có trên máy N1:

```powershell
.\.venv\Scripts\python.exe -m src.collect.prepare_handoff --metadata data/processed/pilot_20260930T165232_235700Z/metadata.json
```

Chỉ chạy khi bốn file đầu ra chưa tồn tại. Script dừng nếu đã có file để bảo vệ annotation
N2 đã sửa. Khi cần mẫu/version mới, N1 phải giữ lại gói cũ và thống nhất đường dẫn/version mới.
N2/N3 đọc mẫu đã commit; không cần có raw/Parquet lớn trên máy mình.
Tái tạo đúng snapshot cần các file nguồn cùng checksum; tải API vào ngày khác có thể thay đổi dữ liệu.

Kiểm tra offline:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_collect_pilot tests.test_prepare_handoff -v
```

N1 commit script, tests, requirements, tài liệu và bốn file bàn giao nhỏ. Raw/Parquet lớn vẫn
theo `.gitignore`. Sau khi push, hai bạn còn lại cập nhật `develop` rồi bắt đầu branch công việc.
Việc tiếp theo của N1 là thu thập EPSS tại cùng ngày T, KEV có metadata và xây bước ghép dữ liệu.
Trước khi huấn luyện chính thức, nhóm còn cần mở rộng khoảng thời gian, kiểm scope, scorer và split.
