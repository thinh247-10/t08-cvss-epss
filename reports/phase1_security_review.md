# Phase 1 — Báo cáo rà soát bảo mật của N2

## 1. Tiếp nhận dữ liệu và môi trường

- Người thực hiện: `CanhLai`
- Ngày kiểm tra: `2026-10-07` (Asia/Ho_Chi_Minh)
- Branch: `feat/p1-scope-assets`
- Scope policy: `draft-v0.1`
- Inventory version: `draft-v0.3`
- Dataset version: `pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z`
- Schema version: `0.1`
- Trạng thái gói: joined pilot; scope và split đang chờ xử lý, chưa phải dataset v1.

Gói ZIP được nhận tại:

`D:\UIT\Tài Liệu\NT\NT213 - Bao Mat Web\T08\t08-p1-joined-20261005T164912_356960Z.zip`

Thư mục làm việc sau khi giải nén:

`data/processed/joined_pilot_20261005T164912_356960Z`

### Kiểm tra checksum

| Thành phần | SHA-256 | Kết quả |
|---|---|---|
| ZIP bàn giao | `46c9b87228b42af7fd8da3d96c93da1fce522eea92cd40c10768756a67f0bf26` | Khớp manifest |
| `cves.parquet` | `5adda10bf13407c582e3e33b716e55378757cea549a7fadaa85067dcc59ffc01` | Khớp manifest |
| `cves.csv` | `5b69b6b2447a8b1ace12ca615ec75cab2f2995a124672440f233424f598be3ca` | Khớp manifest |
| `metadata.json` | `23856ea5eaf71336a134083f59e00b4fbc4c77b350811251aa9e8a3272cbf1b6` | Khớp manifest |
| `data_quality.md` | `859356f3b484b85e2bf42b4eccb4241009550d1d31c1fe7db106f293361b6996` | Khớp manifest |

### Kiểm tra khả năng đọc

Đọc `cves.parquet` bằng pandas/pyarrow thành công và thu được:

| Chỉ số | Giá trị |
|---|---:|
| Tổng số dòng | 71.653 |
| CVE ID duy nhất | 71.653 |
| Có EPSS | 68.769 |
| Thuộc KEV | 325 |
| `scope_status=needs_review` | 71.653 |
| Rejected theo metadata | 2.884 |

Các số liệu khớp manifest, metadata và `data_quality.md`.

### Môi trường

| Thành phần | Phiên bản / đường dẫn |
|---|---|
| Python | 3.13.12 |
| Interpreter | `.venv\Scripts\python.exe` của repo |
| pandas | 3.0.6 |
| pyarrow | 25.0.1 |
| PyYAML | 6.0.3 |

API key không cần cho bước đọc và audit gói offline.

## 2. Cách hiểu và giới hạn của gói

- Gói chỉ chứa bảng đã ghép, metadata và báo cáo chất lượng; không chứa raw NVD/EPSS/KEV.
- EPSS dùng snapshot ngày `2026-09-29`; KEV phát hành ngày `2026-09-30` và được tải ngày `2026-10-01` UTC.
- `in_scope=false` cùng `scope_status=needs_review` nghĩa là chưa được xét vào cohort, không phải đã xác nhận ngoài phạm vi.
- Rejected vẫn nằm trong master để truy vết nhưng phải bị loại khỏi cohort nghiên cứu.
- Dữ liệu chưa có split và chưa sẵn sàng để train hoặc công bố ranking.
- Bảng ghép không chứa đầy đủ references/CPE/raw cho từng CVE; N2 phải dùng annotation mẫu và advisory chính thức để xác minh scope.

## 3. Trạng thái công việc N2

- [x] Cập nhật `develop` đến bản bàn giao Phase 1.
- [x] Tạo branch `feat/p1-scope-assets`.
- [x] Đọc `docs/scope.md`, `docs/data_contract.md`, `config/assets.yaml` và `docs/pilot-handoff.md`.
- [x] Xác minh checksum ZIP và bốn file trong gói.
- [x] Đọc đủ 71.653 dòng trên máy N2.
- [x] Rà 10 annotation đầu tiên và thống nhất quy tắc.
- [x] Hoàn thành đủ 30 annotation với evidence.
- [x] Chuẩn bị case Web/mobile và mapping CVE–tài sản.
- [x] Triển khai và kiểm thử loader/validator inventory.

## 4. Task 2 — Rà soát annotation scope

Đã rà thủ công đủ 30 CVE trong `data/annotations/scope_review.csv`, giữ nguyên các trường nguồn (`cve_id`, `description`, `reference_urls`, `dataset_version`) và điền đầy đủ quyết định, lý do, bằng chứng, người rà, thời điểm rà và phiên bản policy.

### Kết quả phân loại

| Trạng thái | Số lượng |
|---|---:|
| `included` | 19 |
| `excluded` | 10 |
| `needs_review` | 1 |
| **Tổng** | **30** |

| Nhãn miền cuối cùng | Số lượng |
|---|---:|
| `["web"]` | 15 |
| `["mobile"]` | 4 |
| `[]` | 11 |

Không có CVE nào bị ép vào Web/mobile khi bằng chứng chưa đủ. `CVE-2022-46489` được giữ ở `needs_review`: issue của GPAC xác nhận lỗi trong thư viện multimedia tổng quát nhưng chưa chứng minh vai trò triển khai Web/mobile theo policy hiện tại.

### Quy tắc đã áp dụng

- Chỉ dùng `included` khi nguồn dự án/vendor xác nhận vai trò Web hoặc mobile; mọi dòng `included` đều có ít nhất một nhãn và URL bằng chứng.
- Dùng `excluded` cho router/firmware, kernel/driver, desktop agent/tool và hệ thống công nghiệp không có vai trò Web/mobile được chứng minh.
- Dùng `needs_review` với `final_domain_tags=[]` khi lỗ hổng có thật nhưng bằng chứng triển khai chưa đủ để gán miền.
- Không suy luận miền chỉ từ CWE, CVSS vector, khả năng khai thác từ xa hoặc tên thành phần.

### Nguồn bằng chứng tiêu biểu

- Vendor: UNISOC product security bulletin, Huawei EMUI bulletin, ZTE advisory, Hitachi Energy alerts, Aruba advisory và JVN.
- Dự án/advisory chính thức: SimpleSAMLphp, JoomGallery, eXtplorer, Discourse, memos, PgHero và GPAC.
- Cơ sở dữ liệu chuyên biệt cho plugin WordPress: WPScan và Iese Web Invoice bulletin.

Mẫu 30 dòng này dùng để hiệu chỉnh cách áp dụng scope policy; chưa được xem là bằng chứng đánh giá accuracy của bộ lọc tự động.

## 5. Task 3 — Case study và applicability mẫu

Đã bổ sung năm ứng viên chờ phân tích vào `docs/03-environmental-context.md`:

- Web: `CVE-2022-43538` (ClearPass), `CVE-2022-46177` (Discourse), `CVE-2023-22626` (PgHero).
- Mobile framework/plugin: `CVE-2023-30470` (Hermes/React Native) và `CVE-2023-41387` (`flutter_downloader`/iOS).

Cả năm CVE đều có trong master 71.653 dòng. Việc chọn ứng viên là có chủ đích để
phân tích context, tách biệt với tiêu chí cohort định lượng và không dùng EPSS/KEV
để quyết định scope. Chưa case nào được mô tả như kết luận sẵn về ưu tiên vá.

### Inventory giả định

`config/assets.yaml` vẫn có sáu tài sản. Năm tài sản được gắn product/version giả định
có nguồn dải phiên bản để thử applicability; `API-02` tiếp tục để `null`. Các giả định
được ghi rõ, không được hiểu là cấu hình thật đã kiểm thử.

### Mapping bàn giao cho N1

| Thuộc tính | Giá trị |
|---|---|
| File | `data/processed/cve_asset_mapping.csv` |
| Số cặp | 5 |
| Applicability | 5 `affected` |
| Cặp Web | 3 |
| Cặp mobile/client | 2 |
| Dataset version | `pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z` |
| SHA-256 | `19b508ff510ac4b5ef424bc78a30c71e734f82ec11758208061a3b11725930f6` |

Đã kiểm tra schema, asset ID duy nhất, khóa CVE tồn tại trong master và version của
cả năm dòng. File mapping nằm trong `data/processed` nên bị Git ignore; cần gửi riêng
file cùng checksum cho N1, không dùng `git add -f`.

Hai cặp mobile có `exposure=client`. `affected` ở đây chỉ xác nhận applicability theo
product/version và điều kiện đã ghi; policy hàng đợi ban đầu vẫn phải giữ
`review_required` vì chưa có `exposure_priority` cho client. Task này không tự sửa
Modified Metrics và không tạo Environmental Score.

## 6. Task 4 — Loader và validator inventory

Đã triển khai `src/environmental/asset_inventory.py` với các giao diện:

- `validate_inventory(raw)`: kiểm tra cấu trúc YAML đã parse.
- `load_inventory(path)`: đọc UTF-8 YAML và trả `AssetInventory` bất biến.
- `load_assets(path)`: trả danh sách tuple các `Asset` đã kiểm tra.

Validator kiểm tra top-level metadata, danh sách tài sản không rỗng, `asset_id` duy
nhất, đủ trường theo data contract, chuỗi/list không rỗng, `domain` thuộc
`web/mobile`, `exposure` thuộc `internet/internal/isolated/client` và CR/IR/AR thuộc
`L/M/H`. `product` và `version` được phép `null` ở giai đoạn thiết kế.

Loader không tự ánh xạ tên sản phẩm thành `affected`, không thay Modified Metrics và
không gán `exposure_priority` cho client.

### Kiểm thử

- Lệnh mục tiêu: `.\.venv\Scripts\python.exe -m unittest tests.test_asset_inventory -v`
- Kết quả mục tiêu: 7/7 test đạt.
- Toàn bộ repo: 55/55 test đạt với `python -m unittest discover -v`.
- Các ca được kiểm: inventory thật, ID trùng, thiếu trường, CR/IR/AR sai,
  domain/exposure sai, product/version null hợp lệ và exposure client hợp lệ.
