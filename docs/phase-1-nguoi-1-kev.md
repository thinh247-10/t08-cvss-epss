# Người 1 — Thu thập catalog KEV

Làm sau bước [EPSS](phase-1-nguoi-1-epss.md). Có thể tiếp tục trên `develop`
trong khi N2/N3 hoàn thiện phần việc Phase 0. Bước này tải catalog KEV và kiểm tra
tính toàn vẹn; chưa ghép với pilot, chưa tạo bảng xếp hạng.

## 1. Các file

| File | Chức năng |
|---|---|
| `src/collect/kev_client.py` | Tải JSON KEV, kiểm tra, xuất bảng Parquet và metadata |
| `tests/test_kev_client.py` | Kiểm tra offline catalog lỗi/trùng/thiếu, ngày, raw/checksum và lỗi mạng |
| `config/project.yaml` | Đọc `project.dataset_version` và ngày EPSS đã chốt để ghi nhận chênh lệch thời gian |

Không cần thư viện mới hoặc API key. Script không đọc `.env`.

## 2. Nguồn dữ liệu

Dùng bản sao chính thức tại [cisagov/kev-data](https://github.com/cisagov/kev-data).
Nguồn `cisa.gov` trước đó trả 403 trên máy nhóm; GitHub của CISA đã tải được.
Theo [README của CISA](https://github.com/cisagov/kev-data/blob/develop/README.md),
repo này được đồng bộ sau khi catalog gốc cập nhật. Script ghi URL nguồn thật,
lưu nguyên bytes JSON và checksum để có thể truy lại dữ liệu đã dùng.

Đây là **catalog hiện tại tại lúc tải**. Nó không phải bản lịch sử tại ngày EPSS
29/09/2026. Không tự gán ngày EPSS cho KEV, cũng không chỉ lọc `dateAdded <= T` rồi
tuyên bố đã khôi phục được toàn bộ catalog lịch sử.

## 3. Chạy từ terminal PowerShell tại thư mục gốc repo

```powershell
.\.venv\Scripts\python.exe -m src.collect.kev_client
```

Script sẽ in:

```text
Catalog version: ...
Ngay phat hanh: ...
Tong CVE trong KEV: ...
Kiem tra count va ID: OK
Ngay EPSS tham chieu: 2026-09-29
Lech ngay phat hanh KEV - EPSS: ... ngay
Lech ngay tai KEV - EPSS: ... ngay (UTC)
Bang: data/raw/kev/catalog_<run_id>/kev.parquet
Metadata: data/raw/kev/catalog_<run_id>/metadata.json
```

Tổng CVE ở đây là **toàn bộ catalog**, không phải số CVE trong pilot 543 dòng.
Số lượng catalog có thể thay đổi giữa các lần tải; không hard-code theo ảnh cũ.

Nếu script báo lỗi thì gửi thông báo lỗi để xử lý. Không dùng lần tải `failed`
để kết luận CVE nào không nằm trong KEV.

## 4. Script kiểm tra gì?

- Có `catalogVersion`, `dateReleased` hợp lệ và timezone.
- Danh sách không rỗng; số entry bằng `count` nguồn khai báo.
- CVE ID đúng dạng và không trùng.
- Các trường bắt buộc dùng trong pipeline đầy đủ; ngày hợp lệ.
- `dateAdded` không sau ngày phát hành catalog.
- `knownRansomwareCampaignUse` giữ nguyên nếu có; nếu vắng thì null.

Đây là kiểm tra các điều kiện cần cho pipeline, không phải xác nhận toàn bộ
JSON Schema hay bảo đảm rằng KEV bao phủ mọi trường hợp khai thác ngoài thực tế.
Các trường ngoài bảng trích xuất vẫn còn nguyên trong JSON gốc.

## 5. Đầu ra

Mỗi lần chạy tạo thư mục mới, gồm:

| File | Nội dung |
|---|---|
| `catalog.json` | Toàn bộ dữ liệu nguồn, giữ cả các trường chưa dùng |
| `kev.parquet` | Bảng catalog, một dòng/CVE; mọi dòng có `is_kev = true` |
| `metadata.json` | Trạng thái, nguồn, phiên bản, thời điểm, checksum, số dòng và độ lệch với ngày EPSS |

Các cột quan trọng: `cve_id`, `is_kev`, `kev_date_added`, `kev_known_ransomware`,
`kev_vendor_project`, `kev_product`, `kev_vulnerability_name`, `kev_short_description`,
`kev_required_action`, `kev_due_date`, `dataset_version`, `retrieved_at`.

Pilot lưu `kev.parquet` trong thư mục từng lần tải thay vì ghi đè
`data/raw/kev.parquet`. Khi ghép ở bước sau phải dùng đường dẫn từ metadata của
một lần tải có `status: complete` và kiểm tra checksum.

Phân biệt ba mốc: ngày điểm EPSS, ngày phát hành catalog KEV và thời điểm tải KEV.
Độ lệch in ra là chênh lệch **ngày lịch UTC**; metadata còn giữ timestamp đầy đủ.
Hai ngày phát hành giống nhau cũng không biến đây thành thí nghiệm dự báo lịch sử.

## 6. Hiểu đúng trước khi ghép

- CVE nằm trong catalog: có tín hiệu khai thác đã được CISA ghi nhận.
- CVE vắng mặt: chỉ biết không có trong catalog đã kiểm tra, không chứng minh chưa bị khai thác.
- `dateAdded` là ngày đưa vào catalog, không phải ngày khai thác đầu tiên.
- Ransomware `Unknown` là chưa có xác nhận, không tương đương `false`.
- Đợi ghép thành công với catalog đã kiểm tra mới gán `is_kev = false` cho ID vắng mặt.
- KEV là tín hiệu/cơ sở của chính sách KEV-first, không phải thang điểm liên tục như CVSS/EPSS.

## 7. Lưu code sau khi chạy thật thành công

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_kev_client -v
git diff --check
git add src/collect/kev_client.py tests/test_kev_client.py docs/phase-1-nguoi-1-kev.md
git diff --cached --stat
git commit -m "feat(data): collect and validate CISA KEV catalog"
git push origin develop
git status --short
```

Không stage file `a`, `.env`, `.venv` hay raw data. Không force push nếu remote
có thay đổi. Gửi thống kê cuối terminal để xác nhận đầu ra trước bước ghép.

## 8. Bước tiếp theo

Ghép theo `cve_id`: NVD 543 dòng + EPSS snapshot đã lưu + catalog KEV đã kiểm tra.
Giữ đủ 543 dòng, missing EPSS vẫn null; chỉ lọc cohort nghiên cứu sau khi có scope
và audit chất lượng. Bước thu thập KEV này không hoàn tất phần việc của N2/N3.

Nguồn schema: [CISA KEV JSON schema](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json).
