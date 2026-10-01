# Người 1 — Ghép pilot NVD + EPSS + KEV

Đây là phần triển khai pilot của [Phase 1, mục 3.5](phases/phase-1-du-lieu-web-mobile.md).
N1 có thể làm khi N2/N3 chưa hoàn thành Phase 0. Dữ liệu ghép vẫn để scope/split
chưa xác định, không coi đây là dataset v1 để train hoặc kết luận về ưu tiên vá.

**Đã chạy và kiểm tra ngày 01/10/2026:** output nằm tại
`data/processed/joined_pilot_20261001T114053_995549Z/`. Parquet và CSV cùng có
543 ID duy nhất, 451 điểm EPSS, 92 thiếu và 2 CVE thuộc KEV. Checksum của bảng,
CSV và báo cáo khớp metadata. Scope và split vẫn chưa được chốt.

## 1. Nguồn đầu vào đã có

| Nguồn | Snapshot và số lượng |
|---|---|
| NVD | `pilot_20260930T165232_235700Z`: 543 CVE, cửa sổ công bố 01–07/01/2023 |
| EPSS | Ngày 29/09/2026, lần tải `20261001T093848_866775Z`: 451 điểm, 92 thiếu |
| KEV | Catalog `2026.09.30`, lần tải `20261001T112934_916972Z`: 1.730 CVE |

Ngày phát hành KEV sau ngày EPSS một ngày; ngày tải KEV sau ngày EPSS hai ngày UTC.
Thông tin này được giữ trong metadata. Không gọi đây là dự báo khai thác hồi cứu.

## 2. Code làm gì?

| File | Trách nhiệm |
|---|---|
| `src/collect/build_dataset.py` | Đọc ba manifest, kiểm tra nguồn/checksum, ghép, xuất pilot và báo cáo |
| `tests/test_build_dataset.py` | Kiểm tra ID trùng, sai snapshot, nguồn lỗi, null/zero, lưu/đọc CSV và Parquet |

Builder không gọi API, không đọc `.env`, không sửa annotations hay mẫu đang bàn giao.
Nó kiểm tra:

1. NVD pilot tải đủ cửa sổ đã yêu cầu; raw và bảng có cùng tập ID.
2. EPSS thuộc đúng NVD snapshot; mọi batch đúng ngày và phủ đủ tập ID.
3. Điểm EPSS trong bảng khớp JSON gốc; missing không bị thay bằng 0.
4. Catalog KEV hợp lệ, count/ID khớp và các trường membership khớp raw.
5. Join theo `cve_id`, không nhân hoặc mất dòng. Giữ cả Rejected và thiếu CVSS.
6. Tám nhãn khớp vector CVSS 3.1; điểm nguồn trong khoảng hợp lệ. Chưa tính lại công thức Base score.

Chỉ sau kiểm tra KEV mới gán `is_kev=false` cho ID không xuất hiện. False nghĩa là
không nằm trong catalog này, không chứng minh CVE chưa bị khai thác.

## 3. Chạy ghép pilot

Tại thư mục gốc repo, chạy khối PowerShell sau. Các biến chỉ giúp lệnh dễ đọc:

```powershell
$nvdMeta = "data/processed/pilot_20260930T165232_235700Z/metadata.json"
$epssMeta = "data/raw/epss/2026-09-29_20261001T093848_866775Z/metadata.json"
$kevMeta = "data/raw/kev/catalog_20261001T112934_916972Z/metadata.json"
.\.venv\Scripts\python.exe -m src.collect.build_dataset --pilot --nvd-metadata $nvdMeta --epss-metadata $epssMeta --kev-metadata $kevMeta
```

Với đúng ba snapshot trên, kiểm tra offline đã cho kết quả:

```text
total_records: 543
unique_cve_count: 543
rejected_records: 92
available_epss: 451
missing_epss: 92
in_kev: 2
not_in_kev: 541
unknown_kev: 0
scope_needs_review: 543
confirmed_in_scope: 0
assigned_split: 0
```

`confirmed_in_scope: 0` nghĩa là **chưa áp dụng đánh giá scope**, không phải đã kết
luận rằng pilot không có CVE Web/mobile. Tương tự, 451 ứng viên có nhãn/mô tả chưa
tự trở thành tập train hoặc cohort ranking hợp lệ.

Muốn chỉ kiểm tra mà không ghi output, thêm `--check-only` vào cuối lệnh.
Nếu dùng các snapshot mới ở tương lai, cần thay đường dẫn và không ép số lượng bằng ví dụ này.

## 4. File đầu ra

Mỗi lần build tạo `data/processed/joined_pilot_<run_id>/` mới:

| File | Cách dùng |
|---|---|
| `cves.parquet` | Pilot có các cột của master theo contract và thêm `epss_status` |
| `cves.csv` | Bản dễ xem, giữ missing bằng ô rỗng; list được mã hóa JSON |
| `metadata.json` | Ba nguồn, hash, version, thời gian, thống kê và giới hạn |
| `data_quality.md` | Báo cáo chất lượng ngắn để đọc cùng bảng |

Parquet giữ timestamp UTC, boolean nullable và list. Đọc CSV phải chỉ định dtype
như data contract; không dùng `bool("False")`. Không sửa bảng xuất bằng tay.
Metadata `status=complete` chỉ xác nhận lần build kỹ thuật hoàn tất; các cờ
`scope_reviewed`, `training_ready`, `ranking_ready` vẫn false.

## 5. Lưu code lên Git

N1 tiếp tục trên `develop` theo lựa chọn đã thống nhất. Sau khi chạy thật thành công:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_kev_client tests.test_build_dataset -v
git diff --check
git add src/collect/kev_client.py tests/test_kev_client.py docs/phase-1-nguoi-1-kev.md src/collect/build_dataset.py tests/test_build_dataset.py docs/phase-1-nguoi-1-ghep-pilot.md docs/phases/phase-1-du-lieu-web-mobile.md
git diff --cached --stat
git commit -m "feat(data): validate KEV and join the three-source pilot"
git push origin develop
git status --short
```

Lệnh add liệt kê cả phần KEV chưa commit. Nếu phần KEV đã commit trước đó, Git chỉ
stage thay đổi còn lại. Không thêm file `a`, `.env`, `.venv` hoặc dữ liệu lớn.
Không force push khi remote có thay đổi.

## 6. Còn có thể làm gì trong lúc chờ N2/N3?

Thứ tự sau khi pilot ghép chạy được:

1. **NVD đầy đủ:** viết phân trang, chia khoảng ngày, retry/checkpoint, cache và
   kiểm tra không bỏ sót hoặc nhân đôi CVE. Có thể kiểm tra trên cửa sổ nhỏ trước.
2. **Chất lượng dữ liệu:** thống kê nhãn thiếu/lớp hiếm, mô tả trùng, nguồn CVSS
   bất đồng và thời gian; cung cấp số liệu để N3 quyết định, không tự khóa split.
3. **Tái lập:** ghi lệnh chạy, phiên bản thư viện và nguồn input; kiểm tra nạp lại
   các snapshot đã lưu. Chuẩn bị mẫu ghép mới trong thư mục riêng nếu nhóm cần,
   không ghi đè mẫu/annotations đang được hai bạn chỉnh.

Chưa tự động mở rộng phạm vi nghiên cứu hoặc khẳng định đủ dataset chỉ vì đã có nhiều dòng.

## 7. Khi nào phải chờ công việc của hai bạn?

| Việc cần chốt | Đầu vào cần từ người khác | N1 làm sau khi nhận |
|---|---|---|
| Lọc cohort Web/mobile chính thức | N2: `docs/scope.md`, quy tắc, bằng chứng và đánh giá mẫu | Triển khai `filter_scope.py`, áp dụng có version |
| Khóa nhãn và train/validation/test | N3: model plan, audit lớp/missing/trùng/split; cùng nhóm thống nhất | Cập nhật config, tạo split cố định và metadata |
| Mapping CVE–tài sản | N2: `config/assets.yaml` và chứng cứ applicability | Tích hợp dữ liệu, không suy đoán affected |
| Nghiệm thu dataset v1 | Kết quả scope của N2 và kiểm tra nhãn/split của N3 | Khóa version, xuất bàn giao và báo cáo chất lượng đầy đủ |

Không cần review độc lập cho từng commit theo lựa chọn của N1. Tuy nhiên, các đầu vào
chuyên môn chưa có vẫn là việc chưa hoàn thành; không thay bằng xác nhận giả.
Khi đến một bước phụ thuộc các đầu vào trên, dừng bước đó và chuyển sang việc độc lập còn lại.
