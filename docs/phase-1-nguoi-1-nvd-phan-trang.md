# Người 1 — NVD nhiều trang, cache và checkpoint

Đây là phần tiếp theo của [Phase 1 §3.1](phases/phase-1-du-lieu-web-mobile.md),
sau khi đã có pilot ghép ba nguồn. N1 làm độc lập trong lúc N2/N3 hoàn thiện
scope và thiết kế/audit mô hình. Bước hiện tại kiểm tra tháng 01/2023, chưa khóa dataset v1.

**Kết quả tháng 01/2023 đã xác minh ngày 03/10/2026:** 2.565 CVE duy nhất qua
6 trang; 228 Rejected và thiếu vector, 2.337 ứng viên có mô tả/vector. Các checksum,
giá trị trích xuất từ raw và checkpoint hoàn tất khớp nhau.
Metadata: `data/processed/nvd_20261002T170958_423579Z/metadata.json`.
Đây vẫn là NVD-only, chưa phải cohort Web/mobile hay tập train đã được chốt.

## 1. Các file và chức năng

| File | Chức năng |
|---|---|
| `src/collect/nvd_collector.py` | Parser đã có: lấy mô tả, chọn vector CVSS 3.1, tách tám nhãn |
| `src/collect/collect_nvd.py` | Điều phối tải: chia ngày, phân trang, retry, lưu raw/checkpoint và xuất NVD Parquet |
| `src/collect/build_dataset.py` | Đọc được cả NVD pilot một trang và NVD nhiều trang, kiểm tra raw trước khi ghép |
| `tests/test_collect_nvd.py` | Kiểm tra biên ngày, dữ liệu trùng, lỗi mạng, resume, cache hỏng và khóa chống chạy đồng thời |
| `tests/test_build_dataset.py` | Kiểm tra tương thích dữ liệu NVD nhiều trang với bước ghép |

Đây là cách tách phần điều phối khỏi parser để giữ lệnh kiểm tra JSON cũ hoạt động.
Không viết lại parser CVSS hoặc thay đổi tiêu chí chọn nguồn trong bước này.

## 2. Chuẩn bị

- Vẫn dùng `.venv` đã tạo, không cần cài thêm thư viện.
- Script khi tải thật đọc `NVD_API_KEY` trong `.env`, gửi qua header NVD.
- Không gửi hoặc chụp API key; checkpoint/metadata không chứa key.
- Khoảng ngày yêu cầu phải nằm trong `collection.start_date/end_date` của config.
- Không chạy nhiều collector NVD đồng thời để tránh cộng dồn request.

## 3. Xem kế hoạch trước khi tải

Chạy trong PowerShell tại thư mục gốc repo:

```powershell
.\.venv\Scripts\python.exe -m src.collect.collect_nvd --start-date 2023-01-01 --end-date 2023-01-31 --page-size 500 --plan
```

Lệnh chỉ in kế hoạch, không đọc API key hay gọi API, không tạo run mới.
Kết quả có một cửa sổ `2023-01-01T00:00:00.000` đến `2023-01-31T23:59:59.999`.

`--page-size 500` nghĩa là tối đa 500 CVE/request, **không phải chỉ lấy 500 CVE**.
Collector tiếp tục cho đến khi đủ tổng kết quả API khai báo trong cửa sổ.

Mặc định chia cửa sổ 31 ngày. Có thể chọn `--window-days`, giới hạn script là
1–90 ngày; giới hạn `--page-size` của script là 1–1.000. Đây là lựa chọn bảo thủ
của dự án, không phải tuyên bố về mức tối đa của API. Các cửa sổ không chồng ngày.

## 4. Tải thật tháng 01/2023

Bỏ `--plan`:

```powershell
.\.venv\Scripts\python.exe -m src.collect.collect_nvd --start-date 2023-01-01 --end-date 2023-01-31 --page-size 500
```

Ngay đầu chương trình in đường dẫn như:

```text
Checkpoint: data/raw/nvd/collection_<run_id>/checkpoint.json
Cache hop le: 0 trang, 0 CVE
Cua so 1/1, startIndex=0...
  Da luu 500/<tong API tra ve> CVE cua cua so nay
Cua so 1/1, startIndex=500...
```

Giữ lại đường dẫn checkpoint. Không nhập số `<run_id>` trong ví dụ như một đường dẫn thật.
Chương trình nghỉ 6,5 giây trước mỗi request theo chính sách thận trọng của dự án.
Cộng thêm thời gian phản hồi và retry nên có thể mất vài phút; đợi khi còn báo tiến độ.

Cuối lượt tải thành công sẽ có:

```text
Da luu: N / N CVE
So trang: ...; so cua so: 1
Da lay du khoang yeu cau: True
Rejected: ...; thieu vector: ...
Ung vien mo ta + vector, khong Rejected: ...
Bang: data/processed/nvd_<build_id>/nvd_cves.parquet
Metadata: data/processed/nvd_<build_id>/metadata.json
NVD ONLY: chua ghep EPSS/KEV, chua scope/split/train.
```

Không đoán trước N hoặc ép N bằng dữ liệu cũ. CVE ID có năm trước 2023 vẫn có thể
được trả về vì bộ lọc dùng ngày `published`, không dùng năm trong tên CVE.

## 5. Nếu lỗi mạng hoặc muốn tạm dừng

Ctrl+C cho phép dừng chương trình; các trang đã checkpoint vẫn được giữ.
Để tiếp tục, dùng **đúng đường dẫn đã in ra**:

```powershell
# Thay chuỗi bên dưới bằng đường dẫn thật của lần chạy.
$nvdCheckpoint = "data/raw/nvd/collection_<run_id>/checkpoint.json"
.\.venv\Scripts\python.exe -m src.collect.collect_nvd --resume $nvdCheckpoint
```

Lệnh resume không nhận thêm ngày/page-size/window-days; dùng kế hoạch đã lưu.
Nó đọc lại raw, kiểm checksum và tính cursor từ các trang hợp lệ trước khi tải tiếp.
Nếu run đã hoàn tất và output còn nguyên vẹn, resume dùng cache, không gọi API lại.

Không đổi các thiết lập NVD/CVSS/project của config giữa chừng rồi resume như cùng
một run. Nếu cần thay đổi thì bắt đầu run mới. Lỗi `totalResults` thay đổi, ID trùng
hoặc raw checksum sai cần được xem xét; không tự bỏ dòng hoặc sửa checkpoint để qua lỗi.

Mỗi run có `run.lock` chống hai tiến trình cùng ghi checkpoint. Dừng bằng Ctrl+C
bình thường sẽ gỡ khóa. Nếu máy/terminal tắt đột ngột và còn khóa, kiểm tra chắc
tiến trình cũ đã dừng trước khi xử lý khóa; không chạy thêm ở terminal thứ hai.

## 6. Đầu ra và quy tắc đầy đủ

Raw mỗi trang được lưu nguyên trạng trong `data/raw/nvd/collection_<run_id>/`.
Checkpoint lưu tham số, số dòng, checksum, thời điểm và chỉ tiến sau khi trang hợp lệ.
Raw bị lỗi vẫn giữ để kiểm tra, nhưng không được đưa vào danh sách trang đã hoàn thành.

Khi tất cả cửa sổ hoàn thành, tạo bảng mới trong `data/processed/nvd_<build_id>/`.
Metadata có `raw_layout: paged-v1`, danh sách `raw_pages`, phạm vi, tổng số CVE,
trạng thái, missing và checksum. Không ghi đè pilot 543 dòng đã ghép.

NVD có thể cập nhật trong quá trình tải. Script dừng khi thấy tổng kết quả thay đổi
hoặc ID trùng; các kiểm tra này không chứng minh một snapshot nguyên tử tại đúng
một thời điểm. Metadata công bố giới hạn này, kể cả khi resume sau nhiều giờ/ngày.

## 7. Sau khi tháng 01/2023 chạy thành công

Gửi thống kê cuối terminal và đường dẫn metadata. Sau khi kiểm tra kết quả:

1. Lưu code lên Git theo lệnh dưới.
2. Có thể mở rộng khoảng thu thập trong cấu hình đã chốt; vẫn giữ master chưa lọc.
3. Lấy EPSS cho tập CVE mới theo metadata mới. Bảng EPSS của 543 CVE cũ không đủ
   để ghép vào NVD tháng 01/2023 hoặc toàn khoảng 2023–2024.
4. Ghép các nguồn rồi thống kê nhãn/missing/phạm vi ứng viên để N2/N3 tiếp tục.

Builder đã đọc được `paged-v1` nhưng vẫn yêu cầu `--pilot`: chưa cho phép tự tuyên bố
dataset v1 khi thiếu xác nhận scope và audit/split. Không thay đổi mẫu/annotations
hai bạn đang làm chỉ vì đã có một lượt tải lớn hơn.

## 8. Commit sau khi chạy thật thành công

```powershell
git add src/collect/collect_nvd.py src/collect/nvd_collector.py src/collect/build_dataset.py tests/test_collect_nvd.py tests/test_build_dataset.py docs/phase-1-nguoi-1-nvd-phan-trang.md docs/phases/phase-1-du-lieu-web-mobile.md
git diff --cached --stat
git commit -m "feat(data): add resumable paged NVD collection"
git push origin develop
git status --short
```

Không stage `a`, `.env`, `.venv` hay dữ liệu raw/processed. Nếu push bị từ chối thì
kiểm tra thay đổi remote, không force push.

## 9. Mở rộng sang khoảng 2023–2024 sau khi lưu Git

Tháng 01/2023 đã xác minh thành công. Bước kế tiếp có thể thực hiện ngay, chưa
phụ thuộc vào kết quả scope của N2 hoặc audit nhãn/split của N3:

```powershell
.\.venv\Scripts\python.exe -m src.collect.collect_nvd --start-date 2023-01-01 --end-date 2024-12-31 --page-size 1000
```

Kế hoạch offline đã kiểm tra gồm **24 cửa sổ**, mỗi cửa sổ tối đa 31 ngày.
Tổng số trang và CVE phụ thuộc API; không hard-code trước. Đây là run mới bao phủ
toàn khoảng, bao gồm tải lại tháng 01/2023 trong snapshot mới; không xóa/ghi đè
run tháng đã có, không dùng checkpoint tháng để mở rộng phạm vi.

Chỉ chạy một tiến trình NVD và giữ máy hoạt động trong lúc tải. Giữ đường dẫn
checkpoint mới in ở đầu terminal; nếu gián đoạn thì resume đúng checkpoint đó.
Sau khi tải đủ, gửi thống kê và metadata để kiểm tra trước khi lấy EPSS cho tập mới.
Không cần làm EPSS riêng cho tháng trước khi bắt đầu run toàn khoảng này.

Thu thập master rộng theo config không có nghĩa đã nhận mọi CVE vào phạm vi nghiên cứu.
N2 vẫn xác nhận cohort Web/mobile; N3 vẫn audit nhãn và split trước huấn luyện.

Nguồn tham khảo: [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
và [NVD Start Here](https://nvd.nist.gov/developers/start-here). CLI và giới hạn bảo thủ
ở trên là lựa chọn triển khai của dự án; kết quả chạy thật là bước xác nhận tiếp theo.
