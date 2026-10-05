# Người 1 — Lấy EPSS trong khi nhóm hoàn thiện Phase 0

Bước này thực hiện độc lập với việc N2 phân loại Web/mobile và N3 thiết kế mô hình.
Đầu vào là pilot NVD đã tải: 543 CVE, gồm cả 92 Rejected. Chưa dùng tập này để train
hoặc công bố kết quả xếp hạng. Có thể tiếp tục trên `develop` theo cách làm đã chọn.

**Tiến độ 03/10/2026:** pilot 543 CVE đã chạy xong. NVD toàn khoảng 2023–2024
đã có 71.653 CVE; chuyển đến **mục 9** để lấy EPSS cho tập mới và dùng resume.
Các mục 2–6 bên dưới giữ lại quy trình pilot ban đầu để tra cứu, không yêu cầu đổi
ngày snapshot đã chốt hoặc chạy lại pilot 543 CVE.

## 1. File được sử dụng

| File | Chức năng |
|---|---|
| `src/collect/epss_client.py` | Kiểm tra ngày EPSS; tải theo lô; kiểm tra phản hồi; lưu JSON, Parquet và metadata |
| `config/project.yaml` | Ghi ngày `epss.snapshot_date` dùng chung cho mọi CVE |
| `tests/test_epss_client.py` | Kiểm tra offline: ngày, giới hạn lô, missing/zero, lỗi mạng, checksum, lưu dữ liệu |
| `data/processed/pilot_20260930T165232_235700Z/metadata.json` | Trỏ tới pilot NVD và checksum của bảng đầu vào |

Không cần cài thêm thư viện nếu môi trường dữ liệu trước đó đã chạy thành công.
EPSS là API công khai; script không đọc `.env` và không sử dụng API key NVD.

## 2. Kiểm tra ngày đang có dữ liệu

Tại thư mục gốc dự án, chạy PowerShell:

```powershell
.\.venv\Scripts\python.exe -m src.collect.epss_client --probe
```

Script in ngày API trả về cho CVE tham chiếu và đoạn YAML tương ứng.
Đây chỉ là kiểm tra khả năng truy vấn; CVE tham chiếu không được thêm vào pilot.
Lệnh không thay đổi cấu hình. Nếu gặp lỗi mạng, xử lý lỗi trước khi tiếp tục.

## 3. Chốt ngày cho lần thu thập này

Mở `config/project.yaml`. Thay `snapshot_date: null` bằng ngày vừa nhận, đặt trong
dấu nháy kép, giữ nguyên mức thụt lề. Không tạo thêm một mục `epss` thứ hai.

Ví dụ minh họa cú pháp, **không phải ngày yêu cầu phải dùng**:

```yaml
epss:
  snapshot_date: "2024-01-15"
```

Nhấn Ctrl+S. Tất cả lô sẽ lấy cùng ngày này. Script kiểm tra ngày thực tế trong
phản hồi và dừng nếu không khớp. Chạy lại vẫn giữ ngày đã chốt, không tự đổi sang hôm nay.

Chỉ dùng một ngày T cho bảng so sánh snapshot. Không dùng `published + 30 ngày`
riêng cho từng CVE. Phân tích trên dữ liệu hiện có không tự trở thành thí nghiệm
dự báo khai thác trong quá khứ. Khi bổ sung KEV, ghi riêng thời điểm tải và ngày
phát hành catalog; nếu khác T thì cần công bố độ lệch hoặc đồng bộ lại.

## 4. Chạy lấy EPSS cho pilot

```powershell
.\.venv\Scripts\python.exe -m src.collect.epss_client --nvd-metadata data/processed/pilot_20260930T165232_235700Z/metadata.json
```

Script kiểm tra checksum bảng NVD, chia lô tối đa 100 ID và tối đa 2.000 ký tự
trong tham số `cve`, tải tuần tự, rồi kiểm tra ID/ngày/điểm/số dòng.
Một request riêng kiểm tra ngày snapshot bằng CVE tham chiếu trước khi tải các lô.

Kết quả cuối cần có:

```text
Ngay EPSS: <ngày đã chốt>
Tong CVE: 543
Co EPSS: <số API trả về>
Thieu EPSS: <số còn lại>
Bang: data/raw/epss/<ngày>_<run_id>/epss.parquet
Metadata: data/raw/epss/<ngày>_<run_id>/metadata.json
```

Không đoán trước số CVE có điểm. `Co EPSS + Thieu EPSS` phải bằng 543.
Không ép số missing bằng số Rejected: đó là hai thuộc tính từ hai nguồn khác nhau.

## 5. Đọc đầu ra

Mỗi lần chạy tạo thư mục mới, không ghi đè gói bàn giao cho N2/N3.

| File trong thư mục output | Ý nghĩa |
|---|---|
| `probe*.json` | Phản hồi kiểm tra ngày của CVE tham chiếu |
| `batch_001*.json`, ... | Phản hồi gốc từng lô; run mới thêm timestamp để tránh ghi đè |
| `epss.parquet` | Một dòng cho mỗi CVE đầu vào, gồm điểm hoặc giá trị thiếu |
| `metadata.json` | Ngày yêu cầu/trả về, thời điểm tải từng lô, tham số, checksum, số dòng, trạng thái |

Bảng có `cve_id`, `epss`, `epss_percentile`, `epss_date`, `epss_status`,
`dataset_version`, `retrieved_at`. Đây là bảng EPSS riêng, chưa phải master ghép.
Pilot đặt Parquet trong thư mục từng lần tải thay vì ghi đè `data/raw/epss.parquet`.

- `available`: API trả về điểm hợp lệ. Điểm 0 vẫn là một điểm hợp lệ.
- `not_returned`: phản hồi thành công, đã kiểm tra đủ dòng, nhưng không có ID đó.
  Điểm, percentile, ngày điểm để null; ngày yêu cầu nằm trong metadata.
  Trạng thái này không giải thích được nguyên nhân vắng mặt và không có nghĩa an toàn.
- Lỗi HTTP, sai ngày, thiếu trang hoặc JSON lỗi: lần tải thất bại, metadata là
  `failed`, không có bảng hoàn chỉnh để dùng tiếp. Không lấy lần `failed` để join.

JSON gốc được giữ để truy nguồn. `version` của REST API không được coi là phiên bản
mô hình EPSS; trường model version để null nếu chưa có bằng chứng từ nguồn.

## 6. Kiểm tra và lưu công việc

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_epss_client -v
git diff --check
git status --short
```

Sau khi tải thật thành công, xem diff rồi commit đúng các file này:

```powershell
git diff -- src/collect/epss_client.py config/project.yaml
git add src/collect/epss_client.py tests/test_epss_client.py docs/phase-1-nguoi-1-epss.md config/project.yaml
git diff --cached --stat
git commit -m "feat(data): collect fixed-date EPSS pilot snapshot"
git push origin develop
```

Nếu push bị từ chối do remote có thay đổi, giữ nguyên công việc và xử lý đồng bộ;
không force push. File `a` không thuộc bước này. `.env`, `.venv` và dữ liệu raw
không đưa vào commit; các quy tắc ignore của dự án đã có sẵn.

Hoàn tất bước này mới chuyển sang collector KEV và ghép theo `cve_id`. Việc chốt
scope, audit nhãn/split và train vẫn theo phần việc của nhóm, không được đánh dấu
hoàn tất chỉ vì thu thập EPSS chạy được.

## Tài liệu nguồn

- [FIRST EPSS API: CVE, ngày và giới hạn truy vấn](https://api.first.org/epss/)
- [FIRST API: phân trang, rate limit và phiên bản API](https://api.first.org/)

## 9. Lấy EPSS cho toàn bộ 71653 CVE và resume

NVD nguồn mới đã được kiểm tra đủ 71.653 ID duy nhất:
`data/processed/nvd_20261002T173033_137668Z/metadata.json`.
Giữ nguyên `epss.snapshot_date: "2026-09-29"` trong config cho lần so sánh này.
Không dùng bảng EPSS 543 CVE cũ để ghép vào NVD mới, không tự đổi sang ngày hiện tại.

Chạy:

```powershell
.\.venv\Scripts\python.exe -m src.collect.epss_client --nvd-metadata data/processed/nvd_20261002T173033_137668Z/metadata.json
```

Script sẽ in sớm:

```text
Metadata/checkpoint EPSS: data/raw/epss/<ngày>_<run_id>/metadata.json
Ngay EPSS: 2026-09-29; tong CVE: 71653; so lo: 717
Cache hop le: 0/717 lo
Lo 1/717: da kiem tra 100 CVE (API)
```

Giữ lại đường dẫn metadata/checkpoint. Lượt này có 717 lô và thêm một truy vấn
tham chiếu, nên có thể mất hàng chục phút tùy mạng/API. Chỉ chạy một tiến trình
cho cùng run và giữ máy hoạt động. Có thể Ctrl+C để dừng rồi resume sau.

Khi bị gián đoạn, dùng đúng đường dẫn metadata **của EPSS**, không phải NVD:

```powershell
# Thay bằng đường dẫn thật đã in ở đầu lượt EPSS.
$epssResume = "data/raw/epss/<ngày>_<run_id>/metadata.json"
.\.venv\Scripts\python.exe -m src.collect.epss_client --resume $epssResume
```

Resume kiểm tra input NVD, ngày snapshot, checksum, tham số và nội dung các lô
đã lưu rồi tải phần còn lại. Không sửa input/config ngày giữa chừng. Không dùng
lệnh khởi tạo run mới nếu mục đích là tiếp tục cùng lượt tải.

Các run tạo bởi collector mới có `collector_version: 2`. Không áp dụng resume
cho metadata pilot cũ chưa có trường này. Pilot cũ vẫn dùng được để đọc/ghép.
Nếu run đã complete, resume kiểm tra cache/bảng rồi trả lại kết quả, không tải lại.

Raw lỗi vẫn được giữ để tra cứu nhưng không được tính là lô hoàn thành. Chỉ các
lô đã kiểm tra hợp lệ được checkpoint; ghi metadata qua file tạm rồi thay thế.
`run.lock` chống ghi đồng thời. Nếu máy tắt đột ngột còn khóa, kiểm tra tiến trình
cũ trước khi xử lý; không xóa khóa khi collector vẫn chạy.

Kết quả cuối phải có `Tong CVE: 71653` và `Co EPSS + Thieu EPSS = 71653`.
Không đoán số thiếu bằng số Rejected hoặc số thiếu CVSS. Gửi thống kê và metadata
để kiểm tra trước bước ghép. Đây vẫn là dữ liệu chưa chốt scope/split.

Sau khi chạy thành công, lưu phần sửa code/tài liệu:

```powershell
git add src/collect/epss_client.py tests/test_epss_client.py docs/phase-1-nguoi-1-epss.md docs/phase-1-nguoi-1-nvd-phan-trang.md docs/phases/phase-1-du-lieu-web-mobile.md
git diff --cached --stat
git commit -m "feat(data): resume EPSS batches for the full NVD collection"
git push origin develop
```

Không stage dữ liệu raw, `.env`, `.venv` hoặc file `a`.

## 10. Kết quả toàn khoảng đã xác minh ngày 05/10/2026

- Manifest: `data/raw/epss/2026-09-29_20261002T173934_585836Z/metadata.json`.
- `status=complete`; đủ 717 batch cho 71.653 ID của NVD đã chọn.
- Có EPSS: 68.769; thiếu EPSS: 2.884; ngày điểm trả về duy nhất: 29/09/2026.
- Trong snapshot này, 2.884 dòng thiếu EPSS đều là Rejected, đã đối chiếu theo ID.
  Đây là kết quả kiểm tra của lượt này, không phải quy tắc để suy ra missing ở lượt khác.
- Builder đã đối chiếu checksum/raw, tham số ngày, tập ID và điểm trong Parquet.
- 24 bài kiểm tra `tests.test_epss_client` và `tests.test_build_dataset` đạt.

Không cần resume hay tải lại lượt đã hoàn thành. Đã ghép offline với NVD toàn khoảng
và KEV đã lưu; xem [bước ghép toàn khoảng](phase-1-nguoi-1-ghep-pilot.md#8-ghép-toàn-khoảng-20232024--đã-kiểm-tra-05102026).
