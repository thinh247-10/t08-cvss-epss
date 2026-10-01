# Người 1 — Lấy EPSS trong khi nhóm hoàn thiện Phase 0

Bước này thực hiện độc lập với việc N2 phân loại Web/mobile và N3 thiết kế mô hình.
Đầu vào là pilot NVD đã tải: 543 CVE, gồm cả 92 Rejected. Chưa dùng tập này để train
hoặc công bố kết quả xếp hạng. Có thể tiếp tục trên `develop` theo cách làm đã chọn.

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
| `probe.json` | Phản hồi kiểm tra ngày của CVE tham chiếu |
| `batch_001.json`, ... | Phản hồi gốc từng lô |
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
