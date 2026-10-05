# Phase 1 — N1 bàn giao bảng ghép cho N2 và N3

Gói ngày 05/10/2026 là đầu vào để kiểm tra dữ liệu, chưa phải dataset v1 được khóa.
Hướng dẫn riêng: [Người 2](phase-1-nguoi-2.md), [Người 3](phase-1-nguoi-3.md).

## 1. N1 gửi gì?

Gửi cùng một file ZIP cho cả hai người, qua kênh chia sẻ file nhóm đang dùng:

`data/processed/handoffs/t08-p1-joined-20261005T164912_356960Z.zip`

Dung lượng khoảng 19 MiB. Không cần gửi `.env`, API key hoặc `.venv`.
ZIP được Git bỏ qua; push tài liệu không tự gửi ZIP lên GitHub.
N1 tự gửi file hoặc link tải cho nhóm; hướng dẫn này không tự gửi tin nhắn.

SHA-256 của ZIP:

```text
46c9b87228b42af7fd8da3d96c93da1fce522eea92cd40c10768756a67f0bf26
```

Manifest độc lập để xác minh: [phase-1-joined-20261005.json](handoffs/phase-1-joined-20261005.json).
ZIP chứa đúng một thư mục `joined_pilot_20261005T164912_356960Z` với bốn file:

| File | Chức năng |
|---|---|
| `cves.parquet` | Bảng 71.653 CVE, ưu tiên dùng cho Python |
| `cves.csv` | Cùng dữ liệu ở dạng CSV; phải đọc đúng dtype/null/list |
| `metadata.json` | Phiên bản, nguồn, checksum, ngày và giới hạn |
| `data_quality.md` | Thống kê kiểm tra kỹ thuật |

Raw NVD/EPSS/KEV không nằm trong gói. Đường dẫn nguồn trong metadata là đường dẫn
trên máy N1, không phải link tải. Gói đủ để đọc/audit bảng ghép; muốn chạy lại bước
ghép từ raw hoặc đối chiếu các metric nguồn khác, yêu cầu N1 gửi đúng snapshot/hash.
N2 dùng references trong mẫu cũ và advisory chính thức để xác minh scope; bảng ghép
không chứa đầy đủ references/CPE/raw của từng CVE.

## 2. N2/N3 cập nhật repo và môi trường

Mở đúng thư mục repo của mình, nơi có `.git`, `README.md`, `src` và `config`.
Không dùng đường dẫn máy N1 nếu máy mình đặt repo chỗ khác.

```powershell
Get-Location
git status --short
git branch --show-current
```

Nếu đang có thay đổi chưa commit, lưu chúng trên branch đang làm trước khi chuyển;
không reset/xóa để làm sạch. Khi sẵn sàng:

```powershell
git switch develop
git pull --ff-only origin develop
if (-not (Test-Path -LiteralPath ".venv")) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
.\.venv\Scripts\python.exe -c "import pandas, pyarrow, yaml; print('DATA ENV OK')"
```

N3 chưa cần Torch/Transformers để audit. API key không cần cho việc đọc gói offline.
Branch từng người được ghi trong hai hướng dẫn riêng; không cùng sửa trực tiếp `develop`.

## 3. Kiểm tra ZIP và giải nén

Lưu ZIP vào Downloads. Nếu lưu nơi khác, sửa `$handoffZip` đúng vị trí thật.
Chạy từng khối, lỗi thì dừng và gửi N1 thông báo.

```powershell
$handoffManifest = Get-Content -Raw -Encoding UTF8 "docs/handoffs/phase-1-joined-20261005.json" | ConvertFrom-Json
$handoffZip = Join-Path $env:USERPROFILE "Downloads/t08-p1-joined-20261005T164912_356960Z.zip"
$actualHash = (Get-FileHash -LiteralPath $handoffZip -Algorithm SHA256).Hash
if ($actualHash -ne $handoffManifest.archive_sha256) { throw "ZIP sai checksum; tai lai dung goi tu N1." }
Write-Output "ZIP CHECKSUM OK"
```

Sau khi thấy `ZIP CHECKSUM OK`:

```powershell
$handoffFolder = "data/processed/joined_pilot_20261005T164912_356960Z"
if (Test-Path -LiteralPath $handoffFolder) {
    Write-Output "Thu muc da ton tai; khong giai nen de ghi de. Kiem checksum o buoc sau."
} else {
    Expand-Archive -LiteralPath $handoffZip -DestinationPath "data/processed"
}
foreach ($entry in $handoffManifest.entries) {
    $entryPath = Join-Path "data/processed" $entry.path
    if ((Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash -ne $entry.sha256) {
        throw "File sai checksum: $entryPath"
    }
}
Write-Output "4 FILES CHECKSUM OK"
```

Không giải nén vào `data/sample` hoặc `data/annotations`.

## 4. Đọc thử trên máy người nhận

```powershell
.\.venv\Scripts\python.exe -c "import pandas as pd; d=pd.read_parquet('data/processed/joined_pilot_20261005T164912_356960Z/cves.parquet'); print('rows:',len(d)); print('unique:',d.cve_id.nunique()); print('EPSS:',d.epss.notna().sum()); print('KEV:',d.is_kev.sum()); print('scope pending:',d.scope_status.eq('needs_review').sum())"
```

Kỳ vọng: rows/unique **71653**, EPSS **68769**, KEV **325**, scope pending **71653**.
Ghi kết quả thật, Python/library versions và dataset_version trong báo cáo của mình.
Nếu đọc sai, gửi lỗi cho N1; không sửa dữ liệu trong ZIP hoặc bảng nguồn để che lỗi.

## 5. Cách hiểu dữ liệu và phối hợp

- 2.884 Rejected vẫn giữ trong master; loại khỏi cohort nghiên cứu.
- 67.912 CVE có mô tả/8 nhãn, không Rejected; chưa phải tập train hoặc Web/mobile đã xác nhận.
- `scope_status=needs_review`, `in_scope=false`, `split=null` là trạng thái chờ xử lý.
- EPSS ngày 29/09/2026; KEV phát hành 30/09, tải 01/10 UTC. Không diễn giải như dự báo lịch sử.
- Không sửa mẫu 35 dòng hoặc annotation 30 dòng để thay version bằng bảng mới.
- N2 ghi scope vào annotation; N3 ghi phát hiện vào báo cáo. N1 sửa pipeline và khóa version sau phối hợp.
- Thống kê/sửa parser/đề xuất split không đồng nghĩa đã train hay có kết quả F1.

## 6. N1 commit tài liệu rồi gửi nhóm

```powershell
git add docs/phase-1-ban-giao.md docs/phase-1-nguoi-2.md docs/phase-1-nguoi-3.md docs/handoffs/phase-1-joined-20261005.json
git diff --cached --stat
git diff --cached --check
git commit -m "docs(p1): hand off joined data and member tasks"
git push origin develop
```

Stage đúng 4 file; ZIP ở ngoài commit. Gửi ZIP/link tải cùng tên hướng dẫn riêng cho từng người.
Yêu cầu mỗi người báo nhận gói, checksum, số dòng, branch; sau đó bắt đầu phần việc của họ.
