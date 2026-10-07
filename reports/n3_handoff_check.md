# N3 — Biên bản nhận gói Phase 1, bước 2–4

Ngày kiểm tra: 07/10/2026 (Asia/Saigon).
Hướng dẫn: `docs/phase-1-ban-giao.md`, bước 2–4.
Kết quả: môi trường dữ liệu, checksum và đọc thử bảng đều đạt.

## 1. Repo và môi trường

- Repo: `D:\Bảo mật web và ứng dụng\t08-cvss-epss`.
- Nhánh thực tế: `test/p1-data-audit`.
- Đã chạy `git fetch origin` thành công.
- `HEAD`, `develop` và `origin/develop` sau fetch cùng commit
  `45e5968e99966f709b7c010ea22a1b3bc591febb`.
- Nhánh N3 đã có và chứa đúng commit mới nhất của `develop`, nên không cần
  chuyển nhánh hoặc pull thêm. Giữ nguyên các thay đổi chưa commit có sẵn.
- `.venv` đã có; cài theo `requirements-data.txt` thành công, các dependency
  đều đã được đáp ứng. Kiểm tra import in ra `DATA ENV OK`.

| Thành phần | Phiên bản thực tế |
|---|---|
| Python | 3.13.16 |
| pandas | 3.0.6 |
| pyarrow | 25.0.1 |
| PyYAML | 6.0.3 |

Các lệnh đã chạy để cập nhật remote và kiểm tra môi trường:

```powershell
git fetch origin
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
.\.venv\Scripts\python.exe -c "import sys, pandas, pyarrow, yaml; print('DATA ENV OK'); print('Python:', sys.version.split()[0]); print('pandas:', pandas.__version__); print('pyarrow:', pyarrow.__version__); print('PyYAML:', yaml.__version__)"
```

`config/model.yaml` và `docs/model-plan.md` chưa có trong working tree hiện tại.
N1 cần tích hợp PR thiết kế Phase 0; việc này không cản trở đọc gói offline.

## 2. Checksum và giải nén

- ZIP nhận tại:
  `C:\Users\ASUS\Downloads\t08-p1-joined-20261005T164912_356960Z.zip`.
- Dung lượng: 19.868.418 bytes, khớp manifest.
- SHA-256 ZIP:
  `46c9b87228b42af7fd8da3d96c93da1fce522eea92cd40c10768756a67f0bf26`.
- Đối chiếu với `docs/handoffs/phase-1-joined-20261005.json`: `ZIP CHECKSUM OK`.
- Giải nén vào `data/processed/joined_pilot_20261005T164912_356960Z`.
- Cả bốn file có checksum và dung lượng khớp manifest:
  `4 FILES CHECKSUM OK`.

| File | Bytes | SHA-256 đã kiểm tra | Kết quả |
|---|---:|---|---|
| cves.parquet | 12839358 | `5adda10bf13407c582e3e33b716e55378757cea549a7fadaa85067dcc59ffc01` | OK |
| cves.csv | 54548474 | `5b69b6b2447a8b1ace12ca615ec75cab2f2995a124672440f233424f598be3ca` | OK |
| metadata.json | 6768 | `23856ea5eaf71336a134083f59e00b4fbc4c77b350811251aa9e8a3272cbf1b6` | OK |
| data_quality.md | 1211 | `859356f3b484b85e2bf42b4eccb4241009550d1d31c1fe7db106f293361b6996` | OK |

Các lệnh chính đã chạy ở bước 3 (chỉ giải nén sau khi checksum ZIP khớp):

```powershell
$handoffManifest = Get-Content -Raw -Encoding UTF8 -LiteralPath 'docs/handoffs/phase-1-joined-20261005.json' | ConvertFrom-Json
$handoffZip = Join-Path $env:USERPROFILE 'Downloads/t08-p1-joined-20261005T164912_356960Z.zip'
$actualHash = (Get-FileHash -LiteralPath $handoffZip -Algorithm SHA256).Hash
if ($actualHash -ne $handoffManifest.archive_sha256) { throw 'ZIP sai checksum; tai lai dung goi tu N1.' }
Expand-Archive -LiteralPath $handoffZip -DestinationPath 'data/processed'
```

Sau giải nén, đã chạy `Get-FileHash -Algorithm SHA256` và `Get-Item` cho từng
entry, dừng nếu checksum hoặc dung lượng khác manifest. Không ghi đè thư mục
đã tồn tại; thư mục đích chưa có trước lần giải nén này.

## 3. Đọc thử trên máy nhận

`dataset_version` đọc từ `metadata.json` và khớp manifest:

```text
pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z
```

Lệnh đọc thử thực sự đã chạy:

```powershell
.\.venv\Scripts\python.exe -c "import pandas as pd; d=pd.read_parquet('data/processed/joined_pilot_20261005T164912_356960Z/cves.parquet'); print('rows:',len(d)); print('unique:',d.cve_id.nunique()); print('EPSS:',d.epss.notna().sum()); print('KEV:',d.is_kev.sum()); print('scope pending:',d.scope_status.eq('needs_review').sum())"
```

| Kiểm tra | Thực tế | Kỳ vọng | Kết quả |
|---|---:|---:|---|
| Số dòng | 71653 | 71653 | OK |
| CVE ID duy nhất | 71653 | 71653 | OK |
| EPSS có giá trị | 68769 | 68769 | OK |
| Trong KEV | 325 | 325 | OK |
| Scope needs_review | 71653 | 71653 | OK |

Đã chạy thêm đối chiếu bằng Python: assert các số trên khớp kỳ vọng và
`dataset_version` khớp manifest, kết thúc bằng `RECIPIENT READ CHECK OK`.
Số dòng có `split` được gán: 0. `training_ready` trong metadata và manifest
đều là `false`.

## 4. Phạm vi kết quả

Biên bản này xác nhận hoàn tất bước 2–4 của hướng dẫn bàn giao cho N3.
Audit nhãn NLP, hỗ trợ lớp, trùng mô tả và đề xuất split sẽ được báo cáo riêng
theo `docs/phase-1-nguoi-3.md`.

Gói chưa khóa thành dataset v1; scope còn chờ duyệt và chưa sẵn sàng train.
Không trộn số liệu gói này với mẫu cũ 35 dòng. Bảng nguồn không bị chỉnh sửa.
ZIP, dữ liệu giải nén và `.venv` nằm ngoài commit theo `.gitignore`.
