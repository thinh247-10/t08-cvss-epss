# Người 2 — Nhận gói v1 và bắt đầu Phase 2

Ngày giao: 2026-10-11. Mốc code Phase 1: `e0b948b` trên `develop`.
Dataset: **`t08-v1.0-20261010`**. Đây là hướng dẫn công việc, chưa phải kết quả Phase 2.

## 1. Nhận code và dữ liệu

N1 gửi riêng `phase1_v1_20261010.zip` (38.599.819 byte). Git chỉ chứa code, tài liệu và
manifest. Không cần tải lại API, xin API key hoặc nhận `.env`/`.venv` của N1.

Trong terminal PowerShell tại thư mục repo có `src` và `README.md`:

```powershell
Get-Location
git status --short
```

Nếu còn thay đổi riêng, lưu/commit đúng file của mình trước khi chuyển branch;
không dùng reset/force để bỏ công việc. Khi đã lưu:

```powershell
git switch develop
git pull --ff-only origin develop
git switch -c feat/p2-cvss-scorer
```

Nếu branch đã tồn tại, dùng `git switch feat/p2-cvss-scorer` rồi kiểm tra nó chứa
bản `develop` mới. Không tạo lại hoặc xóa branch để né lỗi.

Nếu đã có `.venv` của riêng mình, giữ và kiểm tra interpreter. Nếu chưa có:

```powershell
py -0p
python -m venv .venv
```

Lệnh tạo môi trường dùng Python đang được `python` trỏ tới; cả nhóm ghi lại phiên bản
thực dùng. Nếu `python` không tồn tại, chọn interpreter đã cài từ kết quả `py -0p`.

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
```

Kiểm checksum ZIP bằng đường dẫn tải thực tế, ví dụ:

```powershell
Get-FileHash -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -Algorithm SHA256
```

Phải là `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
Giải nén vào `data/processed/` để có `data/processed/phase1_v1_20261010/metadata.json`.
Nếu thư mục đã tồn tại, kiểm bản đó trước, không ghi đè.

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

Cần thấy `PHASE1 RELEASE OK`. Gửi N1 version, kết quả và Python version thực tế.
Việc này xác nhận máy bạn đọc được gói, không phải yêu cầu review độc lập.

## 2. Phần đã làm xong — dùng lại

| Đầu vào | Cách dùng |
|---|---|
| `src/environmental/cvss_base.py` | Hàm `calculate_base_score(vector)` tính Base CVSS 3.1; dùng chung với N3 |
| `src/environmental/asset_inventory.py` | Loader/validator inventory đã triển khai |
| `config/assets.yaml` | 6 tài sản giả định, version `phase1-v1`; PgHero là 3.0.1 |
| Gói v1: `cve_asset_mapping.csv` | 5 cặp có điều kiện; dùng bản hiệu chỉnh này cho phần tiếp theo |
| Gói v1: `ranking_cohort.parquet` | 396 CVE, 388 Web + 8 mobile, 3 KEV; cùng tập ID cho ba chính sách |
| `reports/n2_mapping_receipt.md` | Ghi nhận file bạn gửi bổ sung và khác biệt với mapping v1 |

Đừng thay file mapping v1 bằng bản dataset cũ. Không sửa các file đã đóng gói;
nếu phát hiện lỗi, ghi CVE/bằng chứng cho N1 để tạo version mới khi cần.

## 3. Việc làm theo thứ tự

### Bước A — Kiểm chứng scorer chung, khoảng 2 giờ

Đọc `src/environmental/cvss_base.py`, parser `parse_base_vector` trong
`src/collect/nvd_collector.py` và các test scorer trong `tests/test_phase1_release.py`.
Đối chiếu [FIRST CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document).

- Tạo `tests/test_cvss.py` nếu cần bổ sung các ca chưa được phủ: Scope C/U, PR N/L/H,
  impact bằng 0, Roundup, vector thiếu/trùng/sai phiên bản.
- Expected score phải có nguồn/giải thích độc lập; không lấy output hàm đang test làm expected.
- Tạo `reports/p2_scorer_check.md`: vector, expected, actual, nguồn, lệnh test và kết quả thật.
- Không viết scorer Base thứ hai vào `cvss_environmental.py`. Environmental vẫn là Phase 3.

Chạy test hiện có trước; test mới chỉ chạy sau khi đã tạo:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_phase1_release -v
# Sau khi đã triển khai file test mới:
.\.venv\Scripts\python.exe -m unittest tests.test_cvss -v
```

Giao cho N3 tên hàm và cách import:

```python
from src.environmental.cvss_base import calculate_base_score
```

### Bước B — Ranking sơ bộ, khoảng 3 giờ, không chờ AI

Triển khai `src/analysis/compare_rankings.py` từ TODO hiện tại. Đọc mục 7 trong
`docs/data_contract.md` và sort policy trong Phase 3 trước khi code.
Input là `ranking_cohort.parquet` của v1; output `data/processed/rankings.csv`
đúng contract, một dòng/CVE, lưu version/cohort/policy và ngày EPSS.

- CVSS: `cvss_base_score` giảm dần, rồi `cve_id` tăng dần.
- EPSS: `epss` giảm dần, rồi `cve_id` tăng dần.
- KEV-first: `is_kev`, `epss`, `cvss_base_score` cùng giảm dần, rồi `cve_id` tăng dần.
- Rank bắt đầu từ 1. Cả ba dùng đúng cùng 396 ID; không merge nhân dòng.
- Viết `tests/test_rankings.py` cho tie-break, đảo thứ tự input, ID trùng/missing và version.
- Chỉ tạo thứ tự sơ bộ. Chưa dùng CVSS dự đoán thay điểm nguồn, chưa viết kết luận
  KEV-first tốt hơn vì chính nó dùng KEV để sort.

CLI cho module này chưa có; khi triển khai xong, ghi lệnh đã chạy vào
`reports/p2_ranking_smoke.md`, gồm 396 dòng, 3 KEV, schema, checksum output.
Chuyển quyền bảo trì module ranking cho N1 ở Phase 3; không cùng sửa một file song song.

### Bước C — Case study và lỗi model, khoảng 5 giờ

Tạo `docs/analysis-results.md`: khung 5 cặp từ mapping v1, nguồn vendor, giả định,
đường tấn công/điều kiện affected, lý do CR/IR/AR; chỗ chưa tính để trống có chú thích.
Hai cặp mobile là client, giữ `review_required` theo policy hiện có.

Khi N3 giao lỗi **validation**, tạo `reports/p2_validation_security_review.md`:
ít nhất 10 lỗi khác nhau nếu có đủ, chọn đa dạng metric và có Web/mobile khi tập
validation cho phép. Nếu có ít hơn 10 lỗi, ghi đúng số có, không tạo lỗi giả.
Mỗi dòng: CVE, trích mô tả liên quan, nhãn nguồn/prediction, giải thích sai khác,
mơ hồ mô tả hoặc giả thuyết lỗi model. Không tự sửa ground truth để khớp dự đoán.
Hiện validation không có mobile; ghi hạn chế này, không lấy mobile train giả làm validation.

N3 phụ trách `docs/model-card.md`; N2 gửi báo cáo lỗi để N3 tổng hợp, tránh đụng file.

## 4. Prompt triển khai bước đầu

```text
Đọc docs/phase-2-nguoi-2.md và scorer/test hiện có. Chỉ làm Bước A:
kiểm CVSS 3.1 Base theo FIRST, bổ sung test có expected độc lập nếu thiếu,
viết reports/p2_scorer_check.md với kết quả thật. Dùng calculate_base_score
hiện có; không tạo scorer thứ hai, không sửa dataset v1, chưa làm Environmental.
```

## 5. Lưu Git và bàn giao

Stage từng file đã thực sự tạo/sửa; ví dụ sau khi hoàn thành cả A/B/C:

```powershell
git status --short
git add tests/test_cvss.py reports/p2_scorer_check.md
git add src/analysis/compare_rankings.py tests/test_rankings.py reports/p2_ranking_smoke.md
git add docs/analysis-results.md reports/p2_validation_security_review.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat(phase2): verify scorer and prepare security analysis"
git push -u origin feat/p2-cvss-scorer
```

Không chạy dòng `git add` cho file chưa tồn tại. Có thể commit riêng từng bước.
Tạo PR: **base `develop`, compare `feat/p2-cvss-scorer`**, báo tests và giới hạn.
Không bắt buộc review độc lập; N1 kiểm tích hợp và merge khi sẵn sàng.
Gửi `rankings.csv` riêng kèm SHA-256/version, không force-add dữ liệu ignored.

Hoàn thành phần N2 khi: đọc được v1; scorer có bằng chứng; ranking sơ bộ chạy được;
case có điều kiện rõ; báo cáo lỗi validation có kết quả thật. Đang chờ prediction
thì chỉ đánh dấu phần đọc lỗi là chờ N3, không báo hoàn thành toàn bộ.
