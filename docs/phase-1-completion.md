# Phase 1 — Nghiệm thu kỹ thuật và bàn giao v1

Ngày hoàn thiện: 2026-10-10. Version: **`t08-v1.0-20261010`**.

Phần triển khai của cả ba người đã được tích hợp trên máy N1 và chạy với dữ liệu thật.
Chưa train AI, chưa có kết quả so sánh ranking hoặc Environmental. Việc commit/push
và gửi gói v1 cho hai bạn là bước bàn giao còn lại; chưa xác nhận họ đã đọc gói mới.

## 1. Kết quả của từng người

| Người | Đã hoàn thiện và kiểm tra |
|---|---|
| N1 | Phân trang NVD, EPSS có resume, KEV, kiểm raw/checksum, ghép master, bộ lọc scope, builder v1 và ZIP/manifest |
| N2 | Tích hợp 30 annotation, sửa 5 quyết định cần thận trọng hơn; inventory 6 tài sản, 5 cặp applicability có điều kiện; scorer Base dùng chung |
| N3 | Audit nhãn/split, validator model, chính sách trùng/gần trùng, bảng support, EDA và cấu hình trỏ tới dataset cuối |

118/118 test đạt. Bộ kiểm release đọc lại 14 file, kiểm checksum, cohort/split,
vector/score và nhóm trùng. ZIP được giải nén vào thư mục riêng và kiểm lại.
Đây là kiểm trên máy N1, không giả làm xác nhận của N2/N3 trên máy họ.

## 2. Dữ liệu đã khóa

| Artifact/chỉ số | Số lượng |
|---|---:|
| Master, CVE ID duy nhất | 71.653 |
| Rejected giữ trong master | 2.884 |
| EPSS thiếu, giữ null | 2.884 |
| Cohort ranking Web/mobile | 396 |
| Web / mobile | 388 / 8 |
| KEV trong cohort ranking | 3 |
| Ứng viên đủ mô tả/nhãn trước duplicate | 67.912 |
| ML sau exact + near duplicate | 67.242 |
| Train / validation / test | 28.815 / 19.606 / 18.821 |
| Web/mobile trong ML theo ba split | 219 / 69 / 108 |

396 > 100 nên đủ để so top-50 có tính chọn lọc. Dùng cùng cohort ID cho cả ba cách
xếp hạng; chưa tạo các bảng xếp hạng ở Phase 1. Cohort nhỏ và chỉ có 3 KEV nên phải
trình bày mẫu số khi tính chỉ số; không tuyên bố dự báo khai thác lịch sử.

## 3. Quyết định phạm vi và ML

- Scope là **cohort sản phẩm có giới hạn** trong `config/scope.yaml`: CPE ứng dụng
  bị ảnh hưởng + vai trò chính thức của sản phẩm, cùng annotation thủ công tương thích
  snapshot. Không nhận mọi CVE chỉ vì có AV:N/CWE/keyword; không lọc bằng EPSS/KEV.
- 68.362 dòng chưa khớp quy tắc còn `needs_review`, không bị coi là đã chứng minh
  ngoài Web/mobile. 2.895 dòng excluded gồm 2.884 Rejected và 11 quyết định ngoài scope.
- ML dùng toàn miền đủ nhãn để giữ đủ lớp. Các model phải báo cả kết quả toàn miền
  và riêng tập `in_scope=true`; không gọi metrics toàn miền là metrics Web/mobile.
- Cả 8 mẫu mobile thuộc train; validation/test scoped chỉ có Web. Chưa có căn cứ
  đo chất lượng model riêng cho mobile; dùng hai case mobile cho phân tích bối cảnh.
- Split thời gian giữ nguyên ranh giới đã đề xuất. Dùng danh sách ID đã lưu;
  không random lại, không chọn siêu tham số bằng test.
- Loại 670 bản trùng ở các giai đoạn sau khỏi ML: 632 do exact, thêm 38 do các nhóm
  gần trùng phát hiện được. Không xóa khỏi master/ranking, không đổi nhãn nguồn.
- MinHash là sàng lọc gần đúng: có thể bỏ sót, đã ghi 16 bucket lớn bị bỏ qua.
  Không tuyên bố không còn mọi rò rỉ. 5.944 nhóm sản phẩm còn xuyên split; phép thử
  chính là chia theo thời gian với sản phẩm có thể gặp lại, không phải unseen-product.

## 4. Cấu trúc gói

Thư mục: `data/processed/phase1_v1_20261010/`.

| File | Cách dùng |
|---|---|
| `cves.parquet` | Master; giữ thiếu nhãn, Rejected, scope pending |
| `ranking_cohort.parquet` | Tập 396 ID chung cho Phase 3 |
| `ml_cohort.parquet` | Tập 67.242 ID và split chính thức cho Phase 2 |
| `ml_decisions.csv` | Quyết định giữ/loại từng ứng viên ML |
| `near_duplicate_edges.csv` | 71 cặp nhóm gần trùng được xác minh bằng Jaccard |
| `label_support.csv` | Tất cả lớp theo split, toàn miền và Web/mobile riêng |
| `product_overlap.csv` | Nhóm sản phẩm còn trùng xuyên split |
| `annotation_transfer.csv` | Kiểm chuyển 30 annotation cũ sang snapshot mới và 5 override |
| `cve_asset_mapping.csv` | 5 cặp hiệu chỉnh từ cấu hình/evidence; bản N2 gửi bổ sung được lưu riêng, xem biên nhận bên dưới |
| `phase1.yaml`, `scope.yaml`, `assets.yaml` | Bản chụp cấu hình của release |
| `source_manifests.json` | Metadata nguồn, raw paths/hashes và thời điểm |
| `metadata.json` | Trạng thái, số liệu, version, checksum, giới hạn |

ZIP: `data/processed/phase1_v1_20261010.zip`, 38.599.819 byte.

SHA-256: `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.

Manifest tracked: `docs/handoffs/phase-1-v1.json`. Không đưa ZIP/Parquet lên Git.
Gói không chứa `.env`, API key, `.venv` hoặc model weights.

Bổ sung 2026-10-11: đã nhận mapping N2 gửi riêng và đối chiếu đủ 5 cặp với release.
Giữ bản gốc ở `data/raw/handoffs/n2_mapping_received_20261011/`; gói v1 không đổi.
Xem [biên nhận](../reports/n2_mapping_receipt.md) về checksum khác báo cáo cũ và
hiệu chỉnh PgHero/Hermes/flutter_downloader. Không cần tạo lại ZIP vì nhận file này.

## 5. N2/N3 nhận gói: từng bước

1. Sau khi N1 push code, lưu thay đổi riêng rồi cập nhật `develop` bằng
   `git pull --ff-only origin develop`. Nếu báo phân kỳ, dừng để xem trạng thái;
   không force/reset và không merge lại các branch cũ đã được tích hợp nội dung.
2. Tự tạo `.venv` nếu chưa có; dùng môi trường đang chạy được của mình. Cài:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
```

3. N1 gửi ZIP qua kênh chia sẻ của nhóm. Kiểm SHA-256 trước khi giải nén:

```powershell
Get-FileHash -LiteralPath "C:\duong-dan-ban-tai\phase1_v1_20261010.zip" -Algorithm SHA256
```

4. Giải nén vào `data/processed/` để có đúng thư mục `phase1_v1_20261010`.
   Không ghi đè nếu đã có một bản khác; so checksum/version trước.
5. Tại thư mục repo có `src`, chạy:

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

Kết quả phải có `PHASE1 RELEASE OK`. Không cần API key/mạng/GPU cho bước kiểm này.
Gửi lại version và kết quả cho N1; không cần tải lại 71.653 CVE hoặc EPSS.

## 6. Người nào làm gì tiếp

- **N1:** commit/push code đã kiểm, gửi ZIP/manifest; giữ raw snapshot để tái tạo.
  Dùng `config/phase1.yaml` cho release. `config/project.yaml` vẫn là cấu hình thu
  thập cũ, giữ nguyên vì checksum nguồn đang tham chiếu nó.
- **N2:** dùng cohort ranking và 5 cặp giả định để bắt đầu Phase 3 theo kế hoạch;
  scorer Environmental/hàng đợi chưa được triển khai. Cặp client vẫn cần
  `review_required` trong policy exposure ban đầu; affected không tự sinh priority.
- **N3:** kiểm gói rồi bắt đầu Dummy/TF-IDF baseline Phase 2; chỉ description là
  feature, tám metric là target, dùng scorer `src.environmental.cvss_base.calculate_base_score`.
  Đánh giá cùng ID/version; DistilBERT vẫn cần kiểm thiết bị và ngân sách D05.

## 7. Tái tạo trên máy có raw

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -m src.collect.finalize_phase1
```

Builder đọc raw đã lưu, không gọi API; không ghi đè release đã tồn tại. Muốn build
bản khác, tạo config có version/output mới. Không chỉnh snapshot cũ để ép hash khớp.
Thời gian và checksum ZIP có thể khác khi build lại; ID/cohort/split cùng input và
policy phải như nhau. Dùng verifier và so manifest để nhận biết bản đang dùng.

EDA: `notebooks/01_eda.ipynb`; báo cáo: `reports/data_quality.md`.

## 8. N1 lưu Git và push khi đã xem bản sửa

Không cần branch mới; bản làm việc đang ở `develop`. Lệnh dưới stage đúng các file
của đợt này, không lấy file `a`, `.env`, `.venv` hay các thư mục dữ liệu lớn.

```powershell
git branch --show-current
git add README.md requirements-data.txt config/assets.yaml config/model.yaml config/phase1.yaml config/scope.yaml
git add data/annotations/scope_review.csv docs/03-environmental-context.md docs/data_contract.md docs/decisions.md docs/scope.md docs/phase-1-nguoi-2.md docs/phase-1-nguoi-3.md docs/phases/phase-1-du-lieu-web-mobile.md docs/handoffs/phase-1-v1.json docs/model-plan.md docs/phase-1-completion.md docs/phase-1-nguoi-3-sau-audit.md
git add reports/data_quality.md reports/full_ml_audit.md reports/full_ml_findings.csv reports/full_ml_label_counts.csv reports/n3_duplicate_policy_preview.md reports/n3_handoff_check.md reports/phase1_security_review.md reports/pilot_ml_audit.md reports/phase1_scope_spotcheck.md notebooks/01_eda.ipynb
git add src/collect/filter_scope.py src/collect/finalize_phase1.py src/collect/verify_phase1.py src/environmental/asset_inventory.py src/environmental/cvss_base.py src/model/audit_data.py src/model/baseline.py src/model/data_validation.py src/model/duplicate_policy.py src/model/near_duplicates.py
git add tests/test_asset_inventory.py tests/test_duplicate_policy.py tests/test_model_data_audit.py tests/test_phase1_release.py
git add docs/handoffs/n2-mapping-receipt-20261011.json reports/n2_mapping_receipt.md
git diff --cached --check
git diff --cached --stat
```

Khi danh sách đúng các file trên, commit/push:

```powershell
git commit -m "feat(data): finalize phase 1 scoped dataset and frozen ML splits"
git push origin develop
git status --short
```

Nếu push bị từ chối do remote có commit mới, không force push; kiểm tra và tích hợp
thay đổi mới trước. Sau khi push, gửi ZIP riêng cho N2/N3; Git không chứa gói dữ liệu.
