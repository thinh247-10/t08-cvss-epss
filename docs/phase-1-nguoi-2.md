# Phase 1 — Người 2: scope, tài sản và bằng chứng

Đọc [hướng dẫn nhận gói](phase-1-ban-giao.md) và làm bước 2–4 trước.
Kế hoạch gốc: [Phase 1, mục 4](phases/phase-1-du-lieu-web-mobile.md).
Đây là phần tiếp theo của Phase 0, không yêu cầu viết lại scope/inventory từ đầu.

## 1. Branch và việc đầu tiên

Sau khi cập nhật `develop`, tạo branch một lần:

```powershell
git switch -c feat/p1-scope-assets
git branch --show-current
```

Nếu branch đã tồn tại, dùng `git switch feat/p1-scope-assets`, không tạo lại.
Đọc `docs/scope.md`, `docs/data_contract.md`, `config/assets.yaml` và `docs/pilot-handoff.md`.
Ghi thông tin nhận dữ liệu/môi trường vào `reports/phase1_security_review.md`.

## 2. Làm annotation trước — 10 dòng, rồi đủ mẫu 30 dòng

**File sửa:** `data/annotations/scope_review.csv` đã có trong Git.
Đây là mẫu từ pilot cũ; giữ nguyên `dataset_version`, ID, description và references của từng dòng.
Không thay version cũ thành version bảng 71.653 CVE. N1 kiểm nguồn trước khi áp dụng sang snapshot mới.

1. Đọc từng description và mở link trong `reference_urls`.
2. Xác minh sản phẩm/vai trò bằng advisory hoặc tài liệu chính thức.
3. Điền `final_domain_tags`, `scope_status`, `reason`, `evidence_url`, `reviewer`,
   `reviewed_at`, `scope_policy_version` theo [mẫu bàn giao, mục 3](pilot-handoff.md).
4. Dùng version policy trong `config/project.yaml` hiện tại; nếu cần đổi quy tắc,
   ghi đề xuất cho N1 để cập nhật đồng bộ, không tự dùng version khác mà không giải thích.
5. Kiểm 10 dòng đầu rồi làm phần còn lại. `needs_review` là kết quả hợp lệ nếu còn thiếu bằng chứng;
   ghi đã kiểm gì và cần bổ sung gì, không chỉ để nguyên dòng trống.

`included` phải có tags web/mobile và evidence. `excluded`/`needs_review` dùng tags rỗng,
lý do rõ ràng. Không suy Web từ AV:N; backend phục vụ điện thoại chưa phải mobile client.
Không ép mẫu phải có đủ cả ba trạng thái hoặc đủ mobile nếu nguồn không hỗ trợ.

Trong `reports/phase1_security_review.md`, ghi số dòng thực sự đã xem, kết quả từng trạng thái,
quy tắc chưa rõ, URL đã đọc và đề xuất cho N1. Đây không phải bằng chứng độ chính xác toàn bộ bộ lọc.

## 3. Case Web/mobile và applicability mẫu

**File sửa:** `docs/03-environmental-context.md`; `config/assets.yaml` nếu có căn cứ mới.

- Thêm danh sách 3–5 ứng viên case study, có CVE ID, sản phẩm, URL advisory và lý do chọn;
  ghi là chờ phân tích, không viết sẵn kết luận về ưu tiên vá.
- Tìm ca ảnh hưởng trực tiếp mobile client/SDK/framework. Nếu mẫu cũ không có,
  tìm ứng viên trong bảng lớn hoặc advisory, ghi nguồn và có/không thuộc dataset đang dùng.
- Phân biệt tiêu chí chọn case có chủ đích với cohort định lượng; không dùng EPSS cao/KEV
  để quyết định scope toàn bộ dataset. Case ngoài cohort phải ghi riêng.
- Chọn sản phẩm/phiên bản giả định cho tài sản khi có nguồn dải phiên bản bị ảnh hưởng.
  Chưa đủ căn cứ thì giữ null/needs_review; chưa biết không có nghĩa unaffected.
- Chuẩn bị khoảng 5–10 cặp tại `data/processed/cve_asset_mapping.csv` theo mục 8 data contract.
  Các cặp thuộc bảng lớn phải ghi đúng dataset_version của gói, không dùng version mẫu cũ.
- `exposure=client` vẫn hợp lệ; policy xếp hạng ban đầu giữ cặp affected ở review_required
  khi chưa có quy tắc exposure phù hợp. Không tự gán 0/internet.

File mapping trong `data/processed` bị Git bỏ qua. Gửi file cùng checksum và dataset_version
cho N1 qua kênh chia sẻ; báo cáo tracked ghi tên file, số cặp, nguồn và giới hạn.
Không dùng `git add -f` để đưa mọi dữ liệu lớn vào Git.

```powershell
Get-FileHash -LiteralPath "data/processed/cve_asset_mapping.csv" -Algorithm SHA256
```

## 4. Code cần làm ở Phase 1

**File triển khai:** `src/environmental/asset_inventory.py` (hiện còn TODO).
Nhiệm vụ: đọc inventory YAML, kiểm ID duy nhất, đủ trường, domain/exposure/CR/IR/AR,
có rationale/assumptions, cho phép product/version null ở giai đoạn thiết kế.
Không tự ánh xạ tên sản phẩm thành affected và không tự sửa Modified Metrics.

Viết kiểm tra có ý nghĩa tại `tests/test_asset_inventory.py`: ID trùng, thiếu trường,
metric sai, inventory null version hợp lệ, exposure client được nhận là dữ liệu inventory.
Client được nhận không có nghĩa đã có thứ hạng ưu tiên số.
Chạy test này sau khi đã tạo; nó chưa tồn tại chỉ vì hướng dẫn có tên file.

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_asset_inventory -v
```

Prompt có thể dùng:

```text
Tôi là N2 Phase 1. Đọc docs/data_contract.md, docs/scope.md và config/assets.yaml.
Chỉ triển khai loader/validator trong src/environmental/asset_inventory.py và test tương ứng.
Cho phép product/version null; exposure client hợp lệ cho inventory nhưng chưa có priority số.
Không gọi API, không sửa dataset, không tự suy affected hoặc điều chỉnh CVSS.
Trước khi sửa hãy đọc giao diện hiện có và giữ phạm vi thay đổi nhỏ.
```

Scorer Base/Environmental dùng chung cần phối hợp trước khi khóa dữ liệu/đánh giá mô hình;
triển khai scoring đầy đủ theo phase liên quan, không lấy loader này làm bằng chứng scorer đã hoàn tất.

## 5. Commit, PR và bàn giao

Kiểm tra diff rồi stage các file thực sự đã hoàn thành; chỉ chạy khối dưới khi đã tạo các file mới:

```powershell
git diff --check
git add data/annotations/scope_review.csv reports/phase1_security_review.md src/environmental/asset_inventory.py tests/test_asset_inventory.py config/assets.yaml docs/03-environmental-context.md
git diff --cached --stat
git commit -m "feat(scope): review samples and validate asset inventory"
git push -u origin feat/p1-scope-assets
```

Tạo PR base `develop`, compare `feat/p1-scope-assets`. Ghi test thực sự đã chạy,
dataset/policy version, số annotation, link gói mapping và những quyết định còn thiếu.
Không yêu cầu review độc lập trước merge theo quy ước nhóm; xung đột thì xử lý,
không dùng force push lên develop. Có thể bàn giao từng phần, không chờ làm xong tất cả.

Checklist phần N2 trước nghiệm thu Phase 1:

- [ ] Nhận đúng gói, checksum và đọc đủ 71.653 dòng trên máy mình.
- [ ] Đã xem mẫu scope, ghi evidence/lý do/phiên bản; nêu rõ phần còn needs_review.
- [ ] Loader inventory chạy, test đạt; tài sản giả định và advisory thật được phân biệt.
- [ ] Mapping mẫu và ứng viên Web/mobile có nguồn; thiếu coverage được báo trung thực.
- [ ] N1 nhận đủ annotation/quy tắc để chạy bộ lọc; kết quả lọc toàn bộ còn cần đối chiếu.
- [ ] Chỉ xác nhận cohort chính thức sau khi N1 áp dụng, thống kê và cùng kiểm các giới hạn.
