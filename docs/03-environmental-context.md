# RQ3 — bối cảnh tài sản và CVSS Environmental

Cập nhật 2026-10-20, kết quả mô phỏng N2. Dataset t08-v1.0-20261010,
context phase3-context-v2, inventory phase1-v1. Không đánh giá hệ thống thật.

## 1. Phạm vi và cách hiểu

Base mô tả severity nội tại, không phải tự nó là lịch vá cho mọi tổ chức.
Environmental điều chỉnh severity theo requirements và các điều kiện có căn cứ,
không phải xác suất khai thác hay rủi ro riêng của tài sản. Policy nhóm dùng thêm
applicability, KEV, exposure và EPSS để thảo luận hành động.

Tham chiếu [FIRST v3.1](https://www.first.org/cvss/v3.1/specification-document)
và [Using EPSS](https://www.first.org/epss/using-epss), đọc 2026-10-19.
Snapshot EPSS 2026-09-29; KEV phát hành 2026-09-30, tải 2026-10-01 UTC.
Không tải lại dữ liệu để cải thiện kết quả hoặc gọi đây là kiểm định dự báo 30 ngày.

## 2. Kịch bản đã chọn và yêu cầu tài sản

Không còn chọn giữa bệnh viện/ngân hàng/thương mại điện tử: kịch bản của nhóm là
thương mại điện tử giả định. config/assets.yaml giữ nguyên release phase1-v1.

| Asset | Product/version giả định | Exposure | CR/IR/AR | Lý do |
|---|---|---|---|---|
| WEB-01 | Joomla/JoomGallery 3.3.3 | internet | M/H/H | sản phẩm một phần công khai; đơn hàng đúng và website sẵn sàng |
| API-01 | Discourse stable 2.8.13 | internet | H/H/H | tài khoản, token và truy cập dịch vụ |
| API-02 | chưa biết product/version | internal | H/H/H | backend thanh toán, cần kiểm kê trước applicability |
| ADMIN-01 | PgHero 3.0.1 | internal | H/H/M | dữ liệu vận hành/khách hàng; dashboard hỗ trợ vận hành |
| MOB-01 | Hermes trước fix commit trong inventory | client | H/H/M | tài khoản, dữ liệu giao dịch trên thiết bị người dùng |
| MOB-02 | iOS flutter_downloader 1.11.1 | client | H/H/M | dữ liệu tài khoản và tính đúng file tải |

Không khẳng định các version trên đang triển khai thật. Context v2 mở mapping có
nguồn, không đổi inventory. Version phần mềm cũ là đối tượng case, không phải
khuyến nghị triển khai hiện tại.

## 3. Cách tính có thể kiểm chứng

Dùng scorer Base chung và Environmental v3.1 trong src/environmental/.
CR/IR/AR theo inventory; chưa có chứng cứ control nên E/RL/RC và toàn bộ Modified
metrics giữ X. X kế thừa metric Base tương ứng, không nghĩa là zero.
MPR dùng Modified Scope. Có cap MISS, công thức Scope Changed lũy thừa 13,
hệ số 0.9731 và hai bước Roundup theo FIRST.

Không suy MAV từ internal, MAC từ WAF, MPR từ nhãn login hoặc MC/MI/MA từ backup.
Nếu có control mới cần ghi bằng chứng, reviewer thực tế và tăng context version,
không trình bày kế hoạch control như đã triển khai/kiểm chứng.

Lưu ý bản giao việc có giả định all-X luôn bằng Base: không đúng cho mọi Scope C.
Ví dụ AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, Base 9.9 nhưng Env all-X 10.0
theo calculator FIRST. Giữ chuẩn FIRST, regression ghi ở reports/p3_environmental_check.md.
Oracle 280 ca khớp; không thay cho N3 kiểm độc lập một case.

## 4. Mapping v2 và chất lượng bằng chứng

Nguồn r1 ở config/phase3_mapping.yaml; 9 cặp bổ sung tại
config/phase3_mapping_extension.yaml. Producer gắn context-v2 đồng nhất.
Output cve_asset_mapping.csv khóa cặp, giữ URL/ngày đọc/range/conditions/
limitations/reviewer. 15 cặp: 10 affected có điều kiện, 5 needs_review.

Bốn candidate Discourse chưa kết luận do cấu hình SMTP/CSP hoặc range xung đột
(2022-46168, 2023-22454, 22455, 22468). CVE-2023-22468 có vendor range khác mô tả
v1: giữ review, không tự nói 2.8.13 đã sửa hoặc chỉnh ground truth.
API-02 còn unknown product/version. Unknown không đồng nghĩa unaffected.

15 cặp không phải 15 hệ thống độc lập; phần mở rộng tập trung Discourse nên có
selection bias. Tất cả vẫn lấy CVE có trong v1; không sửa cohort 396 ID.
10 cặp tính được score, 5 exclusions có reason; source=observed.
Không dùng AI score trộn vào luồng chính.

## 5. Kết quả và hàng đợi

Năm case gốc có Base→Env: WEB 7.2→7.2; Discourse reset 8.1→8.8;
PgHero 7.5→9.3; Hermes 9.8→9.8; downloader 9.1→9.8.
Chi tiết 5 case và vector ở docs/analysis-results.md và environmental_scores.csv.

Queue giữ đủ 15 cặp: 8 patch, 7 review_required (gồm hai client có score).
Patch rank 1..8, review rank null. Policy context-v1:
KEV giảm → exposure internet/internal/isolated 2/1/0 → Env → EPSS → CVE/asset.
Client không có numeric weight. KEV thiếu không thành false; KEV present ở review
cần xác minh sớm, không được biến mất khỏi danh sách.

Sensitivity env-first hoán đổi exposure/Env sau KEV trên cùng 8 patch pairs.
Base-only/Env-only cũng trên đúng 8 cặp; không lấy top-50 của 396 CVE để so với 10
scored pairs. K=1/2, context vs env-first Jaccard=1 và 1/3; Base vs Env=0 và 1/3.
Top-1 không đổi giữa hai context policies; không ép kết quả phải đảo hết thứ tự.
Hướng delta là rank phương án đầu trừ rank phương án sau.

## 6. Hành động và giới hạn

Áp dụng playbook tại docs/04-patch-playbook.md: version check → staging →
backup/restore → duyệt thay đổi → rollout/rollback → xác nhận sau vá.
Review_required là hàng việc xác minh có owner, không phải cho phép trì hoãn không hạn.

Requirements do nhóm giả định, chưa được chủ nghiệp vụ xác nhận. Không đo SLA,
downtime, số sự cố ngăn chặn hoặc tiền/công tiết kiệm. KEV chỉ 3 ở cohort RQ2,
không có trong KEV không chứng minh an toàn. Scorer không tự chứng minh ứng dụng
affected hoặc control hiệu quả. Chờ N1/N3 bổ sung case/kiểm độc lập/hình, không
đánh dấu tiếp nhận hoặc merge thay nhóm.
