# Dataset v1 — Báo cáo chất lượng Phase 1

Version `t08-v1.0-20261010`, ngày 2026-10-10. Kết quả từ lần chạy thật,
không phải dữ liệu fixture hoặc kết quả huấn luyện.

## Nguồn và tính toàn vẹn

NVD published 2023–2024, 82 trang/24 cửa sổ đã kiểm raw. EPSS snapshot 2026-09-29,
717 batch đã kiểm raw, missing giữ null. KEV phát hành 2026-09-30 và tải 2026-10-01 UTC;
membership dựa trên catalog đầy đủ của snapshot này. Nguồn không đồng ngày được công bố,
không diễn giải là dự báo 30 ngày đã được kiểm chứng.

Đối chiếu source manifests/checksum và dựng lại join offline: khớp mô tả, vector,
Base, EPSS/ngày và KEV; 71.653 ID duy nhất. Metadata nguồn theo từng raw page/batch
nằm trong `source_manifests.json`; không chọn điểm cao nhất trong nhiều nguồn CVSS.

| Chỉ số | Kết quả |
|---|---:|
| Master | 71.653 |
| Rejected | 2.884 |
| Thiếu vector CVSS 3.1 | 3.741 |
| Không Rejected nhưng thiếu nhãn | 857 |
| Thiếu mô tả | 0 |
| EPSS có / thiếu | 68.769 / 2.884 |
| KEV trong master | 325 |
| Base vector đối chiếu lại | 67.912 |
| Sai lệch điểm Base | 0 |

Scorer độc lập với cột điểm NVD, triển khai từ [FIRST CVSS 3.1, mục 7 và Appendix A](https://www.first.org/cvss/v3.1/specification-document).
Có kiểm Scope changed, PR phụ thuộc Scope, zero impact, Roundup và đầu vào sai phiên bản.
Environmental/Temporal không được suy từ điểm Base và còn thuộc phase phân tích bối cảnh.

## Scope có giới hạn

Policy `web-mobile-cpe-v1` dùng vulnerable application CPE + vai trò sản phẩm trên
nguồn chính thức (URL nằm trong `config/scope.yaml`), kết hợp annotation N2 chuyển
qua snapshot mới khi description bằng nhau và references có giao nhau.

30 annotation được giữ nguyên nguồn ghi nhận của N2; `annotation_transfer.csv`
ghi chuyển snapshot và 5 quyết định được sửa: Chrome desktop không tự thành Web-app;
bốn ca dịch vụ/module OS chuyển needs_review vì chưa đủ liên hệ trực tiếp app/SDK.
Không xóa dữ liệu gốc hoặc ghi đè annotation của N2 để giấu thay đổi.

| Kết quả scope | Số dòng |
|---|---:|
| included | 396 |
| Web | 388 |
| Mobile | 8 |
| excluded (gồm Rejected) | 2.895 |
| needs_review | 68.362 |
| Ranking đủ dữ liệu | 396 |
| KEV trong ranking | 3 |

Đây là cohort của danh sách sản phẩm đã công bố, không phải toàn bộ CVE Web/mobile.
CVE ngoài danh sách vẫn có thể thuộc Web/mobile; không báo accuracy/recall của bộ lọc
trên toàn bộ 71.653 dòng. Không chọn cohort theo điểm/KEV. Top-50 có mẫu số 396.

Đã xem 27 mẫu (tối đa hai mẫu theo hash ID mỗi rule trong 14 rule) từ mô tả/raw CPE,
kết hợp nguồn vai trò chính thức; các ví dụ/method ở `phase1_scope_spotcheck.md`.
Mẫu bị loại/chờ xem lại gồm Chrome desktop, các dịch vụ Android/EMUI,
GPAC đa dụng, kernel/driver và tool desktop trong 30 annotation. Không tuyên bố review độc lập.

## Nhãn và split ML cuối

| Cohort | Train | Validation | Test | Tổng |
|---|---:|---:|---:|---:|
| Đủ nhãn trước duplicate | 28.815 | 19.921 | 19.176 | 67.912 |
| ML cuối | 28.815 | 19.606 | 18.821 | 67.242 |
| Riêng Web/mobile trong ML | 219 | 69 | 108 | 396 |

Train 2023; validation 2024-H1; test 2024-H2, UTC, end exclusive. Không dùng năm trong
CVE ID. Chưa fit vectorizer hoặc model. ML miền rộng được ghi quyết định trước train
để giữ coverage lớp; đánh giá phạm vi môn học báo riêng và không trộn mẫu số.

Support đầy đủ 22 lớp × 3 split × 2 cohort trong `label_support.csv`.
Toàn miền có đủ tất cả lớp trong từng split. Riêng Web/mobile: AV:P vắng cả ba tập;
AV:A vắng validation/test. Khi tính macro-F1 phải giữ mapping đầy đủ và báo support 0.
Mobile rất ít: cả 8 dòng thuộc train; validation/test scoped chỉ có Web (69/108).
Không có mẫu mobile held-out nên chưa được công bố chất lượng model riêng cho mobile.
Case study mobile vẫn có bằng chứng để phân tích bối cảnh; không dùng train metrics
thay cho đánh giá độc lập. Mở rộng mobile sau này phải tạo dataset/protocol mới.

## Trùng và giới hạn đánh giá

Exact normalization: NFKC, gộp whitespace, strip, casefold. Giữ mọi mẫu ở giai đoạn
đầu tiên của component, loại các mẫu giai đoạn sau khỏi ML, không dời CVE qua thời gian.
Mô tả khác vector không bị sửa nhãn; đây là hạn chế của dự đoán chỉ từ mô tả.

Near audit: 3-token shingles, 32 MinHash seed 42, 8 band × 4, kiểm Jaccard >=0,95.
63.948 mô tả chuẩn hóa duy nhất; 400.471 cặp ứng viên, 71 cạnh nhóm vượt ngưỡng.
16 bucket >200 mục bị bỏ qua để giới hạn phép so; ghi rõ retrieval không bảo đảm recall.
Tổng 670 dòng bị loại (632 exact, 38 bổ sung do near). Sau loại không còn giao exact
hoặc component near đã phát hiện giữa split. Gần trùng ngữ nghĩa vẫn có thể còn.

5.944 nhóm CPE sản phẩm chia sẻ giữa split, liệt kê ở `product_overlap.csv`.
Giao thức là temporal evaluation có thể gặp lại sản phẩm; không khẳng định unseen-product
generalization. Thử product holdout nếu làm sau phải là thí nghiệm bổ sung, không thay test chính.
NVD last_modified có thể sau published; đây là chia thời gian trên snapshot hiện tại,
không khôi phục nội dung lịch sử đúng thời điểm công bố.

## Tài sản và bàn giao

Inventory 6 tài sản giả định đã qua validator. 5 mapping được tái dựng trong gói từ
evidence/config vì file mapping riêng của N2 chưa có trên máy N1. Không gán checksum
của file cũ cho file mới. PgHero sửa giả định sang 3.0.1 theo [issue chính thức](https://github.com/ankane/pghero/issues/439);
Hermes chỉ affected trong giả định xử lý JavaScript không tin cậy với tối ưu hóa;
flutter_downloader có điều kiện iOS riêng. Không coi scope bằng applicability.

Bổ sung 2026-10-11: đã nhận mapping N2 gửi riêng, đủ 5 cặp và đúng version nguồn cũ.
Lưu bản gốc cùng checksum thực nhận; mapping v1 và toàn bộ release giữ nguyên.
Xem [biên nhận và khác biệt nội dung/hash](n2_mapping_receipt.md).

118 test đạt; verifier đã chạy trên release và bản giải nén ZIP ở thư mục riêng.
Manifest/checksum và hướng dẫn đọc gói: [bàn giao v1](../docs/phase-1-completion.md).
Chưa có xác nhận N2/N3 đọc **gói mới** trên máy riêng; báo cáo cũ của họ là cho gói pilot.
