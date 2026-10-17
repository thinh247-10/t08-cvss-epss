# Nhật ký quyết định — T08

Người ghi: Người 1 — Data/Integration, nhóm trưởng.

Tài liệu liên quan:
- [Kế hoạch chung](05-ke-hoach-phan-cong.md)
- [Data contract](data_contract.md)
- [Quy trình Git](06-git-workflow.md)

Các quyết định bên dưới là đề xuất ban đầu.
Chỉ chuyển sang “Đã thống nhất” sau khi thành viên liên quan review.

## D01 — Phạm vi bảo mật

- Đề xuất: phân tích lỗ hổng liên quan nền tảng Web và ứng dụng di động.
- Mục tiêu chính: giải thích vì sao CVSS cao chưa đủ để quyết định vá trước.
- AI phục vụ dự đoán vector CVSS từ mô tả.
- Không thực hiện khai thác CVE hoặc kiểm thử hệ thống thật.
- Người review: Người 2.
- Trạng thái: Chờ review.

## D02 — Dữ liệu và nhãn CVSS

- Nguồn dữ liệu CVE: NVD.
- Input của mô hình: mô tả CVE tiếng Anh.
- Nhãn dự đoán: tám thành phần AV/AC/PR/UI/S/C/I/A của CVSS v3.1.
- Giữ toàn bộ metric gốc và nguồn chấm để truy nguyên.
- Chọn một vector hợp lệ theo quy tắc trong data contract.
- Không đưa CVSS, EPSS hoặc KEV vào feature của mô hình.
- Người review: Người 2 và Người 3.
- Trạng thái: Chờ review.

## D03 — Khoảng thu thập và chia dữ liệu

- Phạm vi dự kiến: CVE công bố trong năm 2023–2024.
- Train: năm 2023.
- Validation: tháng 1–6/2024.
- Test: tháng 7–12/2024.
- Chạy pilot và kiểm tra số mẫu/lớp trước khi khóa split.
- Có thể mở rộng khoảng năm nếu dữ liệu không đủ.
- Không điều chỉnh split dựa trên kết quả test.
- Người review: Người 3; Người 2 kiểm tra độ phủ Web/mobile.
- Trạng thái: Chờ pilot và review.

## D04 — EPSS và KEV

- Lấy EPSS từ FIRST; không tự huấn luyện lại EPSS.
- Toàn bộ bảng ranking chính dùng điểm EPSS tại cùng một ngày.
- Ngày snapshot chưa chọn; sẽ điền khi bắt đầu thu thập.
- Lấy KEV từ catalog CISA, lưu bản gốc và thời điểm tải.
- CVE không có trong KEV không được coi là chắc chắn an toàn.
- So sánh tại snapshot hiện có; không coi đây là backtest dự báo lịch sử.
- Người review: Người 2.
- Trạng thái: Chờ chọn snapshot và review.

## D05 — Mô hình AI

- Baseline đề xuất: TF-IDF + Logistic Regression.
- Nhánh mô hình sâu: DistilBERT dùng một encoder chung và tám đầu phân loại.
- Dự đoán tám metric, ghép vector rồi tính Base Score bằng công thức CVSS.
- Đánh giá: F1 từng metric/lớp, exact-vector accuracy, Base Score MAE/RMSE.
- Cần chốt: DistilBERT là đầu ra bắt buộc hay phần mở rộng.
- Kế hoạch hiện tại: baseline bắt buộc; DistilBERT có giới hạn thời gian.
- Người review: Người 3; cả nhóm chốt phạm vi sau khi kiểm tra tài nguyên.
- Trạng thái: Chờ review.

### Cập nhật D05 ngày 17/10/2026 — N1 yêu cầu hoàn tất Phase 2

- Baseline bắt buộc đã chạy và tái lập: Dummy + TF-IDF; metric N1 khớp N3.
- Theo yêu cầu tiếp tục của N1, thử phần mở rộng DistilBERT trên RTX 3050 6 GB.
  Không ghi thay xác nhận review của các thành viên khác.
- Gate: cài backend CUDA, một smoke run 20 batch train, kiểm save/load và đo
  thời gian; chỉ full run nếu ước tính dưới 6 giờ máy gồm dự phòng.
- Cấu hình cố định trước train tại `config/distilbert.yaml`: một epoch,
  max_length 256, batch 8, accumulation 4, seed 42; không grid search.
- Quyết định một epoch dựa vào phạm vi thử nghiệm và tài nguyên, không dựa vào
  điểm test. Việc mở test của baseline trước đó phải được công khai; nhánh mới
  không chọn cấu hình hoặc checkpoint dựa trên test.
- Kết quả cuối ngày 17/10/2026: đã hoàn tất DistilBERT một epoch trên RTX 3050 6 GB; train 410,49 giây, toàn quy trình 2103,31 giây. Không tuning lại sau test. Log, cấu hình khóa và giới hạn: [báo cáo](../reports/p2_distilbert_run.md).
  Kết quả và quyết định cuối sẽ ghi tại `reports/p2_distilbert_run.md`.

## D06 — Xử lý dữ liệu thiếu và bàn giao

- Master có một dòng cho mỗi CVE ID.
- Giữ CVE thiếu CVSS hoặc EPSS trong master.
- Chỉ lọc các tập đủ điều kiện khi huấn luyện hoặc so sánh ranking.
- EPSS thiếu giữ null, không thay bằng 0.
- Chỉ xác định không thuộc KEV khi catalog tải đầy đủ thành công.
- Dùng tên cột và đường dẫn trong data contract.
- Thay dữ liệu, nhãn, snapshot hoặc split phải cập nhật dataset_version.
- Người review: Người 2 và Người 3.
- Trạng thái: Chờ review.

## D07 — Chính sách mô tả trùng cho cohort ML (2026-10-08)

- N1 yêu cầu tích hợp/sửa phần N3; code và thiết kế gốc từ `8b4b282` và `1182468`.
- Chính sách `exact-earliest-period-v1`: chuẩn hóa NFKC, gộp whitespace, strip,
  casefold; giữ mọi mẫu thuộc giai đoạn thời gian đầu tiên của mỗi mô tả.
  Loại bản trùng ở giai đoạn sau khỏi cohort ML dự kiến, không dời ngày/split.
- Không dùng target, EPSS/KEV hoặc kết quả model để chọn mẫu giữ; không sửa nhãn.
- Không xóa master hay cohort ranking. Trùng trong cùng giai đoạn vẫn được giữ.
- Đã triển khai preview offline và chạy thật: 67.912 -> 67.280 ứng viên;
  loại 632, còn 0 nhóm exact-description xuyên các split dự kiến.
- Trạng thái: đã triển khai/kiểm tra preview; **chưa khóa dataset/split cuối**.
  Phải tính lại trên cohort sau scope và kiểm scorer; ghi version/checksum mới.
- Gần trùng/product group chưa kiểm đầy đủ. Cần rà raw/CPE và ghi giới hạn còn lại
  trước khi train; không diễn giải 0 exact-duplicate thành không còn mọi leakage.
- Chi tiết: [bàn giao sau audit](phase-1-nguoi-3-sau-audit.md).

## Các thông tin cần bổ sung

### Cập nhật nghiệm thu kỹ thuật ngày 2026-10-10 — D08

Theo yêu cầu N1 hoàn thiện Phase 1 của cả nhóm, tích hợp code N2 `1a03bf8`,
N3 `8b4b282`, thiết kế N3 `1182468` và các bản sửa trên working tree.
Không yêu cầu review độc lập; không ghi thay chữ xác nhận đã tải gói mới của N2/N3.

- D03 chốt mốc thời gian như ban đầu, danh sách ID và split khóa tại `config/phase1.yaml`
  và artifact `t08-v1.0-20261010`. `config/project.yaml` giữ snapshot cũ để kiểm hash.
- D04 chốt EPSS 2026-09-29, công bố lệch ngày KEV phát hành/tải; chỉ phân tích snapshot.
- D07 được thay bằng `exact-near-earliest-v1`; 670 dòng loại khỏi ML, không loại khỏi
  master/ranking. MinHash/Jaccard có giới hạn recall; bucket lớn bị bỏ qua có thống kê.
- Cohort scope giới hạn theo 14 rule sản phẩm CPE + annotation tương thích snapshot:
  396 CVE (388 Web, 8 mobile), không tuyên bố bao phủ mọi CVE Web/mobile.
- ML dùng miền rộng 67.242 CVE để có đủ lớp. Báo riêng Web/mobile trên 219/69/108
  train/validation/test; giữ support 0 và hạn chế coverage mobile, không đổi mẫu số.
- Cho phép chia sẻ sản phẩm giữa split trong giao thức temporal hiện tại; không
  tuyên bố khả năng tổng quát hóa sang sản phẩm chưa gặp. Lưu 5.944 nhóm giao nhau.
- Tài sản là giả định; tái dựng mapping có version/evidence riêng vì file N2 gửi
  ngoài Git chưa có tại N1. PgHero dùng 3.0.1 khớp issue chính thức, không suy 3.0.4.
- Scorer Base đã kiểm toàn bộ 67.912 vector hợp lệ, không sai lệch với điểm nguồn.
  Scorer Environmental/hàng đợi và thí nghiệm model còn thuộc phase tiếp theo.
- Trạng thái: hoàn thành gate kỹ thuật v1; còn commit/push, gửi ZIP và nhận kết quả
  verifier trên máy hai bạn. Xem [biên bản bàn giao](phase-1-completion.md).

### Bổ sung D08 — nhận mapping N2 ngày 2026-10-11

Đã nhận file N2 gửi riêng sau khi build v1; đủ 5 cặp và đúng version gói cũ.
Giữ nguyên byte làm nguồn, ghi checksum thực nhận vì không khớp hash trong báo cáo cũ.
Không thay mapping v1 đã hiệu chỉnh hoặc build lại release. Chi tiết tại
[biên nhận mapping](../reports/n2_mapping_receipt.md). Ghi chú chưa nhận ở trên
chỉ phản ánh thời điểm quyết định ban đầu.

### Thông tin nhóm

- Ngày nộp chính thức:
- Tên thành viên Người 1:
- Tên thành viên Người 2:
- Tên thành viên Người 3:
- Đề cương và quy cách nộp đã được đối chiếu:
- Kết luận về phạm vi DistilBERT:
