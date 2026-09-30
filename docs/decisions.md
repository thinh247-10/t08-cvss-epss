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

## Các thông tin cần bổ sung

- Ngày nộp chính thức:
- Tên thành viên Người 1:
- Tên thành viên Người 2:
- Tên thành viên Người 3:
- Đề cương và quy cách nộp đã được đối chiếu:
- Kết luận về phạm vi DistilBERT: