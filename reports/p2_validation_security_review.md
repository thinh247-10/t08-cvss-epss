# Phase 2 N2 — Review bảo mật lỗi validation

**Trạng thái: ĐÃ REVIEW 13 CVE lỗi validation; không còn chờ prediction N3.**
Người review: CanhLai; ngày 2026-10-15 (Asia/Saigon).
Dataset `t08-v1.0-20261010`; model `tfidf-v1-candidate-1`.

## 1. Nguồn và xác minh

N3 đã push branch `feat/p2-nlp-baseline`, commit
`a5c0c16` của repository `thinh247-10/t08-cvss-epss`.
Đọc trực tiếp Git blobs tại commit này, không cần merge code N3 để review.

- `reports/validation_errors_n2.csv`: 10 lỗi đầu được N3 chọn theo CVE ID.
- `reports/validation_errors.csv`: 12.083 CVE lỗi validation.
- `docs/handoffs/phase-2-model.json`: xác định dataset/model và hash bàn giao.
- `reports/validation_error_analysis.md`: nhận xét N3, tham khảo sau khi đối chiếu
  description/nhãn; phần nhận định bên dưới là review N2.

Hash Git blob LF của mẫu 10 dòng:
`9580621b7843eac40145a789ff828fc434a7161f61f0b5be9c37a07ff8786016`.
Manifest N3 ghi bản Windows CRLF, 6.474 byte, hash
`fe7e466ec7375f5b09f53b9f4164645fab172c030f583c6db152cf50dea3c599`.
Đã kiểm chuyển LF -> CRLF cho ra đúng byte count/hash này; khác biệt là xuống dòng.

N2 nối CVE ID với `ml_cohort.parquet` v1 trên máy, kiểm description, tám nhãn,
vector nguồn, dataset version và split validation. Kiểm nhãn dự đoán khớp vector,
tính lại Base nguồn/dự đoán bằng scorer chung. Đây là xác minh artifact review,
không phải tái chạy model trên máy thứ hai. `predictions.csv` đầy đủ và joblib
vẫn cần bàn giao riêng nếu N1 làm reproduction.

## 2. Cách chọn và giới hạn

Review đủ 10 ID N3 đề xuất; thêm hai lỗi đầu thuộc scope Web trong bảng đầy đủ
(Apache HTTP Server và Discourse), cùng lỗi AV đầu theo CVE ID (HiveOS, cũng sai AC).
Tổng 13 CVE khác nhau, phủ lỗi của cả AV/AC/PR/UI/S/C/I/A.
Đây là mẫu có chủ đích; không lấy tỷ lệ trong mẫu làm accuracy toàn validation.

Validation có 19.606 CVE, 69 Web và 0 mobile theo scope v1. Trong 69 Web có
53 lỗi exact-vector ở bảng N3. Mẫu review có hai CVE được scope v1 nhận Web.
Các plugin WordPress trong 10 ID đầu vẫn có tags rỗng trong v1: mô tả Web không
tự biến chúng thành thành viên cohort định lượng. Không thay scope hoặc nhãn.
Năm case mapping ở train không được dùng thay lỗi validation mobile.

## 3. Review từng CVE

Nhãn ghi nguồn -> dự đoán. Trích đoạn lấy từ description v1 đã đối chiếu.
Base là nguồn -> dự đoán. Các giải thích dưới đây đánh giá ý nghĩa bảo mật của
sai khác; chưa kiểm chứng lại advisory riêng từng CVE hoặc attribution của model.

| CVE | Đoạn mô tả liên quan | Metric sai | Base | Nhận định N2 |
|---|---|---|---|---|
| CVE-2010-10011 | “path traversal”; “launch the attack remotely” | PR:N->L | 7.5->6.5 | Model thêm yêu cầu tài khoản quyền thấp. Remote chỉ mô tả vị trí attacker, không chứng minh PR. Description thiếu cơ chế xác thực nên chưa đủ quyết định nguồn đúng tuyệt đối; cần advisory nếu xác minh nhãn. |
| CVE-2012-6664 | “read or write arbitrary files”; “get” / “put” | I:H->N | 9.1->7.5 | Giữ tác động đọc nhưng bỏ mất Integrity dù mô tả có nhánh ghi file. Đây là dấu hiệu trực tiếp cho hậu quả sửa dữ liệu; không tự thêm thực thi mã hoặc Availability chỉ từ chữ arbitrary. |
| CVE-2014-125110 | “wfu_ajax_action_callback”; “cross site scripting” | PR:L->N; S:U->C; C:N->L | 3.5->6.1 | Callback AJAX và XSS chưa cho biết ai có quyền gọi, nạn nhân hay security authority. Mẫu dự đoán XSS phổ biến là giả thuyết; cần đường xử lý thực để phân biệt PR/S/C. |
| CVE-2014-125111 | “unknown functionality”; “cross site scripting” | PR:L->N; S:U->C; C:N->L | 3.5->6.1 | Mô tả Wp-Insert lược bỏ quyền và hậu quả đọc dữ liệu. Không nhắc login không chứng minh PR:N; tên XSS không tự quyết định Scope changed. |
| CVE-2015-10123 | “unautheticated remote attacker”; “authenticated user then views that data” | PR:N->L; UI:R->N | 8.8->8.8 | Quyền attacker và quyền người xem là hai chủ thể. Prediction gán điều kiện xác thực sang attacker và bỏ tương tác của nạn nhân. Hai lỗi bù nhau về Base: sai số điểm 0 vẫn sai vector/điều kiện khai thác. |
| CVE-2015-10129 | “admin/inc/auth.inc.php”; “incorrect comparison” | PR:N->H; C:H->L | 5.9->2.2 | Đường dẫn admin/auth không chứng minh attacker phải có quyền cao; lỗi ở kiểm tra xác thực có thể chính là vượt kiểm tra đó. Description cũng chưa đủ định lượng bí mật bị lộ. Giữ AC:H đúng không cứu được hai metric còn lại. |
| CVE-2015-10131 | “admin_page_load/admin_page”; “cross site scripting” | PR:L->N; S:U->C; C:N->L | 3.5->6.1 | Tên hàm admin không xác định quyền attacker hay ai xem nội dung. Phải có bằng chứng gọi hàm/đọc dữ liệu để kiểm nhãn; chưa thể coi mọi XSS có cùng vector. |
| CVE-2015-10132 | “argument Spreadplugin”; “cross site scripting” | PR:L->N; S:U->C; C:N->L | 3.5->6.1 | Mô tả chỉ rõ tham số, thiếu đường thực thi và ranh giới quyền. Bốn mẫu XSS gần nhau cùng lỗi là quan sát trong mẫu, không chứng minh tần suất lỗi XSS toàn mô hình. |
| CVE-2016-15038 | “deletefile.php”; “filename”; “path traversal” | C:N->H; I:L->H; A:L->H | 6.5->9.8 | Prediction nâng cả ba tác động lên High. Tên deletefile gợi ý thao tác xóa nhưng không chứng minh đọc bí mật hoặc phá hủy toàn bộ dịch vụ. Cần phạm vi file và quyền tiến trình; không suy High từ chữ critical trong description. |
| CVE-2016-20021 | “missing PGP validation of executed code”; “Unless emerge-webrsync is used” | C:H->N | 9.8->9.1 | Cần hiểu chuỗi thiếu kiểm chữ ký -> thực thi mã -> truy cập tài nguyên theo quyền mã. Không có chữ leak không có nghĩa C:N. Điều kiện dùng emerge-webrsync còn là điều kiện applicability, không bỏ qua khi diễn giải. |
| CVE-2023-38709 | “backend/content generators to split HTTP responses” | C:L->N; I:L->H; A:L->H | 7.3->9.1 | Web thuộc scope v1. Mô tả response splitting chưa định lượng mức kiểm soát dữ liệu/gián đoạn; model vừa bỏ Confidentiality vừa tăng Integrity/Availability. Cần xem cấu hình backend và cách response đến người dùng; chưa thể kết luận H chỉ từ thuật ngữ split. |
| CVE-2023-48297 | “expanded chat mentions (@all and @here)”; “very long array of users” | PR:N->L; C:N->L; A:H->N | 7.5->4.3 | Web thuộc scope v1. Kích thước mảng gợi ý tiêu thụ tài nguyên/Availability; prediction bỏ A và thêm Confidentiality. Description chưa đủ quyết PR; việc có mentions không chứng minh caller phải đăng nhập. |
| CVE-2019-19754 | “SSH host keys baked into the installation image”; “man-in-the-middle” | AV:A->N; AC:L->H; UI:R->N; I:N->H | 5.7->7.4 | Tìm thấy public IP không đồng nghĩa đường khai thác không cần vị trí trung gian mạng. MITM và host key có sẵn phải được diễn giải theo điều kiện kết nối/trust. Description chưa đủ định lượng UI/I; không tự sửa nguồn từ suy luận về SSH. |

## 4. Kết luận review và bàn giao

- Đã xem 13 CVE lỗi thật, có hai case scoped Web; không có mobile validation.
- PR/UI cần phân biệt attacker với nạn nhân; Scope cần security authority chứ không
  chỉ loại XSS; C/I/A cần chuỗi hậu quả và mức độ cụ thể.
- Mơ hồ hoặc thiếu dữ kiện của description là giới hạn input; nhận định nguyên nhân
  model chỉ là giả thuyết khi chưa có attribution/ablation.
- Không sửa ground truth, train lại, chọn cấu hình hoặc đọc lỗi test cho review này.
- N3 có thể tổng hợp báo cáo N2 này vào model card; N2 không ghi đè file N3 sở hữu.
- Phần review N2 đã hoàn thành. N1 reproduction, D05/DistilBERT và xác nhận tích hợp
  của nhóm vẫn là các mục riêng, không suy là đã xong từ báo cáo này.

- [x] Nhận artifact lỗi validation đã push từ N3.
- [x] Kiểm dataset/model version, split, nhãn nguồn, vector và score.
- [x] Review 13 lỗi khác nhau và nêu coverage/giới hạn.
- [x] Báo cáo N2 đã có trên PR #6, base `develop`, để N3 tổng hợp model card.
- [ ] N3 xác nhận tiếp nhận/tổng hợp; chưa có bằng chứng xác nhận.
