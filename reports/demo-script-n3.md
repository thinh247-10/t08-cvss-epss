# Thao tác và lời dẫn N3 — demo dự kiến 6 phút

Ngày ghép 23/10/2026. Đã nhận nguyên bản lời thoại N2 tại commit
`43ce98028a817eff7643581a26e48cd9fd233408`; xem
[bản N2](demo-script-security.md) và [receipt](../docs/handoffs/p4-n2-received-by-n3-20261023.json).
Đây là phần ghép thao tác của N3, chưa thay script cuối hoặc xác nhận N1/N2.
Người dùng xác nhận hiện chỉ có handoff Phase 3, chưa có runbook/diễn tập riêng.

## Trước khi bắt đầu

Chạy theo [hướng dẫn máy nhận N3](../docs/demo-receiver-n3.md).
Mở `notebooks/03_demo.ipynb` đã thực thi; thu gọn code, giữ output.
Chuẩn bị dự phòng `offline-demo.html` trong ZIP có receipt. Khi xem output cũ,
luôn nói “kết quả đã lưu”; chỉ nói “vừa chạy” khi vừa thực thi cell/lệnh live.
Lần chạy 5–6 giây trong log là thời gian máy tính, không phải thời gian thuyết trình.

## 0:00–0:45 — Tổng quan, code cell 2

Mở summary và scatter. Nói theo đoạn đầu N2: 396 CVE (388 Web/8 mobile), 3 KEV;
EPSS 29/09, KEV phát hành 30/09 và tải 01/10 UTC. Đây là snapshot cố định và
inventory giả định, không phải dữ liệu thời gian thực. Không-KEV không chứng minh
chưa từng khai thác. Nhấn câu hỏi “xác minh và vá cái nào trước?”.

## 0:45–2:00 — Top-50, code cell 3

Chỉ đủ hai trang 1–25 và 26–50; xem hàng CVE-2023-23752 vừa được ghép vào cell:
Base 5.3, EPSS 0.99827, KEV=true, EPSS/KEV-first rank 3.
Theo N2: CVSS đo severity, EPSS ước lượng khả năng khai thác, KEV-first là policy.
CVSS/EPSS top-50 chung 10 CVE; Jaccard khoảng 0.111. CVSS chứa 1/3 KEV,
EPSS 3/3; KEV-first recall N/A vì dùng trực tiếp KEV. Không kết luận mô hình thắng
forecast từ snapshot chỉ 3 KEV. Không đọc từng dòng bảng, chỉ chỉ ví dụ và mẫu số.

## 2:00–3:30 — Web, code cell 4

PgHero CVE-2023-22626/ADMIN-01: giả định 3.0.1 internal, Base 7.5 → Env 9.3.
Mở hàng context từ artifact: Base rank 2, Env rank 1, queue rank 8,
sensitivity rank 2 trên cùng 8 patch pairs. Không suy internal là an toàn.
API-02 cùng CVE vẫn review, thiếu product/version nên Env/rank N/A.
Chuyển sang Discourse CVE-2022-46177/API-01: bản giả định 2.8.13,
Base 8.1 → Env 8.8, Internet, queue rank 2. Xác minh applicability trước quyết định.
Điểm Environmental không phải xác suất; không sửa vector quan sát cho khớp advisory.

## 3:30–4:30 — Mobile, code cell 5

MOB-02/CVE-2023-41387: iOS/flutter_downloader 1.11.1 giả định, Base 9.1,
EPSS 0.00874, Env 9.8. Chỉ trạng thái review_required và priority rank N/A;
client chưa có policy exposure số, không đổi thành Internet. Review không cho phép
bỏ qua vá. CVE này thuộc train nên không có prediction held-out để đánh giá AI.

## 4:30–5:20 — AI, code cell 6

Chọn CVE-2023-38709, validation. Chỉ bảng tám metric AV/AC/PR/UI/S/C/I/A:
quan sát C:L/I:L/A:L; TF-IDF dự đoán C:N/I:H/A:H. Base 7.3 khác 9.1.
Vector quan sát và dự đoán ở hai cột riêng. Model là
`tfidf-v1-n1-reproduction-20261017`, bản N1 khóa; không gọi model gốc N3.

- Nếu vừa chạy `predict CVE-2023-38709 --live`: nói “TF-IDF CPU vừa dự đoán từ mô tả
  validation, mode live; không train lại”.
- Nếu mở notebook/HTML output cũ hoặc fallback: nói “đây là kết quả đã lưu”.
- Nếu live không khả dụng: đọc fallback_reason; giữ mode saved, không đổi model khác.

Tập validation chung 69 CVE, rank observed 25/predicted 2, delta +23.
Test N=108 đọc riêng. Sai số làm thay thứ tự severity, không đo hiệu quả vá;
không dùng test để tuning và không khái quát sang mobile khi không có held-out mobile.

## 5:20–6:00 — Kết luận, code cell 7

15 mapping = 15 cặp CVE–tài sản, không phải 15 deployment; 8 patch/7 review.
Trước hành động: xác minh ảnh hưởng, chọn bản còn hỗ trợ có fix, backup/rollback,
staging và kiểm sau vá. Chính sách/SLA là giả định; chưa đo giảm rủi ro thực tế.
AI và tín hiệu giúp người phân tích, quyết định cuối cần bằng chứng tài sản.

## Phiếu ghi diễn tập thật

Chưa có người nói/thao tác trong phiên kiểm tự động. Không điền thời lượng giả.

| Đoạn | Dự kiến | Thời gian thực tế | Người nói/thao tác | Lỗi/feedback |
|---|---|---|---|---|
| Tổng quan | 45 giây | pending | pending | pending |
| Top-50 | 75 giây | pending | pending | pending |
| Web | 90 giây | pending | pending | pending |
| Mobile | 60 giây | pending | pending | pending |
| AI | 50 giây | pending | pending | pending |
| Quyết định | 40 giây | pending | pending | pending |

Ghi thêm commit, input receipt, model/mode, ngày/máy, tổng thời lượng và người
xác nhận nội dung. N2 dùng [báo cáo N3](p4_n3_delivery.md) để review màn hình;
không đổi các ô pending trong báo cáo N2 thay thành viên đó.
